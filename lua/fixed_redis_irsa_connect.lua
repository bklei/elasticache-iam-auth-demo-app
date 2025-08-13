local ngx                    = require "ngx"
local redis                  = require "resty.redis"
local http                   = require "resty.http"
local sha256                 = require "resty.sha256"
local hmac                   = require "hpe.hmac"
local str                    = require "resty.string"

--
-- Close unused connections after 10 seconds,
-- starting pool size at 250:
--  (max connections/(num_workers * max pods))
--  (10000/(8 * 5))
--
local redis_max_idle_timeout = 10000
local redis_pool_size        = 250
local ssl_options            = {
  ssl = true,
  verify_ssl = true,
}

local _M                     = {}

-- token cache for elasticache auth
local token_cache            = ngx.shared.token_cache

-------------------------------
-- utility functions
-------------------------------

-- compute hmac-sha256; returns raw binary digest
local function hmac_sha256(key, data)
  local algo = hmac.ALGOS.SHA256
  local hm, err = hmac:new(key, algo)
  if not hm then
    error("failed to create hmac object: " .. (err or "unknown error"))
  end
  hm:update(data)
  return hm:final()
end

-- compute sha256 hash and return hex string
local function sha256_hash(data)
  local hash = sha256:new()
  hash:update(data)
  return str.to_hex(hash:final())
end

-- simple url encoding
local function urlencode(url)
  if url then
    url = string.gsub(url, "\n", "\r\n")
    url = string.gsub(url, "([^%w%-_%.~])", function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  end
  return url
end

-------------------------------
-- generate Elasticache auth token using sigv4
-------------------------------
local function generate_elasticache_auth_token(replication_group_id, user_id, region, access_key, secret_key, session_token, elasticache_host)
  local timestamp = ngx.time()
  local amz_date = os.date("!%Y%m%dT%H%M%SZ", timestamp)
  local short_date = amz_date:sub(1, 8)
  local service = "elasticache"
  local expires = 900
  
  -- Use replication_group_id as host for signing
  local host = replication_group_id
  
  -- Create the credential scope
  local credential_scope = short_date .. "/" .. region .. "/" .. service .. "/aws4_request"
  local credential = access_key .. "/" .. credential_scope
  
  -- Build query parameters for presigned URL
  local query_params = {
    {"Action", "connect"},
    {"User", user_id}
  }
  
  -- Add session token if present
  if session_token then
    table.insert(query_params, {"X-Amz-Security-Token", session_token})
  end
  
  -- Continue with remaining parameters
  table.insert(query_params, {"X-Amz-Algorithm", "AWS4-HMAC-SHA256"})
  table.insert(query_params, {"X-Amz-Date", amz_date})
  table.insert(query_params, {"X-Amz-SignedHeaders", "host"})
  table.insert(query_params, {"X-Amz-Expires", tostring(expires)})
  table.insert(query_params, {"X-Amz-Credential", credential})
  
  -- Sort parameters lexicographically for canonical query string
  table.sort(query_params, function(a, b) return a[1] < b[1] end)
  
  -- Build canonical query string
  local canonical_parts = {}
  for _, param in ipairs(query_params) do
    table.insert(canonical_parts, urlencode(param[1]) .. "=" .. urlencode(param[2]))
  end
  local canonical_query_string = table.concat(canonical_parts, "&")
  
  -- Build canonical request
  local canonical_uri = "/" .. replication_group_id .. "/"
  local canonical_headers = "host:" .. host .. "\n"
  local signed_headers = "host"
  local payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  -- Empty payload
  
  local canonical_request = table.concat({
    "GET",
    canonical_uri,
    canonical_query_string,
    canonical_headers,
    signed_headers,
    payload_hash
  }, "\n")
  
  -- Create string to sign
  local hashed_canonical_request = sha256_hash(canonical_request)
  local string_to_sign = table.concat({
    "AWS4-HMAC-SHA256",
    amz_date,
    credential_scope,
    hashed_canonical_request
  }, "\n")
  
  -- Calculate signature
  local kDate = hmac_sha256("AWS4" .. secret_key, short_date)
  local kRegion = hmac_sha256(kDate, region)
  local kService = hmac_sha256(kRegion, service)
  local kSigning = hmac_sha256(kService, "aws4_request")
  local signature = str.to_hex(hmac_sha256(kSigning, string_to_sign))
  
  -- Add signature to query string
  local final_query = canonical_query_string .. "&X-Amz-Signature=" .. signature
  
  -- Return the presigned URL without protocol
  local result = replication_group_id .. "/?" .. final_query
  return result
end

-------------------------------
-- STS AssumeRoleWithWebIdentity (unchanged - this part looks correct)
-------------------------------
local function assume_role_with_sts(role_arn, role_session_name, region)
  -- check for cached keys
  local cached_access_key    = token_cache:get("sts_access_key")
  local cached_secret_key    = token_cache:get("sts_secret_key")
  local cached_session_token = token_cache:get("sts_session_token")

  if not (cached_access_key and cached_secret_key and cached_session_token) then
    -- read the web identity token from the file
    local token_file = os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE") or
        "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    local f, err     = io.open(token_file, "r")
    if not f then
      ngx.log(ngx.ERR, "failed to open web identity token file: " .. tostring(err))
      error("failed to open web identity token file: " .. tostring(err))
    end
    local web_identity_token = f:read("*a")
    f:close()

    -- build query parameters for the STS request
    local params = {
      Action = "AssumeRoleWithWebIdentity",
      RoleArn = role_arn,
      RoleSessionName = role_session_name,
      WebIdentityToken = web_identity_token,
      Version = "2011-06-15"
    }
    local query = ""
    for k, v in pairs(params) do
      query = query .. k .. "=" .. urlencode(v) .. "&"
    end
    query = query:sub(1, -2) -- remove trailing '&'

    local sts_url = "https://sts." .. region .. ".amazonaws.com/?" .. query

    local httpc = http.new()
    local res, err = httpc:request_uri(sts_url, { method = "GET", ssl_verify = true })
    if not res then
      ngx.log(ngx.ERR, "failed to call sts: " .. tostring(err))
      error("failed to call sts: " .. tostring(err))
    end
    if res.status ~= 200 then
      ngx.log(ngx.ERR, "sts returned non-200 (" .. tostring(res.status) .. "): " .. tostring(res.body))
      error("sts returned non-200 (" .. tostring(res.status) .. "): " .. tostring(res.body))
    end

    -- simple xml parsing to extract temporary credentials
    local xml = res.body
    local temp_access_key = xml:match("<AccessKeyId>(.-)</AccessKeyId>")
    local temp_secret_key = xml:match("<SecretAccessKey>(.-)</SecretAccessKey>")
    local temp_session_token = xml:match("<SessionToken>(.-)</SessionToken>")
    if not (temp_access_key and temp_secret_key and temp_session_token) then
      ngx.log(ngx.ERR, "failed to parse sts response: " .. tostring(xml))
      error("failed to parse sts response: " .. tostring(xml))
    end

    -- cache the keys with a ttl of 3600 seconds (1 hour)
    token_cache:set("sts_access_key", temp_access_key, 3600)
    token_cache:set("sts_secret_key", temp_secret_key, 3600)
    token_cache:set("sts_session_token", temp_session_token, 3600)

    return temp_access_key, temp_secret_key, temp_session_token
  else
    ngx.log(ngx.INFO, "using cached sts role keys")
    return cached_access_key, cached_secret_key, cached_session_token
  end
end

--------------------------------------------
-- Get cached token with proper parameters
--------------------------------------------
local function get_auth_token(replication_group_id, user_id, elasticache_host)
  -- read required env variables
  local role_arn = os.getenv("AWS_ROLE_ARN")
  if not role_arn then error("missing AWS_ROLE_ARN") end
  local role_session_name = os.getenv("AWS_ROLE_SESSION_NAME") or "nginx-ingress"
  local region = os.getenv("AWS_REGION") or "us-west-2"

  local cache_key = "elasticache_auth_token:" .. replication_group_id .. ":" .. user_id
  local auth_token = token_cache:get(cache_key)
  
  if auth_token then
    ngx.log(ngx.INFO, "using cached token for " .. cache_key)
  else
    -- Generate new token
    local access_key, secret_key, session_token = assume_role_with_sts(role_arn, role_session_name, region)
    
    auth_token = generate_elasticache_auth_token(replication_group_id, user_id, region, access_key, secret_key, session_token, elasticache_host)
    
    ngx.log(ngx.INFO, "generated fresh token: " .. cache_key)
    token_cache:set(cache_key, auth_token, 900)
  end
  return auth_token
end

-------------------------------
-- Set keepalive for redis connection (unchanged)
-------------------------------
function _M.set_keepalive(red, host)
  ngx.log(ngx.INFO, "adding " .. host .. " to connection pool")
  local ok, err = red:set_keepalive(redis_max_idle_timeout, redis_pool_size)
  if not ok then
    ngx.log(ngx.WARN, "continuing without adding " .. host .. " to connection pool - error: ", err)
  end
end

-------------------------------
-- Generate Elasticache token and connect with authentication
-------------------------------
function _M.connect(elasticache_host, elasticache_port, replication_group_id, user_id)
  ngx.log(ngx.INFO, string.format("Connecting to redis with host: %s on port: %s", elasticache_host, tostring(elasticache_port)))
  
  -- Extract replication_group_id from host if not provided
  if not replication_group_id then
    -- Extract from clustercfg.replication-group-id.hash.region.cache.amazonaws.com
    local extracted_id = elasticache_host:match("clustercfg%.([^%.]+)%.")
    if extracted_id then
      replication_group_id = extracted_id
      ngx.log(ngx.INFO, "Extracted replication group ID: " .. replication_group_id)
    else
      error("replication_group_id is required for IAM authentication and could not be extracted from host")
    end
  end
  
  -- Set default user_id if not provided
  if not user_id then
    user_id = replication_group_id .. "-user"
    ngx.log(ngx.INFO, "Using default user ID: " .. user_id)
  end
  
  local red = redis:new()
  red:set_timeout(5000)
  
  -- Generate auth token with proper parameters
  local auth_token = get_auth_token(replication_group_id, user_id, elasticache_host)
  
  -- Connect to Redis
  local ok, err = red:connect(elasticache_host, elasticache_port, ssl_options)
  if not ok then
    error("failed to connect to elasticache: " .. err)
  end
  
  -- Authenticate with the generated token
  ngx.log(ngx.INFO, "Attempting to authenticate with user: " .. user_id)
  local auth_result, auth_err = red:auth(user_id, auth_token)
  if not auth_result or auth_result == ngx.null then
    red:close()
    error("failed to authenticate with elasticache: " .. (auth_err or "authentication failed"))
  end
  
  ngx.log(ngx.INFO, "Connected and authenticated to Elasticache Redis successfully")
  return red
end

return _M
