-- ElastiCache IAM Authentication Module for OpenResty/nginx
-- This module replicates the functionality of IAMAuthTokenGeneratorApp.java
-- using lua-resty-aws with IRSA (IAM Roles for Service Accounts) support

local aws_config = require("resty.aws.config")
local aws = require("resty.aws")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")
local cjson = require("cjson")

local _M = {}

-- Cache for AWS client and credentials
local aws_client = nil
local credential_cache = {}
local cache_expiry = 0

-- ElastiCache IAM Auth Token configuration
local TOKEN_EXPIRY_SECONDS = 900  -- 15 minutes
local SERVICE_NAME = "elasticache"
local ACTION_NAME = "connect"

-- Initialize AWS configuration (should be called in init_by_lua)
function _M.init()
    -- This will automatically pick up IRSA credentials from environment:
    -- AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE, AWS_REGION, etc.
    local config = aws_config.global
    aws_client = aws(config)
    
    ngx.log(ngx.INFO, "ElastiCache IAM Auth initialized with IRSA support")
    return true
end

-- Get AWS credentials with caching
local function get_credentials()
    local now = ngx.time()
    
    -- Check if cached credentials are still valid
    if credential_cache.credentials and now < cache_expiry then
        return credential_cache.credentials
    end
    
    -- Get fresh credentials from AWS
    local config = aws_config.global
    local credentials_provider = config.credentials
    
    if not credentials_provider then
        ngx.log(ngx.ERR, "No AWS credentials provider available")
        return nil, "No AWS credentials provider"
    end
    
    local credentials = credentials_provider:resolveCredentials()
    if not credentials then
        ngx.log(ngx.ERR, "Failed to resolve AWS credentials")
        return nil, "Failed to resolve credentials"
    end
    
    -- Cache credentials for 5 minutes (they typically last much longer)
    credential_cache.credentials = credentials
    cache_expiry = now + 300
    
    ngx.log(ngx.DEBUG, "Retrieved fresh AWS credentials")
    return credentials
end

-- Create canonical request for ElastiCache IAM auth
local function create_canonical_request(replication_group_id, user_id, timestamp)
    local method = "GET"
    local uri = "/" .. replication_group_id .. "/"
    local query_string = "Action=" .. ACTION_NAME .. "&User=" .. user_id
    local headers = "host:" .. replication_group_id
    local signed_headers = "host"
    local payload_hash = resty_string.to_hex(resty_sha256:new():update(""):final())
    
    local canonical_request = method .. "\n" ..
                             uri .. "\n" ..
                             query_string .. "\n" ..
                             headers .. "\n\n" ..
                             signed_headers .. "\n" ..
                             payload_hash
    
    return canonical_request, signed_headers
end

-- Create string to sign for AWS Signature Version 4
local function create_string_to_sign(canonical_request, timestamp, region)
    local algorithm = "AWS4-HMAC-SHA256"
    local credential_scope = os.date("!%Y%m%d", timestamp) .. "/" .. region .. "/" .. SERVICE_NAME .. "/aws4_request"
    local canonical_request_hash = resty_string.to_hex(resty_sha256:new():update(canonical_request):final())
    
    local string_to_sign = algorithm .. "\n" ..
                          os.date("!%Y%m%dT%H%M%SZ", timestamp) .. "\n" ..
                          credential_scope .. "\n" ..
                          canonical_request_hash
    
    return string_to_sign, credential_scope
end

-- Calculate AWS Signature Version 4 signing key
local function get_signing_key(secret_key, timestamp, region)
    local function hmac_sha256(key, data)
        return ngx.hmac_sha256(key, data)
    end
    
    local date_stamp = os.date("!%Y%m%d", timestamp)
    local k_date = hmac_sha256("AWS4" .. secret_key, date_stamp)
    local k_region = hmac_sha256(k_date, region)
    local k_service = hmac_sha256(k_region, SERVICE_NAME)
    local k_signing = hmac_sha256(k_service, "aws4_request")
    
    return k_signing
end

-- Generate AWS Signature Version 4 signature
local function calculate_signature(string_to_sign, signing_key)
    local signature = ngx.hmac_sha256(signing_key, string_to_sign)
    return resty_string.to_hex(signature)
end

-- Generate ElastiCache IAM Auth Token
function _M.generate_token(user_id, replication_group_id, region)
    -- Validate inputs
    if not user_id or user_id == "" then
        return nil, "user_id cannot be null or empty"
    end
    if not replication_group_id or replication_group_id == "" then
        return nil, "replication_group_id cannot be null or empty" 
    end
    if not region then
        region = "us-east-1"  -- Default region
    end
    
    -- Get AWS credentials
    local credentials, err = get_credentials()
    if not credentials then
        return nil, "Failed to get AWS credentials: " .. (err or "unknown error")
    end
    
    -- Calculate expiry time (15 minutes from now)
    local timestamp = ngx.time()
    local expiry_timestamp = timestamp + TOKEN_EXPIRY_SECONDS
    
    -- Create canonical request
    local canonical_request, signed_headers = create_canonical_request(replication_group_id, user_id, timestamp)
    
    -- Create string to sign
    local string_to_sign, credential_scope = create_string_to_sign(canonical_request, timestamp, region)
    
    -- Calculate signature
    local signing_key = get_signing_key(credentials.secretAccessKey, timestamp, region)
    local signature = calculate_signature(string_to_sign, signing_key)
    
    -- Build authorization header
    local authorization = "AWS4-HMAC-SHA256 " ..
                         "Credential=" .. credentials.accessKeyId .. "/" .. credential_scope .. "," ..
                         "SignedHeaders=" .. signed_headers .. "," ..
                         "Signature=" .. signature
    
    -- Construct the pre-signed URL (this is what becomes the auth token)
    local query_params = {
        "Action=" .. ACTION_NAME,
        "User=" .. user_id,
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "X-Amz-Credential=" .. ngx.escape_uri(credentials.accessKeyId .. "/" .. credential_scope),
        "X-Amz-Date=" .. os.date("!%Y%m%dT%H%M%SZ", timestamp),
        "X-Amz-Expires=" .. TOKEN_EXPIRY_SECONDS,
        "X-Amz-SignedHeaders=" .. signed_headers,
        "X-Amz-Signature=" .. signature
    }
    
    -- Add session token if present (for temporary credentials like IRSA)
    if credentials.sessionToken then
        table.insert(query_params, "X-Amz-Security-Token=" .. ngx.escape_uri(credentials.sessionToken))
    end
    
    local query_string = table.concat(query_params, "&")
    local signed_url = replication_group_id .. "/?" .. query_string
    
    ngx.log(ngx.DEBUG, "Generated ElastiCache IAM auth token for user: " .. user_id)
    return signed_url
end

-- Get cached token or generate new one
local token_cache = {}
function _M.get_cached_token(user_id, replication_group_id, region)
    local cache_key = user_id .. ":" .. replication_group_id .. ":" .. (region or "us-east-1")
    local now = ngx.time()
    
    -- Check if we have a valid cached token
    local cached = token_cache[cache_key]
    if cached and now < cached.expiry then
        ngx.log(ngx.DEBUG, "Using cached ElastiCache token for: " .. cache_key)
        return cached.token
    end
    
    -- Generate new token
    local token, err = _M.generate_token(user_id, replication_group_id, region)
    if not token then
        ngx.log(ngx.ERR, "Failed to generate ElastiCache token: " .. (err or "unknown error"))
        return nil, err
    end
    
    -- Cache the token (expires 5 minutes before AWS expiry for safety)
    token_cache[cache_key] = {
        token = token,
        expiry = now + TOKEN_EXPIRY_SECONDS - 300  -- 10 minutes cache
    }
    
    return token
end

return _M
