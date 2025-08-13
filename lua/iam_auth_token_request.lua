-- ElastiCache IAM Auth Token Request (Lua equivalent of IAMAuthTokenRequest.java)
-- This module implements the exact same signing logic as the Java version

local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

-- Constants matching the Java implementation
local REQUEST_METHOD = "GET"
local REQUEST_PROTOCOL = "http://"
local PARAM_ACTION = "Action"
local PARAM_USER = "User"
local ACTION_NAME = "connect"
local SERVICE_NAME = "elasticache"
local TOKEN_EXPIRY_DURATION_SECONDS = 900

function _M.new(user_id, replication_group_id, region)
    local self = {
        user_id = user_id,
        replication_group_id = replication_group_id,
        region = region or "us-east-1"
    }
    return setmetatable(self, { __index = _M })
end

-- Equivalent to Java's toSignedRequestUri method
function _M:to_signed_request_uri(credentials)
    local request = self:get_signable_request()
    local signed_request = self:sign(request, credentials)
    
    -- Return the signed URI without the protocol prefix
    local uri = signed_request.uri
    if uri:sub(1, #REQUEST_PROTOCOL) == REQUEST_PROTOCOL then
        uri = uri:sub(#REQUEST_PROTOCOL + 1)
    end
    
    return uri
end

-- Equivalent to Java's getSignableRequest method
function _M:get_signable_request()
    local uri = self:get_request_uri()
    
    -- Parse the URI to add query parameters
    local base_uri = uri
    local query_params = {
        [PARAM_ACTION] = ACTION_NAME,
        [PARAM_USER] = self.user_id
    }
    
    return {
        method = REQUEST_METHOD,
        uri = base_uri,
        query_params = query_params,
        headers = {},
        body = ""
    }
end

-- Equivalent to Java's getRequestUri method  
function _M:get_request_uri()
    return REQUEST_PROTOCOL .. self.replication_group_id .. "/"
end

-- Equivalent to Java's sign method using AWS Signature Version 4
function _M:sign(request, credentials)
    local timestamp = ngx.time()
    local expiry_instant = timestamp + TOKEN_EXPIRY_DURATION_SECONDS
    
    -- Parse URI components
    local protocol, host, path = request.uri:match("^(https?://)([^/]+)(.*)$")
    if not path or path == "" then
        path = "/"
    end
    
    -- Build canonical query string for presigning
    local query_params = {}
    for k, v in pairs(request.query_params) do
        table.insert(query_params, k .. "=" .. ngx.escape_uri(tostring(v)))
    end
    
    -- Add AWS signature parameters for presigning
    local date_stamp = os.date("!%Y%m%d", timestamp)
    local amz_date = os.date("!%Y%m%dT%H%M%SZ", timestamp)
    local credential_scope = date_stamp .. "/" .. self.region .. "/" .. SERVICE_NAME .. "/aws4_request"
    
    table.insert(query_params, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
    table.insert(query_params, "X-Amz-Credential=" .. ngx.escape_uri(credentials.accessKeyId .. "/" .. credential_scope))
    table.insert(query_params, "X-Amz-Date=" .. amz_date)
    table.insert(query_params, "X-Amz-Expires=" .. TOKEN_EXPIRY_DURATION_SECONDS)
    table.insert(query_params, "X-Amz-SignedHeaders=host")
    
    -- Add session token if present (required for IRSA)
    if credentials.sessionToken then
        table.insert(query_params, "X-Amz-Security-Token=" .. ngx.escape_uri(credentials.sessionToken))
    end
    
    -- Sort query parameters for canonical request
    table.sort(query_params)
    local canonical_query_string = table.concat(query_params, "&")
    
    -- Create canonical request
    local canonical_headers = "host:" .. host .. "\n"
    local signed_headers = "host"
    local payload_hash = self:sha256_hex("")
    
    local canonical_request = request.method .. "\n" ..
                             path .. "\n" ..
                             canonical_query_string .. "\n" ..
                             canonical_headers .. "\n" ..
                             signed_headers .. "\n" ..
                             payload_hash
    
    -- Create string to sign
    local algorithm = "AWS4-HMAC-SHA256"
    local string_to_sign = algorithm .. "\n" ..
                          amz_date .. "\n" ..
                          credential_scope .. "\n" ..
                          self:sha256_hex(canonical_request)
    
    -- Calculate signature
    local signing_key = self:get_signature_key(credentials.secretAccessKey, date_stamp, self.region)
    local signature = self:hmac_sha256_hex(signing_key, string_to_sign)
    
    -- Add signature to query parameters
    canonical_query_string = canonical_query_string .. "&X-Amz-Signature=" .. signature
    
    -- Return signed request
    return {
        method = request.method,
        uri = protocol .. host .. path .. "?" .. canonical_query_string,
        headers = request.headers,
        body = request.body
    }
end

-- Helper method to calculate signing key (equivalent to AWS SDK's implementation)
function _M:get_signature_key(secret_key, date_stamp, region)
    local function hmac_sha256(key, data)
        return ngx.hmac_sha256(key, data)
    end
    
    local k_date = hmac_sha256("AWS4" .. secret_key, date_stamp)
    local k_region = hmac_sha256(k_date, region)
    local k_service = hmac_sha256(k_region, SERVICE_NAME)
    local k_signing = hmac_sha256(k_service, "aws4_request")
    
    return k_signing
end

-- Helper method for SHA256 hex encoding
function _M:sha256_hex(data)
    local sha256 = resty_sha256:new()
    sha256:update(data)
    return resty_string.to_hex(sha256:final())
end

-- Helper method for HMAC-SHA256 hex encoding
function _M:hmac_sha256_hex(key, data)
    local hmac = ngx.hmac_sha256(key, data)
    return resty_string.to_hex(hmac)
end

return _M
