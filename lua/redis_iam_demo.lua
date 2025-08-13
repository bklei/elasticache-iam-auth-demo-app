-- Complete Redis ElastiCache IAM Authentication Example
-- This demonstrates how to connect to Redis using IAM authentication
-- equivalent to the Java IAMAuthDemoApp

local aws_config = require("resty.aws.config")
local IAMAuthTokenRequest = require("iam_auth_token_request")
local redis = require("resty.redis")  -- lua-resty-redis

local _M = {}

-- Configuration
local DEFAULT_REGION = "us-east-1"
local DEFAULT_PORT = 6379
local CONNECTION_TIMEOUT = 5000  -- 5 seconds
local SEND_TIMEOUT = 5000       -- 5 seconds  
local READ_TIMEOUT = 5000       -- 5 seconds

-- Token cache
local token_cache = {}
local TOKEN_CACHE_SECONDS = 600  -- 10 minutes (tokens last 15)

-- Initialize AWS configuration (call this in init_by_lua_block)
function _M.init()
    -- This automatically picks up IRSA configuration:
    -- AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE, AWS_REGION
    local config = aws_config.global
    
    ngx.log(ngx.INFO, "Redis ElastiCache IAM Auth initialized")
    ngx.log(ngx.INFO, "AWS Region: " .. (config.region or "not set"))
    
    return true
end

-- Get cached IAM auth token or generate a new one
local function get_iam_auth_token(user_id, replication_group_id, region)
    local cache_key = user_id .. ":" .. replication_group_id .. ":" .. region
    local now = ngx.time()
    
    -- Check cache first
    local cached = token_cache[cache_key]
    if cached and now < cached.expiry then
        ngx.log(ngx.DEBUG, "Using cached IAM auth token for " .. cache_key)
        return cached.token
    end
    
    -- Generate new token
    ngx.log(ngx.DEBUG, "Generating new IAM auth token for " .. cache_key)
    
    -- Get AWS credentials (from IRSA or other provider)
    local config = aws_config.global
    local credentials_provider = config.credentials
    
    if not credentials_provider then
        return nil, "No AWS credentials provider available"
    end
    
    local credentials = credentials_provider:resolveCredentials()
    if not credentials then
        return nil, "Failed to resolve AWS credentials"
    end
    
    -- Create IAM auth token request and sign it
    local iam_auth_request = IAMAuthTokenRequest.new(user_id, replication_group_id, region)
    local token = iam_auth_request:to_signed_request_uri(credentials)
    
    if not token then
        return nil, "Failed to generate IAM auth token"
    end
    
    -- Cache the token
    token_cache[cache_key] = {
        token = token,
        expiry = now + TOKEN_CACHE_SECONDS
    }
    
    ngx.log(ngx.INFO, "Generated new IAM auth token for user: " .. user_id)
    return token
end

-- Connect to Redis with IAM authentication
function _M.connect_redis(config)
    -- Validate required parameters
    if not config.redis_host then
        return nil, "redis_host is required"
    end
    if not config.user_id then
        return nil, "user_id is required"
    end
    if not config.replication_group_id then
        return nil, "replication_group_id is required"
    end
    
    -- Set defaults
    local redis_host = config.redis_host
    local redis_port = config.redis_port or DEFAULT_PORT
    local user_id = config.user_id
    local replication_group_id = config.replication_group_id
    local region = config.region or DEFAULT_REGION
    local tls_enabled = config.tls or false
    
    -- Get IAM auth token
    local token, err = get_iam_auth_token(user_id, replication_group_id, region)
    if not token then
        return nil, "Failed to get IAM auth token: " .. (err or "unknown error")
    end
    
    -- Create Redis connection
    local red = redis:new()
    red:set_timeouts(CONNECTION_TIMEOUT, SEND_TIMEOUT, READ_TIMEOUT)
    
    -- Connect to Redis
    local connect_opts = {
        ssl = tls_enabled,
        ssl_verify = tls_enabled
    }
    
    local ok, err = red:connect(redis_host, redis_port, connect_opts)
    if not ok then
        return nil, "Failed to connect to Redis: " .. (err or "unknown error")
    end
    
    -- Authenticate using IAM token
    local auth_result, err = red:auth(user_id, token)
    if not auth_result or auth_result == ngx.null then
        red:close()
        return nil, "Redis IAM authentication failed: " .. (err or "unknown error")
    end
    
    ngx.log(ngx.INFO, "Successfully connected to Redis with IAM auth")
    return red
end

-- Example usage function - performs Redis operations
function _M.redis_example(config)
    local red, err = _M.connect_redis(config)
    if not red then
        ngx.log(ngx.ERR, "Failed to connect to Redis: " .. err)
        return false, err
    end
    
    -- Perform some Redis operations
    local operations_count = 0
    
    -- SET operation
    local set_result, err = red:set("test_key", "Hello from Lua with IAM auth!")
    if not set_result then
        ngx.log(ngx.ERR, "Redis SET failed: " .. (err or "unknown"))
        red:close()
        return false, err
    end
    operations_count = operations_count + 1
    
    -- GET operation  
    local get_result, err = red:get("test_key")
    if not get_result then
        ngx.log(ngx.ERR, "Redis GET failed: " .. (err or "unknown"))
        red:close()
        return false, err
    end
    operations_count = operations_count + 1
    
    -- PING operation
    local ping_result, err = red:ping()
    if not ping_result then
        ngx.log(ngx.ERR, "Redis PING failed: " .. (err or "unknown"))
        red:close()
        return false, err
    end
    operations_count = operations_count + 1
    
    -- Close connection
    red:close()
    
    ngx.log(ngx.INFO, "Successfully performed " .. operations_count .. " Redis operations")
    return true, {
        operations = operations_count,
        set_result = set_result,
        get_result = get_result,
        ping_result = ping_result
    }
end

-- Continuous connection test (similar to Java demo app)
function _M.continuous_test(config)
    local sleep_time = config.sleep_time or 1
    local max_iterations = config.max_iterations or 10
    local connections = 0
    
    for i = 1, max_iterations do
        local success, result = _M.redis_example(config)
        
        if success then
            connections = connections + 1
            ngx.log(ngx.INFO, "=> Successful connections: " .. connections)
        else
            ngx.log(ngx.ERR, "Connection failed: " .. (result or "unknown error"))
        end
        
        -- Sleep between iterations
        if i < max_iterations then
            ngx.sleep(sleep_time)
        end
    end
    
    return connections
end

return _M
