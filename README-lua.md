# ElastiCache IAM Authentication with Lua and IRSA

This implementation provides ElastiCache IAM authentication using Lua modules that work with your existing IRSA (IAM Roles for Service Accounts) setup in EKS.

## Prerequisites

1. **OpenResty or nginx with Lua support**
2. **lua-resty-aws** - AWS SDK for OpenResty
3. **lua-resty-redis** - Redis client for OpenResty
4. **IRSA configured** - Your pod should have AWS environment variables set up

## Installation

### 1. Install Required Lua Modules

```bash
# Install lua-resty-aws (Kong's AWS SDK)
luarocks install lua-resty-aws

# Install Redis client
luarocks install lua-resty-redis

# Install additional dependencies
luarocks install lua-resty-string
```

### 2. Verify IRSA Environment

Your pod should have these environment variables (check with `env | grep AWS`):
```bash
AWS_REGION=us-west-2
AWS_ROLE_ARN=arn:aws:iam::YOUR-ACCOUNT:role/YOUR-IRSA-ROLE
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
AWS_STS_REGIONAL_ENDPOINTS=regional
```

### 3. Copy Lua Modules

Copy the Lua modules to your nginx/OpenResty Lua path:
```bash
# Copy to your Lua modules directory
cp lua/*.lua /usr/local/openresty/site/lualib/
# or
cp lua/*.lua /usr/local/share/lua/5.1/
```

### 4. Configure nginx

Update your nginx configuration:
```nginx
# Add Lua package path
lua_package_path "/path/to/lua/modules/?.lua;;";

# Initialize in init phase (REQUIRED for IRSA)
init_by_lua_block {
    local redis_demo = require("redis_iam_demo")
    redis_demo.init()
}
```

## Usage Examples

### Basic Usage in Lua Code

```lua
local redis_demo = require("redis_iam_demo")

-- Configuration
local config = {
    redis_host = "your-cluster.xxxxx.cache.amazonaws.com",
    redis_port = 6379,
    user_id = "your-elasticache-user",
    replication_group_id = "your-replication-group",
    region = "us-west-2",
    tls = true
}

-- Connect and perform operations
local success, result = redis_demo.redis_example(config)
if success then
    print("Redis operations successful!")
else
    print("Error: " .. result)
end
```

### Generate Token Only

```lua
local IAMAuthTokenRequest = require("iam_auth_token_request")
local aws_config = require("resty.aws.config")

-- Get credentials from IRSA
local config = aws_config.global
local credentials = config.credentials:resolveCredentials()

-- Generate token
local token_request = IAMAuthTokenRequest.new(
    "your-user-id", 
    "your-replication-group-id", 
    "us-west-2"
)
local token = token_request:to_signed_request_uri(credentials)
print("IAM Auth Token: " .. token)
```

## HTTP API Endpoints

If using the provided nginx configuration:

### Test Redis Connection
```bash
curl http://localhost/test-redis
```

### Generate Token
```bash
curl "http://localhost/generate-token?user_id=test-user&replication_group_id=my-rg"
```

### Check AWS Environment
```bash
curl http://localhost/aws-info
```

### Continuous Connection Test
```bash
curl http://localhost/test-redis-continuous
```

## Configuration Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `redis_host` | ElastiCache endpoint | Yes | - |
| `redis_port` | Redis port | No | 6379 |
| `user_id` | ElastiCache IAM user | Yes | - |
| `replication_group_id` | ElastiCache replication group ID | Yes | - |
| `region` | AWS region | No | us-east-1 |
| `tls` | Enable TLS/SSL | No | false |

## How It Works

1. **IRSA Integration**: The modules automatically detect and use IRSA credentials from environment variables
2. **Token Generation**: Implements AWS Signature Version 4 signing identical to the Java SDK
3. **Token Caching**: Caches tokens for 10 minutes (tokens are valid for 15 minutes)
4. **Redis Authentication**: Uses the generated token as the password for Redis AUTH command

## Troubleshooting

### Check IRSA Setup
```bash
# In your pod
env | grep AWS
ls -la /var/run/secrets/eks.amazonaws.com/serviceaccount/
```

### Enable Debug Logging
```nginx
error_log /var/log/nginx/error.log debug;
```

### Test AWS Credentials
```bash
# If AWS CLI is available
aws sts get-caller-identity
```

### Common Issues

1. **"No AWS credentials provider available"**
   - Verify IRSA environment variables are set
   - Check that the serviceaccount token file exists

2. **"Redis IAM authentication failed"**
   - Verify the IRSA role has ElastiCache permissions
   - Check that user_id exists in ElastiCache
   - Ensure replication_group_id is correct

3. **"attempt to yield across C-call boundary"**
   - Make sure to call `redis_demo.init()` in `init_by_lua_block`
   - Don't call AWS functions at module load time

## Comparison with Java Implementation

This Lua implementation provides the same functionality as the Java version:

| Feature | Java | Lua |
|---------|------|-----|
| IRSA Support | ✅ DefaultCredentialsProvider | ✅ lua-resty-aws |
| Token Generation | ✅ IAMAuthTokenRequest | ✅ iam_auth_token_request.lua |
| Token Caching | ✅ Redis credentials provider | ✅ Built-in caching |
| Redis Connection | ✅ Lettuce client | ✅ lua-resty-redis |
| Performance | ~100-200ms startup | ~1-5ms per request |

## Security Notes

- Tokens are cached in memory only
- IRSA tokens are automatically rotated by Kubernetes
- All network communication can use TLS
- No credentials are logged (only token generation events)
