# Penpal AI - Authentication Service

This microservice handles authentication and user management for the Penpal AI application with enterprise-grade security features.

## Architecture

This service follows a microservice architecture pattern where:

- **Auth Service** (this service): Manages authentication, user registration, and OAuth integrations with advanced security
- **DB Service** (separate): Handles all database operations and is the only service with direct database access

The Auth Service communicates with the DB Service via HTTP requests, maintaining a clear separation of concerns.

## Features

### Core Authentication

- User registration and login
- JWT-based authentication with secure token management
- Advanced OAuth 2.0 authentication with PKCE (Google, Facebook, Apple, GitHub)
- Password reset functionality
- Email verification
- Role-based access control

### Security Features

- **PKCE (Proof Key for Code Exchange)** for OAuth flows
- **State parameter validation** with timing-safe comparison
- **ID token verification** with comprehensive validation
- **Rate limiting** with intelligent IP-based protection
- **CSRF protection** with strict same-site policies
- **Secure session management** with temporary tokens
- **Real-time security monitoring** and anomaly detection
- **Protection against injection attacks** and parameter validation
- **Secure cookie handling** with httpOnly and secure flags

### Monitoring & Security

- Security event logging and tracking
- Rate limiting with automatic IP blocking
- Suspicious activity detection
- Real-time security statistics
- Comprehensive audit trails

## Technology Stack

- [NestJS](https://nestjs.com/) - A progressive Node.js framework
- [MongoDB](https://www.mongodb.com/) - NoSQL database
- [Mongoose](https://mongoosejs.com/) - MongoDB object modeling
- [Passport](https://www.passportjs.org/) - Authentication middleware
- [JWT](https://jwt.io/) - JSON Web Tokens for secure authentication
- [Argon2](https://github.com/ranisalt/node-argon2) - Password hashing
- [LRU Cache](https://github.com/isaacs/node-lru-cache) - Secure state and session management

## Environment Variables

Copy the `.env.example` file to a new file named `.env`:

```bash
cp .env.example .env
```

Then update the values in the `.env` file:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your_strong_jwt_secret_here
JWT_EXPIRES_IN=1d

# DB Service Configuration
DB_SERVICE_URL=http://localhost:3001
DB_SERVICE_API_KEY=your_api_key_here

# OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/oauth/google/callback

# Frontend Configuration
FRONTEND_URL=http://localhost:5173

# Security Configuration (Optional)
OAUTH_MAX_ATTEMPTS=10
OAUTH_WINDOW_MS=900000        # 15 minutes in milliseconds
OAUTH_BLOCK_DURATION_MS=3600000  # 1 hour in milliseconds
```

## API Endpoints

### Authentication

#### Traditional Authentication (Secure Implementation)

- `POST /api/v1/auth/register` - Register a new user with security validation
- `POST /api/v1/auth/login` - Login a user with rate limiting and monitoring
- `POST /api/v1/auth/logout` - Secure logout with cookie cleanup
- `GET /api/v1/auth/security/stats` - Get authentication security statistics

#### OAuth Authentication (Secure Implementation)

- `GET /api/v1/auth/oauth/google/login` - Initiate secure Google OAuth login with PKCE
- `GET /api/v1/auth/oauth/google/callback` - Google OAuth callback with comprehensive validation
- `GET /api/v1/auth/oauth/session/user` - Retrieve user data after OAuth completion
- `POST /api/v1/auth/oauth/facebook` - Facebook OAuth authentication
- `POST /api/v1/auth/oauth/apple` - Apple OAuth authentication
- `POST /api/v1/auth/oauth/github` - GitHub OAuth authentication

#### Security Monitoring

- `GET /api/v1/auth/oauth/security/stats` - Get security statistics (admin only)

### Protected Routes

All protected routes require a valid JWT token in the Authorization header:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

### User Management

- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me/password` - Change password (coming soon)

### Health Check

- `GET /api/v1/health` - Check service health

## Security Features Detail

### Unified Security Architecture

Both traditional email/password authentication and OAuth flows share the same comprehensive security framework:

### Traditional Authentication Security

1. **Rate Limiting**: Intelligent protection against brute force attacks on login and registration
2. **Request Validation**: All authentication requests are validated for security anomalies
3. **IP Monitoring**: Suspicious IP addresses are detected and blocked automatically
4. **Secure Session Management**: Enhanced cookie security with httpOnly, secure, and sameSite strict settings
5. **Audit Logging**: Complete logging of all authentication attempts, successes, and failures
6. **Parameter Validation**: Protection against injection attacks in form data

### OAuth 2.0 Security Implementation

Our OAuth implementation follows the latest security best practices:

1. **PKCE (RFC 7636)**: All OAuth flows use Proof Key for Code Exchange to prevent authorization code interception attacks
2. **State Parameter Validation**: Cryptographically secure state parameters with timing-safe comparison
3. **Nonce Validation**: ID tokens include nonce validation to prevent replay attacks
4. **Token Verification**: Comprehensive validation of ID tokens including issuer, audience, expiration, and signature verification
5. **Secure Session Management**: Temporary session tokens for secure data transfer without exposing sensitive information in URLs

### Rate Limiting & Protection

- **Intelligent Rate Limiting**: IP and User-Agent based rate limiting with configurable thresholds
- **Automatic IP Blocking**: Suspicious IPs are automatically blocked for configurable duration
- **Parameter Injection Protection**: All request parameters are validated against injection attacks
- **User-Agent Validation**: Suspicious user agents are detected and logged

### Secure Cookie Management

- **httpOnly**: Prevents JavaScript access to authentication cookies
- **Secure**: Cookies only sent over HTTPS in production
- **SameSite**: Strict CSRF protection
- **Domain Scoped**: Proper domain scoping for multi-subdomain deployments

## OAuth Flow Security

### Secure Authorization Flow

1. **Initiation**: `/auth/oauth/google/login`

   - Generates secure state with PKCE challenge
   - Validates redirect URLs against allowlist
   - Applies rate limiting and security checks

2. **Callback**: `/auth/oauth/google/callback`

   - Validates state parameter with timing-safe comparison
   - Exchanges code for tokens using PKCE verifier
   - Verifies ID token signature, nonce, and claims
   - Cross-validates user information
   - Generates temporary session token

3. **Completion**: `/auth/oauth/session/user`
   - Exchanges session token for user data
   - One-time use tokens with automatic cleanup
   - Secure user data transfer

## Monitoring & Observability

The service provides comprehensive security monitoring:

- **Security Events**: All authentication attempts, failures, and suspicious activities
- **Rate Limiting Status**: Current rate limit status per IP
- **Anomaly Detection**: Automatic detection of unusual patterns
- **Audit Trails**: Complete audit logs for compliance

### Security Statistics

Access comprehensive security statistics for both authentication methods:

- OAuth: `/api/v1/auth/oauth/security/stats`
- Traditional Auth: `/api/v1/auth/security/stats`

```json
{
  "totalEvents": 150,
  "suspiciousIPs": 2,
  "rateLimitedIPs": 5,
  "recentEvents": [
    {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "timestamp": 1703123456789,
      "event": "oauth_success",
      "details": "Successful OAuth for user@example.com"
    }
  ]
}
```

## Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov

# Linting
npm run lint

# Format code
npm run format
```

## Installation

```bash
npm install
```

## Running the app

```bash
# development
npm run start

# watch mode
npm run start:dev

# production mode
npm run start:prod
```

## Production Deployment

### Security Considerations

1. **Environment Variables**: Ensure all sensitive environment variables are properly set
2. **HTTPS**: Always use HTTPS in production
3. **Rate Limiting**: Configure appropriate rate limits based on your traffic patterns
4. **Monitoring**: Set up monitoring for security events and anomalies
5. **Domain Configuration**: Properly configure frontend and callback URLs
6. **Secret Management**: Use proper secret management for JWT secrets and OAuth credentials

### Recommended Production Configuration

```env
NODE_ENV=production
FRONTEND_URL=https://your-frontend-domain.com
GOOGLE_CALLBACK_URL=https://your-api-domain.com/api/v1/auth/oauth/google/callback
OAUTH_MAX_ATTEMPTS=5
OAUTH_WINDOW_MS=600000      # 10 minutes
OAUTH_BLOCK_DURATION_MS=1800000  # 30 minutes
```

## Troubleshooting

### Common OAuth Issues

1. **State Mismatch**: Ensure cookies are enabled and properly configured
2. **Invalid Redirect URI**: Verify callback URLs match exactly in OAuth provider settings
3. **Rate Limited**: Check security statistics and adjust rate limits if needed
4. **CORS Issues**: Ensure proper CORS configuration for frontend domains

### Security Logs

Monitor security events in application logs:

- `oauth_success`: Successful authentications
- `oauth_failure`: Failed authentication attempts
- `rate_limit_exceeded`: Rate limit violations
- `suspicious_ip`: Suspicious activity detected
- `parameter_injection`: Injection attempt detected

## License

This project is proprietary and confidential.

## Contributors

- Your Team
