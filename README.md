# Penpal AI - Authentication Service

This microservice handles authentication and user management for the Penpal AI application with enterprise-grade security features.

## Architecture

This service follows a microservice architecture pattern where:

- **Auth Service** (this service): Manages authentication, user registration, and OAuth integrations with advanced security
- **DB Service** (separate): Handles all database operations and is the only service with direct database access
- **Notification Service** (separate): Handles email notifications including welcome emails for new users

The Auth Service communicates with the DB Service and Notification Service via HTTP requests, maintaining a clear separation of concerns.

## Features

### Core Authentication

- User registration and login
- JWT-based authentication with secure token management
- Advanced OAuth 2.0 authentication with PKCE (Google, Facebook, Apple, GitHub)
- Password reset functionality
- Email verification
- Role-based access control
- **Automated welcome emails** for new OAuth users

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
- [Nodemailer](https://nodemailer.com/) - Email service integration (via notification service)

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- MongoDB instance running
- Notification service running (for email functionality)
- Google OAuth credentials (for Google authentication)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Database Service
DB_SERVICE_URL=http://localhost:3001/api/v1
DB_SERVICE_API_KEY=your-db-service-api-key

# Notification Service
NOTIFICATION_SERVICE_URL=http://localhost:3002/api/v1
NOTIFY_SERVICE_API_KEY=your-notify-service-api-key

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=1d

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/oauth/google/callback

# Frontend Configuration
FRONTEND_URL=http://localhost:5173

# Server Configuration
PORT=3000
NODE_ENV=development
```

### Installation

```bash
# Install dependencies
npm install

# Start the service
npm run start:dev
```

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - Register a new user with email/password
- `POST /api/v1/auth/login` - Login with email/password
- `POST /api/v1/auth/logout` - Logout and invalidate token

### OAuth 2.0 (Google)

- `GET /api/v1/auth/oauth/google` - Initiate Google OAuth flow
- `GET /api/v1/auth/oauth/google/callback` - Handle Google OAuth callback
- `POST /api/v1/auth/oauth/google/mobile` - Handle mobile Google OAuth (coming soon)

### OAuth Security Endpoints

- `GET /api/v1/auth/oauth/security/status` - Get security monitoring status
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

## Notification Integration

When a new user registers via OAuth (e.g., Google), the service automatically:

1. **Detects new user registration** - Checks if the OAuth user already exists
2. **Sends welcome email** - Calls the notification service to send a personalized welcome email
3. **Non-blocking operation** - Email sending doesn't block the authentication flow
4. **Error resilience** - Authentication succeeds even if email sending fails

### Welcome Email Features

- **Personalized content** - Uses user's name and OAuth provider
- **Responsive design** - Works on all email clients
- **Multi-language support** - Currently in French, easily extensible
- **Call-to-action** - Direct link to user dashboard
- **Professional branding** - Consistent with Penpal AI brand

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

- **Smart Rate Limiting**: Different limits for different endpoints with progressive penalties
- **IP-based Protection**: Automatic blocking of suspicious IP addresses
- **Time-window Protection**: Sliding window rate limiting with automatic reset
- **Geographic Monitoring**: Optional geographic-based anomaly detection
- **Real-time Alerting**: Immediate notifications for potential security threats

## Development

### Running Tests

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

### Building for Production

```bash
# Build the application
npm run build

# Start in production mode
npm run start:prod
```

## Troubleshooting

### Common Issues

1. **Email notifications not working**

   - Check `NOTIFICATION_SERVICE_URL` and `NOTIFY_SERVICE_API_KEY` environment variables
   - Ensure notification service is running and accessible
   - Check notification service logs for email configuration issues

2. **Google OAuth errors**

   - Verify Google OAuth credentials in environment variables
   - Check OAuth callback URL matches Google Console configuration
   - Ensure frontend URL is correctly configured

3. **Database connection issues**
   - Verify `DB_SERVICE_URL` and `DB_SERVICE_API_KEY`
   - Check if DB service is running and accessible
   - Review database connection logs

### Monitoring

- Check `/api/v1/health` endpoint for service health
- Monitor security statistics via `/api/v1/auth/oauth/security/stats`
- Review application logs for detailed error information

## License

This project is licensed under the MIT License.

## Contributors

- Your Team
