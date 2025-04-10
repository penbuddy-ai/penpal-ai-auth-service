# Penpal AI - Authentication Microservice

This is the authentication microservice for the Penpal AI application. It is responsible for user management, authentication (email/password and OAuth), and session management.

## Features

- User registration and login
- JWT-based authentication
- OAuth authentication (Google)
- Password reset functionality
- Email verification
- Role-based access control

## Technology Stack

- [NestJS](https://nestjs.com/) - A progressive Node.js framework
- [MongoDB](https://www.mongodb.com/) - NoSQL database
- [Mongoose](https://mongoosejs.com/) - MongoDB object modeling
- [Passport](https://www.passportjs.org/) - Authentication middleware
- [JWT](https://jwt.io/) - JSON Web Tokens for secure authentication
- [Argon2](https://github.com/ranisalt/node-argon2) - Password hashing

## Requirements

- Node.js (>= 18.x)
- MongoDB (>= 5.0)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-organization/penpal-ai-auth-service.git
cd penpal-ai-auth-service

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit the .env file with your configuration
```

## Running the application

```bash
# Development mode
npm run start:dev

# Production mode
npm run build
npm run start:prod
```

## API Endpoints

The service exposes the following endpoints:

### Authentication

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Authenticate a user and get tokens
- `POST /api/v1/auth/refresh` - Refresh authentication token
- `POST /api/v1/auth/logout` - Logout and invalidate tokens

### User Management

- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update current user profile
- `PUT /api/v1/users/me/password` - Change password

### OAuth

- `GET /api/v1/auth/google` - Initiate Google OAuth flow
- `GET /api/v1/auth/google/callback` - Google OAuth callback

### Health Check

- `GET /api/v1/health` - Check service health

## Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## License

This project is proprietary and confidential.

## Contributors

- Your Team
