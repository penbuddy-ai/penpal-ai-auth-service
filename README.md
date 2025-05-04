# Penpal AI - Authentication Service

This microservice handles authentication and user management for the Penpal AI application.

## Architecture

This service follows a microservice architecture pattern where:

- **Auth Service** (this service): Manages authentication, user registration, and OAuth integrations
- **DB Service** (separate): Handles all database operations and is the only service with direct database access

The Auth Service communicates with the DB Service via HTTP requests, maintaining a clear separation of concerns.

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

## Environment Variables

Copy the `.env.example` file to a new file named `.env`:

```bash
cp .env.example .env
```

Then update the values in the `.env` file:

```
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRES_IN=1d

# DB Service Configuration
DB_SERVICE_URL=http://localhost:3001
DB_SERVICE_API_KEY=your_api_key_here

# OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
```

## Requirements

The service exposes the following endpoints:

### Authentication

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login a user
- `GET /auth/google` - Initiate Google OAuth login
- `GET /auth/google/callback` - Google OAuth callback

### Protected Routes

All protected routes require a valid JWT token in the Authorization header:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

### User Management

- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update current user profile
- `PUT /api/v1/users/me/password` - Change password

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

## License

This project is proprietary and confidential.

## Contributors

- Your Team
