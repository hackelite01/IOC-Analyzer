# Authentication & Authorization System

This document describes the comprehensive authentication and authorization system implemented for the IOC Analyzer application.

## Overview

The system provides:
- **JWT-based authentication** with secure token management
- **Role-based access control** (Admin/User roles)
- **Activity logging** for all user actions
- **Secure password handling** with bcrypt hashing
- **MongoDB-backed** user and activity storage

## User Roles

### Admin
- View all users and their information
- View activity logs for any user
- Change user roles
- Access all IOC data and analysis features

### User (Default)
- View only their own profile and activity logs
- Access IOC analysis features
- Submit IOCs for analysis

## API Endpoints

### Authentication Endpoints

#### POST `/api/auth/register`
Register a new user account.

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "user_id",
    "username": "john_doe",
    "email": "john@example.com",
    "role": "user",
    "createdAt": "2025-09-03T10:00:00.000Z"
  }
}
```

#### POST `/api/auth/login`
Authenticate user and receive access token.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user_id",
    "username": "john_doe",
    "email": "john@example.com",
    "role": "user",
    "createdAt": "2025-09-03T10:00:00.000Z"
  }
}
```

#### GET `/api/auth/me`
Get current authenticated user's profile.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "user": {
    "id": "user_id",
    "username": "john_doe",
    "email": "john@example.com",
    "role": "user",
    "createdAt": "2025-09-03T10:00:00.000Z",
    "updatedAt": "2025-09-03T10:00:00.000Z"
  }
}
```

### Protected Endpoints

#### GET `/api/activities`
Get user activity logs (with role-based filtering).

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page` (optional): Page number for pagination (default: 1)
- `limit` (optional): Items per page (default: 50, max: 100)
- `userId` (admin only): Filter by specific user ID
- `action` (optional): Filter by action type

**User Response:** Only their own activities
**Admin Response:** All activities or filtered by userId

```json
{
  "activities": [
    {
      "id": "activity_id",
      "userId": "user_id",
      "username": "john_doe",
      "email": "john@example.com",
      "userRole": "user",
      "action": "LOGIN_SUCCESS",
      "details": {
        "email": "john@example.com",
        "username": "john_doe"
      },
      "ipAddress": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "timestamp": "2025-09-03T10:00:00.000Z"
    }
  ],
  "pagination": {
    "currentPage": 1,
    "totalPages": 5,
    "totalCount": 250,
    "hasNextPage": true,
    "hasPrevPage": false,
    "limit": 50
  },
  "meta": {
    "canViewAllUsers": false,
    "viewingUserId": "user_id"
  }
}
```

### Admin-Only Endpoints

#### GET `/api/admin/users`
Get list of all users (admin only).

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page` (optional): Page number for pagination
- `limit` (optional): Items per page (max: 50)
- `search` (optional): Search by username or email
- `role` (optional): Filter by role (admin/user)

#### PATCH `/api/admin/users`
Update user role (admin only).

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "userId": "target_user_id",
  "role": "admin"
}
```

## Database Schema

### User Collection
```typescript
{
  _id: ObjectId,
  username: string,      // Unique, 3-30 chars, alphanumeric + _-
  email: string,         // Unique, valid email format
  password: string,      // Bcrypt hashed, never stored as plain text
  role: 'admin' | 'user', // Default: 'user'
  createdAt: Date,
  updatedAt: Date
}
```

### UserActivity Collection
```typescript
{
  _id: ObjectId,
  userId: ObjectId,      // Reference to User
  action: string,        // Action type (e.g., 'LOGIN_SUCCESS')
  details: object,       // Additional action details
  ipAddress: string,     // Client IP address
  userAgent: string,     // Client user agent
  timestamp: Date        // When the action occurred
}
```

## Security Features

### Password Security
- **Bcrypt hashing** with salt rounds of 12
- **Password validation** requiring:
  - Minimum 6 characters
  - At least one lowercase letter
  - At least one uppercase letter
  - At least one number

### JWT Token Security
- **Configurable expiration** (default: 7 days)
- **Secure secret key** from environment variables
- **Token verification** on every protected request

### Activity Logging
All user actions are automatically logged with:
- User ID and details
- Action type and additional context
- IP address and user agent
- Precise timestamp

### Role-Based Access Control
- **Middleware-based** role checking
- **Granular permissions** per endpoint
- **Automatic authorization** validation

## Environment Variables

Add these to your `.env.local` file:

```bash
# JWT Authentication
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d

# MongoDB (existing)
MONGODB_URI=mongodb://localhost:27017/ioc-analyzer
```

## Setup Instructions

### 1. Install Dependencies
```bash
npm install bcryptjs jsonwebtoken @types/bcryptjs @types/jsonwebtoken tsx
```

### 2. Set Environment Variables
Update your `.env.local` file with the JWT configuration above.

### 3. Create Admin User
```bash
npm run create-admin
```

This creates an initial admin user with:
- **Email:** admin@ioc-analyzer.com
- **Password:** admin123
- **Role:** admin

**⚠️ Change the default admin password after first login!**

### 4. Test the System

#### Register a new user:
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123"
  }'
```

#### Login:
```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123"
  }'
```

#### Use the token:
```bash
curl -X GET http://localhost:3001/api/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Common Activity Log Actions

The system automatically logs these actions:
- `USER_REGISTERED` - New user registration
- `LOGIN_SUCCESS` - Successful authentication
- `LOGIN_FAILED` - Failed login attempt
- `GET_PROFILE` - Profile access
- `GET_ACTIVITIES` - Activity log access
- `SUBMIT_IOC_ANALYSIS` - IOC analysis submission
- `VIEW_DASHBOARD` - Dashboard access
- `GET_ALL_USERS` - Admin user list access
- `UPDATE_USER_ROLE` - Role change by admin
- `AUTH_TEST` - Authentication test

## Error Handling

The system provides detailed error responses:

```json
{
  "error": "Error message",
  "details": ["Specific validation errors"]
}
```

Common HTTP status codes:
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (invalid/missing token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate user)
- `500` - Internal Server Error

## Integration with Existing Features

All existing IOC analysis endpoints now require authentication:
- Dashboard access requires valid JWT token
- IOC submission requires authentication
- User can only see their own IOC analysis results
- Admin can view all IOC data across users

The authentication system is fully integrated and ready for production use!
