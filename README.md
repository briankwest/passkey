# Passkey Authentication

A complete passwordless authentication system using WebAuthn/Passkeys with cross-device authentication support.

## 🚀 Features

### Core Authentication
- **🔐 Passwordless Authentication** - Primary authentication using WebAuthn/Passkeys
- **🔑 Optional Password Support** - Email/password registration and login available
- **📱 Two-Factor Authentication (2FA)** - TOTP support with backup codes
- **🔄 Password Reset Flow** - Secure password reset via email tokens
- **✉️ Email Verification** - Required email verification for new accounts

### Security Features
- **🛡️ Multiple Passkeys** - Support for multiple passkeys per account
- **💾 Backup Codes** - 8 single-use recovery codes for 2FA
- **🔒 Account Security** - Password history tracking, strength validation
- **📊 Security Activity Log** - Track authentication methods and devices
- **🚫 Account Lockout** - Automatic lockout after failed attempts

### User Experience
- **📱 Cross-Device Authentication** - QR code support for mobile device authentication
- **👤 User Profile Management** - First name, last name, display name, bio
- **🎨 Modern UI** - Clean, responsive interface with loading states
- **⚠️ Smart Error Handling** - User-friendly error messages and retry options
- **📧 Email Notifications** - Welcome emails, verification, password reset

### Developer Features
- **🐳 Docker Support** - Full containerization with development and production configs
- **🪝 Custom React Hooks** - Reusable hooks for API calls, loading states, errors
- **🛠️ Error Middleware** - Centralized error handling with custom error classes
- **📝 TypeScript** - Full type safety across frontend and backend
- **🔄 Hot Reload** - Development environment with automatic reloading

## 📋 Requirements

- Docker and Docker Compose
- Modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)
- Device with biometric authentication (Touch ID, Face ID, Windows Hello) or security key (YubiKey, etc.)
- For development: Node.js 20+ (if running without Docker)

## 🏃 Quick Start

### One Command Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/briankwest/passkey.git
cd passkey

# Start everything with Docker
make dev
```

This will:
- Start PostgreSQL database
- Run database migrations
- Start backend API (port 5001)
- Start frontend development server (port 3000)

Visit http://localhost:3000 to access the demo.

### Alternative: Manual Setup

If you prefer to run services individually:

```bash
# 1. Start database
make up

# 2. Run database migrations
make db-migrate

# 3. Start backend (in one terminal)
cd backend
npm install
npm run dev

# 4. Start frontend (in another terminal)
cd frontend
npm install
npm run dev
```

## 🎯 Usage Guide

### Creating an Account

#### Option 1: Passkey Only (Recommended)
1. Visit http://localhost:3000
2. Click "Create Account"
3. Choose "Passkey" option
4. Enter your email, first name, and last name
5. Your browser will prompt for biometric authentication or security key
6. Check your email to verify your account

#### Option 2: Email/Password
1. Choose "Email & Password" option
2. Enter your details and a strong password (12+ characters)
3. Password strength indicator will guide you
4. Verify your email before signing in

### Signing In

#### With Passkey
1. Click "Sign In" and choose "Passkey"
2. Use your registered passkey when prompted
3. For cross-device authentication, scan the QR code

#### With Email/Password
1. Choose "Email & Password" option
2. Enter your credentials
3. Complete 2FA if enabled (TOTP code or backup code)

### Cross-Device Authentication
1. On desktop, click "Use another device" during sign-in
2. Scan the QR code with your mobile device
3. Authenticate on your mobile device
4. Desktop will automatically sign in

## 🛠️ Available Commands

```bash
# Development
make dev          # Start all services in development mode
make logs         # View logs from all services
make health       # Check health status of all services

# Docker Management
make up           # Start database only
make down         # Stop all Docker services
make clean        # Remove all containers and volumes

# Database
make db-migrate   # Run database migrations
make db-reset     # Reset database (warning: deletes all data)

# Production
make build        # Build production images
make prod         # Run in production mode

# Testing with ngrok
make ngrok        # Start ngrok tunnel for external testing
```

## 🏗️ Architecture

### Technology Stack
- **Frontend**: React 18, TypeScript, Vite
- **Backend**: Node.js, Express, TypeScript
- **Database**: PostgreSQL 16
- **Authentication**: @simplewebauthn library
- **Container**: Docker & Docker Compose

### Project Structure
```
passkey/
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── pages/           # Page components
│   │   │   ├── SignIn.tsx   # Multi-method sign in
│   │   │   ├── SignUp.tsx   # Multi-method registration
│   │   │   ├── Profile.tsx  # User profile management
│   │   │   └── SecuritySettings.tsx  # Security management
│   │   ├── components/      # Reusable UI components
│   │   ├── services/        # API service layer
│   │   ├── hooks/           # Custom React hooks
│   │   │   ├── useAuth.tsx  # Authentication context
│   │   │   ├── useApiCall.ts # API call management
│   │   │   └── useLoading.ts # Loading state management
│   │   └── utils/           # Utility functions
│   └── Dockerfile           # Production Docker config
├── backend/                  # Express backend API
│   ├── src/
│   │   ├── controllers/     # Request handlers
│   │   │   ├── auth.controller.ts  # Auth endpoints
│   │   │   ├── user.controller.ts  # User endpoints
│   │   │   └── passkey.controller.ts # Passkey management
│   │   ├── services/        # Business logic
│   │   │   ├── webauthn.service.ts # WebAuthn implementation
│   │   │   ├── password.service.ts # Password management
│   │   │   ├── totp.service.ts     # 2FA implementation
│   │   │   └── email.service.ts    # Email notifications
│   │   ├── middleware/      # Express middleware
│   │   │   └── errorHandler.ts # Global error handling
│   │   ├── email-templates/ # Email templates (HTML/TXT)
│   │   ├── routes/          # API routes
│   │   ├── db/              # Database config
│   │   ├── utils/           # Utility functions
│   │   │   ├── jwt.ts       # JWT token generation
│   │   │   └── getClientIp.ts # IP address extraction
│   │   └── types/           # TypeScript types
│   └── Dockerfile           # Production Docker config
├── database/                 # Database files
│   └── schema.sql           # Database schema
├── docker-compose.yml        # Development Docker config
├── docker-compose.prod.yml   # Production Docker config
├── Makefile                 # Build and deployment commands
└── README.md                # This file
```

### API Endpoints

#### Authentication
```
# Passkey Authentication
POST   /api/auth/registration/options     # Get registration options
POST   /api/auth/registration/verify      # Verify registration
POST   /api/auth/authentication/options   # Get authentication options
POST   /api/auth/authentication/verify    # Verify authentication

# Email/Password Authentication
POST   /api/auth/register                 # Register with email/password
POST   /api/auth/register/passkey         # Register with passkey (no password)
POST   /api/auth/login                    # Login with email/password
GET    /api/auth/check-email             # Check email availability
POST   /api/auth/logout                   # Logout user

# Email Verification
GET    /api/auth/verify-email/:token      # Verify email address
POST   /api/auth/resend-verification      # Resend verification email
POST   /api/auth/send-verification        # Send verification after passkey registration

# Password Management
POST   /api/auth/forgot-password          # Request password reset
POST   /api/auth/reset-password           # Reset password with token
POST   /api/auth/change-password          # Change password (authenticated)
POST   /api/auth/check-password-strength  # Check password strength

# Two-Factor Authentication
POST   /api/auth/totp/setup               # Setup TOTP
POST   /api/auth/totp/verify              # Verify TOTP setup
POST   /api/auth/totp/disable             # Disable TOTP
GET    /api/auth/totp/status              # Get TOTP status
GET    /api/auth/backup-codes             # Get backup codes status
POST   /api/auth/backup-codes/regenerate  # Regenerate backup codes

# Security
GET    /api/auth/recent-activity          # Get recent auth activity
```

#### User Management
```
GET    /api/user/profile                  # Get user profile  
PUT    /api/user/profile                  # Update user profile
```

#### Passkey Management
```
GET    /api/passkeys                      # List user's passkeys
DELETE /api/passkeys/:id                  # Delete a passkey
```

#### Cross-Device Authentication
```
POST   /api/auth/cross-device/create      # Create cross-device session
GET    /api/auth/cross-device/check/:id   # Check session status
POST   /api/auth/cross-device/complete    # Complete cross-device auth
```

## 🔒 Security Features

### Authentication Security
- **Passkey-First Design**: Primary authentication via WebAuthn/FIDO2
- **Physical Security Keys**: Full support for YubiKey and other FIDO2 security keys
- **Flexible PIN Policy**: Configurable PIN requirements for security keys
- **Challenge-Response**: Every authentication uses a unique challenge
- **Password Security**: 
  - Bcrypt hashing with 12 rounds
  - Strength validation using zxcvbn
  - Password history tracking (last 10)
  - Minimum 12 characters required

### Account Protection
- **Two-Factor Authentication**: TOTP with authenticator apps
- **Backup Codes**: 8 single-use recovery codes (format: XXXXX-XXXXX)
- **Account Lockout**: Progressive lockout after failed attempts (30-60 minutes)
- **Email Verification**: Required for all new accounts
- **Password Reset**: Secure token-based reset (1-hour expiration)

### Session & Data Security
- **JWT Tokens**: Secure session management with 7-day expiration
- **Secure Storage**: All sensitive data encrypted in PostgreSQL
- **CORS Protection**: Configurable for production environments
- **Input Validation**: All inputs validated and sanitized
- **Rate Limiting**: Protection against brute force attacks
- **IP Tracking**: Real client IP logging with X-Forwarded-For support

## ⚙️ Configuration

### Environment Variables

See [ENV_CONFIGURATION.md](./ENV_CONFIGURATION.md) for a complete list of all configuration options.

Backend configuration (`.env`):
```env
NODE_ENV=development
PORT=5001
DATABASE_URL=postgresql://postgres:password@localhost:5432/passkey

# Security
JWT_SECRET=your-secret-key
SESSION_SECRET=your-session-secret

# WebAuthn Configuration
RPID=localhost
RP_NAME=Passkey
ORIGIN=http://localhost:3000
# User verification: 'required' (always require PIN), 'preferred' (optional PIN), 'discouraged' (no PIN)
USER_VERIFICATION=preferred

# Email Configuration (Optional - uses console if not set)
MAILGUN_API_KEY=your-mailgun-api-key
MAILGUN_DOMAIN=your-domain.mailgun.org
EMAIL_FROM=noreply@your-domain.com
```

Frontend configuration (`.env`):
```env
VITE_API_URL=http://localhost:5001
```

### Port Configuration
- **Frontend**: 3000
- **Backend**: 5001 (changed from 5000 to avoid macOS AirPlay conflict)
- **PostgreSQL**: 5432

### YubiKey/Security Key Configuration

The `USER_VERIFICATION` environment variable controls PIN requirements:

- **`required`**: Always require PIN/biometric verification
  - Most secure option
  - May require setting up a PIN on the security key first
  
- **`preferred`** (default): Use PIN/biometric if available
  - Balances security and usability
  - Works with keys that have PIN and those without
  
- **`discouraged`**: Don't prompt for PIN/biometric
  - Least secure but most convenient
  - Suitable for low-risk environments

**Note**: Some security keys always require PIN regardless of this setting if they've been configured with one.

## 🐛 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Check what's using the port
lsof -i :5001
# Kill the process
kill -9 <PID>
```

**Database Connection Failed**
```bash
# Restart Docker services
make down
make dev
```

**WebAuthn Not Available**
- Ensure you're using HTTPS or localhost
- Check browser compatibility
- Verify device has biometric/security key support

**Docker Build Issues**
```bash
# Clean and rebuild
make clean
make build
make dev
```

**TypeScript Build Errors**
```bash
# For frontend
cd frontend && npm run type-check

# For backend
cd backend && npm run build
```

**Email Not Sending**
- Without Mailgun configuration, emails are logged to console
- Check backend logs to see email content
- Configure Mailgun for production email delivery

**2FA Issues**
- Ensure system time is synchronized
- Backup codes format: XXXXX-XXXXX (5 chars, hyphen, 5 chars)
- Each backup code can only be used once

### Browser Requirements
- Chrome 67+
- Safari 14+
- Firefox 60+
- Edge 18+

### Device Requirements
- **macOS**: Touch ID or connected security key (YubiKey via USB/NFC)
- **Windows**: Windows Hello or security key (YubiKey via USB/NFC)
- **iOS/Android**: Device with biometric authentication or NFC YubiKey support

## 📱 Mobile Testing with Ngrok

To test on mobile devices or external networks:

1. Start ngrok tunnel:
```bash
ngrok http 3000
```

2. Update **backend/.env** with your ngrok domain:
```env
RP_ID=your-subdomain.ngrok.app
ORIGIN=https://your-subdomain.ngrok.app
ALLOWED_ORIGINS=https://your-subdomain.ngrok.app,http://localhost:3000
```

3. Update **frontend/.env** with your ngrok domain:
```env
VITE_API_URL=http://localhost:5001
VITE_ORIGIN=https://your-subdomain.ngrok.app
```

4. Restart both backend and frontend servers:
```bash
make restart
```

5. Access the ngrok URL on your mobile device

**Note**: The RP_ID must match the domain you're accessing from. For ngrok, use the full subdomain.

## 🚀 Production Deployment

### Using Docker

```bash
# Build production images
make build

# Run in production mode
make prod
```

### Production Build

```bash
# Build production Docker images
make docker-prod

# Or build individually
docker build -f backend/Dockerfile -t passkey-backend .
docker build -f frontend/Dockerfile -t passkey-frontend .
```

### Environment Setup
1. Set `NODE_ENV=production`
2. Use strong JWT_SECRET and SESSION_SECRET
3. Configure proper CORS origins
4. Use HTTPS (required for WebAuthn)
5. Set appropriate RP_ID for your domain

## 📊 Recent Updates

### Security Enhancements
- Added Two-Factor Authentication (TOTP) with backup codes
- Implemented password reset flow with email tokens
- Added account lockout protection
- Enhanced IP logging with X-Forwarded-For support

### Code Quality Improvements
- Centralized error handling with custom middleware
- Created reusable React hooks for API calls
- Extracted email templates with Mustache templating
- Refactored large functions for better maintainability
- Added TypeScript strict mode

### User Experience
- Added first/last name fields to user profile
- Improved loading states and error messages
- Enhanced security settings page
- Added password strength indicator

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure TypeScript builds pass
5. Test all authentication flows
6. Submit a pull request

## 📄 License

This is a demonstration project for educational purposes.

## 🙏 Acknowledgments

- Built with [@simplewebauthn](https://github.com/MasterKale/SimpleWebAuthn) libraries
- Uses WebAuthn/FIDO2 standards
- Inspired by passwordless authentication best practices