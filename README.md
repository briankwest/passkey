# Passkey Authentication Demo

A complete passwordless authentication demo using WebAuthn/Passkeys with cross-device authentication support.

## 🚀 Features

- **🔐 Passwordless Authentication** - No passwords, only passkeys using WebAuthn
- **📱 Cross-Device Authentication** - QR code support for mobile device authentication
- **👤 User Profile Management** - Complete profile after passkey registration
- **🐳 Docker Support** - Full containerization for all services
- **🔒 Secure Sessions** - JWT-based authentication with secure session management
- **🎨 Modern UI** - Clean, responsive interface with error handling
- **⚠️ Smart Error Handling** - User-friendly error messages and device compatibility checks

## 📋 Requirements

- Docker and Docker Compose
- Modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)
- Device with biometric authentication (Touch ID, Face ID, Windows Hello) or security key
- For development: Node.js 20+ (if running without Docker)

## 🏃 Quick Start

### One Command Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd passkey-demo

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
1. Visit http://localhost:3000
2. Click "Create Account with Passkey"
3. Your browser will prompt for biometric authentication or security key
4. After successful registration, complete your profile

### Signing In
1. Click "Sign In" from the home page
2. Use your registered passkey when prompted
3. For cross-device authentication, click "Use another device" to show QR code

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
passkey-demo/
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── pages/           # Page components
│   │   ├── components/      # Reusable UI components
│   │   ├── services/        # API service layer
│   │   ├── hooks/           # Custom React hooks
│   │   └── utils/           # Utility functions
│   └── Dockerfile.dev       # Frontend Docker config
├── backend/                  # Express backend API
│   ├── src/
│   │   ├── controllers/     # Request handlers
│   │   ├── services/        # Business logic
│   │   ├── routes/          # API routes
│   │   ├── db/              # Database config & migrations
│   │   └── types/           # TypeScript types
│   └── Dockerfile.dev       # Backend Docker config
├── docker-compose.yml        # Docker services configuration
└── Makefile                 # Build and deployment commands
```

### API Endpoints

```
POST   /api/auth/registration/options     # Get registration options
POST   /api/auth/registration/verify      # Verify registration
POST   /api/auth/authentication/options   # Get authentication options
POST   /api/auth/authentication/verify    # Verify authentication
POST   /api/auth/logout                   # Logout user

GET    /api/user/profile                  # Get user profile
PUT    /api/user/profile                  # Update user profile

POST   /api/auth/cross-device/create      # Create cross-device session
GET    /api/auth/cross-device/check/:id   # Check session status
POST   /api/auth/cross-device/complete    # Complete cross-device auth
```

## 🔒 Security Features

- **No Passwords**: Only passkeys are supported for authentication
- **Challenge-Response**: Every authentication uses a unique challenge
- **Secure Storage**: Credentials are stored encrypted in the database
- **Session Security**: JWT tokens with 7-day expiration
- **CORS Protection**: Configured for local development
- **Input Validation**: All inputs are validated and sanitized

## ⚙️ Configuration

### Environment Variables

Backend configuration (`.env`):
```env
NODE_ENV=development
PORT=5001
DATABASE_URL=postgresql://postgres:password@localhost:5432/passkey_demo
JWT_SECRET=your-secret-key
SESSION_SECRET=your-session-secret
RPID=localhost
RP_NAME=Passkey Demo
ORIGIN=http://localhost:3000
```

### Port Configuration
- **Frontend**: 3000
- **Backend**: 5001 (changed from 5000 to avoid macOS AirPlay conflict)
- **PostgreSQL**: 5432

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

### Browser Requirements
- Chrome 67+
- Safari 14+
- Firefox 60+
- Edge 18+

### Device Requirements
- **macOS**: Touch ID or connected security key
- **Windows**: Windows Hello or security key
- **iOS/Android**: Device with biometric authentication

## 📱 Mobile Testing

To test on mobile devices:

1. Use ngrok for HTTPS tunnel:
```bash
make ngrok
```

2. Update backend `.env`:
```env
ALLOWED_ORIGINS=https://your-domain.ngrok.io
```

3. Access the ngrok URL on your mobile device

## 🚀 Production Deployment

### Using Docker

```bash
# Build production images
make build

# Run in production mode
make prod
```

### Environment Setup
1. Set `NODE_ENV=production`
2. Use strong JWT_SECRET and SESSION_SECRET
3. Configure proper CORS origins
4. Use HTTPS (required for WebAuthn)
5. Set appropriate RP_ID for your domain

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests (when available)
5. Submit a pull request

## 📄 License

This is a demonstration project for educational purposes.

## 🙏 Acknowledgments

- Built with [@simplewebauthn](https://github.com/MasterKale/SimpleWebAuthn) libraries
- Uses WebAuthn/FIDO2 standards
- Inspired by passwordless authentication best practices