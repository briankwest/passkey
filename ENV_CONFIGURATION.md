# Environment Configuration Guide

This guide explains all environment variables available in the Passkey authentication system.

## Backend Configuration (.env)

### Required Settings

These settings must be configured for the application to work properly:

```bash
# Database connection string
DATABASE_URL=postgresql://username:password@host:port/database_name

# Secret keys (generate strong random strings for production)
SESSION_SECRET=your-session-secret-here
JWT_SECRET=your-jwt-secret-here
```

### Server Configuration

```bash
# Server port (default: 5001)
PORT=5001

# Environment: development, staging, production
NODE_ENV=development
```

### WebAuthn/Passkey Settings

```bash
# Relying Party Name (shown to users during passkey registration)
RP_NAME=Passkey

# Relying Party ID (domain name in production, 'localhost' for development)
RP_ID=localhost

# Frontend origin URL
ORIGIN=http://localhost:3000

# User verification requirement for passkeys
# Options: 'required', 'preferred', 'discouraged'
USER_VERIFICATION=preferred
```

### Email Configuration

Email is optional. If not configured, emails will be logged to console.

```bash
# Mailgun API credentials (sign up at https://www.mailgun.com/)
MAILGUN_API_KEY=your-mailgun-api-key
MAILGUN_DOMAIN=mg.yourdomain.com
MAILGUN_FROM_EMAIL=noreply@yourdomain.com
MAILGUN_FROM_NAME=Passkey

# Email verification settings
EMAIL_VERIFICATION_EXPIRY=24h
EMAIL_VERIFICATION_REQUIRED=true

# Password reset token expiry
PASSWORD_RESET_EXPIRY=1h
```

### Security Settings

```bash
# Account lockout configuration
MAX_FAILED_ATTEMPTS=5
LOCKOUT_DURATION=30  # minutes
EXTENDED_LOCKOUT_DURATION=60  # minutes (after 10+ attempts)

# Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_MIN_SCORE=3  # zxcvbn score (0-4)
PASSWORD_HISTORY_LIMIT=10  # number of previous passwords to check

# Two-Factor Authentication
TOTP_WINDOW=1  # time window for TOTP codes
BACKUP_CODE_COUNT=8
BACKUP_CODE_LENGTH=10
```

### CORS and Rate Limiting

```bash
# Allowed origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Rate limiting
RATE_LIMIT_WINDOW_MS=60000  # 1 minute
RATE_LIMIT_MAX_REQUESTS=100
```

### Session Configuration

```bash
SESSION_COOKIE_NAME=passkey_session
SESSION_COOKIE_MAX_AGE=604800000  # 7 days in milliseconds
SESSION_COOKIE_SECURE=false  # set to true in production with HTTPS
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax
```

### Logging

```bash
# Log level: error, warn, info, debug
LOG_LEVEL=info
```

### Development Options

```bash
# Disable email sending (logs to console instead)
DISABLE_EMAIL_SENDING=false
```

## Frontend Configuration (.env)

```bash
# Backend API URL
VITE_API_URL=http://localhost:5001

# Frontend origin (should match backend ORIGIN)
VITE_ORIGIN=http://localhost:3000

# Optional analytics
VITE_GA_TRACKING_ID=
VITE_SENTRY_DSN=

# Feature flags
VITE_ENABLE_PASSKEYS=true
VITE_ENABLE_PASSWORD_AUTH=true
VITE_ENABLE_TOTP=true
VITE_ENABLE_CROSS_DEVICE=true

# Debug mode
VITE_ENABLE_DEBUG=false
```

## Production Deployment

For production deployment, ensure you:

1. **Generate strong secrets**:
   ```bash
   # Generate random secrets
   openssl rand -base64 32  # For JWT_SECRET
   openssl rand -base64 32  # For SESSION_SECRET
   ```

2. **Update domain settings**:
   - Set `RP_ID` to your domain (e.g., `example.com`)
   - Set `ORIGIN` to your frontend URL (e.g., `https://example.com`)
   - Update `ALLOWED_ORIGINS` to include your production domain

3. **Enable security features**:
   - Set `SESSION_COOKIE_SECURE=true` (requires HTTPS)
   - Set `NODE_ENV=production`
   - Configure proper email service (Mailgun)

4. **Database security**:
   - Use a strong database password
   - Enable SSL for database connections
   - Regular backups

## Environment-Specific Files

The application supports multiple environment files:

- `.env` - Default environment file
- `.env.production` - Production overrides
- `.env.development` - Development overrides
- `.env.local` - Local overrides (gitignored)

Files are loaded in this order, with later files overriding earlier ones.

## Docker Environment

When using Docker, you can pass environment variables through:

1. **docker-compose.yml** - Define in the `environment` section
2. **Docker run command** - Use `-e` flags
3. **.env file** - Docker Compose automatically loads .env files

## Troubleshooting

### Email not sending
- Check Mailgun credentials are correct
- Verify domain is verified in Mailgun
- Check `DISABLE_EMAIL_SENDING` is `false`

### Passkeys not working
- Ensure `RP_ID` matches your domain
- Verify HTTPS is enabled in production
- Check browser console for WebAuthn errors

### Session issues
- Verify `SESSION_SECRET` hasn't changed
- Check cookie settings match your deployment
- Ensure `ALLOWED_ORIGINS` includes your frontend URL