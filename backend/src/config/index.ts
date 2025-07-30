import dotenv from 'dotenv';
dotenv.config();
export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  database: {
    url: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/passkey_demo'
  },
  session: {
    secret: process.env.SESSION_SECRET || 'development-secret-change-in-production'
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'development-jwt-secret-change-in-production'
  },
  webauthn: {
    rpName: process.env.RP_NAME || 'Passkey Demo',
    rpID: process.env.RP_ID || 'localhost',
    origin: process.env.ORIGIN || 'http://localhost:3000',
    // User verification: 'required' (always require PIN), 'preferred' (optional PIN), 'discouraged' (no PIN)
    userVerification: (process.env.USER_VERIFICATION || 'preferred') as 'required' | 'preferred' | 'discouraged'
  },
  app: {
    name: process.env.APP_NAME || 'Passkey Demo',
    url: process.env.APP_URL || process.env.ORIGIN || 'http://localhost:3000'
  },
  email: {
    mailgunApiKey: process.env.MAILGUN_API_KEY || '',
    mailgunDomain: process.env.MAILGUN_DOMAIN || '',
    fromEmail: process.env.MAILGUN_FROM_EMAIL || 'noreply@example.com',
    fromName: process.env.MAILGUN_FROM_NAME || 'Passkey Demo',
    verificationExpiry: process.env.EMAIL_VERIFICATION_EXPIRY || '24h',
    verificationRequired: process.env.EMAIL_VERIFICATION_REQUIRED === 'true'
  }
};