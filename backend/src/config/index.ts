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
    origin: process.env.ORIGIN || 'http://localhost:3000'
  }
};