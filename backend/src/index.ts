import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import connectPgSession from 'connect-pg-simple';
import { pool } from './db';
import { config } from './config';
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import passkeyRoutes from './routes/passkey.routes';
import { errorHandler } from './middleware/errorHandler';
import { csrfProtection, setCsrfToken } from './middleware/csrf';
import cookieParser from 'cookie-parser';

const app = express();
const PgSession = connectPgSession(session);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Disable for WebAuthn compatibility
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimit?.windowMs || 15 * 60 * 1000, // 15 minutes
  max: config.rateLimit?.maxRequests || 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  skipSuccessfulRequests: true,
  message: 'Too many authentication attempts, please try again later.',
});

// Apply rate limiting
app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    // Allow configured origin
    if (origin === config.webauthn.origin) return callback(null, true);
    // Allow ngrok domains for development
    if (origin.includes('ngrok.io') || origin.includes('ngrok.app')) {
      return callback(null, true);
    }
    // Allow localhost variations
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// Body parsing with size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie parser (required for CSRF)
app.use(cookieParser());

// Trust proxy for secure cookies
app.set('trust proxy', 1);
// Session setup
app.use(session({
  store: new PgSession({
    pool,
    tableName: 'sessions'
  }),
  secret: config.session.secret,
  resave: false,
  saveUninitialized: true, // Changed to true to ensure session is created
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    secure: config.nodeEnv === 'production' || config.security.sessionCookie.secure,
    sameSite: config.security.sessionCookie.sameSite as 'strict' | 'lax' | 'none',
    // Note: 'lax' is more secure but may cause issues with cross-device auth
    // Use 'none' only when necessary and always with secure: true
  }
}));

// CSRF protection
app.use(setCsrfToken);
app.use(csrfProtection);

// CSRF token endpoint
app.get('/api/csrf-token', (req: any, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/passkeys', passkeyRoutes);
// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});
// Error handler middleware (must be last)
app.use(errorHandler);
app.listen(config.port, () => {
});