import express from 'express';
import cors from 'cors';
import session from 'express-session';
import connectPgSession from 'connect-pg-simple';
import { pool } from './db';
import { config } from './config';
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import passkeyRoutes from './routes/passkey.routes';
const app = express();
const PgSession = connectPgSession(session);
// Middleware
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
app.use(express.json());
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
    secure: true, // Always true for https
    sameSite: 'none' // Required for cross-origin
    // Removed domain restriction to allow any domain
  }
}));
// Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/passkeys', passkeyRoutes);
// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});
// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.status(500).json({ error: 'Something went wrong!' });
});
app.listen(config.port, () => {
});