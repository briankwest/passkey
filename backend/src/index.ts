import express from 'express';
import cors from 'cors';
import session from 'express-session';
import connectPgSession from 'connect-pg-simple';
import { pool } from './db';
import { config } from './config';
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';

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
    if (origin.includes('ngrok.io') || origin.includes('ngrok-free.app')) {
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

// Session setup
app.use(session({
  store: new PgSession({
    pool,
    tableName: 'sessions'
  }),
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'lax'
  }
}));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
});