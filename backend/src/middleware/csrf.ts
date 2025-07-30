import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { AppError } from './errorHandler';

interface CsrfRequest extends Request {
  csrfToken?: () => string;
}

// Generate a CSRF token
const generateToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

// CSRF protection middleware
export const csrfProtection = (req: CsrfRequest, res: Response, next: NextFunction) => {
  // Skip CSRF for GET requests and WebAuthn endpoints (they use different security measures)
  if (req.method === 'GET' || req.path.includes('/webauthn') || req.path.includes('/passkey')) {
    return next();
  }

  // Skip for authentication endpoints that don't have a session yet
  const skipPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/check-email',
    '/api/auth/authentication/options',
    '/api/auth/authentication/verify',
    '/api/auth/registration/options',
    '/api/auth/registration/verify',
    '/api/auth/resend-verification',
    '/api/auth/send-verification',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/auth/verify-email',
    '/api/auth/check-password-strength',
    '/api/auth/check-methods',
    '/api/auth/cross-device/create',
    '/api/auth/cross-device/check',
    '/api/auth/cross-device/complete',
    '/api/auth/refresh',
    '/api/auth/logout'
  ];
  if (skipPaths.some(path => req.path === path || req.path.startsWith(path))) {
    return next();
  }

  // Get token from header or body
  const headerToken = req.headers['x-csrf-token'] as string;
  const bodyToken = req.body?._csrf;
  const token = headerToken || bodyToken;

  // Get token from cookie
  const cookieToken = req.cookies?.['csrf-token'];

  // Validate tokens match
  if (!token || !cookieToken || token !== cookieToken) {
    throw new AppError(403, 'Invalid CSRF token', 'CSRF_ERROR');
  }

  next();
};

// Middleware to set CSRF token
export const setCsrfToken = (req: CsrfRequest, res: Response, next: NextFunction) => {
  // Generate new token if none exists
  if (!req.cookies?.['csrf-token']) {
    const token = generateToken();
    res.cookie('csrf-token', token, {
      httpOnly: false, // Must be accessible to JavaScript
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Add method to get token
    req.csrfToken = () => token;
  } else {
    req.csrfToken = () => req.cookies['csrf-token'];
  }

  // Add token to response locals for templates
  res.locals.csrfToken = req.csrfToken();
  
  next();
};

// Endpoint to get CSRF token
export const getCsrfToken = (req: CsrfRequest, res: Response) => {
  res.json({ csrfToken: req.csrfToken?.() || '' });
};