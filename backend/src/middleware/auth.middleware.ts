import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
export interface AuthRequest extends Request {
  user?: {
    userId: string;
    username: string;
  };
}
export const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  try {
    const decoded = verifyToken(token);
    req.user = decoded as { userId: string; username: string };
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};