const jwt = require('jsonwebtoken');
import { config } from '../config';

/**
 * Generate a JWT authentication token for a user
 * @param userId - The user's ID to include in the token
 * @param expiresIn - Token expiration time (default: 7 days)
 * @returns Signed JWT token
 */
export const generateAuthToken = (userId: string, expiresIn: string = '7d'): string => {
  return jwt.sign(
    { userId },
    config.jwt.secret,
    { expiresIn }
  );
};

/**
 * Verify and decode a JWT token
 * @param token - JWT token to verify
 * @returns Decoded token payload
 * @throws Error if token is invalid or expired
 */
export const verifyToken = (token: string): any => {
  return jwt.verify(token, config.jwt.secret);
};