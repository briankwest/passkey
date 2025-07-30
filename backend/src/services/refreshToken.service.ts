import { pool } from '../db';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config';

export class RefreshTokenService {
  private static readonly REFRESH_TOKEN_EXPIRY_DAYS = 30;
  private static readonly ACCESS_TOKEN_EXPIRY = '15m';

  // Generate refresh token
  static async generateRefreshToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRY_DAYS);

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token, expires_at, created_at)
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id) 
       DO UPDATE SET token = $2, expires_at = $3, created_at = CURRENT_TIMESTAMP`,
      [userId, token, expiresAt]
    );

    return token;
  }

  // Verify refresh token and return new access token
  static async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; userId: string } | null> {
    const result = await pool.query(
      `SELECT user_id, expires_at FROM refresh_tokens 
       WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP`,
      [refreshToken]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const { user_id: userId } = result.rows[0];

    // Generate new access token
    const accessToken = jwt.sign(
      { userId },
      config.jwt.secret,
      { expiresIn: this.ACCESS_TOKEN_EXPIRY }
    );

    // Update last used timestamp
    await pool.query(
      'UPDATE refresh_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token = $1',
      [refreshToken]
    );

    return { accessToken, userId };
  }

  // Revoke refresh token
  static async revokeRefreshToken(userId: string): Promise<void> {
    await pool.query('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);
  }

  // Revoke all expired tokens (cleanup)
  static async cleanupExpiredTokens(): Promise<void> {
    await pool.query('DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP');
  }

  // Get active refresh tokens for a user
  static async getActiveTokens(userId: string): Promise<any[]> {
    const result = await pool.query(
      `SELECT created_at, last_used_at, expires_at 
       FROM refresh_tokens 
       WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP`,
      [userId]
    );
    return result.rows;
  }
}