import { query } from '../db';
import crypto from 'crypto';

export class ChallengeService {
  private readonly CHALLENGE_EXPIRY_MINUTES = 5;

  async storeChallenge(challenge: string, userId: string | null, type: 'registration' | 'authentication'): Promise<void> {
    // Store in database with expiry
    const expiresAt = new Date(Date.now() + this.CHALLENGE_EXPIRY_MINUTES * 60 * 1000);
    
    await query(
      `INSERT INTO authentication_challenges (challenge, user_id, type, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (challenge) DO UPDATE 
       SET user_id = $2, type = $3, expires_at = $4`,
      [challenge, userId, type, expiresAt]
    );
    
    // Clean up expired challenges
    this.cleanupExpired();
  }

  async verifyChallenge(challenge: string, type: 'registration' | 'authentication'): Promise<{ valid: boolean; userId?: string }> {
    const result = await query(
      `SELECT user_id FROM authentication_challenges 
       WHERE challenge = $1 AND type = $2 AND expires_at > NOW()`,
      [challenge, type]
    );
    
    if (result.rows.length === 0) {
      return { valid: false };
    }
    
    // Delete the challenge after verification (one-time use)
    await query(
      `DELETE FROM authentication_challenges WHERE challenge = $1`,
      [challenge]
    );
    
    return {
      valid: true,
      userId: result.rows[0].user_id
    };
  }

  async cleanupExpired(): Promise<void> {
    // Run async, don't wait
    query(
      `DELETE FROM authentication_challenges WHERE expires_at < NOW()`
    ).catch(err => console.error('Failed to cleanup expired challenges:', err));
  }
}

export const challengeService = new ChallengeService();