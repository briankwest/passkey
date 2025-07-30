import { query } from '../db';

interface CrossDeviceSession {
  session_id: string;
  status: 'pending' | 'authenticated';
  user_id?: string;
  created_at: Date;
  expires_at: Date;
}

export class CrossDeviceService {
  async createSession(sessionId: string): Promise<void> {
    await query(
      `INSERT INTO authentication_challenges (challenge, type, expires_at) 
       VALUES ($1, $2, $3)`,
      [sessionId, 'cross-device', new Date(Date.now() + 300000)] // 5 minutes
    );
  }

  async completeSession(sessionId: string, userId: string, token: string): Promise<void> {
    await query(
      `UPDATE authentication_challenges 
       SET user_id = $1 
       WHERE challenge = $2 AND type = 'cross-device'`,
      [userId, sessionId]
    );
  }

  async getSession(sessionId: string): Promise<{ authenticated: boolean; userId?: string; token?: string }> {
    return this.checkSession(sessionId);
  }

  async checkSession(sessionId: string): Promise<{ authenticated: boolean; userId?: string }> {
    const result = await query(
      `SELECT user_id FROM authentication_challenges 
       WHERE challenge = $1 AND type = 'cross-device' AND expires_at > NOW()`,
      [sessionId]
    );

    if (result.rows.length === 0) {
      return { authenticated: false };
    }

    const userId = result.rows[0].user_id;
    return {
      authenticated: !!userId,
      userId
    };
  }

  async cleanupExpiredSessions(): Promise<void> {
    await query(
      `DELETE FROM authentication_challenges 
       WHERE type = 'cross-device' AND expires_at < NOW()`
    );
  }
}