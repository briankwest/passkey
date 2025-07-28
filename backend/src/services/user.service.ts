import { query } from '../db';
import { User } from '../types';

export class UserService {
  async createUser(username?: string): Promise<User> {
    const result = await query(
      'INSERT INTO users (username) VALUES ($1) RETURNING *',
      [username || `user_${Date.now()}`]
    );
    return result.rows[0];
  }

  async getUserById(id: string): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  async updateProfile(
    userId: string,
    data: {
      username?: string;
      email?: string;
      display_name?: string;
      avatar_url?: string;
      bio?: string;
    }
  ): Promise<User> {
    const fields: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    });

    values.push(userId);
    
    const result = await query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    return result.rows[0];
  }

  async checkUsernameAvailable(username: string): Promise<boolean> {
    const result = await query(
      'SELECT COUNT(*) FROM users WHERE username = $1',
      [username]
    );
    return parseInt(result.rows[0].count) === 0;
  }
}