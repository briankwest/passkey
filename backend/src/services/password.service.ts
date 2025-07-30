import bcrypt from 'bcrypt';
import zxcvbn from 'zxcvbn';
import { query } from '../db';

interface PasswordStrength {
  score: number;
  feedback: {
    warning?: string;
    suggestions: string[];
  };
  crackTime: string;
  isAcceptable: boolean;
}

interface PasswordValidation {
  isValid: boolean;
  errors: string[];
  strength?: PasswordStrength;
}

export class PasswordService {
  private readonly saltRounds = 12;
  private readonly minLength = 12;
  private readonly maxLength = 128;
  private readonly minScore = 3; // zxcvbn score (0-4)

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  validatePassword(password: string, userInputs: string[] = []): PasswordValidation {
    const errors: string[] = [];

    // Check length
    if (password.length < this.minLength) {
      errors.push(`Password must be at least ${this.minLength} characters long`);
    }
    if (password.length > this.maxLength) {
      errors.push(`Password must be no more than ${this.maxLength} characters long`);
    }

    // Check strength using zxcvbn
    const result = zxcvbn(password, userInputs);
    
    const strength: PasswordStrength = {
      score: result.score,
      feedback: result.feedback,
      crackTime: String(result.crack_times_display.offline_slow_hashing_1e4_per_second),
      isAcceptable: result.score >= this.minScore && password.length >= this.minLength
    };

    if (result.score < this.minScore) {
      errors.push('Password is too weak. Try a longer phrase or add more unique words');
      
      if (result.feedback.warning) {
        errors.push(result.feedback.warning);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      strength
    };
  }

  async checkPasswordHistory(userId: string, password: string, limit: number = 5): Promise<boolean> {
    const result = await query(
      `SELECT password_hash FROM password_history 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2`,
      [userId, limit]
    );

    for (const row of result.rows) {
      if (await this.verifyPassword(password, row.password_hash)) {
        return false; // Password was used before
      }
    }

    return true; // Password not found in history
  }

  async savePasswordToHistory(userId: string, passwordHash: string): Promise<void> {
    await query(
      `INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`,
      [userId, passwordHash]
    );

    // Clean up old password history (keep last 10)
    await query(
      `DELETE FROM password_history 
       WHERE user_id = $1 
       AND id NOT IN (
         SELECT id FROM password_history 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 10
       )`,
      [userId]
    );
  }

  generatePasswordSuggestions(): string[] {
    return [
      'Try a passphrase with 4+ random words',
      'Example: "purple-elephant-dances-moonlight"',
      'Longer passwords are stronger than complex ones',
      'Avoid common patterns like "Password123!"',
      'Don\'t use personal information like names or birthdays'
    ];
  }

  checkStrength(password: string): { score: number; feedback: string; suggestions?: string[] } {
    if (!password) {
      return { score: 0, feedback: 'Password is required' };
    }

    const result = zxcvbn(password);
    
    return {
      score: result.score,
      feedback: result.feedback.warning || this.getStrengthFeedback(result.score),
      suggestions: result.feedback.suggestions
    };
  }

  private getStrengthFeedback(score: number): string {
    const feedbacks = [
      'Very weak password',
      'Weak password',
      'Fair password',
      'Good password',
      'Strong password'
    ];
    return feedbacks[score] || 'Password strength unknown';
  }

  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const hash = await this.hashPassword(newPassword);
    
    // Update user password
    await query(
      `UPDATE users 
       SET password_hash = $1, 
           password_updated_at = NOW(),
           require_password_change = FALSE
       WHERE id = $2`,
      [hash, userId]
    );

    // Save to password history
    await this.savePasswordToHistory(userId, hash);
  }

  async checkAccountLockout(email: string): Promise<{ isLocked: boolean; lockedUntil?: Date }> {
    const result = await query(
      `SELECT locked_until FROM users 
       WHERE email = $1 AND locked_until > NOW()`,
      [email]
    );

    if (result.rows.length > 0) {
      return {
        isLocked: true,
        lockedUntil: result.rows[0].locked_until
      };
    }

    return { isLocked: false };
  }

  async recordFailedLogin(email: string): Promise<void> {
    const result = await query(
      `UPDATE users 
       SET failed_login_attempts = failed_login_attempts + 1
       WHERE email = $1
       RETURNING failed_login_attempts`,
      [email]
    );

    if (result.rows.length > 0) {
      const attempts = result.rows[0].failed_login_attempts;
      
      // Lock account after 5 failed attempts
      if (attempts >= 5) {
        const lockDuration = attempts >= 10 ? 60 : 30; // 30 or 60 minutes
        await query(
          `UPDATE users 
           SET locked_until = NOW() + INTERVAL '${lockDuration} minutes'
           WHERE email = $1`,
          [email]
        );
      }
    }
  }

  async clearFailedLoginAttempts(email: string): Promise<void> {
    await query(
      `UPDATE users 
       SET failed_login_attempts = 0, locked_until = NULL
       WHERE email = $1`,
      [email]
    );
  }
}