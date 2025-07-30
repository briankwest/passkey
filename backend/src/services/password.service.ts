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
  private readonly maxFailedAttempts = 5;
  private readonly lockDurationMinutes = {
    standard: 30,
    extended: 60
  };
  private readonly historyLimit = 10;
  private readonly historyCheckLimit = 5;
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
  validatePassword(password: string, userInputs: string[] = []): PasswordValidation {
    const errors: string[] = [];
    
    // Validate length
    const lengthErrors = this.validateLength(password);
    errors.push(...lengthErrors);
    
    // Check strength
    const strength = this.analyzeStrength(password, userInputs);
    
    // Add strength-based errors
    const strengthErrors = this.getStrengthErrors(strength);
    errors.push(...strengthErrors);
    
    return {
      isValid: errors.length === 0,
      errors,
      strength
    };
  }
  
  private validateLength(password: string): string[] {
    const errors: string[] = [];
    if (password.length < this.minLength) {
      errors.push(`Password must be at least ${this.minLength} characters long`);
    }
    if (password.length > this.maxLength) {
      errors.push(`Password must be no more than ${this.maxLength} characters long`);
    }
    return errors;
  }
  
  private analyzeStrength(password: string, userInputs: string[] = []): PasswordStrength {
    const result = zxcvbn(password, userInputs);
    return {
      score: result.score,
      feedback: result.feedback,
      crackTime: String(result.crack_times_display.offline_slow_hashing_1e4_per_second),
      isAcceptable: result.score >= this.minScore && password.length >= this.minLength
    };
  }
  
  private getStrengthErrors(strength: PasswordStrength): string[] {
    const errors: string[] = [];
    if (strength.score < this.minScore) {
      errors.push('Password is too weak. Try a longer phrase or add more unique words');
      if (strength.feedback.warning) {
        errors.push(strength.feedback.warning);
      }
    }
    return errors;
  }
  async checkPasswordHistory(userId: string, password: string, limit: number = this.historyCheckLimit): Promise<boolean> {
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
    // Add new password to history
    await this.addToHistory(userId, passwordHash);
    
    // Clean up old entries
    await this.cleanupPasswordHistory(userId);
  }
  
  private async addToHistory(userId: string, passwordHash: string): Promise<void> {
    await query(
      `INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`,
      [userId, passwordHash]
    );
  }
  
  private async cleanupPasswordHistory(userId: string): Promise<void> {
    await query(
      `DELETE FROM password_history 
       WHERE user_id = $1 
       AND id NOT IN (
         SELECT id FROM password_history 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT $2
       )`,
      [userId, this.historyLimit]
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
    const attempts = await this.incrementFailedAttempts(email);
    
    if (attempts >= this.maxFailedAttempts) {
      await this.lockAccount(email, attempts);
    }
  }
  
  private async incrementFailedAttempts(email: string): Promise<number> {
    const result = await query(
      `UPDATE users 
       SET failed_login_attempts = failed_login_attempts + 1
       WHERE email = $1
       RETURNING failed_login_attempts`,
      [email]
    );
    
    return result.rows.length > 0 ? result.rows[0].failed_login_attempts : 0;
  }
  
  private async lockAccount(email: string, attempts: number): Promise<void> {
    const lockDuration = this.calculateLockDuration(attempts);
    await query(
      `UPDATE users 
       SET locked_until = NOW() + INTERVAL '${lockDuration} minutes'
       WHERE email = $1`,
      [email]
    );
  }
  
  private calculateLockDuration(attempts: number): number {
    return attempts >= 10 ? this.lockDurationMinutes.extended : this.lockDurationMinutes.standard;
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