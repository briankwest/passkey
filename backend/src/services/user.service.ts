import { query } from '../db';
import { User } from '../types';
import { PasswordService } from './password.service';
import { EmailService } from './email.service';
import crypto from 'crypto';

interface CreateUserData {
  email: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
}

export class UserService {
  private passwordService: PasswordService;
  private emailService: EmailService;

  constructor() {
    this.passwordService = new PasswordService();
    this.emailService = new EmailService();
  }

  async createUser(data: CreateUserData): Promise<User> {
    // Check if email already exists
    const existing = await this.getUserByEmail(data.email);
    if (existing) {
      throw new Error('Email already registered');
    }

    // Generate username if not provided
    const username = data.username || `user_${Date.now()}`;

    // Hash password if provided
    let passwordHash = null;
    if (data.password) {
      passwordHash = await this.passwordService.hashPassword(data.password);
    }

    const result = await query(
      `INSERT INTO users (
        username, email, first_name, last_name, password_hash, email_verified
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        username,
        data.email,
        data.firstName || null,
        data.lastName || null,
        passwordHash,
        false // Email not verified by default
      ]
    );

    const user = result.rows[0];

    // Save password to history if password was set
    if (passwordHash) {
      await this.passwordService.savePasswordToHistory(user.id, passwordHash);
    }

    return user;
  }

  async createPasskeyUser(username?: string): Promise<User> {
    // For passkey-only users (backward compatibility)
    const result = await query(
      'INSERT INTO users (username, email_verified) VALUES ($1, $2) RETURNING *',
      [username || `user_${Date.now()}`, true] // Passkey users don't need email verification
    );
    return result.rows[0];
  }

  async getUserById(id: string): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
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
      first_name?: string;
      last_name?: string;
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

  async checkEmailAvailable(email: string): Promise<boolean> {
    const result = await query(
      'SELECT COUNT(*) FROM users WHERE email = $1',
      [email]
    );
    return parseInt(result.rows[0].count) === 0;
  }

  async createEmailVerificationToken(userId: string): Promise<string> {
    // Generate secure token
    const token = crypto.randomBytes(32).toString('hex');
    
    // Set expiration (24 hours)
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    await query(
      `INSERT INTO email_verification_tokens (user_id, token, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, token, expiresAt]
    );

    return token;
  }

  async verifyEmailToken(token: string): Promise<{ valid: boolean; userId?: string; alreadyUsed?: boolean }> {
    // First check if token exists at all
    const tokenResult = await query(
      `SELECT * FROM email_verification_tokens WHERE token = $1`,
      [token]
    );

    if (tokenResult.rows.length === 0) {
      return { valid: false };
    }

    const tokenData = tokenResult.rows[0];

    // Check if already used
    if (tokenData.used_at) {
      return { 
        valid: false, 
        alreadyUsed: true,
        userId: tokenData.user_id 
      };
    }

    // Check if expired
    if (new Date(tokenData.expires_at) < new Date()) {
      return { valid: false };
    }

    // Mark token as used
    await query(
      `UPDATE email_verification_tokens SET used_at = NOW() WHERE token = $1`,
      [token]
    );

    // Mark user as verified
    await query(
      `UPDATE users SET email_verified = true, email_verified_at = NOW() WHERE id = $1`,
      [tokenData.user_id]
    );

    return { valid: true, userId: tokenData.user_id };
  }

  async hasPassword(userId: string): Promise<boolean> {
    const result = await query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    );
    return result.rows[0]?.password_hash !== null;
  }

  async getAvailableAuthMethods(email: string): Promise<{
    password: boolean;
    passkey: boolean;
    totp: boolean;
  }> {
    const user = await this.getUserByEmail(email);
    if (!user) {
      return { password: false, passkey: false, totp: false };
    }

    // Check for password
    const hasPassword = user.password_hash !== null;

    // Check for passkeys
    const passkeyResult = await query(
      'SELECT COUNT(*) as count FROM passkeys WHERE user_id = $1',
      [user.id]
    );
    const hasPasskey = parseInt(passkeyResult.rows[0].count) > 0;

    // Check for TOTP
    const totpResult = await query(
      'SELECT COUNT(*) as count FROM user_totp WHERE user_id = $1 AND verified = true',
      [user.id]
    );
    const hasTOTP = parseInt(totpResult.rows[0].count) > 0;

    return {
      password: hasPassword,
      passkey: hasPasskey,
      totp: hasTOTP
    };
  }

  async trackAuthMethod(userId: string, method: string, success: boolean, ipAddress?: string, userAgent?: string): Promise<void> {
    await query(
      `INSERT INTO auth_methods (user_id, method, success, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, method, success, ipAddress, userAgent]
    );
  }

  async updatePassword(userId: string, passwordHash: string): Promise<void> {
    // Update user's password
    await query(
      `UPDATE users 
       SET password_hash = $1, 
           password_updated_at = NOW(),
           failed_login_attempts = 0,
           locked_until = NULL
       WHERE id = $2`,
      [passwordHash, userId]
    );

    // Save to password history
    await this.passwordService.savePasswordToHistory(userId, passwordHash);
  }

  async logAuthMethod(userId: string, method: string, req: any): Promise<void> {
    const ipAddress = req.ip || req.connection?.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    await this.trackAuthMethod(userId, method, true, ipAddress, userAgent);
  }
}