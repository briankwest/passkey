import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { query } from '../db';

interface TOTPSetup {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

interface BackupCode {
  code: string;
  hashedCode: string;
}

export class TOTPService {
  private readonly appName = process.env.APP_NAME || 'Passkey Demo';
  private readonly backupCodeLength = 10;
  private readonly backupCodeCount = 8;

  async setupTOTP(userId: string, userEmail: string): Promise<TOTPSetup> {
    // Check if user already has TOTP
    const existing = await query(
      'SELECT id FROM user_totp WHERE user_id = $1',
      [userId]
    );

    if (existing.rows.length > 0) {
      throw new Error('TOTP is already configured for this user');
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.appName} (${userEmail})`,
      issuer: this.appName,
      length: 32
    });

    // Store unverified secret (encrypted in production)
    await query(
      'INSERT INTO user_totp (user_id, secret, verified) VALUES ($1, $2, $3)',
      [userId, secret.base32, false]
    );

    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url!);

    // Generate backup codes
    const backupCodes = await this.generateBackupCodes(userId);

    return {
      secret: secret.base32,
      qrCode,
      backupCodes: backupCodes.map(bc => bc.code)
    };
  }

  async verifyTOTPSetup(userId: string, token: string): Promise<boolean> {
    const result = await query(
      'SELECT secret FROM user_totp WHERE user_id = $1 AND verified = false',
      [userId]
    );

    if (result.rows.length === 0) {
      throw new Error('No pending TOTP setup found');
    }

    const secret = result.rows[0].secret;
    
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 intervals for clock drift
    });

    if (verified) {
      await query(
        'UPDATE user_totp SET verified = true WHERE user_id = $1',
        [userId]
      );
    }

    return verified;
  }

  async verifyTOTP(userId: string, token: string): Promise<boolean> {
    const result = await query(
      'SELECT secret FROM user_totp WHERE user_id = $1 AND verified = true',
      [userId]
    );

    if (result.rows.length === 0) {
      return false;
    }

    const secret = result.rows[0].secret;
    
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2
    });

    if (verified) {
      await query(
        'UPDATE user_totp SET last_used = NOW() WHERE user_id = $1',
        [userId]
      );
    }

    return verified;
  }

  async hasTOTP(userId: string): Promise<boolean> {
    const result = await query(
      'SELECT id FROM user_totp WHERE user_id = $1 AND verified = true',
      [userId]
    );
    return result.rows.length > 0;
  }

  async disableTOTP(userId: string): Promise<void> {
    await query('DELETE FROM user_totp WHERE user_id = $1', [userId]);
    await query('DELETE FROM backup_codes WHERE user_id = $1', [userId]);
  }

  private async generateBackupCodes(userId: string): Promise<BackupCode[]> {
    // Clear existing backup codes
    await query('DELETE FROM backup_codes WHERE user_id = $1', [userId]);

    const codes: BackupCode[] = [];
    
    for (let i = 0; i < this.backupCodeCount; i++) {
      const code = this.generateSecureCode();
      const hashedCode = await this.hashBackupCode(code);
      
      codes.push({ code, hashedCode });
      
      await query(
        'INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, hashedCode]
      );
    }

    return codes;
  }

  async regenerateBackupCodes(userId: string): Promise<string[]> {
    const codes = await this.generateBackupCodes(userId);
    return codes.map(bc => bc.code);
  }

  async getBackupCodes(userId: string): Promise<Array<{ code: string; used: boolean }>> {
    const result = await query(
      'SELECT id, used FROM backup_codes WHERE user_id = $1 ORDER BY created_at',
      [userId]
    );

    // We can't return the actual codes since they're hashed
    // Return masked codes with usage status
    return result.rows.map((row, index) => ({
      code: `****-****-${(index + 1).toString().padStart(2, '0')}`,
      used: row.used
    }));
  }

  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const result = await query(
      'SELECT id, code_hash FROM backup_codes WHERE user_id = $1 AND used = false',
      [userId]
    );

    for (const row of result.rows) {
      if (await this.verifyBackupCodeHash(code, row.code_hash)) {
        // Mark as used
        await query(
          'UPDATE backup_codes SET used = true, used_at = NOW() WHERE id = $1',
          [row.id]
        );
        return true;
      }
    }

    return false;
  }

  async getBackupCodeCount(userId: string): Promise<{ total: number; used: number }> {
    const result = await query(
      `SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN used THEN 1 ELSE 0 END) as used
       FROM backup_codes 
       WHERE user_id = $1`,
      [userId]
    );

    return {
      total: parseInt(result.rows[0].total),
      used: parseInt(result.rows[0].used) || 0
    };
  }

  private generateSecureCode(): string {
    // Generate a secure random code
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 alphabet
    const bytes = crypto.randomBytes(this.backupCodeLength);
    let code = '';
    
    for (let i = 0; i < this.backupCodeLength; i++) {
      code += characters[bytes[i] % characters.length];
      // Add hyphen every 5 characters for readability
      if (i === 4) code += '-';
    }
    
    return code;
  }

  private async hashBackupCode(code: string): Promise<string> {
    // Use bcrypt for backup code hashing
    const bcrypt = await import('bcrypt');
    return bcrypt.hash(code, 10);
  }

  private async verifyBackupCodeHash(code: string, hash: string): Promise<boolean> {
    const bcrypt = await import('bcrypt');
    return bcrypt.compare(code, hash);
  }
}