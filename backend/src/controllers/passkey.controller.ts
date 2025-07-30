import { Request, Response } from 'express';
import { query } from '../db';
import { asyncHandler, AuthError, NotFoundError, ValidationError, AppError } from '../middleware/errorHandler';

export class PasskeyController {
  listPasskeys = asyncHandler(async (req: Request, res: Response) => {
    const userId = (req as any).user?.userId;
    if (!userId) {
      throw new AuthError('Unauthorized');
    }
    
    const result = await query(
      `SELECT 
        id, 
        name, 
        device_type, 
        authenticator_attachment,
        created_at, 
        last_used
       FROM passkeys 
       WHERE user_id = $1 
       ORDER BY last_used DESC NULLS LAST, created_at DESC`,
      [userId]
    );
    
    const passkeys = result.rows.map(row => ({
      id: row.id,
      name: row.name || this.generateDefaultName(row),
      deviceType: row.device_type,
      authenticatorAttachment: row.authenticator_attachment,
      createdAt: row.created_at,
      lastUsed: row.last_used
    }));
    
    res.json(passkeys);
  })

  renamePasskey = asyncHandler(async (req: Request, res: Response) => {
    const userId = (req as any).user?.userId;
    const { id } = req.params;
    const { name } = req.body;
    
    if (!userId) {
      throw new AuthError('Unauthorized');
    }
    
    if (!name || name.trim().length === 0) {
      throw new ValidationError('Name is required');
    }
    
    // Verify ownership
    const ownership = await query(
      'SELECT id FROM passkeys WHERE id = $1 AND user_id = $2',
      [id, userId]
    );
    
    if (ownership.rows.length === 0) {
      throw new NotFoundError('Passkey not found');
    }
    
    // Update name
    await query(
      'UPDATE passkeys SET name = $1 WHERE id = $2',
      [name.trim(), id]
    );
    
    res.json({ success: true });
  })

  deletePasskey = asyncHandler(async (req: Request, res: Response) => {
    const userId = (req as any).user?.userId;
    const { id } = req.params;
    
    if (!userId) {
      throw new AuthError('Unauthorized');
    }
    
    // Check if this is the last passkey and user has no password
    const authMethods = await query(
      `SELECT 
        (SELECT COUNT(*) FROM passkeys WHERE user_id = $1) as passkey_count,
        (SELECT password_hash IS NOT NULL FROM users WHERE id = $1) as has_password`,
      [userId]
    );
    
    const { passkey_count, has_password } = authMethods.rows[0];
    
    if (passkey_count <= 1 && !has_password) {
      throw new AppError(
        400, 
        'Cannot delete your only authentication method. Please add a password or another passkey first.',
        'LAST_AUTH_METHOD'
      );
    }
    
    // Delete passkey
    const result = await query(
      'DELETE FROM passkeys WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, userId]
    );
    
    if (result.rows.length === 0) {
      throw new NotFoundError('Passkey not found');
    }
    
    res.json({ success: true });
  })

  private generateDefaultName(passkey: any): string {
    const attachment = passkey.authenticator_attachment;
    const createdDate = new Date(passkey.created_at).toLocaleDateString();
    
    if (attachment === 'platform') {
      return `Device Passkey (${createdDate})`;
    } else if (attachment === 'cross-platform') {
      return `Security Key (${createdDate})`;
    }
    
    return `Passkey (${createdDate})`;
  }
}