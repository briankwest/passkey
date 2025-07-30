// Example of converting auth controller methods to use asyncHandler and custom errors
// This shows the pattern for converting the entire controller

import { Request, Response } from 'express';
import { asyncHandler, ValidationError, AuthError, NotFoundError, AppError } from '../middleware/errorHandler';

export class AuthControllerExample {
  
  // BEFORE:
  // async checkPasswordStrength(req: Request, res: Response) {
  //   try {
  //     const { password } = req.body;
  //     if (!password) {
  //       return res.json({ score: 0, feedback: 'Password is required' });
  //     }
  //     const result = passwordService.checkStrength(password);
  //     res.json(result);
  //   } catch (error) {
  //     res.status(500).json({ error: 'Failed to check password strength' });
  //   }
  // }

  // AFTER:
  checkPasswordStrength = asyncHandler(async (req: Request, res: Response) => {
    const { password } = req.body;
    if (!password) {
      return res.json({ score: 0, feedback: 'Password is required' });
    }
    const result = passwordService.checkStrength(password);
    res.json(result);
  })

  // BEFORE:
  // async checkEmail(req: Request, res: Response) {
  //   try {
  //     const { email } = req.query;
  //     if (!email || typeof email !== 'string') {
  //       return res.status(400).json({ error: 'Email is required' });
  //     }
  //     const available = await userService.checkEmailAvailable(email);
  //     res.json({ available });
  //   } catch (error) {
  //     res.status(500).json({ error: 'Failed to check email availability' });
  //   }
  // }

  // AFTER:
  checkEmail = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.query;
    if (!email || typeof email !== 'string') {
      throw new ValidationError('Email is required');
    }
    const available = await userService.checkEmailAvailable(email);
    res.json({ available });
  })

  // BEFORE:
  // async changePassword(req: Request, res: Response) {
  //   try {
  //     const { currentPassword, newPassword } = req.body;
  //     const userId = (req as any).user.userId;
  //     
  //     const user = await userService.getUserById(userId);
  //     if (!user) {
  //       return res.status(404).json({ error: 'User not found' });
  //     }
  //     
  //     if (!user.password_hash) {
  //       return res.status(400).json({ error: 'No password set for this account' });
  //     }
  //     
  //     const validPassword = await passwordService.verifyPassword(currentPassword, user.password_hash);
  //     if (!validPassword) {
  //       return res.status(401).json({ error: 'Current password is incorrect' });
  //     }
  //     
  //     // ... rest of method
  //   } catch (error) {
  //     res.status(500).json({ error: 'Failed to change password' });
  //   }
  // }

  // AFTER:
  changePassword = asyncHandler(async (req: Request, res: Response) => {
    const { currentPassword, newPassword } = req.body;
    const userId = (req as any).user.userId;
    
    const user = await userService.getUserById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    if (!user.password_hash) {
      throw new ValidationError('No password set for this account');
    }
    
    const validPassword = await passwordService.verifyPassword(currentPassword, user.password_hash);
    if (!validPassword) {
      throw new AuthError('Current password is incorrect');
    }
    
    // ... rest of method
  })

  // Pattern for converting complex error responses:
  
  // BEFORE:
  // if (!passwordValidation.isValid) {
  //   return res.status(400).json({ 
  //     error: 'Password does not meet requirements',
  //     details: passwordValidation.errors,
  //     strength: passwordValidation.strength
  //   });
  // }

  // AFTER:
  // if (!passwordValidation.isValid) {
  //   throw new ValidationError('Password does not meet requirements', {
  //     errors: passwordValidation.errors,
  //     strength: passwordValidation.strength
  //   });
  // }

  // For custom status codes:
  // throw new AppError(409, 'Email already registered', 'DUPLICATE_EMAIL');
  
  // For rate limiting:
  // throw new AppError(429, 'Too many requests', 'RATE_LIMIT');
}