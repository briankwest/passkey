import { Request, Response } from 'express';
import { UserService } from '../services/user.service';
import { asyncHandler, AuthError, NotFoundError, ValidationError } from '../middleware/errorHandler';

const userService = new UserService();

export class UserController {
  getProfile = asyncHandler(async (req: Request, res: Response) => {
    const userId = (req as any).user?.userId;
    if (!userId) {
      throw new AuthError('Unauthorized');
    }
    
    const user = await userService.getUserById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      display_name: user.display_name,
      avatar_url: user.avatar_url,
      bio: user.bio,
      created_at: user.created_at,
      has_password: !!user.password_hash
    });
  })
  
  updateProfile = asyncHandler(async (req: Request, res: Response) => {
    const userId = (req as any).user?.userId;
    if (!userId) {
      throw new AuthError('Unauthorized');
    }
    
    const { username, email, display_name, avatar_url, bio } = req.body;
    
    // Check username availability if changing
    if (username) {
      const available = await userService.checkUsernameAvailable(username);
      if (!available) {
        const currentUser = await userService.getUserById(userId);
        if (currentUser?.username !== username) {
          throw new ValidationError('Username already taken');
        }
      }
    }
    
    const updatedUser = await userService.updateProfile(userId, {
      username,
      email,
      display_name,
      avatar_url,
      bio
    });
    
    res.json({
      id: updatedUser.id,
      username: updatedUser.username,
      email: updatedUser.email,
      display_name: updatedUser.display_name,
      avatar_url: updatedUser.avatar_url,
      bio: updatedUser.bio
    });
  })
}