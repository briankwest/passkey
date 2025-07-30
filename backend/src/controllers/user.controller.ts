import { Request, Response } from 'express';
import { UserService } from '../services/user.service';
const userService = new UserService();
export class UserController {
  async getProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const user = await userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
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
    } catch (error) {
      res.status(500).json({ error: 'Failed to get profile' });
    }
  }
  async updateProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const { username, email, display_name, avatar_url, bio } = req.body;
      // Check username availability if changing
      if (username) {
        const available = await userService.checkUsernameAvailable(username);
        if (!available) {
          const currentUser = await userService.getUserById(userId);
          if (currentUser?.username !== username) {
            return res.status(400).json({ error: 'Username already taken' });
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
    } catch (error) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
}