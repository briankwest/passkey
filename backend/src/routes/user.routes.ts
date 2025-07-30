import { Router } from 'express';
import { UserController } from '../controllers/user.controller';
import { authenticateToken } from '../middleware/auth.middleware';
import { validateProfileUpdate } from '../middleware/validation';

const router = Router();
const userController = new UserController();

router.get('/profile', authenticateToken, userController.getProfile);
router.put('/profile', authenticateToken, validateProfileUpdate, userController.updateProfile);
export default router;