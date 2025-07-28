import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();
const authController = new AuthController();

router.post('/register/options', authController.registrationOptions);
router.post('/register/verify', authController.verifyRegistration);
router.post('/authenticate/options', authController.authenticationOptions);
router.post('/authenticate/verify', authController.verifyAuthentication);
router.post('/logout', authController.logout);

// Cross-device authentication
router.post('/cross-device/create', authController.createCrossDeviceSession);
router.get('/cross-device/check/:sessionId', authController.checkCrossDeviceSession);
router.post('/cross-device/complete', authenticateToken, authController.completeCrossDeviceAuth);

export default router;