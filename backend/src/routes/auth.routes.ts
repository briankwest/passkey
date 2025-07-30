import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();
const authController = new AuthController();

// Email/Password Registration & Login
router.post('/register', authController.register);
router.post('/register/passkey', authController.registerWithPasskey);
router.post('/login', authController.login);
router.get('/check-email', authController.checkEmail);
router.post('/check-password-strength', authController.checkPasswordStrength);

// Email Verification
router.get('/verify-email', authController.verifyEmail);
router.post('/resend-verification', authController.resendVerification);
router.post('/send-verification', authController.sendVerification);

// Passkey Authentication
router.post('/registration/options', authController.registrationOptions);
router.post('/registration/verify', authController.verifyRegistration);
router.post('/authentication/options', authController.authenticationOptions);
router.post('/authentication/verify', authController.verifyAuthentication);

// Passkey Management (authenticated)
router.post('/passkey/add/options', authenticateToken, authController.registrationOptions);
router.post('/passkey/add/verify', authenticateToken, authController.verifyRegistration);

// TOTP Management (authenticated)
router.post('/totp/setup', authenticateToken, authController.setupTOTP);
router.post('/totp/verify-setup', authenticateToken, authController.verifyTOTPSetup);
router.post('/totp/verify', authController.verifyTOTP);
router.delete('/totp', authenticateToken, authController.disableTOTP);
router.post('/totp/backup-codes/regenerate', authenticateToken, authController.regenerateBackupCodes);

// Authentication Methods Check
router.post('/check-methods', authController.checkAuthMethods);

// Cross-device authentication
router.post('/cross-device/create', authController.createCrossDeviceSession);
router.get('/cross-device/check/:sessionId', authController.checkCrossDeviceSession);
router.post('/cross-device/complete', authenticateToken, authController.completeCrossDeviceAuth);

// Password Management
router.post('/change-password', authenticateToken, authController.changePassword);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Session Management
router.post('/logout', authController.logout);

// Security Settings endpoints (authenticated)
router.get('/totp/status', authenticateToken, authController.getTOTPStatus);
router.get('/backup-codes', authenticateToken, authController.getBackupCodes);
router.get('/recent-activity', authenticateToken, authController.getRecentActivity);

export default router;