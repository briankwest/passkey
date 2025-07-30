import { Request, Response } from 'express';
import { WebAuthnService } from '../services/webauthn.service';
import { UserService } from '../services/user.service';
import { PasswordService } from '../services/password.service';
import { EmailService } from '../services/email.service';
import { TOTPService } from '../services/totp.service';
import { CrossDeviceService } from '../services/crossDevice.service';
import { challengeService } from '../services/challenge.service';
import { generateAuthToken } from '../utils/jwt';
import { getClientIp } from '../utils/getClientIp';
import { config } from '../config';
import crypto from 'crypto';
import { query } from '../db';
import { asyncHandler, ValidationError, AuthError, NotFoundError, AppError } from '../middleware/errorHandler';
// Extend session type inline
declare module 'express-session' {
  interface SessionData {
    currentChallenge?: string;
    pendingUserId?: string;
    authMethod?: string;
  }
}
const webauthnService = new WebAuthnService();
const userService = new UserService();
const passwordService = new PasswordService();
const emailService = new EmailService();
const totpService = new TOTPService();
const crossDeviceService = new CrossDeviceService();
export class AuthController {
  // ============= Registration Methods =============
  // Email/Password Registration
  register = asyncHandler(async (req: Request, res: Response) => {
      const { email, password, passwordConfirm, firstName, lastName } = req.body;
      // Validate inputs
      if (!email || !password) {
        throw new ValidationError('Email and password are required');
      }
      if (password !== passwordConfirm) {
        throw new ValidationError('Passwords do not match');
      }
      // Validate password strength
      const passwordValidation = passwordService.validatePassword(
        password, 
        [email, firstName, lastName].filter(Boolean)
      );
      if (!passwordValidation.isValid) {
        throw new ValidationError('Password does not meet requirements', {
          errors: passwordValidation.errors,
          strength: passwordValidation.strength
        });
      }
      // Check email availability
      const emailAvailable = await userService.checkEmailAvailable(email);
      if (!emailAvailable) {
        throw new ValidationError('Email already registered');
      }
      // Create user
      const user = await userService.createUser({
        email,
        password,
        firstName,
        lastName
      });
      // Generate verification token and send email
      const verificationToken = await userService.createEmailVerificationToken(user.id);
      await emailService.sendVerificationEmail({
        id: user.id,
        email: user.email!,
        firstName: user.first_name,
        lastName: user.last_name
      }, verificationToken);
      res.json({
        success: true,
        message: 'Account created successfully. Please check your email to verify your account.',
        requiresVerification: true
      });
  })
  // Check email availability
  async checkEmail(req: Request, res: Response) {
    try {
      const { email } = req.query;
      if (!email || typeof email !== 'string') {
        return res.status(400).json({ error: 'Email is required' });
      }
      const available = await userService.checkEmailAvailable(email);
      res.json({ available });
    } catch (error) {
      res.status(500).json({ error: 'Failed to check email availability' });
    }
  }
  // Register with passkey (creates user with email, requires verification)
  async registerWithPasskey(req: Request, res: Response) {
    try {
      const { email, firstName, lastName } = req.body;
      if (!email) {
        return res.status(400).json({ error: 'Email is required' });
      }
      // Check if email already exists
      const existingUser = await userService.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      // Create user without password
      const user = await userService.createUser({
        email,
        firstName,
        lastName
      });
      // Create verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      await query(
        `INSERT INTO email_verification_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, verificationToken, expiresAt]
      );
      // Send verification email
      if (user.email) {
        await emailService.sendVerificationEmail({
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name
        }, verificationToken);
      }
      res.json({ 
        success: true, 
        message: 'Please check your email to verify your account. You can add a passkey after verification.' 
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: error.message || 'Failed to register' 
      });
    }
  }
  // ============= Passkey Methods =============
  async registrationOptions(req: Request, res: Response) {
    try {
      const origin = req.get('origin') || req.get('referer');
      const userId = (req as any).user?.userId;
      const { deviceName, email } = req.body;
      // Pass user data if registering new user with email
      const userData = email ? { email } : undefined;
      const options = await webauthnService.generateRegistrationOptions(userId, origin, userData);
      // Store challenge in database instead of session
      await challengeService.storeChallenge(options.challenge, userId, 'registration');
      res.json(options);
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Failed to generate registration options',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
  async verifyRegistration(req: Request, res: Response) {
    try {
      const { credential, deviceName, userData } = req.body;
      const existingUserId = (req as any).user?.userId;
      const origin = req.get('origin') || req.get('referer');
      // Let the webauthn service handle all verification including challenge
      const verification = await webauthnService.verifyRegistrationResponse(
        credential,
        null, // Let webauthn service find the challenge
        origin
      );
      if (verification.verified && verification.registrationInfo) {
        let userId = existingUserId || verification.userId;
        // Create new user if not adding to existing account
        if (!userId) {
          // If userData is provided, create user with that data
          if (userData) {
            const user = await userService.createUser({
              email: userData.email,
              firstName: userData.firstName,
              lastName: userData.lastName
            });
            userId = user.id;
          } else {
            // Fallback to anonymous passkey user (shouldn't happen with new flow)
            const user = await userService.createPasskeyUser();
            userId = user.id;
          }
        }
        // Save credential with device info
        const userAgent = req.get('user-agent') || '';
        const ipAddress = getClientIp(req);
        await webauthnService.saveCredential(
          userId,
          verification.registrationInfo.credentialID,
          Buffer.from(verification.registrationInfo.credentialPublicKey).toString('base64'),
          verification.registrationInfo.counter,
          credential.response.transports,
          credential.type,
          credential.authenticatorAttachment,
          deviceName || this.generateDeviceName(userAgent),
          userAgent,
          ipAddress
        );
        // If adding to existing account, return success
        if (existingUserId) {
          return res.json({ 
            verified: true,
            message: 'Passkey added successfully'
          });
        }
        // Generate JWT for new user
        const token = generateAuthToken(userId);
        res.json({ 
          verified: true, 
          token,
          user: { id: userId }
        });
      } else {
        res.status(400).json({ 
          verified: false, 
          error: 'Registration verification failed' 
        });
      }
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Failed to verify registration',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
  async authenticationOptions(req: Request, res: Response) {
    try {
      const origin = req.get('origin') || req.get('referer');
      const { email } = req.body;
      let userId;
      if (email) {
        const user = await userService.getUserByEmail(email);
        userId = user?.id;
      }
      const options = await webauthnService.generateAuthenticationOptions(userId, origin);
      // Store challenge in database
      await challengeService.storeChallenge(options.challenge, userId || null, 'authentication');
      res.json(options);
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Failed to generate authentication options',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
  async verifyAuthentication(req: Request, res: Response) {
    try {
      const { credential } = req.body;
      const origin = req.get('origin') || req.get('referer');
      // Let the webauthn service handle all verification including challenge
      const verification = await webauthnService.verifyAuthenticationResponse(
        credential,
        null, // Let webauthn service find the challenge
        origin
      );
      if (verification.verified) {
        const user = await userService.getUserById(verification.userId);
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
        // Track authentication method
        await userService.trackAuthMethod(
          user.id, 
          'passkey', 
          true,
          getClientIp(req),
          req.get('user-agent')
        );
        // Passkey is already multi-factor authentication (possession + biometrics)
        // No need to require TOTP on top of it
        // Generate JWT
        const token = generateAuthToken(user.id);
        res.json({ 
          verified: true, 
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name
          }
        });
      } else {
        await userService.trackAuthMethod(
          '', 
          'passkey', 
          false,
          getClientIp(req),
          req.get('user-agent')
        );
        res.status(400).json({ 
          verified: false, 
          error: 'Authentication verification failed' 
        });
      }
    } catch (error: any) {
      if (error.message?.includes('No passkey found')) {
        return res.status(404).json({ 
          error: 'No passkey found for this device',
          code: 'PASSKEY_NOT_FOUND'
        });
      }
      res.status(500).json({ 
        error: 'Failed to verify authentication',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
  // ============= Email/Password Login =============
  async login(req: Request, res: Response) {
    try {
      const { email, password, totpCode } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }
      // Check account lockout
      const lockout = await passwordService.checkAccountLockout(email);
      if (lockout.isLocked) {
        return res.status(423).json({ 
          error: 'Account is locked due to too many failed attempts',
          lockedUntil: lockout.lockedUntil
        });
      }
      // Get user
      const user = await userService.getUserByEmail(email);
      if (!user || !user.password_hash) {
        await passwordService.recordFailedLogin(email);
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      // Verify password
      const validPassword = await passwordService.verifyPassword(password, user.password_hash);
      if (!validPassword) {
        await passwordService.recordFailedLogin(email);
        await userService.trackAuthMethod(user.id, 'password', false, getClientIp(req), req.get('user-agent'));
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      // Clear failed attempts
      await passwordService.clearFailedLoginAttempts(email);
      // Check email verification
      if (!user.email_verified) {
        return res.status(403).json({ 
          error: 'email_not_verified',
          message: 'Please verify your email before logging in',
          canResend: await emailService.checkRateLimit(email, 'verification')
        });
      }
      // Track successful password auth
      await userService.trackAuthMethod(user.id, 'password', true, getClientIp(req), req.get('user-agent'));
      // Check if TOTP is required
      const hasTOTP = await totpService.hasTOTP(user.id);
      if (hasTOTP) {
        // If TOTP code provided, verify it
        if (totpCode) {
          let validAuth = false;
          let authMethod = 'totp';
          // Check if it's a backup code format (contains hyphens)
          if (totpCode.includes('-')) {
            // Try as backup code
            validAuth = await totpService.verifyBackupCode(user.id, totpCode);
            authMethod = 'backup_code';
          } else {
            // Try as TOTP code
            validAuth = await totpService.verifyTOTP(user.id, totpCode);
          }
          if (!validAuth) {
            await userService.trackAuthMethod(user.id, authMethod, false, getClientIp(req), req.get('user-agent'));
            return res.status(401).json({ error: 'Invalid 2FA code' });
          }
          // Auth verified, continue with login
          await userService.trackAuthMethod(user.id, authMethod, true, getClientIp(req), req.get('user-agent'));
        } else {
          // No TOTP code provided, request it
          req.session.pendingUserId = user.id;
          req.session.authMethod = 'password';
          return res.json({
            success: true,
            requiresTOTP: true
          });
        }
      }
      // Generate JWT
      const token = generateAuthToken(user.id);
      res.json({ 
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          display_name: user.display_name
        }
      });
    } catch (error: any) {
      res.status(500).json({ error: 'Failed to login' });
    }
  }
  // ============= Email Verification =============
  async verifyEmail(req: Request, res: Response) {
    try {
      const verificationToken = req.query.token;
      if (!verificationToken || typeof verificationToken !== 'string') {
        return res.status(400).json({ error: 'Invalid verification token' });
      }
      const result = await userService.verifyEmailToken(verificationToken);
      if (!result.valid) {
        // Check if token was already used
        if (result.alreadyUsed && result.userId) {
          // Get user details
          const user = await userService.getUserById(result.userId);
          if (user && user.email_verified) {
            // User is already verified, redirect to success
            const authToken = generateAuthToken(user.id);
            // Check if user has any passkeys
            const passkeyResult = await query(
              'SELECT COUNT(*) as count FROM passkeys WHERE user_id = $1',
              [user.id]
            );
            const hasPasskey = parseInt(passkeyResult.rows[0].count) > 0;
            return res.json({ 
              success: true,
              message: 'Email already verified',
              alreadyVerified: true,
              token: authToken,
              hasPasskey,
              user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
              }
            });
          }
        }
        return res.status(400).json({ 
          error: 'Invalid or expired verification token' 
        });
      }
      // Get user details and check if they have passkeys
      const user = await userService.getUserById(result.userId!);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      // Check if user has any passkeys
      const passkeyResult = await query(
        'SELECT COUNT(*) as count FROM passkeys WHERE user_id = $1',
        [user.id]
      );
      const hasPasskey = parseInt(passkeyResult.rows[0].count) > 0;
      // Send welcome email
      if (user.email) {
        await emailService.sendWelcomeEmail({
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name
        });
      }
      // Generate JWT token for the verified user
      const authToken = generateAuthToken(user.id);
      res.json({ 
        success: true,
        message: 'Email verified successfully',
        token: authToken,
        hasPasskey,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name
        }
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to verify email' });
    }
  }
  async sendVerification(req: Request, res: Response) {
    try {
      const { userId } = req.body;
      if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
      }
      const user = await userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      if (!user.email) {
        return res.status(400).json({ error: 'User has no email address' });
      }
      if (user.email_verified) {
        return res.status(400).json({ error: 'Email already verified' });
      }
      // Create verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      await query(
        `INSERT INTO email_verification_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
        [user.id, verificationToken, expiresAt]
      );
      // Send verification email
      await emailService.sendVerificationEmail({
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name
      }, verificationToken);
      res.json({ 
        success: true, 
        message: 'Verification email sent' 
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: error.message || 'Failed to send verification email' 
      });
    }
  }
  async resendVerification(req: Request, res: Response) {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: 'Email is required' });
      }
      // Check rate limit
      const canSend = await emailService.checkRateLimit(email, 'verification');
      if (!canSend) {
        return res.status(429).json({ 
          error: 'Too many verification emails sent. Please try again later.' 
        });
      }
      // Get user
      const user = await userService.getUserByEmail(email);
      if (!user) {
        // Don't reveal if email exists
        return res.json({ 
          success: true,
          message: 'If the email exists, a verification link has been sent' 
        });
      }
      if (user.email_verified) {
        return res.status(400).json({ 
          error: 'Email is already verified' 
        });
      }
      // Generate new token and send email
      const token = await userService.createEmailVerificationToken(user.id);
      await emailService.sendVerificationEmail({
        id: user.id,
        email: user.email!,
        firstName: user.first_name,
        lastName: user.last_name
      }, token);
      res.json({ 
        success: true,
        message: 'Verification email sent' 
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to resend verification email' });
    }
  }
  // ============= TOTP Methods =============
  async setupTOTP(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const user = await userService.getUserById(userId);
      if (!user || !user.email) {
        return res.status(400).json({ error: 'User email required for TOTP setup' });
      }
      const setup = await totpService.setupTOTP(userId, user.email);
      res.json(setup);
    } catch (error: any) {
      res.status(500).json({ error: error.message || 'Failed to setup TOTP' });
    }
  }
  async verifyTOTPSetup(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      const { token } = req.body;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      if (!token) {
        return res.status(400).json({ error: 'Verification code required' });
      }
      const verified = await totpService.verifyTOTPSetup(userId, token);
      if (verified) {
        res.json({ 
          success: true,
          message: 'Two-factor authentication enabled successfully' 
        });
      } else {
        res.status(400).json({ 
          error: 'Invalid verification code' 
        });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message || 'Failed to verify TOTP' });
    }
  }
  async verifyTOTP(req: Request, res: Response) {
    try {
      const { token } = req.body;
      const userId = req.session.pendingUserId;
      if (!userId) {
        return res.status(400).json({ error: 'No pending authentication session' });
      }
      if (!token) {
        return res.status(400).json({ error: 'Verification code required' });
      }
      const verified = await totpService.verifyTOTP(userId, token);
      if (!verified) {
        // Try backup code
        const backupVerified = await totpService.verifyBackupCode(userId, token);
        if (!backupVerified) {
          await userService.trackAuthMethod(userId, 'totp', false, getClientIp(req), req.get('user-agent'));
          return res.status(400).json({ error: 'Invalid verification code' });
        }
        await userService.trackAuthMethod(userId, 'backup_code', true, getClientIp(req), req.get('user-agent'));
      } else {
        await userService.trackAuthMethod(userId, 'totp', true, getClientIp(req), req.get('user-agent'));
      }
      // Clear session
      delete req.session.pendingUserId;
      delete req.session.authMethod;
      // Get user and generate token
      const user = await userService.getUserById(userId);
      const jwtToken = generateAuthToken(userId);
      res.json({ 
        success: true,
        token: jwtToken,
        user: {
          id: user!.id,
          username: user!.username,
          email: user!.email,
          display_name: user!.display_name
        }
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to verify code' });
    }
  }
  async disableTOTP(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      await totpService.disableTOTP(userId);
      res.json({ 
        success: true,
        message: 'Two-factor authentication disabled' 
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to disable TOTP' });
    }
  }
  async regenerateBackupCodes(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const codes = await totpService.regenerateBackupCodes(userId);
      res.json({ 
        success: true,
        backupCodes: codes
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to regenerate backup codes' });
    }
  }
  // ============= Authentication Check =============
  async checkAuthMethods(req: Request, res: Response) {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: 'Email is required' });
      }
      const methods = await userService.getAvailableAuthMethods(email);
      res.json(methods);
    } catch (error) {
      res.status(500).json({ error: 'Failed to check authentication methods' });
    }
  }
  // ============= Cross-Device Authentication =============
  async createCrossDeviceSession(req: Request, res: Response) {
    try {
      const { sessionId } = req.body;
      if (!sessionId) {
        return res.status(400).json({ error: 'Session ID required' });
      }
      await crossDeviceService.createSession(sessionId);
      res.json({ success: true });
    } catch (error: any) {
      res.status(500).json({ error: 'Failed to create session' });
    }
  }
  async checkCrossDeviceSession(req: Request, res: Response) {
    try {
      const { sessionId } = req.params;
      const session = await crossDeviceService.getSession(sessionId);
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }
      // If authenticated, generate a token for the desktop session
      if (session.authenticated && session.userId) {
        const token = generateAuthToken(session.userId);
        res.json({
          authenticated: true,
          userId: session.userId,
          token
        });
      } else {
        res.json(session);
      }
    } catch (error: any) {
      res.status(500).json({ error: 'Failed to check session' });
    }
  }
  async completeCrossDeviceAuth(req: Request, res: Response) {
    try {
      const { sessionId, userId } = req.body;
      if (!sessionId || !userId) {
        return res.status(400).json({ error: 'Session ID and user ID required' });
      }
      const user = await userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      const token = generateAuthToken(userId);
      await crossDeviceService.completeSession(sessionId, userId, token);
      res.json({ success: true });
    } catch (error: any) {
      res.status(500).json({ error: 'Failed to complete authentication' });
    }
  }
  // ============= Password Management =============
  async checkPasswordStrength(req: Request, res: Response) {
    try {
      const { password } = req.body;
      if (!password) {
        return res.json({ score: 0, feedback: 'Password is required' });
      }
      const result = passwordService.checkStrength(password);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to check password strength' });
    }
  }
  async changePassword(req: Request, res: Response) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = (req as any).user.userId;
      // Get user
      const user = await userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ 
          error: 'User not found' 
        });
      }
      // Check if this is password creation or change
      const isCreatingPassword = !user.password_hash;
      // Validate inputs based on context
      if (!isCreatingPassword && !currentPassword) {
        return res.status(400).json({ 
          error: 'Current password is required' 
        });
      }
      if (!newPassword) {
        return res.status(400).json({ 
          error: 'New password is required' 
        });
      }
      // Verify current password (only if changing, not creating)
      if (!isCreatingPassword) {
        const isValidPassword = await passwordService.verifyPassword(
          currentPassword!, 
          user.password_hash!
        );
        if (!isValidPassword) {
          return res.status(401).json({ 
            error: 'Current password is incorrect' 
          });
        }
      }
      // Validate new password
      const passwordValidation = passwordService.validatePassword(
        newPassword,
        [user.email, user.first_name, user.last_name].filter(Boolean) as string[]
      );
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'Password does not meet requirements',
          details: passwordValidation.errors,
          strength: passwordValidation.strength
        });
      }
      // Check if new password is same as current (only if changing)
      if (!isCreatingPassword) {
        const isSamePassword = await passwordService.verifyPassword(
          newPassword,
          user.password_hash!
        );
        if (isSamePassword) {
          return res.status(400).json({ 
            error: 'New password must be different from current password' 
          });
        }
      }
      // Update password
      const newPasswordHash = await passwordService.hashPassword(newPassword);
      await userService.updatePassword(userId, newPasswordHash);
      // Log authentication method
      await userService.logAuthMethod(userId, 'password_change', req);
      res.json({ 
        success: true,
        message: isCreatingPassword ? 'Password created successfully' : 'Password changed successfully' 
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to change password' });
    }
  }
  async forgotPassword(req: Request, res: Response) {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: 'Email is required' });
      }
      // Get user
      const user = await userService.getUserByEmail(email);
      // Always return success to prevent email enumeration
      if (!user) {
        return res.json({ success: true });
      }
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      // Store reset token
      await query(
        `INSERT INTO password_reset_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
        [user.id, resetToken, expiresAt]
      );
      // Send reset email
      await emailService.sendPasswordResetEmail({
        id: user.id,
        email: user.email!,
        firstName: user.first_name,
        lastName: user.last_name
      }, resetToken);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Failed to process request' });
    }
  }
  async resetPassword(req: Request, res: Response) {
    try {
      const { token, password } = req.body;
      if (!token || !password) {
        return res.status(400).json({ error: 'Token and password are required' });
      }
      // Find valid token
      const result = await query(
        `SELECT user_id FROM password_reset_tokens 
         WHERE token = $1 AND expires_at > NOW() AND used_at IS NULL`,
        [token]
      );
      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }
      const userId = result.rows[0].user_id;
      // Validate password
      const passwordValidation = passwordService.validatePassword(password);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'Password does not meet requirements',
          requirements: passwordValidation.errors,
          strength: passwordValidation.strength
        });
      }
      // Update password
      const hashedPassword = await passwordService.hashPassword(password);
      await userService.updatePassword(userId, hashedPassword);
      // Mark token as used
      await query(
        'UPDATE password_reset_tokens SET used_at = NOW() WHERE token = $1',
        [token]
      );
      // Track password change
      await userService.trackAuthMethod(userId, 'password_reset', true, getClientIp(req), req.get('user-agent'));
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Failed to reset password' });
    }
  }
  // ============= Session Management =============
  async logout(req: Request, res: Response) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to logout' });
      }
      res.json({ success: true });
    });
  }
  // ============= Security Settings Methods =============
  async getTOTPStatus(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const hasTOTP = await totpService.hasTOTP(userId);
      if (!hasTOTP) {
        return res.json({ enabled: false });
      }
      // Get TOTP creation date
      const result = await query(
        'SELECT created_at FROM user_totp WHERE user_id = $1 AND verified = true',
        [userId]
      );
      res.json({
        enabled: true,
        created_at: result.rows[0]?.created_at
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get TOTP status' });
    }
  }
  async getBackupCodes(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const codes = await totpService.getBackupCodes(userId);
      const hasUnusedCodes = codes.some(code => !code.used);
      res.json({ codes, hasUnusedCodes });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get backup codes' });
    }
  }
  async getRecentActivity(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const result = await query(
        `SELECT method, created_at as timestamp, ip_address, user_agent
         FROM auth_methods 
         WHERE user_id = $1 AND success = true
         ORDER BY created_at DESC
         LIMIT 20`,
        [userId]
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ error: 'Failed to get recent activity' });
    }
  }
  // ============= Helper Methods =============
  private generateDeviceName(userAgent: string): string {
    // Parse user agent for better device names
    let browser = 'Unknown Browser';
    let os = 'Unknown OS';
    // Detect browser
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
      browser = 'Chrome';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
      browser = 'Safari';
    } else if (userAgent.includes('Firefox')) {
      browser = 'Firefox';
    } else if (userAgent.includes('Edg')) {
      browser = 'Edge';
    }
    // Detect OS
    if (userAgent.includes('Mac OS')) {
      os = 'macOS';
    } else if (userAgent.includes('Windows')) {
      os = 'Windows';
    } else if (userAgent.includes('Linux')) {
      os = 'Linux';
    } else if (userAgent.includes('Android')) {
      os = 'Android';
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
      os = 'iOS';
    }
    return `${browser} on ${os}`;
  }
}