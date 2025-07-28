import { Request, Response } from 'express';
import { WebAuthnService } from '../services/webauthn.service';
import { UserService } from '../services/user.service';
import { CrossDeviceService } from '../services/crossDevice.service';
import jwt from 'jsonwebtoken';
import { config } from '../config';

// Extend session type inline
declare module 'express-session' {
  interface SessionData {
    currentChallenge?: string;
  }
}

const webauthnService = new WebAuthnService();
const userService = new UserService();
const crossDeviceService = new CrossDeviceService();

export class AuthController {
  async registrationOptions(req: Request, res: Response) {
    try {
      const origin = req.get('origin') || req.get('referer');
      const options = await webauthnService.generateRegistrationOptions(undefined, origin);
      
      // Store options in session
      req.session.currentChallenge = options.challenge;
      
      res.json(options);
    } catch (error: any) {
      console.error('Registration options error:', error);
      res.status(500).json({ 
        error: 'Failed to generate registration options',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  async verifyRegistration(req: Request, res: Response) {
    try {
      const { credential } = req.body;
      const challenge = req.session.currentChallenge;

      if (!challenge) {
        return res.status(400).json({ 
          error: 'No authentication session found. Please start the registration process again.' 
        });
      }

      const origin = req.get('origin') || req.get('referer');
      const verification = await webauthnService.verifyRegistrationResponse(
        credential,
        challenge,
        origin
      );

      if (!verification.verified || !verification.registrationInfo) {
        return res.status(400).json({ error: 'Verification failed' });
      }

      // Create new user
      const user = await userService.createUser();

      // Save credential
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      // Store the credential ID as provided by the browser (which is base64url)
      const credentialIdString = credential.id || Buffer.from(credentialID).toString('base64url');
      console.log('Storing credential with ID:', credentialIdString);
      
      await webauthnService.saveCredential(
        user.id,
        credentialIdString,
        Buffer.from(credentialPublicKey).toString('base64'),
        counter,
        credential.response.transports,
        credential.response.authenticatorAttachment
      );

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        config.jwt.secret,
        { expiresIn: '7d' }
      );

      // Clear challenge
      delete req.session.currentChallenge;

      res.json({
        verified: true,
        user: {
          id: user.id,
          username: user.username
        },
        token
      });
    } catch (error) {
      console.error('Registration verification error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  }

  async authenticationOptions(req: Request, res: Response) {
    try {
      const origin = req.get('origin') || req.get('referer');
      const options = await webauthnService.generateAuthenticationOptions(undefined, origin);
      
      req.session.currentChallenge = options.challenge;
      
      res.json(options);
    } catch (error) {
      console.error('Authentication options error:', error);
      res.status(500).json({ error: 'Failed to generate authentication options' });
    }
  }

  async verifyAuthentication(req: Request, res: Response) {
    try {
      const { credential } = req.body;
      const challenge = req.session.currentChallenge;

      console.log('Authentication attempt with credential ID:', credential?.id);

      if (!challenge) {
        return res.status(400).json({ 
          error: 'No authentication session found. Please try signing in again.' 
        });
      }

      const origin = req.get('origin') || req.get('referer');
      const verification = await webauthnService.verifyAuthenticationResponse(
        credential,
        challenge,
        origin
      );

      if (!verification.verified) {
        return res.status(400).json({ error: 'Authentication failed' });
      }

      // Get user
      const user = await userService.getUserById(verification.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        config.jwt.secret,
        { expiresIn: '7d' }
      );

      delete req.session.currentChallenge;

      res.json({
        verified: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          display_name: user.display_name
        },
        token
      });
    } catch (error: any) {
      console.error('Authentication verification error:', error);
      const statusCode = error.statusCode || 500;
      res.status(statusCode).json({ 
        error: error.message || 'Authentication failed',
        code: error.code
      });
    }
  }

  async logout(req: Request, res: Response) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ message: 'Logged out successfully' });
    });
  }

  // Cross-device authentication endpoints
  async createCrossDeviceSession(req: Request, res: Response) {
    try {
      const { sessionId } = req.body;
      
      if (!sessionId) {
        return res.status(400).json({ error: 'Session ID required' });
      }

      await crossDeviceService.createSession(sessionId);
      res.json({ success: true });
    } catch (error) {
      console.error('Cross-device session error:', error);
      res.status(500).json({ error: 'Failed to create session' });
    }
  }

  async checkCrossDeviceSession(req: Request, res: Response) {
    try {
      const { sessionId } = req.params;
      const result = await crossDeviceService.checkSession(sessionId);
      
      if (result.authenticated && result.userId) {
        const user = await userService.getUserById(result.userId);
        const token = jwt.sign(
          { userId: user!.id, username: user!.username },
          config.jwt.secret,
          { expiresIn: '7d' }
        );
        
        res.json({
          authenticated: true,
          user,
          token
        });
      } else {
        res.json({ authenticated: false });
      }
    } catch (error) {
      console.error('Check session error:', error);
      res.status(500).json({ error: 'Failed to check session' });
    }
  }

  async completeCrossDeviceAuth(req: Request, res: Response) {
    try {
      const { sessionId } = req.body;
      const userId = (req as any).user?.userId;
      
      if (!sessionId || !userId) {
        return res.status(400).json({ error: 'Invalid request' });
      }

      await crossDeviceService.completeSession(sessionId, userId);
      res.json({ success: true });
    } catch (error) {
      console.error('Complete cross-device error:', error);
      res.status(500).json({ error: 'Failed to complete authentication' });
    }
  }
}