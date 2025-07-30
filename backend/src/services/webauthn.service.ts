import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse
} from '@simplewebauthn/server';
import { query } from '../db';
import { config } from '../config';
import { User, Passkey } from '../types';
import crypto from 'crypto';

export class WebAuthnService {
  private rpName = config.webauthn.rpName;
  private rpID = config.webauthn.rpID;
  private origin = config.webauthn.origin;

  private getRPID(origin?: string): string {
    // In development with ngrok, extract the domain from the origin
    if (process.env.NODE_ENV === 'development' && origin) {
      try {
        const url = new URL(origin);
        // For ngrok domains, use the ngrok subdomain
        if (url.hostname.includes('ngrok.io') || url.hostname.includes('ngrok.app')) {
          return url.hostname;
        }
      } catch (e) {
        // Fall back to configured RP ID
      }
    }
    return this.rpID;
  }

  async generateRegistrationOptions(userId?: string, origin?: string, userData?: { email?: string; username?: string }) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    const rpID = this.getRPID(origin);
    
    // Store challenge in database
    await query(
      'INSERT INTO authentication_challenges (challenge, user_id, type, expires_at) VALUES ($1, $2, $3, $4)',
      [challenge, userId, 'registration', new Date(Date.now() + 60000 * 5)] // 5 min expiry
    );

    // Generate a unique user ID for new registrations
    const userIdBytes = userId ? Buffer.from(userId) : crypto.randomBytes(32);
    const userName = userData?.email || userData?.username || `user_${Date.now()}`;
    const userDisplayName = userData?.email || 'New User';

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: rpID,
      userID: userIdBytes,
      userName: userName,
      userDisplayName: userDisplayName,
      attestationType: 'none',
      excludeCredentials: [],
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: config.webauthn.userVerification
      },
      supportedAlgorithmIDs: [-7, -257] // ES256, RS256
    });

    // Override challenge with our stored one
    options.challenge = challenge;

    return options;
  }

  async verifyRegistrationResponse(
    response: any,
    challengeFromController: string | null,
    origin?: string
  ): Promise<VerifiedRegistrationResponse & { userId?: string }> {
    // Extract challenge from the credential response
    // Handle both direct response and nested response formats
    const responseData = response.response || response;
    const clientDataJSON = JSON.parse(Buffer.from(responseData.clientDataJSON, 'base64').toString());
    const challengeFromClient = clientDataJSON.challenge;
    
    // Verify challenge exists in database
    const challengeResult = await query(
      'SELECT challenge, user_id FROM authentication_challenges WHERE challenge = $1 AND type = $2 AND expires_at > NOW()',
      [challengeFromClient, 'registration']
    );

    if (challengeResult.rows.length === 0) {
      throw new Error('Invalid or expired challenge');
    }
    
    const challenge = challengeResult.rows[0].challenge;

    // For development, accept multiple origins
    const expectedOrigins = [this.origin];
    if (process.env.NODE_ENV === 'development') {
      expectedOrigins.push('http://localhost:3000');
      expectedOrigins.push('http://127.0.0.1:3000');
      // Add any allowed origins from environment
      if (process.env.ALLOWED_ORIGINS) {
        const additionalOrigins = process.env.ALLOWED_ORIGINS.split(',');
        expectedOrigins.push(...additionalOrigins);
      }
    }

    const rpID = this.getRPID(origin);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID
    });

    // Clean up used challenge
    await query('DELETE FROM authentication_challenges WHERE challenge = $1', [challenge]);

    return {
      ...verification,
      userId: challengeResult.rows[0].user_id
    };
  }

  async generateAuthenticationOptions(userId?: string, origin?: string) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    
    // Get user's credentials if userId provided
    let allowCredentials: any[] = [];
    if (userId) {
      const credentialsResult = await query(
        'SELECT id, transports FROM passkeys WHERE user_id = $1',
        [userId]
      );
      
      allowCredentials = credentialsResult.rows.map(cred => ({
        id: Buffer.from(cred.id, 'base64url'),
        type: 'public-key' as const,
        transports: cred.transports || []
      }));
    }

    // Store challenge
    await query(
      'INSERT INTO authentication_challenges (challenge, user_id, type, expires_at) VALUES ($1, $2, $3, $4)',
      [challenge, userId, 'authentication', new Date(Date.now() + 60000 * 5)]
    );

    const rpID = this.getRPID(origin);
    const options = await generateAuthenticationOptions({
      rpID: rpID,
      allowCredentials,
      userVerification: config.webauthn.userVerification
    });

    options.challenge = challenge;

    return options;
  }

  async verifyAuthenticationResponse(
    response: any,
    challengeFromController: string | null,
    origin?: string
  ): Promise<VerifiedAuthenticationResponse & { userId: string }> {
    // Extract challenge from the credential response
    const clientDataJSON = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64').toString());
    const challengeFromClient = clientDataJSON.challenge;
    
    // Verify challenge exists in database
    const challengeResult = await query(
      'SELECT challenge, user_id FROM authentication_challenges WHERE challenge = $1 AND type = $2 AND expires_at > NOW()',
      [challengeFromClient, 'authentication']
    );

    if (challengeResult.rows.length === 0) {
      throw new Error('Invalid or expired challenge');
    }
    
    const challenge = challengeResult.rows[0].challenge;
    // Get stored credential
    const credentialId = response.id;
    
    // Try multiple encoding variations to find the credential
    const credentialIdVariations = [
      credentialId,
      // Convert between base64 and base64url
      credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
      credentialId.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * credentialId.length) % 4)
    ];
    
    const credentialResult = await query(
      'SELECT p.*, u.username FROM passkeys p JOIN users u ON p.user_id = u.id WHERE p.id = ANY($1)',
      [credentialIdVariations]
    );

    if (credentialResult.rows.length === 0) {
      console.error('Credential not found for ID:', credentialId);
      const error = new Error('No passkey found for this device. Please register a passkey first.');
      (error as any).statusCode = 404;
      throw error;
    }

    const credential = credentialResult.rows[0];
    
    // For development, accept multiple origins
    const expectedOrigins = [this.origin];
    if (process.env.NODE_ENV === 'development') {
      expectedOrigins.push('http://localhost:3000');
      expectedOrigins.push('http://127.0.0.1:3000');
      // Add any allowed origins from environment
      if (process.env.ALLOWED_ORIGINS) {
        const additionalOrigins = process.env.ALLOWED_ORIGINS.split(',');
        expectedOrigins.push(...additionalOrigins);
      }
    }

    const rpID = this.getRPID(origin);
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      authenticator: {
        credentialID: credential.id,
        credentialPublicKey: Buffer.from(credential.public_key, 'base64'),
        counter: credential.counter
      }
    });

    if (verification.verified) {
      // Update counter and last used
      await query(
        'UPDATE passkeys SET counter = $1, last_used = NOW() WHERE id = $2',
        [verification.authenticationInfo.newCounter, credentialId]
      );
    }

    // Clean up challenge
    await query('DELETE FROM authentication_challenges WHERE challenge = $1', [challenge]);

    return {
      ...verification,
      userId: credential.user_id
    };
  }

  async saveCredential(
    userId: string,
    credentialId: string,
    publicKey: string,
    counter: number,
    transports?: string[],
    deviceType?: string,
    authenticatorAttachment?: string,
    name?: string,
    userAgent?: string,
    ipAddress?: string
  ) {
    console.log('Saving credential to database:', {
      credentialId,
      userId,
      name,
      deviceType,
      authenticatorAttachment
    });
    
    try {
      await query(
        `INSERT INTO passkeys 
         (id, user_id, public_key, counter, transports, device_type, authenticator_attachment, name, user_agent, ip_address) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [credentialId, userId, publicKey, counter, transports, deviceType, authenticatorAttachment, name, userAgent, ipAddress]
      );
      console.log('Credential saved successfully');
    } catch (error) {
      console.error('Error saving credential:', error);
      throw error;
    }
  }
}