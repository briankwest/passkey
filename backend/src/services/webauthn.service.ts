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

  /**
   * Get expected origins for WebAuthn verification
   */
  private getExpectedOrigins(): string[] {
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
    
    return expectedOrigins;
  }

  /**
   * Store a challenge in the database
   */
  private async storeChallenge(
    challenge: string, 
    userId: string | null, 
    type: 'registration' | 'authentication'
  ): Promise<void> {
    await query(
      'INSERT INTO authentication_challenges (challenge, user_id, type, expires_at) VALUES ($1, $2, $3, $4)',
      [challenge, userId, type, new Date(Date.now() + 60000 * 5)] // 5 min expiry
    );
  }

  /**
   * Verify and retrieve a challenge from the database
   */
  private async verifyChallenge(
    challenge: string, 
    type: 'registration' | 'authentication'
  ): Promise<{ challenge: string; user_id: string | null }> {
    const result = await query(
      'SELECT challenge, user_id FROM authentication_challenges WHERE challenge = $1 AND type = $2 AND expires_at > NOW()',
      [challenge, type]
    );
    
    if (result.rows.length === 0) {
      throw new Error('Invalid or expired challenge');
    }
    
    return result.rows[0];
  }

  /**
   * Clean up a used challenge
   */
  private async cleanupChallenge(challenge: string): Promise<void> {
    await query('DELETE FROM authentication_challenges WHERE challenge = $1', [challenge]);
  }

  /**
   * Extract challenge from client response
   */
  private extractChallengeFromResponse(response: any): string {
    const responseData = response.response || response;
    const clientDataJSON = JSON.parse(
      Buffer.from(responseData.clientDataJSON, 'base64').toString()
    );
    return clientDataJSON.challenge;
  }

  async generateRegistrationOptions(
    userId?: string, 
    origin?: string, 
    userData?: { email?: string; username?: string }
  ) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    const rpID = this.getRPID(origin);
    
    // Store challenge in database
    await this.storeChallenge(challenge, userId || null, 'registration');
    
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
    // Extract and verify challenge
    const challengeFromClient = this.extractChallengeFromResponse(response);
    const challengeData = await this.verifyChallenge(challengeFromClient, 'registration');
    
    const rpID = this.getRPID(origin);
    const expectedOrigins = this.getExpectedOrigins();
    
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID
    });
    
    // Clean up used challenge
    await this.cleanupChallenge(challengeData.challenge);
    
    return {
      ...verification,
      userId: challengeData.user_id || undefined
    };
  }

  async generateAuthenticationOptions(userId?: string, origin?: string) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    
    // Get user's credentials if userId provided
    let allowCredentials: any[] = [];
    if (userId) {
      allowCredentials = await this.getUserCredentials(userId);
    }
    
    // Store challenge
    await this.storeChallenge(challenge, userId || null, 'authentication');
    
    const rpID = this.getRPID(origin);
    const options = await generateAuthenticationOptions({
      rpID: rpID,
      allowCredentials,
      userVerification: config.webauthn.userVerification
    });
    
    options.challenge = challenge;
    return options;
  }

  /**
   * Get user's credentials for authentication
   */
  private async getUserCredentials(userId: string): Promise<any[]> {
    const credentialsResult = await query(
      'SELECT id, transports FROM passkeys WHERE user_id = $1',
      [userId]
    );
    
    return credentialsResult.rows.map(cred => ({
      id: Buffer.from(cred.id, 'base64url'),
      type: 'public-key' as const,
      transports: cred.transports || []
    }));
  }

  /**
   * Find credential by ID with encoding variations
   */
  private async findCredential(credentialId: string): Promise<any> {
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
      const error = new Error('No passkey found for this device. Please register a passkey first.');
      (error as any).statusCode = 404;
      throw error;
    }
    
    return credentialResult.rows[0];
  }

  /**
   * Update credential counter after successful authentication
   */
  private async updateCredentialCounter(
    credentialId: string, 
    newCounter: number
  ): Promise<void> {
    await query(
      'UPDATE passkeys SET counter = $1, last_used = NOW() WHERE id = $2',
      [newCounter, credentialId]
    );
  }

  async verifyAuthenticationResponse(
    response: any,
    challengeFromController: string | null,
    origin?: string
  ): Promise<VerifiedAuthenticationResponse & { userId: string }> {
    // Extract and verify challenge
    const challengeFromClient = this.extractChallengeFromResponse(response);
    const challengeData = await this.verifyChallenge(challengeFromClient, 'authentication');
    
    // Find stored credential
    const credential = await this.findCredential(response.id);
    
    // Prepare verification parameters
    const rpID = this.getRPID(origin);
    const expectedOrigins = this.getExpectedOrigins();
    
    // Verify authentication response
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      authenticator: {
        credentialID: credential.id,
        credentialPublicKey: Buffer.from(credential.public_key, 'base64'),
        counter: credential.counter
      }
    });
    
    // Update credential if verification successful
    if (verification.verified) {
      await this.updateCredentialCounter(
        response.id, 
        verification.authenticationInfo.newCounter
      );
    }
    
    // Clean up challenge
    await this.cleanupChallenge(challengeData.challenge);
    
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
    try {
      await query(
        `INSERT INTO passkeys 
         (id, user_id, public_key, counter, transports, device_type, authenticator_attachment, name, user_agent, ip_address) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [credentialId, userId, publicKey, counter, transports, deviceType, authenticatorAttachment, name, userAgent, ipAddress]
      );
    } catch (error) {
      throw error;
    }
  }
}