# Feature Request: Passkey and TOTP Authentication for SignalWire Dashboard

## Executive Summary

This feature request proposes adding modern authentication methods to the SignalWire dashboard:
1. **Passkey Authentication** - Passwordless authentication using WebAuthn/FIDO2
2. **TOTP Authentication** - Time-based One-Time Password via authenticator apps

These methods would complement or replace existing password-based authentication, significantly improving security and user experience.

## Business Case

### Benefits
- **Enhanced Security**: Passkeys are phishing-resistant and eliminate password vulnerabilities
- **Improved UX**: One-touch biometric authentication reduces login friction
- **Compliance**: Meets modern security standards and regulations
- **Reduced Support**: Fewer password reset requests and account recovery issues
- **Competitive Advantage**: Positions SignalWire as a security-forward platform

### User Impact
- Enterprise customers gain stronger authentication options
- Developers appreciate modern security practices
- Reduced authentication friction increases platform engagement

## Technical Specification

### 1. Passkey Authentication (WebAuthn/FIDO2)

#### Overview
Passkeys use public-key cryptography for passwordless authentication. Users authenticate with biometrics (Touch ID, Face ID, Windows Hello) or security keys.

#### Implementation Components

##### Backend Requirements
```typescript
// Required Libraries
@simplewebauthn/server
@simplewebauthn/typescript-types

// Database Schema
CREATE TABLE user_passkeys (
  id VARCHAR(255) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  public_key TEXT NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  device_type VARCHAR(50),
  transports TEXT[],
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP,
  name VARCHAR(255) -- User-friendly name
);

CREATE TABLE webauthn_challenges (
  challenge VARCHAR(255) PRIMARY KEY,
  user_id UUID,
  type VARCHAR(20) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

##### API Endpoints
```typescript
// Registration Flow
POST /api/auth/passkey/register/options
POST /api/auth/passkey/register/verify

// Authentication Flow  
POST /api/auth/passkey/authenticate/options
POST /api/auth/passkey/authenticate/verify

// Management
GET /api/auth/passkey/list
DELETE /api/auth/passkey/:id
PUT /api/auth/passkey/:id/rename
```

##### Core Implementation
```typescript
// Registration Options Generation
async generateRegistrationOptions(userId: string, userEmail: string) {
  const user = await getUserById(userId);
  
  // Get existing credentials to exclude
  const existingCredentials = await getPasskeysByUserId(userId);
  
  const options = await generateRegistrationOptions({
    rpName: 'SignalWire',
    rpID: 'signalwire.com',
    userID: userId,
    userName: userEmail,
    userDisplayName: user.name || userEmail,
    attestationType: 'none',
    excludeCredentials: existingCredentials.map(cred => ({
      id: Buffer.from(cred.id, 'base64url'),
      type: 'public-key'
    })),
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      residentKey: 'required',
      userVerification: 'required'
    },
    supportedAlgorithmIDs: [-7, -257] // ES256, RS256
  });

  // Store challenge
  await storeChallenge(options.challenge, userId, 'registration');
  
  return options;
}

// Verify Registration
async verifyRegistration(credential: any, challenge: string, userId: string) {
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: challenge,
    expectedOrigin: 'https://signalwire.com',
    expectedRPID: 'signalwire.com'
  });

  if (verification.verified && verification.registrationInfo) {
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    
    await savePasskey({
      id: credentialID,
      userId,
      publicKey: credentialPublicKey,
      counter,
      deviceType: credential.authenticatorAttachment,
      transports: credential.response.transports
    });
  }
  
  return verification;
}
```

### 2. TOTP Authentication

#### Overview
Time-based One-Time Passwords using authenticator apps (Google Authenticator, Authy, etc.)

#### Implementation Components

##### Backend Requirements
```typescript
// Required Libraries
speakeasy or otplib
qrcode

// Database Schema
CREATE TABLE user_totp (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  secret VARCHAR(255) NOT NULL,
  verified BOOLEAN DEFAULT FALSE,
  backup_codes TEXT[],
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);
```

##### API Endpoints
```typescript
// Setup Flow
POST /api/auth/totp/setup     // Generate secret & QR code
POST /api/auth/totp/verify    // Verify initial setup
POST /api/auth/totp/disable   // Remove TOTP

// Authentication
POST /api/auth/totp/authenticate

// Recovery
POST /api/auth/totp/backup-codes/generate
POST /api/auth/totp/backup-codes/verify
```

##### Core Implementation
```typescript
// TOTP Setup
async setupTOTP(userId: string) {
  const secret = speakeasy.generateSecret({
    name: `SignalWire (${userEmail})`,
    issuer: 'SignalWire',
    length: 32
  });

  // Store unverified secret
  await saveTOTPSecret(userId, secret.base32, false);

  // Generate QR code
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  // Generate backup codes
  const backupCodes = generateBackupCodes(8, 10); // 8 codes, 10 chars each
  
  return {
    secret: secret.base32,
    qrCode: qrCodeUrl,
    backupCodes
  };
}

// Verify TOTP
async verifyTOTP(userId: string, token: string) {
  const { secret } = await getTOTPSecret(userId);
  
  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2 // Allow 2 intervals for clock drift
  });

  if (verified) {
    await markTOTPVerified(userId);
  }
  
  return verified;
}
```

### 3. Authentication Flow Integration

#### Multi-Factor Decision Logic
```typescript
async determineAuthenticationMethod(email: string) {
  const user = await getUserByEmail(email);
  
  const methods = {
    password: user.has_password,
    passkey: await hasPasskeys(user.id),
    totp: await hasTOTP(user.id)
  };

  // Determine required factors based on security policy
  if (user.require_mfa) {
    return {
      primary: methods.passkey ? 'passkey' : 'password',
      secondary: methods.totp ? 'totp' : null
    };
  }

  return {
    primary: methods.passkey ? 'passkey' : 'password',
    secondary: null
  };
}
```

#### Session Management
```typescript
interface AuthSession {
  userId: string;
  factors: {
    passkey?: boolean;
    password?: boolean;
    totp?: boolean;
  };
  complete: boolean;
  expiresAt: Date;
}
```

## Frontend Implementation

### UI Components

#### Login Flow
```typescript
// Progressive Enhancement
1. Email input
2. Detect available auth methods
3. Show appropriate UI:
   - Passkey button (if available)
   - Password field (fallback)
   - TOTP field (if required)

// React Component Example
const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [authMethods, setAuthMethods] = useState(null);
  
  const checkAuthMethods = async () => {
    const response = await api.post('/auth/check-methods', { email });
    setAuthMethods(response.data);
  };

  const authenticateWithPasskey = async () => {
    const options = await api.post('/auth/passkey/authenticate/options');
    const credential = await startAuthentication(options.data);
    const result = await api.post('/auth/passkey/authenticate/verify', { 
      credential 
    });
    
    if (result.data.requiresTOTP) {
      showTOTPInput();
    } else {
      completeLogin(result.data.token);
    }
  };
};
```

#### Account Settings
```typescript
// Passkey Management UI
- List registered passkeys with device names
- Add new passkey button
- Remove passkey with confirmation
- Rename passkey for easy identification

// TOTP Management UI
- Enable/Disable TOTP
- View backup codes
- Regenerate backup codes
- QR code display for setup
```

## Security Considerations

### 1. Passkey Security
- **RP ID Validation**: Strictly validate Relying Party ID
- **Origin Validation**: Check request origin matches expected domains
- **Challenge Management**: Single-use challenges with expiration
- **Counter Validation**: Prevent credential cloning
- **Attestation**: Consider requiring attestation for high-security accounts

### 2. TOTP Security
- **Secret Storage**: Encrypt TOTP secrets at rest
- **Rate Limiting**: Limit verification attempts
- **Time Window**: Allow reasonable clock drift (±30 seconds)
- **Backup Codes**: Single-use, securely generated codes
- **Recovery Flow**: Secure account recovery process

### 3. General Security
- **Session Management**: Secure session tokens with appropriate expiration
- **Audit Logging**: Log all authentication events
- **Account Recovery**: Secure fallback mechanisms
- **Cross-Origin**: Proper CORS configuration
- **Transport Security**: Enforce HTTPS

## Testing Methodology

### 1. Unit Tests
```typescript
describe('Passkey Authentication', () => {
  test('generates valid registration options', async () => {
    const options = await generateRegistrationOptions(userId, email);
    expect(options.challenge).toHaveLength(43); // Base64url
    expect(options.rp.id).toBe('signalwire.com');
  });

  test('verifies valid registration', async () => {
    const mockCredential = createMockCredential();
    const result = await verifyRegistration(mockCredential, challenge, userId);
    expect(result.verified).toBe(true);
  });

  test('rejects invalid challenge', async () => {
    const result = await verifyRegistration(credential, 'invalid', userId);
    expect(result.verified).toBe(false);
  });
});

describe('TOTP Authentication', () => {
  test('generates valid secret', async () => {
    const result = await setupTOTP(userId);
    expect(result.secret).toMatch(/^[A-Z2-7]{52}$/);
    expect(result.backupCodes).toHaveLength(8);
  });

  test('verifies valid token', async () => {
    const token = speakeasy.totp({ secret, encoding: 'base32' });
    const verified = await verifyTOTP(userId, token);
    expect(verified).toBe(true);
  });

  test('rejects expired token', async () => {
    const oldToken = '123456';
    const verified = await verifyTOTP(userId, oldToken);
    expect(verified).toBe(false);
  });
});
```

### 2. Integration Tests
```typescript
describe('Authentication Flow', () => {
  test('complete passkey + TOTP flow', async () => {
    // Setup
    await createUser(testUser);
    await setupPasskey(testUser.id);
    await setupTOTP(testUser.id);

    // Login
    const methods = await checkAuthMethods(testUser.email);
    expect(methods).toEqual({
      passkey: true,
      totp: true,
      password: true
    });

    // Authenticate with passkey
    const passkeyResult = await authenticateWithPasskey();
    expect(passkeyResult.requiresTOTP).toBe(true);

    // Complete with TOTP
    const totpToken = generateTOTPToken();
    const finalResult = await completeTOTP(totpToken);
    expect(finalResult.token).toBeDefined();
  });
});
```

### 3. Browser Testing
```javascript
// Playwright/Cypress Tests
describe('Passkey UI Tests', () => {
  test('registers new passkey', async ({ page }) => {
    await page.goto('/settings/security');
    await page.click('[data-testid="add-passkey"]');
    
    // Mock WebAuthn API
    await mockWebAuthnAPI(page);
    
    await page.click('[data-testid="register-passkey"]');
    await expect(page.locator('[data-testid="passkey-list"]')).toContainText('Chrome on Mac');
  });

  test('authenticates with passkey', async ({ page }) => {
    await page.goto('/login');
    await page.fill('[name="email"]', 'test@example.com');
    await page.click('[data-testid="continue"]');
    
    await expect(page.locator('[data-testid="passkey-button"]')).toBeVisible();
    await page.click('[data-testid="passkey-button"]');
    
    await mockWebAuthnAuthentication(page);
    await expect(page).toHaveURL('/dashboard');
  });
});
```

### 4. Device Testing Matrix
| Platform | Browser | Passkey Support | TOTP | Notes |
|----------|---------|----------------|------|-------|
| macOS 13+ | Safari 16+ | ✅ Touch ID | ✅ | Native |
| macOS 13+ | Chrome 108+ | ✅ Touch ID | ✅ | Native |
| Windows 11 | Edge 108+ | ✅ Windows Hello | ✅ | Native |
| Windows 10 | Chrome 108+ | ✅ Windows Hello | ✅ | Native |
| iOS 16+ | Safari | ✅ Face/Touch ID | ✅ | Native |
| Android 9+ | Chrome | ✅ Biometric | ✅ | Native |
| Linux | Chrome/Firefox | ✅ Security Key | ✅ | USB/NFC |

### 5. Performance Testing
```typescript
describe('Performance', () => {
  test('registration completes within 2 seconds', async () => {
    const start = Date.now();
    await completePasskeyRegistration();
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(2000);
  });

  test('authentication completes within 1 second', async () => {
    const start = Date.now();
    await authenticateWithPasskey();
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(1000);
  });
});
```

## Rollout Strategy

### Phase 1: Beta Testing (Weeks 1-4)
1. Enable for internal team
2. Select beta customers
3. Feature flag: `enable_passkey_auth`
4. Monitor error rates and success metrics

### Phase 2: Gradual Rollout (Weeks 5-8)
1. 10% of users
2. 25% of users
3. 50% of users
4. 100% availability

### Phase 3: Migration Campaign (Weeks 9-12)
1. In-app notifications encouraging passkey setup
2. Email campaign highlighting security benefits
3. Documentation and video tutorials
4. Support team training

## Monitoring and Analytics

### Key Metrics
```typescript
// Success Metrics
- Passkey registration success rate
- Passkey authentication success rate
- TOTP setup completion rate
- Time to authenticate
- Support ticket reduction

// Error Tracking
- WebAuthn API failures
- Browser compatibility issues
- Timeout errors
- Challenge validation failures

// Usage Analytics
- Daily active passkey users
- Passkey vs password usage ratio
- Device type distribution
- Cross-device authentication usage
```

### Monitoring Implementation
```typescript
// Datadog/NewRelic Integration
track('auth.passkey.register', {
  success: boolean,
  duration: number,
  errorType?: string,
  browser: string,
  platform: string
});

track('auth.passkey.authenticate', {
  success: boolean,
  duration: number,
  requiresMFA: boolean,
  deviceType: string
});
```

## Error Handling

### User-Friendly Error Messages
```typescript
const ERROR_MESSAGES = {
  // Passkey Errors
  'NotAllowedError': 'Authentication was cancelled. Please try again.',
  'NotSupportedError': 'Your device doesn\'t support passkeys. Please use password authentication.',
  'InvalidStateError': 'This passkey is already registered. Please sign in instead.',
  'SecurityError': 'Passkeys require a secure connection. Please check your URL.',
  
  // TOTP Errors
  'INVALID_TOKEN': 'Invalid code. Please check and try again.',
  'TOKEN_EXPIRED': 'Code expired. Please use the current code from your authenticator.',
  'ALREADY_CONFIGURED': 'Two-factor authentication is already enabled.',
  
  // General Errors
  'RATE_LIMITED': 'Too many attempts. Please try again in a few minutes.',
  'SESSION_EXPIRED': 'Your session expired. Please start over.'
};
```

## Backwards Compatibility

### Migration Path
1. Existing users maintain password authentication
2. Passkey/TOTP added as optional security upgrade
3. No forced migration
4. Legacy auth endpoints remain functional
5. Gradual deprecation with ample notice

### API Versioning
```typescript
// v1 - Current password-only
POST /api/v1/auth/login

// v2 - Multi-factor support
POST /api/v2/auth/login
POST /api/v2/auth/methods
POST /api/v2/auth/passkey/*
POST /api/v2/auth/totp/*
```

## Documentation Requirements

### Developer Documentation
1. API reference for all endpoints
2. SDK updates for client libraries
3. Integration examples
4. Security best practices
5. Troubleshooting guide

### User Documentation
1. Getting started with passkeys
2. Setting up two-factor authentication
3. Managing security settings
4. Account recovery procedures
5. FAQ section

## Support Considerations

### Customer Support Training
1. Understanding passkey technology
2. Common troubleshooting steps
3. Device-specific guidance
4. Account recovery procedures
5. Security best practices

### Self-Service Resources
1. In-app setup wizards
2. Video tutorials
3. Knowledge base articles
4. Community forum discussions
5. Troubleshooting flowcharts

## Success Criteria

### Launch Metrics
- 95%+ registration success rate
- 98%+ authentication success rate
- <2% increase in support tickets
- 50% user adoption within 6 months
- Zero security incidents

### Long-term Goals
- 80% of active users with passkey/TOTP enabled
- 50% reduction in password reset requests
- Improved security posture scores
- Industry recognition for security leadership

## Conclusion

Implementing passkey and TOTP authentication will significantly enhance SignalWire's security posture while improving user experience. The phishing-resistant nature of passkeys combined with the widespread support for TOTP provides flexible, strong authentication options for all users.

This implementation follows industry best practices and standards (WebAuthn, FIDO2, RFC 6238) ensuring compatibility and security. The gradual rollout strategy minimizes risk while the comprehensive testing approach ensures reliability.

## Appendix: Reference Implementation

The accompanying demo application (`passkey-demo`) provides a working implementation of passkey authentication with cross-device support. Key files:

- `/backend/src/services/webauthn.service.ts` - Core WebAuthn logic
- `/backend/src/controllers/auth.controller.ts` - Authentication endpoints
- `/frontend/src/services/auth.service.ts` - Client-side authentication
- `/frontend/src/pages/SignUp.tsx` - Registration flow
- `/frontend/src/pages/SignIn.tsx` - Authentication flow
- `/database/schema.sql` - Database structure

This reference implementation can be adapted for SignalWire's specific architecture and requirements.