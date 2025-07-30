import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import QRCode from 'qrcode';
import api from '../services/api';
import { ErrorAlert } from '../components/ErrorAlert';
import { getErrorMessage, isPasskeyNotFoundError } from '../utils/errorMessages';
type LoginMethod = 'choice' | 'passkey' | 'email' | 'qr';
export const SignIn: React.FC = () => {
  const [loginMethod, setLoginMethod] = useState<LoginMethod>('choice');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [browserSupported, setBrowserSupported] = useState(true);
  // Email login state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [needsEmailVerification, setNeedsEmailVerification] = useState(false);
  const [showTOTP, setShowTOTP] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [totpAttempts, setTotpAttempts] = useState(0);
  const [useBackupCode, setUseBackupCode] = useState(false);
  // QR Code state
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [qrError, setQrError] = useState('');
  const pollingInterval = useRef<NodeJS.Timeout>();
  const navigate = useNavigate();
  const { login, refreshUser } = useAuth();
  useEffect(() => {
    // Check if browser supports WebAuthn
    if (!window.PublicKeyCredential) {
      setBrowserSupported(false);
    }
  }, []);
  useEffect(() => {
    // Cleanup polling on unmount or method change
    return () => {
      if (pollingInterval.current) {
        clearInterval(pollingInterval.current);
      }
    };
  }, [loginMethod]);
  useEffect(() => {
    if (loginMethod === 'qr') {
      generateQRCode();
    }
  }, [loginMethod]);
  const generateQRCode = async () => {
    try {
      setQrError('');
      // Generate a session ID for cross-device authentication
      const newSessionId = crypto.randomUUID();
      // Create session on backend
      await api.post('/auth/cross-device/create', { sessionId: newSessionId });
      // Create URL with session ID
      const baseUrl = window.location.origin.includes('ngrok') 
        ? window.location.origin 
        : `${window.location.protocol}//${window.location.hostname}:${window.location.port}`;
      const authUrl = `${baseUrl}/mobile-auth?session=${newSessionId}`;
      const url = await QRCode.toDataURL(authUrl, {
        width: 200,
        margin: 2,
      });
      setQrCodeUrl(url);
      // Start polling for authentication
      startPolling(newSessionId);
    } catch (err) {
      console.error('QR generation failed:', err);
      setQrError('Unable to generate QR code. Please try again.');
    }
  };
  const startPolling = (sessionId: string) => {
    pollingInterval.current = setInterval(async () => {
      try {
        const { data } = await api.get(`/auth/cross-device/check/${sessionId}`);
        if (data.authenticated && data.token) {
          // Authentication successful
          localStorage.setItem('token', data.token);
          clearInterval(pollingInterval.current!);
          // Force a page reload to ensure auth context updates
          window.location.href = '/profile';
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2000); // Poll every 2 seconds
  };
  const handlePasskeyLogin = async () => {
    setLoading(true);
    setError('');
    try {
      await login();
      navigate('/profile');
    } catch (err: any) {
      console.error('Authentication error:', err);
      const errorMessage = getErrorMessage(err);
      setError(errorMessage);
      // If passkey not found, suggest registration
      if (isPasskeyNotFoundError(err)) {
        setTimeout(() => {
          if (window.confirm('No passkey found for this device. Would you like to create one?')) {
            navigate('/signup');
          }
        }, 100);
      }
    } finally {
      setLoading(false);
    }
  };
  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setNeedsEmailVerification(false);
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email,
          password,
          totpCode: showTOTP ? totpCode : undefined
        })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw { response: { data } };
      }
      if (data.token) {
        // Login successful (with or without TOTP)
        localStorage.setItem('token', data.token);
        // Update the auth context with the new user data
        await refreshUser();
        navigate('/profile');
      } else if (data.requiresTOTP) {
        // TOTP required, show the input
        setShowTOTP(true);
        setError('');
        setTotpAttempts(0); // Reset attempts counter
        setUseBackupCode(false); // Reset backup code mode
        setLoading(false);
        return;
      }
    } catch (err: any) {
      console.error('Login error:', err);
      const errorData = err.response?.data;
      if (errorData?.error === 'email_not_verified') {
        setNeedsEmailVerification(true);
        setError('Please verify your email before logging in.');
      } else if (errorData?.error === 'totp_required') {
        setShowTOTP(true);
        setError('Please enter your 2FA code');
      } else if (errorData?.error === 'Invalid 2FA code' && showTOTP) {
        // Handle invalid TOTP code
        const newAttempts = totpAttempts + 1;
        setTotpAttempts(newAttempts);
        if (newAttempts >= 3) {
          // Reset after 3 attempts
          setShowTOTP(false);
          setTotpCode('');
          setTotpAttempts(0);
          setUseBackupCode(false);
          setError('Too many failed attempts. Please sign in again.');
        } else {
          setError(`Invalid 2FA code. ${3 - newAttempts} attempts remaining.`);
          setTotpCode(''); // Clear the code for retry
        }
      } else if (errorData?.error === 'Account is locked due to too many failed attempts') {
        const lockedUntil = errorData?.lockedUntil;
        if (lockedUntil) {
          const lockTime = new Date(lockedUntil);
          const now = new Date();
          const minutesLeft = Math.ceil((lockTime.getTime() - now.getTime()) / 60000);
          setError(`Account locked due to too many failed attempts. Please try again in ${minutesLeft} minute${minutesLeft > 1 ? 's' : ''}.`);
        } else {
          setError('Account locked due to too many failed attempts. Please try again later.');
        }
      } else {
        setError(errorData?.error || errorData?.message || 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };
  const handleResendVerification = async () => {
    setLoading(true);
    try {
      await api.post('/auth/resend-verification', { email });
      setError('');
      alert('Verification email sent! Please check your inbox.');
    } catch (err) {
      setError('Failed to resend verification email');
    } finally {
      setLoading(false);
    }
  };
  if (loginMethod === 'choice') {
    return (
      <div className="auth-container">
        <h1>Welcome Back</h1>
        <p>Choose how you'd like to sign in</p>
        <div className="login-options">
          <button
            className="option-card"
            onClick={() => setLoginMethod('passkey')}
            disabled={!browserSupported}
          >
            <div className="option-icon">🔐</div>
            <h3>Passkey</h3>
            <p>Sign in with biometrics or security key</p>
            {!browserSupported && (
              <span className="badge">Not supported</span>
            )}
          </button>
          <button
            className="option-card"
            onClick={() => setLoginMethod('email')}
          >
            <div className="option-icon">📧</div>
            <h3>Email & Password</h3>
            <p>Traditional email and password login</p>
          </button>
          <button
            className="option-card"
            onClick={() => setLoginMethod('qr')}
          >
            <div className="option-icon">📱</div>
            <h3>Mobile Device</h3>
            <p>Scan QR code with your phone</p>
          </button>
        </div>
        <div className="text-center mt-3">
          Don't have an account? <Link to="/signup" className="link">Create Account</Link>
        </div>
      </div>
    );
  }
  if (loginMethod === 'passkey') {
    return (
      <div className="auth-container">
        <button 
          className="back-button"
          onClick={() => setLoginMethod('choice')}
        >
          ← Back
        </button>
        <h1>Sign In with Passkey</h1>
        <p>Use your saved passkey, YubiKey, or other security key</p>
        <ErrorAlert 
          error={error} 
          onRetry={handlePasskeyLogin}
          showRetry={!loading}
        />
        <button 
          className="btn" 
          onClick={handlePasskeyLogin}
          disabled={loading}
        >
          {loading ? <span className="loading"></span> : 'Sign In with Passkey'}
        </button>
        <div className="alternative-methods">
          <p>Having trouble?</p>
          <button 
            className="link-button"
            onClick={() => setLoginMethod('email')}
          >
            Sign in with email instead
          </button>
        </div>
      </div>
    );
  }
  if (loginMethod === 'qr') {
    return (
      <div className="auth-container">
        <button 
          className="back-button"
          onClick={() => {
            setLoginMethod('choice');
            if (pollingInterval.current) {
              clearInterval(pollingInterval.current);
            }
          }}
        >
          ← Back
        </button>
        <h1>Sign In with Mobile Device</h1>
        <p>Scan this QR code with your authenticated mobile device</p>
        {qrError ? (
          <ErrorAlert error={qrError} onRetry={generateQRCode} showRetry={true} />
        ) : qrCodeUrl ? (
          <>
            <div className="qr-code">
              <img src={qrCodeUrl} alt="QR Code for mobile authentication" />
            </div>
            <div className="info-alert" style={{ marginTop: '10px' }}>
              <svg className="info-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
              <span>Waiting for authentication...</span>
            </div>
          </>
        ) : (
          <div className="loading"></div>
        )}
        <p style={{ fontSize: '14px', color: '#666', textAlign: 'center', marginTop: '20px' }}>
          Make sure you're already signed in on your mobile device
        </p>
      </div>
    );
  }
  // Email & Password Login
  return (
    <div className="auth-container">
      <button 
        className="back-button"
        onClick={() => setLoginMethod('choice')}
      >
        ← Back
      </button>
      <h1>Sign In</h1>
      <p>Enter your email and password</p>
      <ErrorAlert error={error} />
      {needsEmailVerification && (
        <div className="warning-alert">
          <p>Your email address needs to be verified.</p>
          <button 
            className="link-button"
            onClick={handleResendVerification}
            disabled={loading}
          >
            Resend verification email
          </button>
        </div>
      )}
      <form onSubmit={handleEmailLogin}>
        <div className="form-group">
          <label htmlFor="email">Email Address</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="john@example.com"
            required
            disabled={showTOTP}
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <div className="password-input">
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
              disabled={showTOTP}
            />
            <button
              type="button"
              className="toggle-password"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
          </div>
        </div>
        {showTOTP && (
          <div className="form-group">
            <label htmlFor="totpCode">
              {useBackupCode ? 'Backup Code' : '2FA Code'}
            </label>
            <input
              type="text"
              id="totpCode"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.toUpperCase())}
              placeholder={useBackupCode ? "XXXXX-XXXXX" : "000000"}
              pattern={useBackupCode ? "[A-Z0-9]{5}-[A-Z0-9]{5}" : "[0-9]{6}"}
              maxLength={useBackupCode ? 11 : 6}
              autoFocus
              required
            />
            <p style={{ fontSize: '14px', color: '#666', marginTop: '5px' }}>
              {useBackupCode 
                ? 'Enter one of your backup codes (e.g., 3R7AC-37MTN)' 
                : 'Enter the 6-digit code from your authenticator app'}
            </p>
            <button
              type="button"
              className="link-button"
              style={{ marginTop: '10px', fontSize: '14px' }}
              onClick={() => {
                setUseBackupCode(!useBackupCode);
                setTotpCode('');
                setError('');
              }}
            >
              {useBackupCode ? 'Use authenticator app instead' : 'Use backup code instead'}
            </button>
          </div>
        )}
        <button 
          type="submit"
          className="btn" 
          disabled={loading}
        >
          {loading ? <span className="loading"></span> : (showTOTP ? 'Verify & Sign In' : 'Sign In')}
        </button>
      </form>
      <div className="links-section">
        <Link to="/forgot-password" className="link">Forgot password?</Link>
      </div>
      <div className="divider">
        <span>or</span>
      </div>
      <button 
        className="secondary-btn"
        onClick={() => setLoginMethod('passkey')}
      >
        Sign in with Passkey
      </button>
      <div className="text-center mt-3">
        Don't have an account? <Link to="/signup" className="link">Create Account</Link>
      </div>
    </div>
  );
};