import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { ErrorAlert } from '../components/ErrorAlert';
import { DeviceCheck } from '../components/DeviceCheck';
import api from '../services/api';
type RegistrationMethod = 'choice' | 'passkey' | 'email';
interface PasswordStrength {
  score: number;
  feedback: string;
  suggestions?: string[];
}
export const SignUp: React.FC = () => {
  const [registrationMethod, setRegistrationMethod] = useState<RegistrationMethod>('choice');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [browserSupported, setBrowserSupported] = useState(true);
  // Email registration form state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [passwordStrength, setPasswordStrength] = useState<PasswordStrength | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  useEffect(() => {
    // Check if browser supports WebAuthn
    if (!window.PublicKeyCredential) {
      setBrowserSupported(false);
    }
  }, []);
  useEffect(() => {
    // Check password strength when password changes
    if (password && registrationMethod === 'email') {
      checkPasswordStrength(password);
    } else {
      setPasswordStrength(null);
    }
  }, [password, registrationMethod]);
  const checkPasswordStrength = async (pwd: string) => {
    try {
      const response = await api.post('/auth/check-password-strength', {
        password: pwd
      });
      setPasswordStrength(response.data);
    } catch (err) {
      console.error('Password strength check failed:', err);
    }
  };
  const handlePasskeyRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      // Step 1: Check if email is available
      const checkResponse = await api.get(`/auth/check-email?email=${encodeURIComponent(email)}`);
      if (!checkResponse.data.available) {
        setError('Email already registered');
        setLoading(false);
        return;
      }
      // Step 2: Get registration options (for new user) with email
      const { data: options } = await api.post('/auth/registration/options', { email });
      // Step 3: Create credential with WebAuthn
      const credential = await startRegistration(options);
      // Step 4: Verify registration with user data
      const { data: result } = await api.post('/auth/registration/verify', {
        credential,
        deviceName: navigator.userAgent.includes('Mac') ? 'Mac' : 
                   navigator.userAgent.includes('Windows') ? 'Windows PC' : 
                   navigator.userAgent.includes('iPhone') ? 'iPhone' : 
                   navigator.userAgent.includes('Android') ? 'Android' : 'Device',
        userData: {
          email,
          firstName,
          lastName
        }
      });
      if (result.verified) {
        // User created with passkey, now send verification email
        await api.post('/auth/send-verification', { 
          userId: result.user.id 
        });
        setEmailSent(true);
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.response?.data?.error || err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };
  const handleEmailRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    // Validate form
    if (!email || !password || !passwordConfirm) {
      setError('Please fill in all required fields');
      setLoading(false);
      return;
    }
    if (password !== passwordConfirm) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }
    try {
      const response = await api.post('/auth/register', {
        email,
        password,
        passwordConfirm,
        firstName,
        lastName
      });
      if (response.data.success) {
        setEmailSent(true);
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };
  const getPasswordStrengthClass = (score: number): string => {
    const classes = ['weak', 'fair', 'good', 'strong'];
    return classes[score] || 'weak';
  };
  if (emailSent) {
    return (
      <div className="auth-container">
        <h1>Check Your Email</h1>
        <div className="success-alert">
          <svg className="success-icon" width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
          <div>
            <p>We've sent a verification link to <strong>{email}</strong></p>
            <p style={{ fontSize: '14px', marginTop: '5px' }}>Please check your email and click the link to verify your account.</p>
          </div>
        </div>
        <div className="text-center mt-3">
          <Link to="/signin" className="link">Back to Sign In</Link>
        </div>
      </div>
    );
  }
  if (registrationMethod === 'choice') {
    return (
      <div className="auth-container">
        <h1>Create Your Account</h1>
        <p>Choose how you'd like to register</p>
        <div className="registration-options">
          <button
            className="option-card"
            onClick={() => setRegistrationMethod('passkey')}
            disabled={!browserSupported}
          >
            <div className="option-icon">🔐</div>
            <h3>Passkey</h3>
            <p>Use biometrics, YubiKey, or security key for passwordless login</p>
            {!browserSupported && (
              <span className="badge">Not supported on this browser</span>
            )}
          </button>
          <button
            className="option-card"
            onClick={() => setRegistrationMethod('email')}
          >
            <div className="option-icon">📧</div>
            <h3>Email & Password</h3>
            <p>Traditional registration with email verification</p>
          </button>
        </div>
        <div className="text-center mt-3">
          Already have an account? <Link to="/signin" className="link">Sign In</Link>
        </div>
      </div>
    );
  }
  if (registrationMethod === 'passkey') {
    return (
      <div className="auth-container">
        <button 
          className="back-button"
          onClick={() => setRegistrationMethod('choice')}
        >
          ← Back
        </button>
        <h1>Create Account with Passkey</h1>
        <p>Enter your email to create a secure account with passkey authentication.</p>
        <DeviceCheck />
        <ErrorAlert error={error} />
        <form onSubmit={handlePasskeyRegister}>
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              placeholder="you@example.com"
            />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="firstName">First Name</label>
              <input
                type="text"
                id="firstName"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
                autoComplete="given-name"
                placeholder="John"
              />
            </div>
            <div className="form-group">
              <label htmlFor="lastName">Last Name</label>
              <input
                type="text"
                id="lastName"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                required
                autoComplete="family-name"
                placeholder="Doe"
              />
            </div>
          </div>
          {browserSupported && (
            <button 
              type="submit"
              className="btn" 
              disabled={loading}
            >
              {loading ? <span className="loading"></span> : 'Create Account with Passkey'}
            </button>
          )}
        </form>
        <div className="info-alert mt-3">
          <svg className="info-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          <span>You'll need to verify your email before you can sign in</span>
        </div>
      </div>
    );
  }
  // Email & Password Registration
  return (
    <div className="auth-container">
      <button 
        className="back-button"
        onClick={() => setRegistrationMethod('choice')}
      >
        ← Back
      </button>
      <h1>Create Account</h1>
      <p>Register with your email address</p>
      <ErrorAlert error={error} />
      <form onSubmit={handleEmailRegister}>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="firstName">First Name</label>
            <input
              type="text"
              id="firstName"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              placeholder="John"
            />
          </div>
          <div className="form-group">
            <label htmlFor="lastName">Last Name</label>
            <input
              type="text"
              id="lastName"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              placeholder="Doe"
            />
          </div>
        </div>
        <div className="form-group">
          <label htmlFor="email">Email Address *</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="john@example.com"
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password *</label>
          <div className="password-input">
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter a strong password"
              required
            />
            <button
              type="button"
              className="toggle-password"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
          </div>
          {passwordStrength && password && (
            <div className="password-strength">
              <div className={`strength-meter ${getPasswordStrengthClass(passwordStrength.score)}`}>
                <div 
                  className="strength-bar" 
                  style={{ width: `${(passwordStrength.score + 1) * 25}%` }}
                />
              </div>
              <p className="strength-text">
                {passwordStrength.feedback || `Strength: ${getPasswordStrengthClass(passwordStrength.score)}`}
              </p>
              {passwordStrength.suggestions && passwordStrength.suggestions.length > 0 && (
                <ul className="strength-suggestions">
                  {passwordStrength.suggestions.map((suggestion, index) => (
                    <li key={index}>{suggestion}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
        <div className="form-group">
          <label htmlFor="passwordConfirm">Confirm Password *</label>
          <input
            type="password"
            id="passwordConfirm"
            value={passwordConfirm}
            onChange={(e) => setPasswordConfirm(e.target.value)}
            placeholder="Confirm your password"
            required
          />
          {passwordConfirm && password !== passwordConfirm && (
            <span className="error-text">Passwords do not match</span>
          )}
        </div>
        <button 
          type="submit"
          className="btn" 
          disabled={loading || (passwordStrength !== null && passwordStrength.score < 2)}
        >
          {loading ? <span className="loading"></span> : 'Create Account'}
        </button>
      </form>
      <div className="info-alert mt-3">
        <svg className="info-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
        </svg>
        <span>You can add a passkey for faster login after email verification</span>
      </div>
      <div className="text-center mt-3">
        Already have an account? <Link to="/signin" className="link">Sign In</Link>
      </div>
    </div>
  );
};