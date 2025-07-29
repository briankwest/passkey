import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { ErrorAlert } from '../components/ErrorAlert';
import { DeviceCheck } from '../components/DeviceCheck';
import { getErrorMessage } from '../utils/errorMessages';

export const SignUp: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [browserSupported, setBrowserSupported] = useState(true);
  const navigate = useNavigate();
  const { register } = useAuth();

  useEffect(() => {
    // Check if browser supports WebAuthn
    if (!window.PublicKeyCredential) {
      setBrowserSupported(false);
      setError('Your browser does not support passkeys. Please use Chrome, Safari, Firefox, or Edge.');
    }
  }, []);

  const handleRegister = async () => {
    setLoading(true);
    setError('');
    
    try {
      await register();
      navigate('/profile');
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h1>Create Account with Passkey</h1>
      <p>Use your device's biometric authentication, YubiKey, or other security key to create a secure account.</p>
      
      <DeviceCheck />
      
      <ErrorAlert 
        error={error} 
        onRetry={handleRegister}
        showRetry={!loading && browserSupported}
      />
      
      {browserSupported && (
        <button 
          className="btn" 
          onClick={handleRegister}
          disabled={loading}
        >
          {loading ? <span className="loading"></span> : 'Create Passkey'}
        </button>
      )}
      
      {!browserSupported && (
        <div className="info-alert">
          <svg className="info-icon" width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          <span>Please update your browser to use passkeys.</span>
        </div>
      )}
      
      <div className="text-center mt-3">
        Already have an account? <Link to="/signin" className="link">Sign In</Link>
      </div>
      
      <div className="mt-3" style={{ fontSize: '14px', color: '#666' }}>
        <strong>Note:</strong> This demo uses passkeys for authentication. Make sure your device supports WebAuthn and has biometric authentication, YubiKey, or other FIDO2 security key set up.
      </div>
    </div>
  );
};