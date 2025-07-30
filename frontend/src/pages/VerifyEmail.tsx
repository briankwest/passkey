import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import api from '../services/api';
import { startRegistration } from '@simplewebauthn/browser';
import { ErrorAlert } from '../components/ErrorAlert';

const VerifyEmail: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [verifying, setVerifying] = useState(true);
  const [verified, setVerified] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [showPasskeyOption, setShowPasskeyOption] = useState(false);
  const [user, setUser] = useState<any>(null);
  
  const browserSupported = 
    typeof window !== 'undefined' && 
    window.PublicKeyCredential !== undefined;

  useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      verifyEmail(token);
    } else {
      setError('No verification token provided');
      setVerifying(false);
    }
  }, [searchParams]);

  const verifyEmail = async (token: string) => {
    try {
      const response = await api.get(`/auth/verify-email?token=${token}`);
      setVerified(true);
      setUser(response.data.user);
      
      // Store token for authenticated requests
      if (response.data.token) {
        localStorage.setItem('token', response.data.token);
      }
      
      // Check if user has passkeys
      if (!response.data.hasPasskey && !response.data.alreadyVerified) {
        setShowPasskeyOption(true);
      }
      
      // If already verified, redirect to profile after a moment
      if (response.data.alreadyVerified) {
        setTimeout(() => navigate('/profile'), 2000);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to verify email');
    } finally {
      setVerifying(false);
    }
  };

  const handleAddPasskey = async () => {
    setAddingPasskey(true);
    setError(null);
    
    try {
      // Determine device name
      const deviceName = navigator.userAgent.includes('Mac') ? 'Mac' : 
                        navigator.userAgent.includes('Windows') ? 'Windows PC' : 
                        navigator.userAgent.includes('iPhone') ? 'iPhone' : 
                        navigator.userAgent.includes('Android') ? 'Android' : 'Device';
      
      // Get registration options from authenticated endpoint
      const { data: options } = await api.post('/auth/passkey/add/options', {
        deviceName
      });
      
      // Start WebAuthn registration
      const credential = await startRegistration(options);
      
      // Verify with server
      const { data } = await api.post('/auth/passkey/add/verify', {
        credential,
        deviceName
      });
      
      if (data.verified) {
        navigate('/profile');
      } else {
        throw new Error('Failed to verify passkey');
      }
    } catch (err: any) {
      console.error('Passkey registration error:', err);
      setError(err.message || 'Failed to add passkey');
      setAddingPasskey(false);
    }
  };

  const handleSkipPasskey = () => {
    navigate('/signin');
  };

  if (verifying) {
    return (
      <div className="container">
        <div className="auth-container">
          <h1>Verifying Email...</h1>
          <div className="loading"></div>
        </div>
      </div>
    );
  }

  if (error && !verified) {
    return (
      <div className="container">
        <div className="auth-container">
          <h1>Verification Failed</h1>
          <ErrorAlert error={error} />
          <Link to="/signin" className="btn">Go to Sign In</Link>
        </div>
      </div>
    );
  }

  if (verified && showPasskeyOption && browserSupported) {
    return (
      <div className="container">
        <div className="auth-container">
          <h1>Email Verified! 🎉</h1>
          <p>Welcome {user?.firstName}! Your email has been verified.</p>
          
          <div className="passkey-setup">
            <h2>Set Up Passkey Authentication</h2>
            <p>Add a passkey for secure, passwordless login using your device's biometrics or security key.</p>
            
            {error && <ErrorAlert error={error} />}
            
            <button 
              className="btn" 
              onClick={handleAddPasskey}
              disabled={addingPasskey}
            >
              {addingPasskey ? <span className="loading"></span> : 'Add Passkey Now'}
            </button>
            
            <button 
              className="secondary-btn" 
              onClick={handleSkipPasskey}
              disabled={addingPasskey}
            >
              Skip for Now
            </button>
            
            <p className="text-muted">You can always add a passkey later in your security settings.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="auth-container">
        <h1>Email Verified! 🎉</h1>
        <p>Your email has been successfully verified.</p>
        
        <Link to="/profile" className="btn">Go to Your Profile</Link>
      </div>
    </div>
  );
};

export default VerifyEmail;