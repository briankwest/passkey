import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { startAuthentication } from '@simplewebauthn/browser';
import api from '../services/api';

export const MobileAuth: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  // Get the session ID from URL params
  const sessionId = searchParams.get('session');

  useEffect(() => {
    // Check if this is a mobile device
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    if (!isMobile) {
      setError('Please open this link on your mobile device');
    }
  }, []);

  const handleAuthenticate = async () => {
    if (!sessionId) {
      setError('No session ID provided');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      // Get authentication options
      const { data: options } = await api.post('/auth/authenticate/options');
      
      // Start WebAuthn authentication
      const credential = await startAuthentication(options);
      
      // Verify with server but don't store the token
      const { data } = await api.post('/auth/authenticate/verify', { credential });
      
      // Complete the cross-device session with the authenticated user
      if (data.token) {
        // Temporarily set the token for the complete request
        const originalToken = localStorage.getItem('token');
        localStorage.setItem('token', data.token);
        
        try {
          await api.post('/auth/cross-device/complete', { sessionId });
          setSuccess(true);
        } finally {
          // Restore original token state (remove the temporary token)
          if (originalToken) {
            localStorage.setItem('token', originalToken);
          } else {
            localStorage.removeItem('token');
          }
        }
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="auth-container">
        <h1>✅ Authentication Successful!</h1>
        <p>You have successfully authenticated on your desktop.</p>
        <p className="text-center" style={{ marginTop: '20px', fontSize: '18px', fontWeight: 'bold' }}>
          You can now close this window and return to your desktop browser.
        </p>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <h1>Mobile Authentication</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      <div style={{ textAlign: 'center', margin: '30px 0' }}>
        <p>Authenticate with your saved passkey on this device</p>
        
        <button 
          className="btn" 
          onClick={handleAuthenticate}
          disabled={loading}
          style={{ marginTop: '20px' }}
        >
          {loading ? <span className="loading"></span> : 'Authenticate with Passkey'}
        </button>
      </div>
      
      <div style={{ fontSize: '14px', color: '#666', marginTop: '30px' }}>
        <strong>Note:</strong> You must have already registered a passkey on this device.
      </div>
    </div>
  );
};