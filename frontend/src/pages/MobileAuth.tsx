import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import api from '../services/api';

export const MobileAuth: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuth();

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
      // First authenticate with passkey
      await login();
      
      // Then complete the cross-device session
      await api.post('/auth/cross-device/complete', { sessionId });
      
      setSuccess(true);
      
      // Show success for a moment before redirecting
      setTimeout(() => {
        navigate('/profile');
      }, 2000);
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
        <p>You can now return to your desktop browser.</p>
        <p className="text-center" style={{ marginTop: '20px' }}>
          Redirecting to profile...
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