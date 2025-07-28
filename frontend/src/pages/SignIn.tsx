import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import QRCode from 'qrcode';
import api from '../services/api';
import { ErrorAlert } from '../components/ErrorAlert';
import { getErrorMessage, isPasskeyNotFoundError, isSessionExpiredError } from '../utils/errorMessages';

export const SignIn: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showQR, setShowQR] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [qrError, setQrError] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();
  const pollingInterval = useRef<NodeJS.Timeout>();

  useEffect(() => {
    // Check if this is a mobile device
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    if (!isMobile && showQR) {
      generateQRCode();
    }
    
    // Cleanup polling on unmount
    return () => {
      if (pollingInterval.current) {
        clearInterval(pollingInterval.current);
      }
    };
  }, [showQR]);

  const generateQRCode = async () => {
    try {
      setQrError('');
      // Generate a session ID for cross-device authentication
      const newSessionId = crypto.randomUUID();
      setSessionId(newSessionId);
      
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
          navigate('/profile');
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2000); // Poll every 2 seconds
  };

  const handleAuthenticate = async () => {
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

  return (
    <div className="auth-container">
      <h1>Sign In with Passkey</h1>
      <p>Use your saved passkey to sign in securely.</p>
      
      <ErrorAlert 
        error={error} 
        onRetry={handleAuthenticate}
        showRetry={!loading}
      />
      
      <button 
        className="btn" 
        onClick={handleAuthenticate}
        disabled={loading}
      >
        {loading ? <span className="loading"></span> : 'Sign In with Passkey'}
      </button>
      
      <div className="text-center mt-3">
        <button 
          className="link" 
          onClick={() => setShowQR(!showQR)}
          style={{ background: 'none', border: 'none', fontSize: '16px' }}
        >
          Use another device
        </button>
      </div>
      
      {showQR && (
        <div className="qr-container">
          <p>Scan this QR code with your mobile device:</p>
          {qrError ? (
            <ErrorAlert error={qrError} onRetry={generateQRCode} showRetry={true} />
          ) : qrCodeUrl ? (
            <>
              <div className="qr-code">
                <img src={qrCodeUrl} alt="QR Code for mobile authentication" />
              </div>
              <div className="info-alert" style={{ marginTop: '10px', maxWidth: '300px' }}>
                <svg className="info-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <span style={{ fontSize: '13px' }}>Waiting for authentication from your mobile device...</span>
              </div>
            </>
          ) : (
            <div className="loading"></div>
          )}
          <p style={{ fontSize: '14px', color: '#666', textAlign: 'center', marginTop: '10px' }}>
            Make sure you have already registered a passkey on your mobile device
          </p>
        </div>
      )}
      
      <div className="text-center mt-3">
        Don't have an account? <Link to="/signup" className="link">Create Account</Link>
      </div>
    </div>
  );
};