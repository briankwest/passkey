import { useState } from 'react';
import authService from '../services/auth.service';

export const useWebAuthn = () => {
  const [isRegistering, setIsRegistering] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const browserSupported = 
    typeof window !== 'undefined' && 
    window.PublicKeyCredential !== undefined &&
    navigator.credentials !== undefined;

  const register = async () => {
    if (!browserSupported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    setIsRegistering(true);
    setError(null);

    try {
      const result = await authService.register();
      return result;
    } catch (err: any) {
      setError(err.message);
      throw err;
    } finally {
      setIsRegistering(false);
    }
  };

  const authenticate = async () => {
    if (!browserSupported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    setIsAuthenticating(true);
    setError(null);

    try {
      const result = await authService.authenticate();
      return result;
    } catch (err: any) {
      setError(err.message);
      throw err;
    } finally {
      setIsAuthenticating(false);
    }
  };

  return {
    register,
    authenticate,
    isRegistering,
    isAuthenticating,
    error,
    browserSupported
  };
};