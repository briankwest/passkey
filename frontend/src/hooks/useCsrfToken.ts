import { useState, useEffect } from 'react';
import axios from 'axios';

let globalCsrfToken = '';

export const useCsrfToken = () => {
  const [csrfToken, setCsrfToken] = useState<string>('');

  useEffect(() => {
    const fetchCsrfToken = async () => {
      // Only fetch CSRF token if user is authenticated
      const token = localStorage.getItem('token');
      if (!token) {
        return;
      }

      try {
        const response = await axios.get('/api/csrf-token', {
          withCredentials: true
        });
        setCsrfToken(response.data.csrfToken);
        globalCsrfToken = response.data.csrfToken;
      } catch (error: any) {
        // Don't log error for 403 or 502 (expected when not authenticated or ngrok issues)
        if (error.response?.status !== 403 && error.response?.status !== 502) {
          // Silently fail - CSRF token might not be needed for all operations
        }
      }
    };

    fetchCsrfToken();
    
    // Re-fetch when token changes
    const handleStorageChange = () => {
      fetchCsrfToken();
    };
    
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  return csrfToken;
};

export const getCsrfToken = () => {
  // Try to get from global variable first
  if (globalCsrfToken) {
    return globalCsrfToken;
  }
  
  // Try to get from cookie
  const match = document.cookie.match(/(?:^|;\s*)csrf-token=([^;]*)/);
  const cookieToken = match ? decodeURIComponent(match[1]) : '';
  
  // Fallback to window object
  const token = cookieToken || (window as any).csrfToken || '';
  return token;
};

// Configure axios to automatically include CSRF token
export const configureAxiosCSRF = (token: string) => {
  axios.defaults.headers.common['X-CSRF-Token'] = token;
};