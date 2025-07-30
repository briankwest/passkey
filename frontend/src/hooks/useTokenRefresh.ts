import { useEffect, useRef } from 'react';
import axios from 'axios';
import { useAuth } from './useAuth';

export const useTokenRefresh = () => {
  const { setToken, logout } = useAuth();
  const refreshTimeoutRef = useRef<NodeJS.Timeout>();

  const refreshToken = async () => {
    try {
      const response = await axios.post('/api/auth/refresh', {}, {
        withCredentials: true
      });
      
      if (response.data.success && response.data.token) {
        setToken(response.data.token);
        // Schedule next refresh 1 minute before token expires (14 minutes)
        scheduleRefresh(14 * 60 * 1000);
        return true;
      }
    } catch (error) {
      console.error('Failed to refresh token:', error);
      logout();
      return false;
    }
  };

  const scheduleRefresh = (delay: number) => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
    }
    
    refreshTimeoutRef.current = setTimeout(() => {
      refreshToken();
    }, delay);
  };

  useEffect(() => {
    // Initial token refresh schedule - 14 minutes
    scheduleRefresh(14 * 60 * 1000);

    // Setup axios interceptor for 401 responses
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          const refreshed = await refreshToken();
          if (refreshed) {
            // Retry the original request with new token
            return axios(originalRequest);
          }
        }
        
        return Promise.reject(error);
      }
    );

    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
      axios.interceptors.response.eject(interceptor);
    };
  }, []);

  return { refreshToken };
};