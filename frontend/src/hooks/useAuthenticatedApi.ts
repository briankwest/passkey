import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApiCall, UseApiCallOptions } from './useApiCall';

interface AuthenticatedApiOptions extends UseApiCallOptions {
  /**
   * Whether to redirect to login on 401 errors (default: true)
   */
  redirectOnUnauthorized?: boolean;
}

/**
 * Hook for authenticated API calls that automatically adds auth headers
 * and handles 401 responses
 */
export const useAuthenticatedApi = <T = any>(options: AuthenticatedApiOptions = {}) => {
  const navigate = useNavigate();
  const { redirectOnUnauthorized = true, ...apiOptions } = options;

  const originalOnError = apiOptions.onError;
  
  // Enhanced error handler that checks for 401s
  const onError = useCallback((error: any) => {
    if (error.response?.status === 401 && redirectOnUnauthorized) {
      // Clear auth token
      localStorage.removeItem('token');
      // Redirect to login
      navigate('/signin', { 
        state: { message: 'Your session has expired. Please sign in again.' } 
      });
    }
    
    if (originalOnError) {
      originalOnError(error);
    }
  }, [navigate, redirectOnUnauthorized, originalOnError]);

  const apiCall = useApiCall<T>({
    ...apiOptions,
    onError
  });

  /**
   * Execute an authenticated API call
   * Automatically adds Authorization header with token
   */
  const executeAuth = useCallback(
    async <R = T>(
      url: string,
      options: RequestInit = {}
    ): Promise<R | null> => {
      const token = localStorage.getItem('token');
      
      if (!token) {
        if (redirectOnUnauthorized) {
          navigate('/signin');
        }
        return null;
      }

      const apiUrl = `${import.meta.env.VITE_API_URL}${url}`;
      
      return apiCall.execute<R>((signal) => 
        fetch(apiUrl, {
          ...options,
          signal,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            ...options.headers
          }
        }).then(async (response) => {
          if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const error = new Error(errorData.error || response.statusText);
            (error as any).response = response;
            (error as any).data = errorData;
            throw error;
          }
          return response.json();
        })
      );
    },
    [apiCall, navigate, redirectOnUnauthorized]
  );

  return {
    ...apiCall,
    executeAuth
  };
};