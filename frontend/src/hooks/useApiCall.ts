import { useState, useCallback, useRef, useEffect } from 'react';
import { useLoading } from './useLoading';
import { useError } from './useError';

interface UseApiCallOptions {
  /**
   * Whether to show loading state (default: true)
   */
  showLoading?: boolean;
  /**
   * Whether to automatically clear errors before making a new call (default: true)
   */
  clearErrorOnCall?: boolean;
  /**
   * Success callback
   */
  onSuccess?: (data: any) => void;
  /**
   * Error callback
   */
  onError?: (error: any) => void;
}

/**
 * Hook to manage API calls with loading and error states
 * @param options - Configuration options
 * @returns {execute, loading, error, data, reset}
 */
export const useApiCall = <T = any>(options: UseApiCallOptions = {}) => {
  const {
    showLoading = true,
    clearErrorOnCall = true,
    onSuccess,
    onError
  } = options;

  const { loading, setLoading } = useLoading(false);
  const { error, setError, clearError, handleError } = useError();
  const [data, setData] = useState<T | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  /**
   * Execute an API call with automatic loading and error handling
   * @param apiCall - The API call function to execute
   * @returns Promise with the result
   */
  const execute = useCallback(
    async <R = T>(apiCall: (signal?: AbortSignal) => Promise<R>): Promise<R | null> => {
      // Cancel any pending request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      // Create new abort controller
      abortControllerRef.current = new AbortController();
      const { signal } = abortControllerRef.current;

      // Clear error if configured
      if (clearErrorOnCall) {
        clearError();
      }

      // Set loading state
      if (showLoading) {
        setLoading(true);
      }

      try {
        const result = await apiCall(signal);
        setData(result as any);
        
        if (onSuccess) {
          onSuccess(result);
        }
        
        return result;
      } catch (err: any) {
        // Ignore abort errors
        if (err.name === 'AbortError') {
          return null;
        }

        handleError(err);
        
        if (onError) {
          onError(err);
        }
        
        return null;
      } finally {
        if (showLoading) {
          setLoading(false);
        }
        abortControllerRef.current = null;
      }
    },
    [showLoading, clearErrorOnCall, clearError, setLoading, handleError, onSuccess, onError]
  );

  /**
   * Reset all states
   */
  const reset = useCallback(() => {
    clearError();
    setData(null);
    setLoading(false);
    
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  }, [clearError, setLoading]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return {
    execute,
    loading,
    error,
    data,
    reset
  };
};