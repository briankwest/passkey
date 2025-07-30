import { useState, useCallback } from 'react';
import { getErrorMessage } from '../utils/errorMessages';

/**
 * Hook to manage error states with automatic error message extraction
 * @returns {error, setError, clearError, handleError}
 */
export const useError = () => {
  const [error, setError] = useState<string>('');

  /**
   * Clear the current error
   */
  const clearError = useCallback(() => {
    setError('');
  }, []);

  /**
   * Handle an error by extracting a user-friendly message
   * @param err - The error to handle
   * @param fallbackMessage - Optional fallback message if error extraction fails
   */
  const handleError = useCallback((err: any, fallbackMessage?: string) => {
    const message = getErrorMessage(err);
    setError(message || fallbackMessage || 'An unexpected error occurred');
  }, []);

  return {
    error,
    setError,
    clearError,
    handleError
  };
};