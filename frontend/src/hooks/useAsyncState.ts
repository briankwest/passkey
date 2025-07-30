import { useLoading } from './useLoading';
import { useError } from './useError';
import { useCallback } from 'react';

/**
 * Combines loading and error states for async operations
 * Provides a convenient wrapper for common async patterns
 */
export const useAsyncState = () => {
  const { loading, setLoading, withLoading } = useLoading();
  const { error, setError, clearError, handleError } = useError();

  /**
   * Execute an async function with automatic loading and error handling
   * @param asyncFn - The async function to execute
   * @returns Promise with the result or null if error
   */
  const execute = useCallback(
    async <T,>(asyncFn: () => Promise<T>): Promise<T | null> => {
      clearError();
      try {
        return await withLoading(asyncFn);
      } catch (err) {
        handleError(err);
        return null;
      }
    },
    [withLoading, clearError, handleError]
  );

  /**
   * Reset all states
   */
  const reset = useCallback(() => {
    setLoading(false);
    clearError();
  }, [setLoading, clearError]);

  return {
    loading,
    error,
    setLoading,
    setError,
    clearError,
    execute,
    reset
  };
};