import { useState, useCallback } from 'react';

/**
 * Hook to manage loading states
 * @param initialState - Initial loading state (default: false)
 * @returns {loading, setLoading, withLoading}
 */
export const useLoading = (initialState: boolean = false) => {
  const [loading, setLoading] = useState(initialState);

  /**
   * Wraps an async function to automatically handle loading state
   * Sets loading to true before execution and false after completion
   */
  const withLoading = useCallback(
    async <T,>(asyncFn: () => Promise<T>): Promise<T> => {
      setLoading(true);
      try {
        const result = await asyncFn();
        return result;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return {
    loading,
    setLoading,
    withLoading
  };
};