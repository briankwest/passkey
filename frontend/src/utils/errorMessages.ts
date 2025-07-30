// Map common WebAuthn and API errors to user-friendly messages
export const getErrorMessage = (error: any): string => {
  // WebAuthn specific errors
  if (error.name === 'NotAllowedError') {
    return 'Authentication was cancelled or timed out. Please try again.';
  }
  
  if (error.name === 'InvalidStateError') {
    return 'A passkey already exists for this device. Please sign in instead.';
  }
  
  if (error.name === 'NotSupportedError') {
    return 'Your browser or device does not support passkeys. Please use a modern browser.';
  }
  
  if (error.name === 'SecurityError') {
    return 'This operation requires a secure context (HTTPS). Please ensure you\'re using HTTPS.';
  }
  
  if (error.name === 'AbortError') {
    return 'The operation was aborted. Please try again.';
  }
  
  // API response errors
  if (error.response) {
    const status = error.response.status;
    const data = error.response.data;
    
    switch (status) {
      case 400:
        return data?.error || 'Invalid request. Please check your input and try again.';
      case 401:
        return 'Your session has expired. Please sign in again.';
      case 403:
        return 'You don\'t have permission to perform this action.';
      case 404:
        return 'The requested resource was not found.';
      case 409:
        return data?.error || 'This action conflicts with existing data.';
      case 422:
        return data?.error || 'The provided data is invalid.';
      case 429:
        return 'Too many requests. Please wait a moment and try again.';
      case 500:
        // Check for specific backend errors
        if (data?.error?.includes('Credential not found')) {
          return 'No passkey found for this account. Please register first.';
        }
        if (data?.error?.includes('challenge')) {
          return 'Authentication session expired. Please try again.';
        }
        return 'Something went wrong on our end. Please try again later.';
      case 502:
      case 503:
      case 504:
        return 'Server is temporarily unavailable. Please try again in a few moments.';
      default:
        return data?.error || 'An unexpected error occurred. Please try again.';
    }
  }
  
  // Network errors
  if (error.code === 'ECONNABORTED') {
    return 'Request timed out. Please check your connection and try again.';
  }
  
  if (error.message === 'Network Error') {
    return 'Unable to connect to the server. Please check your internet connection.';
  }
  
  // Default message
  return error.message || 'An unexpected error occurred. Please try again.';
};

// Specific error checkers
export const isPasskeyNotFoundError = (error: any): boolean => {
  return error.response?.data?.error?.includes('Credential not found') || 
         error.response?.status === 404;
};