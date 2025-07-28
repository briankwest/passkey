import React from 'react';

interface ErrorAlertProps {
  error: string;
  onRetry?: () => void;
  showRetry?: boolean;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({ error, onRetry, showRetry = false }) => {
  if (!error) return null;

  return (
    <div className="error-alert" role="alert">
      <div className="error-content">
        <svg className="error-icon" width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
        </svg>
        <span className="error-text">{error}</span>
      </div>
      {showRetry && onRetry && (
        <button className="retry-button" onClick={onRetry}>
          Try Again
        </button>
      )}
    </div>
  );
};