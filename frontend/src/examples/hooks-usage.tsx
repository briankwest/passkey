/**
 * Examples of using the custom hooks in different scenarios
 */

import React, { useEffect } from 'react';
import { 
  useLoading, 
  useError, 
  useApiCall, 
  useAuthenticatedApi, 
  useAsyncState 
} from '../hooks';

// Example 1: Simple loading state management
export const LoadingExample: React.FC = () => {
  const { loading, withLoading } = useLoading();

  const handleClick = async () => {
    await withLoading(async () => {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
    });
  };

  return (
    <button onClick={handleClick} disabled={loading}>
      {loading ? 'Loading...' : 'Click me'}
    </button>
  );
};

// Example 2: Error handling
export const ErrorExample: React.FC = () => {
  const { error, handleError, clearError } = useError();

  const riskyOperation = async () => {
    try {
      throw new Error('Something went wrong!');
    } catch (err) {
      handleError(err, 'Failed to perform operation');
    }
  };

  return (
    <div>
      {error && (
        <div className="error">
          {error}
          <button onClick={clearError}>Dismiss</button>
        </div>
      )}
      <button onClick={riskyOperation}>Trigger Error</button>
    </div>
  );
};

// Example 3: API call with loading and error states
export const ApiCallExample: React.FC = () => {
  const { execute, loading, error, data } = useApiCall<{ users: any[] }>();

  const loadUsers = () => {
    execute(async (signal) => {
      const response = await fetch('/api/users', { signal });
      if (!response.ok) throw new Error('Failed to load users');
      return response.json();
    });
  };

  return (
    <div>
      <button onClick={loadUsers} disabled={loading}>
        Load Users
      </button>
      {loading && <div>Loading...</div>}
      {error && <div className="error">{error}</div>}
      {data && (
        <ul>
          {data.users.map(user => (
            <li key={user.id}>{user.name}</li>
          ))}
        </ul>
      )}
    </div>
  );
};

// Example 4: Authenticated API calls
export const AuthenticatedApiExample: React.FC = () => {
  const { executeAuth, loading, error, data } = useAuthenticatedApi<any>();

  useEffect(() => {
    // Load user profile on mount
    executeAuth('/api/user/profile');
  }, []);

  const updateProfile = async (profileData: any) => {
    const result = await executeAuth('/api/user/profile', {
      method: 'PUT',
      body: JSON.stringify(profileData)
    });

    if (result) {
      console.log('Profile updated successfully');
    }
  };

  return (
    <div>
      {loading && <div>Loading profile...</div>}
      {error && <div className="error">{error}</div>}
      {data && <div>Welcome, {data.name}!</div>}
    </div>
  );
};

// Example 5: Combined async state management
export const AsyncStateExample: React.FC = () => {
  const { loading, error, execute } = useAsyncState();

  const handleSubmit = async (formData: any) => {
    const result = await execute(async () => {
      const response = await fetch('/api/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      
      if (!response.ok) {
        throw new Error('Submission failed');
      }
      
      return response.json();
    });

    if (result) {
      console.log('Success!', result);
    }
  };

  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      handleSubmit({ /* form data */ });
    }}>
      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={loading}>
        {loading ? 'Submitting...' : 'Submit'}
      </button>
    </form>
  );
};

// Example 6: Multiple concurrent API calls
export const MultipleApiCallsExample: React.FC = () => {
  const profileApi = useAuthenticatedApi();
  const settingsApi = useAuthenticatedApi();
  
  const loadAllData = async () => {
    // Execute multiple calls concurrently
    const [profile, settings] = await Promise.all([
      profileApi.executeAuth('/api/user/profile'),
      settingsApi.executeAuth('/api/user/settings')
    ]);

    console.log('Loaded:', { profile, settings });
  };

  const isLoading = profileApi.loading || settingsApi.loading;
  const hasError = profileApi.error || settingsApi.error;

  return (
    <div>
      <button onClick={loadAllData} disabled={isLoading}>
        Load All Data
      </button>
      {isLoading && <div>Loading data...</div>}
      {hasError && <div className="error">Failed to load some data</div>}
    </div>
  );
};