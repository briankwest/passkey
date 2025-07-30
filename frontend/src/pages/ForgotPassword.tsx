import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';

export const ForgotPassword: React.FC = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await api.post('/auth/forgot-password', { email });
      setSuccess(true);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to send reset email');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="auth-container">
        <h1>Check Your Email</h1>
        <p>If an account exists with {email}, we've sent password reset instructions to that email address.</p>
        <p>Please check your inbox and follow the link to reset your password.</p>
        <Link to="/signin" className="btn">Back to Sign In</Link>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <h1>Forgot Password</h1>
      <p>Enter your email address and we'll send you instructions to reset your password.</p>

      {error && <div className="error-message">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
            placeholder="Enter your email address"
          />
        </div>

        <button type="submit" className="btn" disabled={loading}>
          {loading ? <span className="loading"></span> : 'Send Reset Email'}
        </button>
      </form>

      <div className="links-section">
        <Link to="/signin" className="link">Back to Sign In</Link>
      </div>
    </div>
  );
};