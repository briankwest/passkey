import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
export const ResetPassword: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState<any>(null);
  const token = searchParams.get('token');
  useEffect(() => {
    if (!token) {
      setError('Invalid reset link');
    }
  }, [token]);
  useEffect(() => {
    if (password) {
      checkPasswordStrength(password);
    } else {
      setPasswordStrength(null);
    }
  }, [password]);
  const checkPasswordStrength = async (pwd: string) => {
    try {
      const response = await api.post('/auth/check-password-strength', { password: pwd });
      setPasswordStrength(response.data);
    } catch (err) {
      console.error('Failed to check password strength:', err);
    }
  };
  const getPasswordStrengthClass = (score: number) => {
    if (score >= 4) return 'strong';
    if (score >= 3) return 'good';
    if (score >= 2) return 'fair';
    return 'weak';
  };
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (passwordStrength && !passwordStrength.valid) {
      setError('Please choose a stronger password');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/reset-password', { token, password });
      alert('Password reset successfully! Please sign in with your new password.');
      navigate('/signin');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to reset password');
    } finally {
      setLoading(false);
    }
  };
  if (!token) {
    return (
      <div className="auth-container">
        <h1>Invalid Reset Link</h1>
        <p>This password reset link is invalid or has expired.</p>
        <button onClick={() => navigate('/forgot-password')} className="btn">
          Request New Reset Link
        </button>
      </div>
    );
  }
  return (
    <div className="auth-container">
      <h1>Reset Password</h1>
      <p>Enter your new password below.</p>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="password">New Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoFocus
            placeholder="Enter new password"
          />
          {passwordStrength && (
            <div className="password-strength">
              <div className={`strength-meter ${getPasswordStrengthClass(passwordStrength.score)}`}>
                <div className="strength-bar" style={{ width: `${(passwordStrength.score + 1) * 20}%` }}></div>
              </div>
              <span className="strength-text">{passwordStrength.feedback}</span>
            </div>
          )}
        </div>
        <div className="form-group">
          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            placeholder="Confirm new password"
          />
        </div>
        <button type="submit" className="btn" disabled={loading || !passwordStrength?.valid}>
          {loading ? <span className="loading"></span> : 'Reset Password'}
        </button>
      </form>
    </div>
  );
};