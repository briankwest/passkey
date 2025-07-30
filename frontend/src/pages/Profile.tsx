import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import userService from '../services/user.service';
import { ErrorAlert } from '../components/ErrorAlert';
import { getErrorMessage } from '../utils/errorMessages';
export const Profile: React.FC = () => {
  const { user, logout, refreshUser } = useAuth();
  const navigate = useNavigate();
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [formData, setFormData] = useState({
    username: user?.username || '',
    email: user?.email || '',
    display_name: user?.display_name || '',
    bio: user?.bio || ''
  });
  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await userService.updateProfile(formData);
      await refreshUser();
      setSuccess('Profile updated successfully!');
      setEditing(false);
    } catch (err: any) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };
  const handleLogout = async () => {
    try {
      await logout();
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };
  const getInitials = () => {
    const name = user?.display_name || user?.username || 'U';
    return name.charAt(0).toUpperCase();
  };
  if (!user) return null;
  return (
    <div className="container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h1>Profile</h1>
        <button className="btn btn-secondary" onClick={handleLogout} style={{ width: 'auto' }}>
          Sign Out
        </button>
      </div>
      <div className="profile-header">
        <div className="avatar">
          {getInitials()}
        </div>
        <div>
          <h2>{user.display_name || user.username || 'New User'}</h2>
          <p style={{ color: '#666', margin: 0 }}>
            Member since {new Date(user.created_at || Date.now()).toLocaleDateString()}
          </p>
        </div>
      </div>
      {!editing ? (
        <div style={{ background: 'white', padding: '30px', borderRadius: '12px', boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)' }}>
          <div className="form-group">
            <label>Username</label>
            <p>{user.username || 'Not set'}</p>
          </div>
          <div className="form-group">
            <label>Email</label>
            <p>{user.email || 'Not set'}</p>
          </div>
          <div className="form-group">
            <label>Display Name</label>
            <p>{user.display_name || 'Not set'}</p>
          </div>
          <div className="form-group">
            <label>Bio</label>
            <p>{user.bio || 'Not set'}</p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn" onClick={() => setEditing(true)}>
              Edit Profile
            </button>
            <button 
              className="btn btn-secondary" 
              onClick={() => navigate('/security')}
              style={{ width: 'auto' }}
            >
              Security Settings
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} style={{ background: 'white', padding: '30px', borderRadius: '12px', boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)' }}>
          <ErrorAlert 
            error={error} 
            onRetry={() => handleSubmit({ preventDefault: () => {} } as React.FormEvent)}
            showRetry={!loading}
          />
          {success && <div className="success-message">{success}</div>}
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="Choose a unique username"
            />
          </div>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="your@email.com"
            />
          </div>
          <div className="form-group">
            <label htmlFor="display_name">Display Name</label>
            <input
              type="text"
              id="display_name"
              name="display_name"
              value={formData.display_name}
              onChange={handleChange}
              placeholder="How should we address you?"
            />
          </div>
          <div className="form-group">
            <label htmlFor="bio">Bio</label>
            <textarea
              id="bio"
              name="bio"
              value={formData.bio}
              onChange={handleChange}
              rows={4}
              placeholder="Tell us about yourself..."
            />
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="submit" className="btn" disabled={loading}>
              {loading ? <span className="loading"></span> : 'Save Changes'}
            </button>
            <button 
              type="button" 
              className="btn btn-secondary" 
              onClick={() => {
                setEditing(false);
                setError('');
                setSuccess('');
                setFormData({
                  username: user.username || '',
                  email: user.email || '',
                  display_name: user.display_name || '',
                  bio: user.bio || ''
                });
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
};