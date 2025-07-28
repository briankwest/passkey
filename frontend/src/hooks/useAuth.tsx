import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import authService from '../services/auth.service';
import userService from '../services/user.service';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: () => Promise<void>;
  register: () => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadUser();
  }, []);

  const loadUser = async () => {
    try {
      if (authService.isAuthenticated()) {
        const userData = await userService.getProfile();
        setUser(userData);
      }
    } catch (error) {
      console.error('Failed to load user:', error);
      localStorage.removeItem('token');
    } finally {
      setLoading(false);
    }
  };

  const login = async () => {
    const response = await authService.authenticate();
    setUser(response.user);
  };

  const register = async () => {
    const response = await authService.register();
    setUser(response.user);
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  const refreshUser = async () => {
    const userData = await userService.getProfile();
    setUser(userData);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};