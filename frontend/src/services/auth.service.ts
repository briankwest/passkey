import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import api from './api';
import { AuthResponse } from '../types';

export class AuthService {
  async register(): Promise<AuthResponse> {
    try {
      // Get registration options from server
      const { data: options } = await api.post('/auth/register/options');
      
      // Start WebAuthn registration
      const credential = await startRegistration(options);
      
      // Verify with server
      const { data } = await api.post<AuthResponse>('/auth/register/verify', {
        credential
      });
      
      // Store token
      if (data.token) {
        localStorage.setItem('token', data.token);
      }
      
      return data;
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        throw new Error('Registration was cancelled or not allowed');
      }
      throw error;
    }
  }

  async authenticate(): Promise<AuthResponse> {
    try {
      // Get authentication options
      const { data: options } = await api.post('/auth/authenticate/options');
      
      // Start WebAuthn authentication
      const credential = await startAuthentication(options);
      
      // Verify with server
      const { data } = await api.post<AuthResponse>('/auth/authenticate/verify', {
        credential
      });
      
      // Store token
      if (data.token) {
        localStorage.setItem('token', data.token);
      }
      
      return data;
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        throw new Error('Authentication was cancelled or not allowed');
      }
      throw error;
    }
  }

  async logout(): Promise<void> {
    await api.post('/auth/logout');
    localStorage.removeItem('token');
  }

  isAuthenticated(): boolean {
    return !!localStorage.getItem('token');
  }
}

export default new AuthService();