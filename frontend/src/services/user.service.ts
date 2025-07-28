import api from './api';
import { User } from '../types';

export class UserService {
  async getProfile(): Promise<User> {
    const { data } = await api.get<User>('/user/profile');
    return data;
  }

  async updateProfile(profile: Partial<User>): Promise<User> {
    const { data } = await api.put<User>('/user/profile', profile);
    return data;
  }
}

export default new UserService();