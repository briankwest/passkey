export interface User {
  id: string;
  username?: string;
  email?: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  created_at?: string;
}

export interface AuthResponse {
  verified: boolean;
  user: User;
  token: string;
}