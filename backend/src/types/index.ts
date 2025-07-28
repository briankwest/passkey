export interface User {
  id: string;
  username?: string;
  email?: string;
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  created_at: Date;
  updated_at: Date;
}

export interface Passkey {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  device_type?: string;
  transports?: string[];
  backed_up: boolean;
  authenticator_attachment?: string;
  created_at: Date;
  last_used?: Date;
  credential_device_type?: string;
  credential_backed_up: boolean;
}

export interface AuthChallenge {
  challenge: string;
  user_id?: string;
  type: 'registration' | 'authentication';
  created_at: Date;
  expires_at: Date;
}