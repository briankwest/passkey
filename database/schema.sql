-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE,
    email VARCHAR(255),
    display_name VARCHAR(255),
    avatar_url TEXT,
    bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create passkeys table (WebAuthn credentials)
CREATE TABLE IF NOT EXISTS passkeys (
    id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    device_type VARCHAR(255),
    transports TEXT[],
    backed_up BOOLEAN DEFAULT false,
    authenticator_attachment VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    credential_device_type VARCHAR(50),
    credential_backed_up BOOLEAN DEFAULT false
);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    sid VARCHAR PRIMARY KEY,
    sess JSON NOT NULL,
    expire TIMESTAMP NOT NULL
);

-- Create authentication challenges table (for WebAuthn flow)
CREATE TABLE IF NOT EXISTS authentication_challenges (
    challenge VARCHAR(255) PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- 'registration' or 'authentication'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires ON authentication_challenges(expires_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();