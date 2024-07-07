-- Indexes for users table
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_verified ON users (verified);

-- Indexes for email_verifications table
CREATE INDEX idx_email_verifications_expires_at ON email_verifications (expires_at);

-- Indexes for refresh_tokens table
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Indexes for reset_codes table
CREATE INDEX idx_reset_codes_created_at ON reset_codes (created_at);