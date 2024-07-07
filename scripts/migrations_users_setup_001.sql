-- Create users table
CREATE TABLE users
(
	id            UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	username      VARCHAR(50)  NOT NULL UNIQUE,
	email         VARCHAR(255) NOT NULL UNIQUE,
	password_hash VARCHAR(255) NOT NULL,
	name          VARCHAR(100),
	about         TEXT,
	created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	verified      BOOLEAN
);

-- Create reset_codes table
CREATE TABLE reset_codes
(
	email      VARCHAR(255) PRIMARY KEY,
	code       VARCHAR(8)               NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE refresh_tokens
(
	token      VARCHAR(255) PRIMARY KEY,
	user_id    UUID                     NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE email_verifications
(
	email      VARCHAR(255) PRIMARY KEY,
	code       VARCHAR(6)               NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

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