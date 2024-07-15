-- Create users tables

CREATE TABLE users
(
	id                   UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	username             VARCHAR(50) UNIQUE  NOT NULL,
	email                VARCHAR(255) UNIQUE NOT NULL,
	password_hash        VARCHAR(255)        NOT NULL,
	bio                  TEXT,
	current_avatar_url   VARCHAR(255),
	is_verified          BOOLEAN                  DEFAULT FALSE,
	last_login           TIMESTAMP WITH TIME ZONE,
	created_at           TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	updated_at           TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	account_status       VARCHAR(20)              DEFAULT 'active' CHECK (account_status IN ('active', 'suspended', 'deactivated')),
	two_factor_enabled   BOOLEAN                  DEFAULT FALSE,
	last_password_change TIMESTAMP WITH TIME ZONE
);

-- Avatar history table
CREATE TABLE user_avatars_history
(
	id         SERIAL PRIMARY KEY,
	user_id    UUID         NOT NULL REFERENCES users (id),
	avatar_url VARCHAR(255) NOT NULL,
	changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create reset_codes table
CREATE TABLE reset_codes
(
	user_id    UUID                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	code       VARCHAR(8)               NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	used       BOOLEAN DEFAULT FALSE,
	PRIMARY KEY (user_id, code)
);

-- Create email_verifications table
CREATE TABLE email_verifications
(
	user_id    UUID                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	code       VARCHAR(8)               NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	used       BOOLEAN DEFAULT FALSE,
	PRIMARY KEY (user_id, code)
);

-- Create a new table for user roles
CREATE TABLE user_roles
(
	user_id UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	role    VARCHAR(20) NOT NULL CHECK (role IN ('user', 'moderator', 'admin')),
	PRIMARY KEY (user_id, role)
);

-- Create a new table for login attempts
CREATE TABLE login_attempts
(
	id           SERIAL PRIMARY KEY,
	user_id      UUID REFERENCES users (id) ON DELETE CASCADE,
	ip_address   INET    NOT NULL,
	attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	success      BOOLEAN NOT NULL
);

-- Add new tables for sessions and devices

-- Create sessions table
CREATE TABLE sessions
(
	id          UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	user_id     UUID                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	device_info TEXT                     NOT NULL,
	ip_address  TEXT                     NOT NULL,
	created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens
(
	token       VARCHAR(255) PRIMARY KEY,
	user_id     UUID                     NOT NULL,
	created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
	device_info TEXT,
	session_id  UUID REFERENCES sessions (id) ON DELETE CASCADE
);

-- Create devices table
CREATE TYPE device_os AS ENUM ('iOS', 'Android', 'Windows', 'MacOs', 'Web');

CREATE TABLE devices
(
	id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	name    VARCHAR(100) NOT NULL,
	token   TEXT         NOT NULL,
	os      device_os    NOT NULL
);

-- Add a check constraint to ensure email format
ALTER TABLE users
	ADD CONSTRAINT check_email_format CHECK (email ~* '^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$');

-- Indexes for users table
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_verified ON users (is_verified);

-- Indexes for email_verifications table
CREATE INDEX idx_email_verifications_expires_at ON email_verifications (expires_at);

-- Indexes for refresh_tokens table
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Indexes for reset_codes table
CREATE INDEX idx_reset_codes_created_at ON reset_codes (created_at);

CREATE INDEX idx_users_last_login ON users (last_login);
CREATE INDEX idx_users_account_status ON users (account_status);
CREATE INDEX idx_login_attempts_user_id ON login_attempts (user_id);
CREATE INDEX idx_login_attempts_ip_address ON login_attempts (ip_address);
CREATE INDEX idx_login_attempts_attempt_time ON login_attempts (attempt_time);

-- Add indexes for sessions table
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

-- Add indexes for devices table
CREATE INDEX idx_devices_user_id ON devices (user_id);
CREATE INDEX idx_devices_token ON devices (token);

CREATE INDEX idx_user_avatars_history_user_id ON user_avatars_history (user_id);

-- -- Create a trigger to clean up expired sessions periodically
-- CREATE
-- EXTENSION
-- IF NOT EXISTS pg_cron;
--
-- SELECT cron.schedule('cleanup_expired_sessions', '0 */1 * * *', 'SELECT cleanup_expired_sessions()');

-- Modify existing tables if necessary

-- Create a function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
	RETURNS void AS
	$$
BEGIN
	DELETE
	FROM sessions
	WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$
	LANGUAGE plpgsql;

-- -- Create a trigger to clean up expired sessions periodically
-- CREATE
-- EXTENSION
-- IF NOT EXISTS pg_cron;
--
-- SELECT cron.schedule('cleanup_expired_sessions', '0 */1 * * *', 'SELECT cleanup_expired_sessions()');

-- Add a trigger to delete associated refresh tokens when a session is deleted
CREATE OR REPLACE FUNCTION delete_associated_refresh_tokens()
	RETURNS TRIGGER AS
	$$
BEGIN
	DELETE
	FROM refresh_tokens
	WHERE session_id = OLD.id;
	RETURN OLD;
END;
$$
	LANGUAGE plpgsql;

CREATE TRIGGER delete_session_refresh_tokens
	BEFORE DELETE
	ON sessions
	FOR EACH ROW
	EXECUTE FUNCTION delete_associated_refresh_tokens();

-- Update the update_last_login function to also update the sessions table
CREATE OR REPLACE FUNCTION update_last_login()
	RETURNS TRIGGER AS
	$$
BEGIN
	UPDATE users
	SET last_login = NEW.attempt_time
	WHERE id = NEW.user_id;
-- Update the expiration time of the associated session
	UPDATE sessions
	SET expires_at = NEW.attempt_time + INTERVAL '7 days'
	WHERE user_id = NEW.user_id
	  AND ip_address = NEW.ip_address;
	RETURN NEW;
END;
$$
	LANGUAGE plpgsql;

-- Ensure the trigger is updated
DROP TRIGGER IF EXISTS update_last_login_trigger ON login_attempts;
CREATE TRIGGER update_last_login_trigger
	AFTER INSERT
	ON login_attempts
	FOR EACH ROW
	WHEN (NEW.success = TRUE)
	EXECUTE FUNCTION update_last_login();

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
BEGIN
	NEW.updated_at = CURRENT_TIMESTAMP;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update the updated_at column
CREATE TRIGGER update_users_updated_at
	BEFORE UPDATE
	ON users
	FOR EACH ROW
	EXECUTE FUNCTION update_updated_at_column();

-- Function to add a new avatar to history and update current avatar
CREATE OR REPLACE FUNCTION update_user_avatar(p_user_id UUID, p_new_avatar_url VARCHAR(255))
	RETURNS VOID AS $$
BEGIN
	-- Insert the new avatar into the history
	INSERT INTO user_avatars_history (user_id, avatar_url)
	VALUES (p_user_id, p_new_avatar_url);

	-- Update the current avatar in the users table
	UPDATE users
	SET current_avatar_url = p_new_avatar_url,
		updated_at         = CURRENT_TIMESTAMP
	WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get user's avatar history
CREATE OR REPLACE FUNCTION get_user_avatar_history(p_user_id UUID)
	RETURNS TABLE
			(
				avatar_url VARCHAR(255),
				changed_at TIMESTAMP WITH TIME ZONE
			) AS $$
BEGIN
	RETURN QUERY
	SELECT uah.avatar_url, uah.changed_at
	FROM user_avatars_history uah
	WHERE uah.user_id = p_user_id
	ORDER BY uah.changed_at DESC;
END;
$$ LANGUAGE plpgsql;
