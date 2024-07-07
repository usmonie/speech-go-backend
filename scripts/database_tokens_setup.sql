CREATE TABLE refresh_tokens
(
	token      VARCHAR(255) PRIMARY KEY,
	user_id    UUID                     NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);