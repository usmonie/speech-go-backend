CREATE TABLE email_verifications
(
	email      VARCHAR(255) PRIMARY KEY,
	code       VARCHAR(6)               NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);