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
