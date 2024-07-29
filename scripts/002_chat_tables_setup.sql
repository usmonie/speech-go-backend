-- Complete Chat System SQL Setup

BEGIN;

-- Enum types
CREATE TYPE chat_type AS ENUM ('personal', 'private_group', 'public_group');
CREATE TYPE message_type AS ENUM ('text', 'voice', 'video_voice', 'image', 'video', 'audio', 'location', 'file', 'contact', 'service');
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'member');

-- Chats table (base table for all chat types)
CREATE TABLE chats
(
	chat_id       UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	chat_type     chat_type NOT NULL,
	created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	last_activity TIMESTAMP WITH TIME ZONE
);

-- Personal chats
CREATE TABLE personal_chats
(
	chat_id  UUID PRIMARY KEY REFERENCES chats (chat_id),
	user1_id UUID NOT NULL REFERENCES users (id),
	user2_id UUID NOT NULL REFERENCES users (id)
);

-- Group chats (base table for private and public groups)
CREATE TABLE group_chats
(
	chat_id    UUID PRIMARY KEY REFERENCES chats (chat_id),
	name       VARCHAR(255) NOT NULL,
	about      TEXT,
	avatar_url VARCHAR(255),
	owner_id   UUID         NOT NULL REFERENCES users (id)
);

-- Private group chats
CREATE TABLE private_group_chats
(
	chat_id UUID PRIMARY KEY REFERENCES group_chats (chat_id)
);

-- Public group chats
CREATE TABLE public_group_chats
(
	chat_id  UUID PRIMARY KEY REFERENCES group_chats (chat_id),
	username VARCHAR(50) UNIQUE NOT NULL
);

-- Group avatars history
CREATE TABLE group_avatars_history
(
	id            SERIAL PRIMARY KEY,
	group_chat_id UUID         NOT NULL REFERENCES group_chats (chat_id),
	avatar_url    VARCHAR(255) NOT NULL,
	changed_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Rooms in group chats
CREATE TABLE rooms
(
	room_id       UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	group_chat_id UUID        NOT NULL REFERENCES group_chats (chat_id),
	name          VARCHAR(50) NOT NULL,
	about         TEXT,
	avatar_url    VARCHAR(255),
	created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE messages
(
	message_id                UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	chat_id                   UUID         NOT NULL REFERENCES chats (chat_id),
	room_id                   UUID REFERENCES rooms (room_id),
	sender_id                 UUID         NOT NULL REFERENCES users (id),
	reply_to_message_id       UUID REFERENCES messages (message_id),
	forwarded_from_message_id UUID REFERENCES messages (message_id),
	message_type              message_type NOT NULL,
	content                   TEXT,
	sent_at                   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	edited_at                 TIMESTAMP WITH TIME ZONE,
	is_deleted                BOOLEAN                  DEFAULT FALSE,
	is_deleted_for_all        BOOLEAN                  DEFAULT FALSE,
	deletion_timestamp        TIMESTAMP WITH TIME ZONE
);

-- Create a new table for media attachments
CREATE TABLE media_attachments
(
	attachment_id UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	message_id    UUID         NOT NULL REFERENCES messages (message_id) ON DELETE CASCADE,
	media_type    VARCHAR(20)  NOT NULL,
	media_url     VARCHAR(255) NOT NULL,
	thumbnail_url VARCHAR(255),
	file_name     VARCHAR(255),
	file_size     BIGINT,
	duration      INTEGER, -- For audio/video files, in seconds
	width         INTEGER, -- For images/videos
	height        INTEGER, -- For images/videos
	created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Forwarded content table
CREATE TABLE forwarded_content
(
	id           SERIAL PRIMARY KEY,
	user_id      UUID NOT NULL REFERENCES users (id),
	message_id   UUID NOT NULL REFERENCES messages (message_id),
	forwarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Chat participants
CREATE TABLE chat_participants
(
	chat_id   UUID      NOT NULL REFERENCES chats (chat_id),
	user_id   UUID      NOT NULL REFERENCES users (id),
	role      user_role NOT NULL       DEFAULT 'member',
	joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	is_active BOOLEAN                  DEFAULT TRUE,
	PRIMARY KEY (chat_id, user_id)
);

-- Admin permissions
CREATE TABLE admin_permissions
(
	chat_id              UUID NOT NULL REFERENCES group_chats (chat_id),
	user_id              UUID NOT NULL REFERENCES users (id),
	can_change_info      BOOLEAN DEFAULT FALSE,
	can_delete_messages  BOOLEAN DEFAULT FALSE,
	can_ban_users        BOOLEAN DEFAULT FALSE,
	can_invite_users     BOOLEAN DEFAULT FALSE,
	can_pin_messages     BOOLEAN DEFAULT FALSE,
	can_remain_anonymous BOOLEAN DEFAULT FALSE,
	custom_title         VARCHAR(50),
	PRIMARY KEY (chat_id, user_id)
);

-- Invite links
CREATE TABLE invite_links
(
	invite_id  UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
	chat_id    UUID NOT NULL REFERENCES private_group_chats (chat_id),
	created_by UUID NOT NULL REFERENCES users (id),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP WITH TIME ZONE,
	is_active  BOOLEAN                  DEFAULT TRUE
);

-- User preferences
CREATE TABLE user_preferences
(
	user_id               UUID PRIMARY KEY REFERENCES users (id),
	notification_settings JSONB,
	theme                 VARCHAR(20),
	language              VARCHAR(10),
	time_zone             VARCHAR(50)
);

-- Deleted messages table
CREATE TABLE deleted_messages
(
	message_id   UUID PRIMARY KEY,
	chat_id      UUID         NOT NULL,
	room_id      UUID,
	sender_id    UUID         NOT NULL,
	message_type message_type NOT NULL,
	content      TEXT,
	media_url    VARCHAR(255),
	sent_at      TIMESTAMP WITH TIME ZONE,
	deleted_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	deleted_by   UUID         NOT NULL REFERENCES users (id)
);

-- Indexes
CREATE INDEX idx_messages_chat_id ON messages (chat_id);
CREATE INDEX idx_messages_sender_id ON messages (sender_id);
CREATE INDEX idx_messages_sent_at ON messages (sent_at);
CREATE INDEX idx_messages_type ON messages (message_type);
CREATE INDEX idx_media_attachments_message_id ON media_attachments (message_id);
CREATE INDEX idx_forwarded_content_user_id ON forwarded_content (user_id);
CREATE INDEX idx_chat_participants_chat_id ON chat_participants (chat_id);
CREATE INDEX idx_chat_participants_user_id ON chat_participants (user_id);
CREATE INDEX idx_admin_permissions_chat_id ON admin_permissions (chat_id);
CREATE INDEX idx_invite_links_chat_id ON invite_links (chat_id);
CREATE INDEX idx_rooms_group_chat_id ON rooms (group_chat_id);
CREATE INDEX idx_deleted_messages_deleted_at ON deleted_messages (deleted_at);

-- Functions and Triggers

-- Function to update last_activity in chats table
CREATE
OR REPLACE FUNCTION update_chat_last_activity()
RETURNS TRIGGER AS $$
BEGIN
UPDATE chats
SET last_activity = NEW.sent_at
WHERE chat_id = NEW.chat_id;
RETURN NEW;
END;
$$
LANGUAGE plpgsql;

-- Trigger to update last_activity when a new message is inserted
CREATE TRIGGER update_chat_last_activity_trigger
	AFTER INSERT
	ON messages
	FOR EACH ROW
	EXECUTE FUNCTION update_chat_last_activity();

-- Function to ensure chat participants are valid
CREATE
OR REPLACE FUNCTION validate_chat_participant()
RETURNS TRIGGER AS $$
BEGIN
    IF
NOT EXISTS (
        SELECT 1 FROM chats WHERE chat_id = NEW.chat_id
    ) THEN
        RAISE EXCEPTION 'Invalid chat_id';
END IF;

    IF
NOT EXISTS (
        SELECT 1 FROM users WHERE user_id = NEW.user_id
    ) THEN
        RAISE EXCEPTION 'Invalid user_id';
END IF;

RETURN NEW;
END;
$$
LANGUAGE plpgsql;

-- Trigger to validate chat participants before insertion
CREATE TRIGGER validate_chat_participant_trigger
	BEFORE INSERT
	ON chat_participants
	FOR EACH ROW
	EXECUTE FUNCTION validate_chat_participant();

-- Function to move a message to deleted_messages and remove it from messages
-- Modify the delete_message_for_all() function to handle media attachments
CREATE
OR REPLACE FUNCTION delete_message_for_all()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert into deleted_messages
INSERT INTO deleted_messages (message_id, chat_id, room_id, sender_id, message_type,
							  content, sent_at, deleted_by)
VALUES (OLD.message_id, OLD.chat_id, OLD.room_id, OLD.sender_id, OLD.message_type,
		OLD.content, OLD.sent_at, NEW.deleted_by);

-- Remove media attachments
DELETE
FROM media_attachments
WHERE message_id = OLD.message_id;

-- Remove from messages
DELETE
FROM messages
WHERE message_id = OLD.message_id;

RETURN OLD;
END;
$$
LANGUAGE plpgsql;


-- Trigger to handle message deletion for all
CREATE TRIGGER delete_message_for_all_trigger
	AFTER UPDATE OF is_deleted_for_all
	ON messages
	FOR EACH ROW
	WHEN (NEW.is_deleted_for_all = TRUE)
	EXECUTE FUNCTION delete_message_for_all();

-- Function to permanently delete messages after a certain time period
CREATE
OR REPLACE FUNCTION permanently_delete_old_messages()
RETURNS void AS $$
BEGIN
    -- Delete messages that have been in deleted_messages for more than 30 days
DELETE
FROM deleted_messages
WHERE deleted_at < CURRENT_TIMESTAMP - INTERVAL '30 days';
END;
$$
LANGUAGE plpgsql;

-- Function to check if a user has permission to delete a message for all
CREATE
OR REPLACE FUNCTION can_delete_message_for_all(p_user_id UUID, p_message_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
v_chat_id UUID;
    v_sender_id
UUID;
    v_user_role
user_role;
    v_can_delete_messages
BOOLEAN;
BEGIN
    -- Get chat_id and sender_id of the message
SELECT chat_id, sender_id
INTO v_chat_id, v_sender_id
FROM messages
WHERE message_id = p_message_id;

-- Check if the user is the sender
IF
v_sender_id = p_user_id THEN
        RETURN TRUE;
END IF;

    -- Get user's role and permissions in the chat
SELECT role, can_delete_messages
INTO v_user_role, v_can_delete_messages
FROM chat_participants
		 LEFT JOIN admin_permissions USING (chat_id, user_id)
WHERE chat_id = v_chat_id
  AND user_id = p_user_id;

-- Check if user is an admin with delete permission or the owner
RETURN (v_user_role = 'admin' AND v_can_delete_messages) OR v_user_role = 'owner';
END;
$$
LANGUAGE plpgsql;

COMMIT;

-- Note: To set up scheduled deletion of old messages, you need to set up a cron job or use pg_cron extension
-- Example using pg_cron (uncomment if pg_cron is available):
-- CREATE
-- EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('nightly-vacuum', '0 10 * * *', $$SELECT permanently_delete_old_messages()$$);
