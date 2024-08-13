-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create chats table
CREATE TABLE chats
(
    id             UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    type           VARCHAR(10) NOT NULL CHECK (type IN ('direct', 'group')),
    name           VARCHAR(100),
    group_type     VARCHAR(10) CHECK (group_type IN ('public', 'private')),
    group_username VARCHAR(50) UNIQUE,
    created_at     TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create chat_participants table
CREATE TABLE chat_participants
(
    chat_id   UUID NOT NULL REFERENCES chats (id) ON DELETE CASCADE,
    user_id   UUID NOT NULL, -- Assuming users table exists
    role      VARCHAR(20)              DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chat_id, user_id)
);

-- Create messages table
CREATE TABLE messages
(
    id                    UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    chat_id               UUID    NOT NULL REFERENCES chats (id) ON DELETE CASCADE,
    sender_id             UUID    NOT NULL, -- Assuming users table exists
    encrypted_content     BYTEA   NOT NULL,
    signature             BYTEA   NOT NULL,
    ratchet_public_key    BYTEA,
    message_number        INTEGER NOT NULL,
    previous_chain_length INTEGER,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create message_status table
CREATE TABLE message_status
(
    message_id UUID        NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL, -- Assuming users table exists
    status     VARCHAR(10) NOT NULL CHECK (status IN ('sent', 'delivered', 'read')),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id, user_id)
);

-- Create replies table
CREATE TABLE replies
(
    reply_message_id    UUID NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    original_message_id UUID NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    PRIMARY KEY (reply_message_id, original_message_id)
);

-- Create pinned_messages table
CREATE TABLE pinned_messages
(
    chat_id    UUID NOT NULL REFERENCES chats (id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    pinned_by  UUID NOT NULL, -- Assuming users table exists
    pinned_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chat_id, message_id)
);

-- Create chat_invitations table
CREATE TABLE chat_invitations
(
    id              UUID PRIMARY KEY                                                        DEFAULT gen_random_uuid(),
    chat_id         UUID               NOT NULL REFERENCES chats (id) ON DELETE CASCADE,
    created_by      UUID               NOT NULL, -- Assuming users table exists
    invitation_code VARCHAR(50) UNIQUE NOT NULL,
    invitation_type VARCHAR(10)        NOT NULL CHECK (invitation_type IN ('link', 'code')) DEFAULT 'code',
    expiration_date TIMESTAMP WITH TIME ZONE,
    is_used         BOOLEAN                                                                 DEFAULT FALSE,
    created_at      TIMESTAMP WITH TIME ZONE                                                DEFAULT CURRENT_TIMESTAMP
);

-- Create custom_roles table
CREATE TABLE custom_roles
(
    id          UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    chat_id     UUID        NOT NULL REFERENCES chats (id) ON DELETE CASCADE,
    name        VARCHAR(50) NOT NULL,
    permissions JSONB       NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (chat_id, name)
);

-- Create indexes
CREATE INDEX idx_messages_chat_id ON messages (chat_id);
CREATE INDEX idx_messages_sender_id ON messages (sender_id);
CREATE INDEX idx_messages_created_at ON messages (created_at);
CREATE INDEX idx_chat_participants_user_id ON chat_participants (user_id);
CREATE INDEX idx_message_status_user_id ON message_status (user_id);
CREATE INDEX idx_chat_invitations_chat_id ON chat_invitations (chat_id);
CREATE INDEX idx_custom_roles_chat_id ON custom_roles (chat_id);
CREATE UNIQUE INDEX idx_chats_group_username ON chats (group_username) WHERE group_username IS NOT NULL;
CREATE INDEX idx_messages_message_number ON messages (message_number);
CREATE INDEX idx_chat_invitations_created_at ON chat_invitations (created_at);
CREATE INDEX idx_chat_participants_composite ON chat_participants (chat_id, user_id, role);
CREATE INDEX idx_message_status_composite ON message_status (message_id, user_id, status);

-- Functions

-- Function to update the updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to generate a unique group username
CREATE OR REPLACE FUNCTION generate_unique_group_username(base_name VARCHAR(50))
    RETURNS VARCHAR(50) AS
$$
DECLARE
    new_username VARCHAR(50);
    counter      INTEGER := 0;
BEGIN
    new_username := base_name;
    WHILE EXISTS (SELECT 1 FROM chats WHERE group_username = new_username)
        LOOP
            counter := counter + 1;
            new_username := base_name || counter::TEXT;
        END LOOP;
    RETURN new_username;
END;
$$ LANGUAGE plpgsql;

-- Function to create a public group
CREATE OR REPLACE FUNCTION create_public_group(
    p_creator_id UUID,
    p_group_name VARCHAR(100),
    p_group_username VARCHAR(50)
)
    RETURNS UUID AS
$$
DECLARE
    new_group_id    UUID;
    unique_username VARCHAR(50);
BEGIN
    unique_username := generate_unique_group_username(p_group_username);

    INSERT INTO chats (type, name, group_type, group_username)
    VALUES ('group', p_group_name, 'public', unique_username)
    RETURNING id INTO new_group_id;

    INSERT INTO chat_participants (chat_id, user_id, role)
    VALUES (new_group_id, p_creator_id, 'admin');

    RETURN new_group_id;
END;
$$ LANGUAGE plpgsql;

-- Function to create a private group
CREATE OR REPLACE FUNCTION create_private_group(
    p_creator_id UUID,
    p_group_name VARCHAR(100)
)
    RETURNS UUID AS
$$
DECLARE
    new_group_id UUID;
BEGIN
    INSERT INTO chats (type, name, group_type)
    VALUES ('group', p_group_name, 'private')
    RETURNING id INTO new_group_id;

    INSERT INTO chat_participants (chat_id, user_id, role)
    VALUES (new_group_id, p_creator_id, 'admin');

    RETURN new_group_id;
END;
$$ LANGUAGE plpgsql;

-- Function to generate an invitation link for a private group
CREATE OR REPLACE FUNCTION generate_private_group_invitation(
    p_group_id UUID,
    p_creator_id UUID,
    p_expiration_date TIMESTAMP WITH TIME ZONE DEFAULT NULL
)
    RETURNS VARCHAR(50) AS
$$
DECLARE
    invitation_code VARCHAR(50);
BEGIN
    invitation_code := encode(gen_random_bytes(24), 'base64');

    INSERT INTO chat_invitations (chat_id, created_by, invitation_code, expiration_date, invitation_type)
    VALUES (p_group_id, p_creator_id, invitation_code, p_expiration_date, 'link');

    RETURN invitation_code;
END;
$$ LANGUAGE plpgsql;

-- Function to join a public group by username
CREATE OR REPLACE FUNCTION join_public_group_by_username(
    p_user_id UUID,
    p_group_username VARCHAR(50)
)
    RETURNS BOOLEAN AS
$$
DECLARE
    group_id UUID;
BEGIN
    SELECT id
    INTO group_id
    FROM chats
    WHERE group_username = p_group_username
      AND group_type = 'public';

    IF group_id IS NOT NULL THEN
        INSERT INTO chat_participants (chat_id, user_id, role)
        VALUES (group_id, p_user_id, 'member')
        ON CONFLICT (chat_id, user_id) DO NOTHING;
        RETURN TRUE;
    ELSE
        RETURN FALSE;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to join a private group by invitation
CREATE OR REPLACE FUNCTION join_private_group_by_invitation(
    p_user_id UUID,
    p_invitation_code VARCHAR(50)
)
    RETURNS BOOLEAN AS
$$
DECLARE
    group_id UUID;
BEGIN
    SELECT chat_id
    INTO group_id
    FROM chat_invitations
    WHERE invitation_code = p_invitation_code
      AND invitation_type = 'link'
      AND (expiration_date IS NULL OR expiration_date > CURRENT_TIMESTAMP)
      AND is_used = FALSE;

    IF group_id IS NOT NULL THEN
        INSERT INTO chat_participants (chat_id, user_id, role)
        VALUES (group_id, p_user_id, 'member')
        ON CONFLICT (chat_id, user_id) DO NOTHING;

        UPDATE chat_invitations
        SET is_used = TRUE
        WHERE invitation_code = p_invitation_code;

        RETURN TRUE;
    ELSE
        RETURN FALSE;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to check if a user is a member of a group
CREATE OR REPLACE FUNCTION is_user_in_group(
    p_user_id UUID,
    p_group_id UUID
)
    RETURNS BOOLEAN AS
$$
BEGIN
    RETURN EXISTS (SELECT 1
                   FROM chat_participants
                   WHERE user_id = p_user_id
                     AND chat_id = p_group_id);
END;
$$ LANGUAGE plpgsql;

-- Function to get group information
CREATE OR REPLACE FUNCTION get_group_info(
    p_group_id UUID
)
    RETURNS TABLE
            (
                id             UUID,
                name           VARCHAR(100),
                group_type     VARCHAR(10),
                group_username VARCHAR(50),
                created_at     TIMESTAMP WITH TIME ZONE,
                updated_at     TIMESTAMP WITH TIME ZONE,
                member_count   BIGINT
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT c.id,
               c.name,
               c.group_type,
               c.group_username,
               c.created_at,
               c.updated_at,
               (SELECT COUNT(*) FROM chat_participants WHERE chat_id = c.id) AS member_count
        FROM chats c
        WHERE c.id = p_group_id
          AND c.type = 'group';
END;
$$ LANGUAGE plpgsql;

-- Function to get chat messages
CREATE OR REPLACE FUNCTION get_chat_messages(
    p_chat_id UUID,
    p_last_message_id UUID,
    p_limit INTEGER
)
    RETURNS TABLE
            (
                id                UUID,
                sender_id         UUID,
                encrypted_content BYTEA,
                signature         BYTEA,
                message_number    INTEGER,
                created_at        TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT m.id, m.sender_id, m.encrypted_content, m.signature, m.message_number, m.created_at
        FROM messages m
        WHERE m.chat_id = p_chat_id
          AND (p_last_message_id IS NULL OR
               m.created_at < (SELECT created_at FROM messages WHERE id = p_last_message_id))
        ORDER BY m.created_at DESC
        LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- Function to add a user to a chat
CREATE OR REPLACE FUNCTION add_user_to_chat(
    p_chat_id UUID,
    p_user_id UUID,
    p_role VARCHAR(20) DEFAULT 'member'
)
    RETURNS VOID AS
$$
BEGIN
    INSERT INTO chat_participants (chat_id, user_id, role)
    VALUES (p_chat_id, p_user_id, p_role)
    ON CONFLICT (chat_id, user_id) DO UPDATE
        SET role = EXCLUDED.role;
END;
$$ LANGUAGE plpgsql;

-- Function to remove a user from a chat
CREATE OR REPLACE FUNCTION remove_user_from_chat(
    p_chat_id UUID,
    p_user_id UUID
)
    RETURNS VOID AS
$$
BEGIN
    DELETE
    FROM chat_participants
    WHERE chat_id = p_chat_id
      AND user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function to update message status
CREATE OR REPLACE FUNCTION update_message_status(
    p_message_id UUID,
    p_user_id UUID,
    p_status VARCHAR(10)
)
    RETURNS VOID AS
$$
BEGIN
    INSERT INTO message_status (message_id, user_id, status)
    VALUES (p_message_id, p_user_id, p_status)
    ON CONFLICT (message_id, user_id) DO UPDATE
        SET status     = EXCLUDED.status,
            updated_at = CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Function to pin a message
CREATE OR REPLACE FUNCTION pin_message(
    p_chat_id UUID,
    p_message_id UUID,
    p_user_id UUID
)
    RETURNS VOID AS
$$
BEGIN
    INSERT INTO pinned_messages (chat_id, message_id, pinned_by)
    VALUES (p_chat_id, p_message_id, p_user_id)
    ON CONFLICT (chat_id, message_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Function to unpin a message
CREATE OR REPLACE FUNCTION unpin_message(
    p_chat_id UUID,
    p_message_id UUID
)
    RETURNS VOID AS
$$
BEGIN
    DELETE
    FROM pinned_messages
    WHERE chat_id = p_chat_id
      AND message_id = p_message_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get or create a direct chat between two users
CREATE OR REPLACE FUNCTION get_or_create_direct_chat(user1_id UUID, user2_id UUID)
    RETURNS UUID AS
$$
DECLARE
    chat_id UUID;
BEGIN
    -- Try to find an existing direct chat
    SELECT c.id
    INTO chat_id
    FROM chats c
             JOIN chat_participants cp1 ON c.id = cp1.chat_id
             JOIN chat_participants cp2 ON c.id = cp2.chat_id
    WHERE c.type = 'direct'
      AND ((cp1.user_id = user1_id AND cp2.user_id = user2_id)
        OR (cp1.user_id = user2_id AND cp2.user_id = user1_id));

    -- If no chat exists, create a new one
    IF chat_id IS NULL THEN
        INSERT INTO chats (type, name) VALUES ('direct', NULL) RETURNING id INTO chat_id;
        INSERT INTO chat_participants (chat_id, user_id) VALUES (chat_id, user1_id), (chat_id, user2_id);
    END IF;

    RETURN chat_id;
END;
$$ LANGUAGE plpgsql;

-- Triggers

-- Trigger to update the 'updated_at' column for chats
CREATE TRIGGER update_chats_updated_at
    BEFORE UPDATE
    ON chats
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Trigger to ensure that only group chats can have a group_type and group_username
CREATE OR REPLACE FUNCTION check_group_chat_properties()
    RETURNS TRIGGER AS
$$
BEGIN
    IF NEW.type = 'direct' AND (NEW.group_type IS NOT NULL OR NEW.group_username IS NOT NULL) THEN
        RAISE EXCEPTION 'Direct chats cannot have group properties';
    END IF;
    IF NEW.type = 'group' AND NEW.group_type IS NULL THEN
        RAISE EXCEPTION 'Group chats must have a group type';
    END IF;
    IF NEW.group_type = 'public' AND NEW.group_username IS NULL THEN
        RAISE EXCEPTION 'Public groups must have a username';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_chat_properties
    BEFORE INSERT OR UPDATE
    ON chats
    FOR EACH ROW
EXECUTE FUNCTION check_group_chat_properties();

-- Trigger to ensure that direct chats have exactly two participants
CREATE OR REPLACE FUNCTION check_direct_chat_participants()
    RETURNS TRIGGER AS
$$
DECLARE
    participant_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO participant_count
    FROM chat_participants
    WHERE chat_id = NEW.chat_id;

    IF (SELECT type FROM chats WHERE id = NEW.chat_id) = 'direct' AND participant_count >= 2 THEN
        RAISE EXCEPTION 'Direct chats can have at most two participants';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_direct_chat_participants
    AFTER INSERT OR UPDATE
    ON chat_participants
    FOR EACH ROW
EXECUTE FUNCTION check_direct_chat_participants();

-- Additional constraints

-- Ensure that public groups always have a username
ALTER TABLE chats
    ADD CONSTRAINT check_public_group_username
        CHECK (
            (group_type = 'public' AND group_username IS NOT NULL) OR
            (group_type != 'public')
            );

-- Ensure that only group chats can have a group_type and group_username
ALTER TABLE chats
    ADD CONSTRAINT check_group_type
        CHECK (
            (type = 'group' AND group_type IS NOT NULL) OR
            (type = 'direct' AND group_type IS NULL AND group_username IS NULL)
            );

-- Additional utility functions

-- Function to get chat participants
CREATE OR REPLACE FUNCTION get_chat_participants(p_chat_id UUID)
    RETURNS TABLE
            (
                user_id   UUID,
                role      VARCHAR(20),
                joined_at TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT cp.user_id, cp.role, cp.joined_at
        FROM chat_participants cp
        WHERE cp.chat_id = p_chat_id
        ORDER BY cp.joined_at;
END;
$$ LANGUAGE plpgsql;

-- Function to get pinned messages for a chat
CREATE OR REPLACE FUNCTION get_pinned_messages(p_chat_id UUID)
    RETURNS TABLE
            (
                message_id        UUID,
                sender_id         UUID,
                encrypted_content BYTEA,
                created_at        TIMESTAMP WITH TIME ZONE,
                pinned_by         UUID,
                pinned_at         TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT m.id, m.sender_id, m.encrypted_content, m.created_at, pm.pinned_by, pm.pinned_at
        FROM pinned_messages pm
                 JOIN messages m ON pm.message_id = m.id
        WHERE pm.chat_id = p_chat_id
        ORDER BY pm.pinned_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get chat invitations for a group
CREATE OR REPLACE FUNCTION get_chat_invitations(p_chat_id UUID)
    RETURNS TABLE
            (
                invitation_id   UUID,
                created_by      UUID,
                invitation_code VARCHAR(50),
                invitation_type VARCHAR(10),
                expiration_date TIMESTAMP WITH TIME ZONE,
                is_used         BOOLEAN,
                created_at      TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT id, created_by, invitation_code, invitation_type, expiration_date, is_used, created_at
        FROM chat_invitations
        WHERE chat_id = p_chat_id
        ORDER BY created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get custom roles for a chat
CREATE OR REPLACE FUNCTION get_custom_roles(p_chat_id UUID)
    RETURNS TABLE
            (
                role_id     UUID,
                name        VARCHAR(50),
                permissions JSONB,
                created_at  TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT id, name, permissions, created_at
        FROM custom_roles
        WHERE chat_id = p_chat_id
        ORDER BY created_at;
END;
$$ LANGUAGE plpgsql;

-- Function to add a custom role to a chat
CREATE OR REPLACE FUNCTION add_custom_role(
    p_chat_id UUID,
    p_role_name VARCHAR(50),
    p_permissions JSONB
)
    RETURNS UUID AS
$$
DECLARE
    new_role_id UUID;
BEGIN
    INSERT INTO custom_roles (chat_id, name, permissions)
    VALUES (p_chat_id, p_role_name, p_permissions)
    RETURNING id INTO new_role_id;

    RETURN new_role_id;
END;
$$ LANGUAGE plpgsql;

-- Function to update a custom role
CREATE OR REPLACE FUNCTION update_custom_role(
    p_role_id UUID,
    p_new_name VARCHAR(50),
    p_new_permissions JSONB
)
    RETURNS VOID AS
$$
BEGIN
    UPDATE custom_roles
    SET name        = p_new_name,
        permissions = p_new_permissions
    WHERE id = p_role_id;
END;
$$ LANGUAGE plpgsql;

-- Function to delete a custom role
CREATE OR REPLACE FUNCTION delete_custom_role(p_role_id UUID)
    RETURNS VOID AS
$$
BEGIN
    DELETE
    FROM custom_roles
    WHERE id = p_role_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get message replies
CREATE OR REPLACE FUNCTION get_message_replies(p_original_message_id UUID)
    RETURNS TABLE
            (
                reply_id          UUID,
                sender_id         UUID,
                encrypted_content BYTEA,
                created_at        TIMESTAMP WITH TIME ZONE
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT m.id, m.sender_id, m.encrypted_content, m.created_at
        FROM replies r
                 JOIN messages m ON r.reply_message_id = m.id
        WHERE r.original_message_id = p_original_message_id
        ORDER BY m.created_at;
END;
$$ LANGUAGE plpgsql;

-- Add any additional indexes that might be needed based on your query patterns

-- Create an index for faster lookups of chat participants by user
CREATE INDEX idx_chat_participants_user_chat ON chat_participants (user_id, chat_id);

-- Create an index for faster retrieval of recent messages in a chat
CREATE INDEX idx_messages_chat_created ON messages (chat_id, created_at DESC);

-- Create an index for faster retrieval of unread messages
CREATE INDEX idx_message_status_unread ON message_status (user_id, chat_id, status) WHERE status = 'sent';