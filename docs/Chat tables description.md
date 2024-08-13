# Chat Feature Database Table Documentation

## Table: chats

Stores information about individual chats, which can be either direct messages between two users or group chats.

| Column         | Type                        | Description                                           |
|----------------|---------------------------|-------------------------------------------------------|
| id             | UUID                      | Primary key, unique identifier for the chat           |
| type           | VARCHAR(10)               | Type of chat: 'direct' or 'group'                     |
| name           | VARCHAR(100)              | Name of the chat (for group chats)                    |
| group_type     | VARCHAR(10)               | Type of group: 'public' or 'private' (NULL for direct chats) |
| group_username | VARCHAR(50)               | Unique username for public groups (NULL for private groups and direct chats) |
| created_at     | TIMESTAMP WITH TIME ZONE  | Timestamp when the chat was created                   |
| updated_at     | TIMESTAMP WITH TIME ZONE  | Timestamp of the last update to the chat              |

**Constraints:**
- CHECK constraint ensures `type` is either 'direct' or 'group'
- CHECK constraint ensures `group_type` is either 'public' or 'private' when `type` is 'group'
- CHECK constraint ensures `group_username` is NOT NULL for public groups

## Table: chat_participants

Links users to the chats they're participating in and stores their role within the chat.

| Column    | Type                        | Description                                           |
|-----------|---------------------------|-------------------------------------------------------|
| chat_id   | UUID                      | Foreign key referencing chats.id                      |
| user_id   | UUID                      | Foreign key referencing the users table               |
| role      | VARCHAR(20)               | Role of the user in the chat (e.g., 'member', 'admin') |
| joined_at | TIMESTAMP WITH TIME ZONE  | Timestamp when the user joined the chat               |

**Constraints:**
- Primary key is a combination of (chat_id, user_id)
- Foreign key constraint on chat_id references chats.id
- Trigger ensures direct chats have exactly two participants

## Table: messages

Stores encrypted messages sent in chats.

| Column                | Type                        | Description                                           |
|-----------------------|---------------------------|-------------------------------------------------------|
| id                    | UUID                      | Primary key, unique identifier for the message        |
| chat_id               | UUID                      | Foreign key referencing chats.id                      |
| sender_id             | UUID                      | Foreign key referencing the users table               |
| encrypted_content     | BYTEA                     | Encrypted content of the message                      |
| signature             | BYTEA                     | Cryptographic signature of the message                |
| ratchet_public_key    | BYTEA                     | Public key used in the Double Ratchet algorithm       |
| message_number        | INTEGER                   | Sequential number of the message in the conversation  |
| previous_chain_length | INTEGER                   | Length of the previous message chain                  |
| created_at            | TIMESTAMP WITH TIME ZONE  | Timestamp when the message was created                |

**Constraints:**
- Foreign key constraint on chat_id references chats.id

## Table: message_status

Tracks the status of messages for each recipient.

| Column     | Type                        | Description                                           |
|------------|---------------------------|-------------------------------------------------------|
| message_id | UUID                      | Foreign key referencing messages.id                   |
| user_id    | UUID                      | Foreign key referencing the users table               |
| status     | VARCHAR(10)               | Status of the message: 'sent', 'delivered', or 'read' |
| updated_at | TIMESTAMP WITH TIME ZONE  | Timestamp of the last status update                   |

**Constraints:**
- Primary key is a combination of (message_id, user_id)
- Foreign key constraint on message_id references messages.id
- CHECK constraint ensures status is 'sent', 'delivered', or 'read'

## Table: replies

Links reply messages to their original messages.

| Column              | Type | Description                                    |
|---------------------|------|------------------------------------------------|
| reply_message_id    | UUID | Foreign key referencing messages.id (the reply)|
| original_message_id | UUID | Foreign key referencing messages.id (the original message) |

**Constraints:**
- Primary key is a combination of (reply_message_id, original_message_id)
- Foreign key constraints on both columns reference messages.id

## Table: pinned_messages

Keeps track of pinned messages in chats.

| Column     | Type                        | Description                                           |
|------------|---------------------------|-------------------------------------------------------|
| chat_id    | UUID                      | Foreign key referencing chats.id                      |
| message_id | UUID                      | Foreign key referencing messages.id                   |
| pinned_by  | UUID                      | Foreign key referencing the users table               |
| pinned_at  | TIMESTAMP WITH TIME ZONE  | Timestamp when the message was pinned                 |

**Constraints:**
- Primary key is a combination of (chat_id, message_id)
- Foreign key constraint on chat_id references chats.id
- Foreign key constraint on message_id references messages.id

## Table: chat_invitations

Stores invitation codes for private chats.

| Column          | Type                        | Description                                           |
|-----------------|---------------------------|-------------------------------------------------------|
| id              | UUID                      | Primary key, unique identifier for the invitation    |
| chat_id         | UUID                      | Foreign key referencing chats.id                      |
| created_by      | UUID                      | Foreign key referencing the users table               |
| invitation_code | VARCHAR(50)               | Unique invitation code                                |
| invitation_type | VARCHAR(10)               | Type of invitation: 'link' or 'code'                  |
| expiration_date | TIMESTAMP WITH TIME ZONE  | Expiration date of the invitation (can be NULL)       |
| is_used         | BOOLEAN                   | Flag indicating if the invitation has been used       |
| created_at      | TIMESTAMP WITH TIME ZONE  | Timestamp when the invitation was created             |

**Constraints:**
- Foreign key constraint on chat_id references chats.id
- UNIQUE constraint on invitation_code
- CHECK constraint ensures invitation_type is either 'link' or 'code'

## Table: custom_roles

Defines custom roles for group chats.

| Column      | Type                        | Description                                           |
|-------------|---------------------------|-------------------------------------------------------|
| id          | UUID                      | Primary key, unique identifier for the custom role    |
| chat_id     | UUID                      | Foreign key referencing chats.id                      |
| name        | VARCHAR(50)               | Name of the custom role                               |
| permissions | JSONB                     | JSON object storing the role's permissions            |
| created_at  | TIMESTAMP WITH TIME ZONE  | Timestamp when the role was created                   |

**Constraints:**
- Foreign key constraint on chat_id references chats.id
- UNIQUE constraint on combination of (chat_id, name)