package chat

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

type Repository interface {
	// Message operations
	CreateMessage(ctx context.Context, message *Message) error
	GetMessage(ctx context.Context, messageID string) (*Message, error)
	UpdateMessageStatus(ctx context.Context, messageID string, status MessageStatusResponse) error
	GetChatMessages(ctx context.Context, chatID string, limit, offset int) ([]*Message, error)

	// ChatResponse operations
	CreateChat(ctx context.Context, chat *ChatResponse) error
	GetChat(ctx context.Context, chatID string) (*ChatResponse, error)
	GetChatByUsername(ctx context.Context, username string) (*ChatResponse, error)

	// User status operations
	UpdateUserStatus(ctx context.Context, userID, chatID string, status UserStatusResponse, activity ActivityStatusResponse) error
	GetUserStatus(ctx context.Context, userID, chatID string) (*StatusUpdateResponse, error)

	// ChatResponse participant operations
	AddChatParticipant(ctx context.Context, chatID, userID, role string) error
	GetChatParticipants(ctx context.Context, chatID string) ([]*ChatParticipantResponse, error)

	// ChatResponse invitation operations
	CreateChatInvitation(ctx context.Context, invitation *ChatInvitation) error
	GetChatInvitation(ctx context.Context, invitationURL string) (*ChatInvitation, error)
	DeactivateInvitation(ctx context.Context, invitationID string) error
	UpdateGroupInfo(ctx context.Context, chatID, newName, newDescription string) error
	DeleteMessage(ctx context.Context, chatID, messageID string) error
	BanUser(ctx context.Context, chatID, userID string, duration time.Duration) error
	UnbanUser(ctx context.Context, chatID, userID string) error
	CreateInviteLink(ctx context.Context, chatID string, expiration time.Duration) (string, error)
	PinMessage(ctx context.Context, chatID, messageID, pinnedBy string) error
	UnpinMessage(ctx context.Context, chatID, messageID string) error

	// New methods for custom roles
	CreateRole(ctx context.Context, chatID string, role *Role) error
	GetRole(ctx context.Context, roleID string) (*Role, error)
	UpdateUserRole(ctx context.Context, chatID, userID, roleID string) error

	// New methods for rooms
	CreateRoom(ctx context.Context, chatID, roomName, description string) (*Room, error)
	UpdateRoom(ctx context.Context, chatID, roomID, newName, newDescription string) error
	DeleteRoom(ctx context.Context, chatID, roomID string) error
	GetRooms(ctx context.Context, chatID string) ([]*Room, error)
}

type ChatParticipantResponse struct {
	UserID   string
	Role     string
	JoinedAt time.Time
}

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateMessage(ctx context.Context, message *Message) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO messages (message_id, chat_id, sender_id, content, sent_at, status, reply_to_message_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, message.MessageId, message.ChatId, message.SenderId, message.Content, message.SentAt.AsTime(), message.Status, message.ReplyToMessageId)
	return err
}

func (r *PostgresRepository) GetMessage(ctx context.Context, messageID string) (*Message, error) {
	var msg Message
	var sentAt, deliveredAt, readAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT message_id, chat_id, sender_id, content, sent_at, status, reply_to_message_id, delivered_at, read_at
		FROM messages WHERE message_id = $1
	`, messageID).Scan(&msg.MessageId, &msg.ChatId, &msg.SenderId, &msg.Content, &sentAt, &msg.Status, &msg.ReplyToMessageId, &deliveredAt, &readAt)
	if err != nil {
		return nil, err
	}
	msg.SentAt = timestamppb.New(sentAt)
	msg.DeliveredAt = timestamppb.New(deliveredAt)
	msg.ReadAt = timestamppb.New(readAt)
	return &msg, nil
}

func (r *PostgresRepository) UpdateMessageStatus(ctx context.Context, messageID string, status MessageStatusResponse) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE messages SET status = $1, 
		delivered_at = CASE WHEN $1 = 1 THEN NOW() ELSE delivered_at END,
		read_at = CASE WHEN $1 = 2 THEN NOW() ELSE read_at END
		WHERE message_id = $2
	`, status, messageID)
	return err
}

func (r *PostgresRepository) GetChatMessages(ctx context.Context, chatID string, limit, offset int) ([]*Message, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT message_id, chat_id, sender_id, content, sent_at, status, reply_to_message_id, delivered_at, read_at
		FROM messages WHERE chat_id = $1 ORDER BY sent_at DESC LIMIT $2 OFFSET $3
	`, chatID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var msg Message
		var sentAt, deliveredAt, readAt time.Time
		err := rows.Scan(&msg.MessageId, &msg.ChatId, &msg.SenderId, &msg.Content, &sentAt, &msg.Status, &msg.ReplyToMessageId, &deliveredAt, &readAt)
		if err != nil {
			return nil, err
		}
		msg.SentAt = timestamppb.New(sentAt)
		msg.DeliveredAt = timestamppb.New(deliveredAt)
		msg.ReadAt = timestamppb.New(readAt)
		messages = append(messages, &msg)
	}
	return messages, nil
}

func (r *PostgresRepository) CreateChat(ctx context.Context, chat *ChatResponse) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert the chat
	_, err = tx.ExecContext(ctx, `
        INSERT INTO chats (chat_id, chat_type, chat_name, username, invitation_url, created_at, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, "chat.ChatId", chat.ChatType, chat.ChatName, chat.Username, chat.InvitationUrl, chat.CreatedAt.AsTime(), chat.CreatedBy)
	if err != nil {
		return fmt.Errorf("failed to insert chat: %w", err)
	}

	// Insert associated rooms
	for _, room := range chat.Rooms {
		_, err = tx.ExecContext(ctx, `
            INSERT INTO rooms (room_id, chat_id, room_name, description)
            VALUES ($1, $2, $3, $4)
        `, room.RoomId, chat.ChatId, room.RoomName, room.Description)
		if err != nil {
			return fmt.Errorf("failed to insert room: %w", err)
		}
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *PostgresRepository) GetChat(ctx context.Context, chatID string) (*ChatResponse, error) {
	// Query to fetch chat and its rooms
	query := `
        SELECT c.chat_id, c.chat_type, c.chat_name, c.username, c.invitation_url, c.created_at, c.created_by,
               r.room_id, r.room_name, r.description
        FROM chats c
        LEFT JOIN rooms r ON c.chat_id = r.chat_id
        WHERE c.chat_id = $1
    `

	rows, err := r.db.QueryContext(ctx, query, chatID)
	if err != nil {
		return nil, fmt.Errorf("failed to query chat: %w", err)
	}
	defer rows.Close()

	var chat *ChatResponse
	rooms := make(map[string]*Room)

	for rows.Next() {
		var (
			chatID, chatType, chatName, username, invitationURL string
			createdAt                                           time.Time
			createdBy                                           string
			roomID, roomName, roomDescription                   sql.NullString
		)

		err := rows.Scan(
			&chatID, &chatType, &chatName, &username, &invitationURL, &createdAt, &createdBy,
			&roomID, &roomName, &roomDescription,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if chat == nil {
			chat = &ChatResponse{
				ChatId:        chatID,
				ChatType:      chatType,
				ChatName:      chatName,
				Username:      username,
				InvitationUrl: invitationURL,
				CreatedAt:     timestamppb.New(createdAt),
				CreatedBy:     createdBy,
			}
		}

		if roomID.Valid {
			rooms[roomID.String] = &Room{
				RoomId:      roomID.String,
				RoomName:    roomName.String,
				Description: roomDescription.String,
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}

	if chat == nil {
		return nil, fmt.Errorf("chat not found")
	}

	chat.Rooms = make([]*Room, 0, len(rooms))
	for _, room := range rooms {
		chat.Rooms = append(chat.Rooms, room)
	}

	return chat, nil
}

func (r *PostgresRepository) GetChatByUsername(ctx context.Context, username string) (*ChatResponse, error) {
	var chat ChatResponse
	var createdAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT chat_id, chat_type, chat_name, username, invitation_url, created_at, created_by
		FROM chats WHERE username = $1 AND chat_type = 'public'
	`, username).Scan(&chat.ChatId, &chat.ChatType, &chat.ChatName, &chat.Username, &chat.InvitationUrl, &createdAt, &chat.CreatedBy)
	if err != nil {
		return nil, err
	}
	chat.CreatedAt = timestamppb.New(createdAt)
	return &chat, nil
}

func (r *PostgresRepository) UpdateUserStatus(ctx context.Context, userID, chatID string, status UserStatusResponse, activity ActivityStatusResponse) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_status (user_id, chat_id, status, activity, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, chat_id) DO UPDATE
		SET status = $3, activity = $4, updated_at = $5
	`, userID, chatID, status, activity, time.Now())
	return err
}

func (r *PostgresRepository) GetUserStatus(ctx context.Context, userID, chatID string) (*StatusUpdateResponse, error) {
	var status StatusUpdateResponse
	var updatedAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT user_id, chat_id, status, activity, updated_at
		FROM user_status WHERE user_id = $1 AND chat_id = $2
	`, userID, chatID).Scan(&status.UserId, &status.ChatId, &status.Status, &status.Activity, &updatedAt)
	if err != nil {
		return nil, err
	}
	status.Timestamp = timestamppb.New(updatedAt)
	return &status, nil
}

func (r *PostgresRepository) AddChatParticipant(ctx context.Context, chatID, userID, role string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO chat_participants (chat_id, user_id, role, joined_at)
		VALUES ($1, $2, $3, $4)
	`, chatID, userID, role, time.Now())
	return err
}

func (r *PostgresRepository) GetChatParticipants(ctx context.Context, chatID string) ([]*ChatParticipantResponse, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT user_id, role, joined_at FROM chat_participants WHERE chat_id = $1
	`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var participants []*ChatParticipantResponse
	for rows.Next() {
		var p ChatParticipantResponse
		err := rows.Scan(&p.UserID, &p.Role, &p.JoinedAt)
		if err != nil {
			return nil, err
		}
		participants = append(participants, &p)
	}
	return participants, nil
}

func (r *PostgresRepository) CreateChatInvitation(ctx context.Context, invitation *ChatInvitation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO chat_invitations (invitation_id, chat_id, inviter_id, invitee_id, invitation_url, created_at, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, invitation.InvitationId, invitation.ChatId, invitation.InviterId, invitation.InviteeId, invitation.InvitationUrl, invitation.CreatedAt.AsTime(), invitation.ExpiresAt.AsTime(), invitation.IsActive)
	return err
}

func (r *PostgresRepository) GetChatInvitation(ctx context.Context, invitationURL string) (*ChatInvitation, error) {
	var invitation ChatInvitation
	var createdAt, expiresAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT invitation_id, chat_id, inviter_id, invitee_id, invitation_url, created_at, expires_at, is_active
		FROM chat_invitations WHERE invitation_url = $1 AND is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())
	`, invitationURL).Scan(&invitation.InvitationId, &invitation.ChatId, &invitation.InviterId, &invitation.InviteeId, &invitation.InvitationUrl, &createdAt, &expiresAt, &invitation.IsActive)
	if err != nil {
		return nil, err
	}
	invitation.CreatedAt = timestamppb.New(createdAt)
	invitation.ExpiresAt = timestamppb.New(expiresAt)
	return &invitation, nil
}

func (r *PostgresRepository) DeactivateInvitation(ctx context.Context, invitationID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE chat_invitations SET is_active = FALSE WHERE invitation_id = $1
	`, invitationID)
	return err
}

func (r *PostgresRepository) DeleteMessage(ctx context.Context, chatID, messageID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM messages WHERE message_id = $1 AND chat_id = $2
	`, messageID, chatID)
	return err
}

func (r *PostgresRepository) BanUser(ctx context.Context, chatID, userID string, duration time.Duration) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO banned_users (ban_id, chat_id, user_id, banned_at, banned_until)
		VALUES ($1, $2, $3, $4, $5)
	`, uuid.New().String(), chatID, userID, time.Now(), time.Now().Add(duration))
	return err
}

func (r *PostgresRepository) UnbanUser(ctx context.Context, chatID, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM banned_users WHERE chat_id = $1 AND user_id = $2
	`, chatID, userID)
	return err
}

func (r *PostgresRepository) CreateInviteLink(ctx context.Context, chatID string, expiration time.Duration) (string, error) {
	inviteLink := uuid.New().String()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO chat_invitations (invitation_id, chat_id, invitation_url, created_at, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, true)
	`, uuid.New().String(), chatID, inviteLink, time.Now(), time.Now().Add(expiration))
	if err != nil {
		return "", err
	}
	return inviteLink, nil
}

func (r *PostgresRepository) PinMessage(ctx context.Context, chatID, messageID, pinnedBy string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO pinned_messages (pin_id, chat_id, message_id, pinned_at, pinned_by)
		VALUES ($1, $2, $3, $4, $5)
	`, uuid.New().String(), chatID, messageID, time.Now(), pinnedBy)
	return err
}

func (r *PostgresRepository) UnpinMessage(ctx context.Context, chatID, messageID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM pinned_messages WHERE chat_id = $1 AND message_id = $2
	`, chatID, messageID)
	return err
}

func (r *PostgresRepository) UpdateGroupInfo(ctx context.Context, chatID, newName, newDescription string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE chats SET chat_name = $1 WHERE chat_id = $2
	`, newName, chatID)
	return err
}

func (r *PostgresRepository) CreateRole(ctx context.Context, chatID string, role *Role) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO roles (role_id, chat_id, role_name, can_change_info, can_delete_messages, can_ban_users, can_invite_users, can_pin_messages, can_manage_roles)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, role.RoleId, chatID, role.RoleName, role.CanChangeInfo, role.CanDeleteMessages, role.CanBanUsers, role.CanInviteUsers, role.CanPinMessages, role.CanManageRoles)
	return err
}

func (r *PostgresRepository) GetRole(ctx context.Context, roleID string) (*Role, error) {
	var role Role
	err := r.db.QueryRowContext(ctx, `
		SELECT role_id, role_name, can_change_info, can_delete_messages, can_ban_users, can_invite_users, can_pin_messages, can_manage_roles
		FROM roles WHERE role_id = $1
	`, roleID).Scan(&role.RoleId, &role.RoleName, &role.CanChangeInfo, &role.CanDeleteMessages, &role.CanBanUsers, &role.CanInviteUsers, &role.CanPinMessages, &role.CanManageRoles)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *PostgresRepository) UpdateUserRole(ctx context.Context, chatID, userID, roleID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE chat_participants SET role_id = $1 WHERE chat_id = $2 AND user_id = $3
	`, roleID, chatID, userID)
	return err
}

func (r *PostgresRepository) CreateRoom(ctx context.Context, chatID, roomName, description string) (*Room, error) {
	room := &Room{
		RoomId:      uuid.New().String(),
		RoomName:    roomName,
		Description: description,
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO rooms (room_id, chat_id, room_name, description)
		VALUES ($1, $2, $3, $4)
	`, room.RoomId, chatID, room.RoomName, room.Description)
	if err != nil {
		return nil, err
	}
	return room, nil
}

func (r *PostgresRepository) UpdateRoom(ctx context.Context, chatID, roomID, newName, newDescription string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE rooms SET room_name = $1, description = $2 WHERE room_id = $3 AND chat_id = $4
	`, newName, newDescription, roomID, chatID)
	return err
}

func (r *PostgresRepository) DeleteRoom(ctx context.Context, chatID, roomID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM rooms WHERE room_id = $1 AND chat_id = $2
	`, roomID, chatID)
	return err
}

func (r *PostgresRepository) GetRooms(ctx context.Context, chatID string) ([]*Room, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT room_id, room_name, description FROM rooms WHERE chat_id = $1
	`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rooms []*Room
	for rows.Next() {
		var room Room
		err := rows.Scan(&room.RoomId, &room.RoomName, &room.Description)
		if err != nil {
			return nil, err
		}
		rooms = append(rooms, &room)
	}
	return rooms, nil
}
