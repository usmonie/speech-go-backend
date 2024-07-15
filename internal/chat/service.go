package chat

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ChatService struct {
	repo               Repository
	userMessageStreams sync.Map
	userStatusStreams  sync.Map
}

func NewChatService(repo Repository) *ChatService {
	return &ChatService{
		repo: repo,
	}
}

func (s *ChatService) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	message := &Message{
		MessageId:        uuid.New().String(),
		ChatId:           req.ChatId,
		SenderId:         req.SenderId,
		Content:          req.Content,
		SentAt:           timestamppb.Now(),
		Status:           MessageStatusResponse_MESSAGE_SENT,
		ReplyToMessageId: req.ReplyToMessageId,
	}

	err := s.repo.CreateMessage(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to create message: %w", err)
	}

	s.broadcastMessage(message)

	return &SendMessageResponse{
		MessageId: message.MessageId,
		Timestamp: message.SentAt,
	}, nil
}

func (s *ChatService) ReceiveMessages(req *ReceiveMessagesRequest, stream ChatService_ReceiveMessagesServer) error {
	messageChan := make(chan *Message, 100)
	s.userMessageStreams.Store(req.UserId, messageChan)
	defer s.userMessageStreams.Delete(req.UserId)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case msg := <-messageChan:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (s *ChatService) UpdateMessageStatus(ctx context.Context, req *UpdateMessageStatusRequest) (*UpdateMessageStatusResponse, error) {
	err := s.repo.UpdateMessageStatus(ctx, req.MessageId, req.Status)
	if err != nil {
		return nil, fmt.Errorf("failed to update message status: %w", err)
	}

	message, err := s.repo.GetMessage(ctx, req.MessageId)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated message: %w", err)
	}

	return &UpdateMessageStatusResponse{
		Success:         true,
		NewStatus:       message.Status,
		StatusUpdatedAt: timestamppb.Now(),
	}, nil
}

func (s *ChatService) ReplyToMessage(ctx context.Context, req *ReplyToMessageRequest) (*ReplyToMessageResponse, error) {
	message := &Message{
		MessageId:        uuid.New().String(),
		ChatId:           req.ChatId,
		SenderId:         req.SenderId,
		Content:          req.Content,
		SentAt:           timestamppb.Now(),
		Status:           MessageStatusResponse_MESSAGE_SENT,
		ReplyToMessageId: req.OriginalMessageId,
	}

	err := s.repo.CreateMessage(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to create reply message: %w", err)
	}

	s.broadcastMessage(message)

	return &ReplyToMessageResponse{
		MessageId: message.MessageId,
		Timestamp: message.SentAt,
	}, nil
}

func (s *ChatService) ForwardMessage(ctx context.Context, req *ForwardMessageRequest) (*ForwardMessageResponse, error) {
	originalMessage, err := s.repo.GetMessage(ctx, req.MessageId)
	if err != nil {
		return nil, fmt.Errorf("failed to get original message: %w", err)
	}

	forwardedMessage := &Message{
		MessageId: uuid.New().String(),
		ChatId:    req.ChatId,
		SenderId:  req.SenderId,
		Content:   originalMessage.Content,
		SentAt:    timestamppb.Now(),
		Status:    MessageStatusResponse_MESSAGE_SENT,
	}

	err = s.repo.CreateMessage(ctx, forwardedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to create forwarded message: %w", err)
	}

	s.broadcastMessage(forwardedMessage)

	return &ForwardMessageResponse{
		NewMessageId: forwardedMessage.MessageId,
		Timestamp:    forwardedMessage.SentAt,
	}, nil
}

func (s *ChatService) CreatePublicGroupChat(ctx context.Context, req *CreatePublicGroupChatRequest) (*CreatePublicGroupChatResponse, error) {
	chat := &ChatResponse{
		ChatId:    uuid.New().String(),
		ChatType:  "public",
		ChatName:  req.Name,
		Username:  req.Username,
		CreatedAt: timestamppb.Now(),
		CreatedBy: req.CreatorId,
	}

	err := s.repo.CreateChat(ctx, chat)
	if err != nil {
		return nil, fmt.Errorf("failed to create public group chat: %w", err)
	}

	err = s.repo.AddChatParticipant(ctx, chat.ChatId, req.CreatorId, "owner")
	if err != nil {
		return nil, fmt.Errorf("failed to add creator as participant: %w", err)
	}

	return &CreatePublicGroupChatResponse{Chat: chat}, nil
}

func (s *ChatService) CreatePrivateGroupChat(ctx context.Context, req *CreatePrivateGroupChatRequest) (*CreatePrivateGroupChatResponse, error) {
	chat := &ChatResponse{
		ChatId:    uuid.New().String(),
		ChatType:  "private",
		ChatName:  req.Name,
		CreatedAt: timestamppb.Now(),
		CreatedBy: req.CreatorId,
	}

	err := s.repo.CreateChat(ctx, chat)
	if err != nil {
		return nil, fmt.Errorf("failed to create private group chat: %w", err)
	}

	err = s.repo.AddChatParticipant(ctx, chat.ChatId, req.CreatorId, "owner")
	if err != nil {
		return nil, fmt.Errorf("failed to add creator as participant: %w", err)
	}

	return &CreatePrivateGroupChatResponse{Chat: chat}, nil
}

func (s *ChatService) JoinPublicGroupChat(ctx context.Context, req *JoinPublicGroupChatRequest) (*JoinPublicGroupChatResponse, error) {
	chat, err := s.repo.GetChatByUsername(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to find public group chat: %w", err)
	}

	err = s.repo.AddChatParticipant(ctx, chat.ChatId, req.UserId, "member")
	if err != nil {
		return nil, fmt.Errorf("failed to add user to public group chat: %w", err)
	}

	return &JoinPublicGroupChatResponse{Success: true}, nil
}

func (s *ChatService) CreateChatInvitation(ctx context.Context, req *CreateChatInvitationRequest) (*CreateChatInvitationResponse, error) {
	invitation := &ChatInvitation{
		InvitationId:  uuid.New().String(),
		ChatId:        req.ChatId,
		InviterId:     req.InviterId,
		InviteeId:     req.InviteeId,
		InvitationUrl: uuid.New().String(),
		CreatedAt:     timestamppb.Now(),
		ExpiresAt:     timestamppb.New(time.Now().Add(req.ExpiresIn.AsDuration())),
		IsActive:      true,
	}

	err := s.repo.CreateChatInvitation(ctx, invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to create chat invitation: %w", err)
	}

	return &CreateChatInvitationResponse{Invitation: invitation}, nil
}

func (s *ChatService) JoinPrivateGroupChat(ctx context.Context, req *JoinPrivateGroupChatRequest) (*JoinPrivateGroupChatResponse, error) {
	invitation, err := s.repo.GetChatInvitation(ctx, req.InvitationUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired invitation: %w", err)
	}

	err = s.repo.AddChatParticipant(ctx, invitation.ChatId, req.UserId, "member")
	if err != nil {
		return nil, fmt.Errorf("failed to add user to private group chat: %w", err)
	}

	err = s.repo.DeactivateInvitation(ctx, invitation.InvitationId)
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate invitation: %w", err)
	}

	return &JoinPrivateGroupChatResponse{Success: true}, nil
}

func (s *ChatService) UpdateGroupInfo(ctx context.Context, req *UpdateGroupInfoRequest) (*UpdateGroupInfoResponse, error) {
	err := s.repo.UpdateGroupInfo(ctx, req.ChatId, req.NewName, req.NewDescription)
	if err != nil {
		return nil, fmt.Errorf("failed to update group info: %w", err)
	}
	return &UpdateGroupInfoResponse{Success: true}, nil
}

func (s *ChatService) DeleteMessage(ctx context.Context, req *DeleteMessageRequest) (*DeleteMessageResponse, error) {
	err := s.repo.DeleteMessage(ctx, req.ChatId, req.MessageId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete message: %w", err)
	}
	return &DeleteMessageResponse{Success: true}, nil
}

func (s *ChatService) BanUser(ctx context.Context, req *BanUserRequest) (*BanUserResponse, error) {
	err := s.repo.BanUser(ctx, req.ChatId, req.UserId, req.Duration.AsDuration())
	if err != nil {
		return nil, fmt.Errorf("failed to ban user: %w", err)
	}
	return &BanUserResponse{Success: true}, nil
}

func (s *ChatService) UnbanUser(ctx context.Context, req *UnbanUserRequest) (*UnbanUserResponse, error) {
	err := s.repo.UnbanUser(ctx, req.ChatId, req.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to unban user: %w", err)
	}
	return &UnbanUserResponse{Success: true}, nil
}

func (s *ChatService) CreateInviteLink(ctx context.Context, req *CreateInviteLinkRequest) (*CreateInviteLinkResponse, error) {
	inviteLink, err := s.repo.CreateInviteLink(ctx, req.ChatId, req.Expiration.AsDuration())
	if err != nil {
		return nil, fmt.Errorf("failed to create invite link: %w", err)
	}
	return &CreateInviteLinkResponse{InviteLink: inviteLink}, nil
}

func (s *ChatService) PinMessage(ctx context.Context, req *PinMessageRequest) (*PinMessageResponse, error) {
	// TODO: Get the user ID from the context
	pinnedBy := "user_id_here"
	err := s.repo.PinMessage(ctx, req.ChatId, req.MessageId, pinnedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to pin message: %w", err)
	}
	return &PinMessageResponse{Success: true}, nil
}

func (s *ChatService) UnpinMessage(ctx context.Context, req *UnpinMessageRequest) (*UnpinMessageResponse, error) {
	err := s.repo.UnpinMessage(ctx, req.ChatId, req.MessageId)
	if err != nil {
		return nil, fmt.Errorf("failed to unpin message: %w", err)
	}
	return &UnpinMessageResponse{Success: true}, nil
}

func (s *ChatService) UpdateUserRole(ctx context.Context, req *UpdateUserRoleRequest) (*UpdateUserRoleResponse, error) {
	err := s.repo.UpdateUserRole(ctx, req.ChatId, req.UserId, req.RoleId)
	if err != nil {
		return nil, fmt.Errorf("failed to update user role: %w", err)
	}
	return &UpdateUserRoleResponse{Success: true}, nil
}

func (s *ChatService) CreateCustomRole(ctx context.Context, req *CreateCustomRoleRequest) (*CreateCustomRoleResponse, error) {
	role := &Role{
		RoleId:            uuid.New().String(),
		RoleName:          req.Role.RoleName,
		CanChangeInfo:     req.Role.CanChangeInfo,
		CanDeleteMessages: req.Role.CanDeleteMessages,
		CanBanUsers:       req.Role.CanBanUsers,
		CanInviteUsers:    req.Role.CanInviteUsers,
		CanPinMessages:    req.Role.CanPinMessages,
		CanManageRoles:    req.Role.CanManageRoles,
	}
	err := s.repo.CreateRole(ctx, req.ChatId, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom role: %w", err)
	}
	return &CreateCustomRoleResponse{RoleId: role.RoleId}, nil
}

func (s *ChatService) CreateRoom(ctx context.Context, req *CreateRoomRequest) (*CreateRoomResponse, error) {
	room, err := s.repo.CreateRoom(ctx, req.ChatId, req.RoomName, req.Description)
	if err != nil {
		return nil, fmt.Errorf("failed to create room: %w", err)
	}
	return &CreateRoomResponse{Room: room}, nil
}

func (s *ChatService) UpdateRoom(ctx context.Context, req *UpdateRoomRequest) (*UpdateRoomResponse, error) {
	err := s.repo.UpdateRoom(ctx, req.ChatId, req.RoomId, req.NewName, req.NewDescription)
	if err != nil {
		return nil, fmt.Errorf("failed to update room: %w", err)
	}
	return &UpdateRoomResponse{Success: true}, nil
}

func (s *ChatService) DeleteRoom(ctx context.Context, req *DeleteRoomRequest) (*DeleteRoomResponse, error) {
	err := s.repo.DeleteRoom(ctx, req.ChatId, req.RoomId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete room: %w", err)
	}
	return &DeleteRoomResponse{Success: true}, nil
}

func (s *ChatService) UpdateStatus(ctx context.Context, req *UpdateStatusRequest) (*UpdateStatusResponse, error) {
	err := s.repo.UpdateUserStatus(ctx, req.UserId, req.ChatId, req.Status, ActivityStatusResponse_NONE)
	if err != nil {
		return nil, fmt.Errorf("failed to update user status: %w", err)
	}

	s.broadcastStatusUpdate(req.UserId, req.ChatId)

	return &UpdateStatusResponse{Success: true}, nil
}

func (s *ChatService) UpdateActivity(ctx context.Context, req *UpdateActivityRequest) (*UpdateActivityResponse, error) {
	status, err := s.repo.GetUserStatus(ctx, req.UserId, req.ChatId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user status: %w", err)
	}

	err = s.repo.UpdateUserStatus(ctx, req.UserId, req.ChatId, status.Status, req.Activity)
	if err != nil {
		return nil, fmt.Errorf("failed to update user activity: %w", err)
	}

	s.broadcastStatusUpdate(req.UserId, req.ChatId)

	return &UpdateActivityResponse{Success: true}, nil
}

func (s *ChatService) ReceiveStatusUpdates(req *ReceiveStatusUpdatesRequest, stream UserStatusService_ReceiveStatusUpdatesServer) error {
	statusChan := make(chan *StatusUpdateResponse, 100)
	s.userStatusStreams.Store(req.UserId, statusChan)
	defer s.userStatusStreams.Delete(req.UserId)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case status := <-statusChan:
			if err := stream.Send(status); err != nil {
				return err
			}
		}
	}
}

func (s *ChatService) broadcastMessage(message *Message) {
	participants, err := s.repo.GetChatParticipants(context.Background(), message.ChatId)
	if err != nil {
		fmt.Printf("Failed to get chat participants: %v\n", err)
		return
	}

	for _, participant := range participants {
		if stream, ok := s.userMessageStreams.Load(participant.UserID); ok {
			select {
			case stream.(chan *Message) <- message:
				// Message sent to participant's stream
			default:
				fmt.Printf("Failed to send message to user %s: channel full\n", participant.UserID)
			}
		}
	}
}

func (s *ChatService) broadcastStatusUpdate(userID, chatID string) {
	status, err := s.repo.GetUserStatus(context.Background(), userID, chatID)
	if err != nil {
		fmt.Printf("Failed to get user status: %v\n", err)
		return
	}

	participants, err := s.repo.GetChatParticipants(context.Background(), chatID)
	if err != nil {
		fmt.Printf("Failed to get chat participants: %v\n", err)
		return
	}

	for _, participant := range participants {
		if participant.UserID != userID {
			if stream, ok := s.userStatusStreams.Load(participant.UserID); ok {
				select {
				case stream.(chan *StatusUpdateResponse) <- status:
					// Status update sent to participant's stream
				default:
					fmt.Printf("Failed to send status update to user %s: channel full\n", participant.UserID)
				}
			}
		}
	}
}

// Helper function to check if a user has a specific permission
func (s *ChatService) hasPermission(ctx context.Context, chatID, userID string, permission string) (bool, error) {
	participants, err := s.repo.GetChatParticipants(ctx, chatID)
	if err != nil {
		return false, fmt.Errorf("failed to get chat participants: %w", err)
	}

	var roleID string
	for _, p := range participants {
		if p.UserID == userID {
			roleID = p.Role
			break
		}
	}

	if roleID == "" {
		return false, fmt.Errorf("user is not a participant of the chat")
	}

	role, err := s.repo.GetRole(ctx, roleID)
	if err != nil {
		return false, fmt.Errorf("failed to get user role: %w", err)
	}

	switch permission {
	case "change_info":
		return role.CanChangeInfo, nil
	case "delete_messages":
		return role.CanDeleteMessages, nil
	case "ban_users":
		return role.CanBanUsers, nil
	case "invite_users":
		return role.CanInviteUsers, nil
	case "pin_messages":
		return role.CanPinMessages, nil
	case "manage_roles":
		return role.CanManageRoles, nil
	default:
		return false, fmt.Errorf("unknown permission: %s", permission)
	}
}

// Add this method to get chat details including rooms
//func (s *ChatService) GetChatDetails(ctx context.Context, req *GetChatDetailsRequest) (*GetChatDetailsResponse, error) {
//	chat, err := s.repo.GetChat(ctx, req.ChatId)
//	if err != nil {
//		return nil, fmt.Errorf("failed to get chat details: %w", err)
//	}
//
//	rooms, err := s.repo.GetRooms(ctx, req.ChatId)
//	if err != nil {
//		return nil, fmt.Errorf("failed to get chat rooms: %w", err)
//	}
//
//	return &GetChatDetailsResponse{
//		Chat:  chat,
//		Rooms: rooms,
//	}, nil
//}
