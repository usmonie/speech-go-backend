package chat

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ChatHandler struct {
	UnimplementedChatServiceServer
	UnimplementedUserStatusServiceServer
	service *ChatService
}

func NewChatHandler(service *ChatService) *ChatHandler {
	return &ChatHandler{service: service}
}

func (h *ChatHandler) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	resp, err := h.service.SendMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to send message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) ReceiveMessages(req *ReceiveMessagesRequest, stream ChatService_ReceiveMessagesServer) error {
	return h.service.ReceiveMessages(req, stream)
}

func (h *ChatHandler) UpdateMessageStatus(ctx context.Context, req *UpdateMessageStatusRequest) (*UpdateMessageStatusResponse, error) {
	resp, err := h.service.UpdateMessageStatus(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update message status: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) ReplyToMessage(ctx context.Context, req *ReplyToMessageRequest) (*ReplyToMessageResponse, error) {
	resp, err := h.service.ReplyToMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to reply to message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) ForwardMessage(ctx context.Context, req *ForwardMessageRequest) (*ForwardMessageResponse, error) {
	resp, err := h.service.ForwardMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to forward message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreatePublicGroupChat(ctx context.Context, req *CreatePublicGroupChatRequest) (*CreatePublicGroupChatResponse, error) {
	resp, err := h.service.CreatePublicGroupChat(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create public group chat: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreatePrivateGroupChat(ctx context.Context, req *CreatePrivateGroupChatRequest) (*CreatePrivateGroupChatResponse, error) {
	resp, err := h.service.CreatePrivateGroupChat(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create private group chat: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) JoinPublicGroupChat(ctx context.Context, req *JoinPublicGroupChatRequest) (*JoinPublicGroupChatResponse, error) {
	resp, err := h.service.JoinPublicGroupChat(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to join public group chat: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreateChatInvitation(ctx context.Context, req *CreateChatInvitationRequest) (*CreateChatInvitationResponse, error) {
	resp, err := h.service.CreateChatInvitation(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create chat invitation: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) JoinPrivateGroupChat(ctx context.Context, req *JoinPrivateGroupChatRequest) (*JoinPrivateGroupChatResponse, error) {
	resp, err := h.service.JoinPrivateGroupChat(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to join private group chat: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UpdateGroupInfo(ctx context.Context, req *UpdateGroupInfoRequest) (*UpdateGroupInfoResponse, error) {
	resp, err := h.service.UpdateGroupInfo(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update group info: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) DeleteMessage(ctx context.Context, req *DeleteMessageRequest) (*DeleteMessageResponse, error) {
	resp, err := h.service.DeleteMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to delete message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) BanUser(ctx context.Context, req *BanUserRequest) (*BanUserResponse, error) {
	resp, err := h.service.BanUser(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to ban user: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UnbanUser(ctx context.Context, req *UnbanUserRequest) (*UnbanUserResponse, error) {
	resp, err := h.service.UnbanUser(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to unban user: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreateInviteLink(ctx context.Context, req *CreateInviteLinkRequest) (*CreateInviteLinkResponse, error) {
	resp, err := h.service.CreateInviteLink(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create invite link: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) PinMessage(ctx context.Context, req *PinMessageRequest) (*PinMessageResponse, error) {
	resp, err := h.service.PinMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to pin message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UnpinMessage(ctx context.Context, req *UnpinMessageRequest) (*UnpinMessageResponse, error) {
	resp, err := h.service.UnpinMessage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to unpin message: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UpdateUserRole(ctx context.Context, req *UpdateUserRoleRequest) (*UpdateUserRoleResponse, error) {
	resp, err := h.service.UpdateUserRole(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update user role: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreateCustomRole(ctx context.Context, req *CreateCustomRoleRequest) (*CreateCustomRoleResponse, error) {
	resp, err := h.service.CreateCustomRole(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create custom role: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) CreateRoom(ctx context.Context, req *CreateRoomRequest) (*CreateRoomResponse, error) {
	resp, err := h.service.CreateRoom(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create room: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UpdateRoom(ctx context.Context, req *UpdateRoomRequest) (*UpdateRoomResponse, error) {
	resp, err := h.service.UpdateRoom(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update room: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) DeleteRoom(ctx context.Context, req *DeleteRoomRequest) (*DeleteRoomResponse, error) {
	resp, err := h.service.DeleteRoom(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to delete room: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UpdateStatus(ctx context.Context, req *UpdateStatusRequest) (*UpdateStatusResponse, error) {
	resp, err := h.service.UpdateStatus(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update status: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) UpdateActivity(ctx context.Context, req *UpdateActivityRequest) (*UpdateActivityResponse, error) {
	resp, err := h.service.UpdateActivity(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update activity: %v", err)
	}
	return resp, nil
}

func (h *ChatHandler) ReceiveStatusUpdates(req *ReceiveStatusUpdatesRequest, stream UserStatusService_ReceiveStatusUpdatesServer) error {
	return h.service.ReceiveStatusUpdates(req, stream)
}
