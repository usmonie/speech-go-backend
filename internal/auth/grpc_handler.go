package auth

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"speech/infrastructure/connection"
	"speech/internal/proto"
	"speech/internal/user"
)

type Handler struct {
	proto.UnimplementedAuthenticationServiceServer
	authUseCase UseCase
}

func NewAuthHandler(authUseCase UseCase) *Handler {
	return &Handler{
		authUseCase: authUseCase,
	}
}

func (h *Handler) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	device, err := connection.GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userResult, tokens, err := h.authUseCase.Login(ctx, req.Email, req.Password, device)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &proto.LoginResponse{
		User:         user.ConvertUserToProtoUser(userResult),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (h *Handler) Logout(ctx context.Context, req *proto.LogoutRequest) (*emptypb.Empty, error) {
	err := h.authUseCase.Logout(ctx, req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}

func (h *Handler) RefreshToken(ctx context.Context, req *proto.RefreshTokenRequest) (*proto.RefreshTokenResponse, error) {
	tokens, err := h.authUseCase.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &proto.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
