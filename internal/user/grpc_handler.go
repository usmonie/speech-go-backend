package user

import (
	"context"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"speech/infrastructure/connection"
	"speech/internal/proto"
)

type Handler struct {
	proto.UnimplementedUserAccountServiceServer
	userUseCase *AccountUseCase
}

func NewUserHandler(userUseCase *AccountUseCase) *Handler {
	return &Handler{
		userUseCase: userUseCase,
	}
}

func (h *Handler) CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*proto.CreateUserResponse, error) {
	device, err := connection.GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	accessToken, refreshToken, user, err := h.userUseCase.CreateUser(
		ctx,
		req.Username,
		req.Email,
		req.GetBio(),
		device,
		req.PasswordHmac,
		req.Salt,
		req.PublicIdentityKey,
		req.PublicSignedPreKey,
		req.SignedPreKeySignature,
		req.PublicKyberKey,
		req.PublicOneTimePreKeys,
		req.EncryptedPrivateKeys,
	)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.CreateUserResponse{
		User:         ConvertUserToProtoUser(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (h *Handler) GetUserById(ctx context.Context, req *proto.GetUserByIdRequest) (protoUser *proto.User, err error) {
	userID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	user, err := h.userUseCase.GetUserByID(ctx, &userID)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return ConvertUserToProtoUser(user), nil
}

func (h *Handler) GetUsersByUsername(ctx context.Context, req *proto.GetUsersByUsernameRequest) (*proto.GetUsersByUsernameResponse, error) {
	users, err := h.userUseCase.GetUsersByUsername(ctx, req.GetUsername())
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	protoUsers := make([]*proto.User, len(users))
	for i, user := range users {
		protoUsers[i] = ConvertUserToProtoUser(user)
	}

	return &proto.GetUsersByUsernameResponse{
		Users: protoUsers,
	}, nil
}

func (h *Handler) UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*proto.User, error) {
	userID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	user, err := h.userUseCase.GetUserByID(ctx, &userID)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	user.Bio = req.GetBio()
	user.Username = req.GetUsername()
	user.Email = req.GetEmail()

	err = h.userUseCase.UpdateUser(ctx, user)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return ConvertUserToProtoUser(user), nil
}

func (h *Handler) DeleteUser(ctx context.Context, req *proto.DeleteUserRequest) (*emptypb.Empty, error) {
	userID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &emptypb.Empty{}, h.userUseCase.DeleteUser(ctx, &userID)
}
