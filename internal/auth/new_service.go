package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/peer"
	math "math/rand"
	"net/mail"
	"speech/config"
	"speech/internal/auth/proto"
	"speech/internal/auth/user"
	"speech/internal/email"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	passwordvalidator "github.com/wagslane/go-password-validator"
)

const (
	PasswordMinEntropyBits = 30
)

var (
	ErrInvalidEmail = errors.New("invalid email")
)

type UserServiceServer struct {
	proto.UnimplementedUserServiceServer
	authRepo   AuthenticatedRepository
	unauthRepo UnauthenticatedRepository
	sender     *email.Sender
}

func NewUserServiceServer(
	authRepo AuthenticatedRepository,
	unauthRepo UnauthenticatedRepository,
	sender *email.Sender,
) *UserServiceServer {
	return &UserServiceServer{
		authRepo:   authRepo,
		unauthRepo: unauthRepo,
		sender:     sender,
	}
}

func checkCredentials(email, password string) error {
	if !validEmail(email) {
		return ErrInvalidEmail
	}

	err := passwordvalidator.Validate(password, PasswordMinEntropyBits)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "Password is not strong enough: %v", err)
	}
	return nil
}

func (s *UserServiceServer) CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*proto.CreateUserResponse, error) {
	err := checkCredentials(req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, err
	}

	device, err := GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, dbUser, code, _, err := s.unauthRepo.CreateUser(ctx, req.GetEmail(), req.GetPassword(), req.GetUsername(), req.GetBio(), device)
	if err != nil {
		return nil, err
	}
	go func() {
		err := s.sender.SendVerificationEmail(dbUser.Email, dbUser.Username, code)
		if err != nil {
			_ = s.sender.SendVerificationEmail(dbUser.Email, dbUser.Username, code)
		}
	}()

	return &proto.CreateUserResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         convertDBUserToProtoUser(dbUser),
	}, nil
}

func (s *UserServiceServer) GetUserById(ctx context.Context, req *proto.GetUserByIdRequest) (*proto.User, error) {
	userID, sessionId, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	requestUserID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request user id is invalid: %v", err)
	}

	dbUser, err := s.authRepo.GetUserById(ctx, userID, sessionId, device, &requestUserID)
	if err != nil {
		return nil, err
	}

	return convertDBUserToProtoUser(dbUser), nil
}

func (s *UserServiceServer) UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*proto.User, error) {
	userID, sessionID, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}
	if req.Email != nil && !validEmail(req.GetEmail()) {
		return nil, ErrInvalidEmail
	}

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid user ID: %v", err)
	}

	dbUser, err := s.authRepo.UpdateUser(
		ctx,
		userID,
		sessionID,
		req.Username,
		req.Email,
		req.Username,
		device,
	)
	if err != nil {
		return nil, err
	}

	return convertDBUserToProtoUser(dbUser), nil
}

func (s *UserServiceServer) DeleteUser(ctx context.Context, req *proto.DeleteUserRequest) (*emptypb.Empty, error) {
	userId, sessionID, device, err := GetUserDataFromMeta(ctx)

	if err != nil {
		return nil, err
	}
	err = s.authRepo.DeleteUser(ctx, userId, sessionID, device)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	err := checkCredentials(req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, err
	}

	device, err := GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, dbUser, err := s.unauthRepo.Login(ctx, req.GetEmail(), req.GetPassword(), device)
	if err != nil {
		return nil, err
	}

	return &proto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         convertDBUserToProtoUser(dbUser),
	}, nil
}

func (s *UserServiceServer) Logout(ctx context.Context, req *proto.LogoutRequest) (*emptypb.Empty, error) {
	// In a real implementation, you might want to invalidate the access token
	// This could involve adding it to a blacklist or updating its status in the database
	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) RefreshToken(ctx context.Context, req *proto.RefreshTokenRequest) (*proto.RefreshTokenResponse, error) {
	device, err := GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, err
	}
	accessToken, refreshToken, err := s.unauthRepo.RefreshToken(ctx, req.GetRefreshToken(), device)
	if err != nil {
		return nil, err
	}

	return &proto.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *UserServiceServer) SendVerificationEmail(ctx context.Context, req *proto.SendVerificationEmailRequest) (*emptypb.Empty, error) {
	_, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid user ID: %v", err)
	}

	//	empty, err2, done := s.storeVerificationEmail(userID)
	//	if done {
	//		return empty, err2
	//	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) VerifyEmail(ctx context.Context, req *proto.VerifyEmailRequest) (*emptypb.Empty, error) {
	id, err := GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	err = s.unauthRepo.VerifyEmail(ctx, id, req.Code)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) RequestPasswordReset(ctx context.Context, req *proto.RequestPasswordResetRequest) (*emptypb.Empty, error) {
	device, err := GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, err
	}
	foundUser, err := s.unauthRepo.GetUserByEmail(ctx, device, req.Email)
	if foundUser == nil || err != nil || !validEmail(req.Email) {
		return nil, status.Errorf(codes.NotFound, "User not found: %v", err)
	}

	code := generateVerificationCode()
	expirationTime := time.Now().Add(15 * time.Minute)
	err = s.unauthRepo.RequestPasswordReset(ctx, foundUser.ID, code, expirationTime, device)
	if err != nil {
		return nil, err
	}

	ipAddr := getIpAddr(ctx)

	// Send email with reset code
	err = s.sender.SendPasswordResetEmail(foundUser.Email, foundUser.Username, code, device.GetName(), ipAddr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to send reset code: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) ResetPassword(ctx context.Context, req *proto.ResetPasswordRequest) (*emptypb.Empty, error) {
	device, err := GetDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid foundUser ID: %v", err)
	}

	foundUser, err := s.unauthRepo.GetUserByEmail(ctx, device, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid foundUser E-mail: %v", err)
	}

	resetCode, err := s.unauthRepo.GetResetPasswordCode(ctx, &foundUser.ID, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Reset code not found: %v", err)
	}

	if resetCode.Used {
		return nil, status.Errorf(codes.AlreadyExists, "Reset code already used")
	}

	if resetCode.ExpiresAt.Before(time.Now()) {
		return nil, status.Errorf(codes.DeadlineExceeded, "Reset code has expired")
	}

	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to hash password: %v", err)
	}
	foundUser.PasswordHash = hashedPassword
	err = s.unauthRepo.ResetPassword(ctx, foundUser, device)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) GetUserSessions(ctx context.Context, req *proto.GetUserSessionsRequest) (*proto.GetUserSessionsResponse, error) {
	userID, sessionID, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	dbSessions, err := s.authRepo.GetUserSessions(ctx, userID, sessionID, device)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get user sessions: %v", err)
	}

	protoSessions := make([]*proto.Session, len(dbSessions))
	for i, dbSession := range dbSessions {
		protoSessions[i] = &proto.Session{
			Id:         dbSession.ID.String(),
			UserId:     dbSession.UserID.String(),
			DeviceInfo: dbSession.DeviceInfo,
			IpAddress:  dbSession.IPAddress,
			CreatedAt:  timestamppb.New(dbSession.CreatedAt),
			ExpiresAt:  timestamppb.New(dbSession.ExpiresAt),
		}
	}

	return &proto.GetUserSessionsResponse{Sessions: protoSessions}, nil
}

func (s *UserServiceServer) GetUsersByUsername(ctx context.Context, req *proto.GetUsersByUsernameRequest) (*proto.GetUsersByUsernameResponse, error) {
	userID, sessionID, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	if len(req.GetUsername()) == 0 {
		return nil, nil
	}

	dbUsers, err := s.authRepo.GetUsersByUsername(ctx, userID, sessionID, device, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get user sessions: %v", err)
	}

	users := make([]*proto.User, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = convertDBUserToProtoUser(dbUser)
	}

	return &proto.GetUsersByUsernameResponse{Username: req.GetUsername(), Users: users}, nil
}

func (s *UserServiceServer) DeleteSession(ctx context.Context, req *proto.DeleteSessionRequest) (*emptypb.Empty, error) {
	userID, sessionID, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	deleteSessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid session ID: %v", err)
	}

	err = s.authRepo.DeleteSession(ctx, userID, sessionID, &deleteSessionID, device)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to delete session: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) GetUserRoles(ctx context.Context, req *proto.GetUserRolesRequest) (*proto.GetUserRolesResponse, error) {
	userID, _, _, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	roles, err := s.authRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get user roles: %v", err)
	}

	return &proto.GetUserRolesResponse{Roles: roles}, nil
}

func (s *UserServiceServer) AddUserRole(ctx context.Context, req *proto.AddUserRoleRequest) (*emptypb.Empty, error) {
	userID, _, _, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid user ID: %v", err)
	}

	err = s.authRepo.AddUserRole(ctx, userID, req.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to add user role: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) RemoveUserRole(ctx context.Context, req *proto.RemoveUserRoleRequest) (*emptypb.Empty, error) {
	userID, _, _, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	err = s.authRepo.RemoveUserRole(ctx, userID, req.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to remove user role: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) UpdateUserAvatar(ctx context.Context, req *proto.UpdateUserAvatarRequest) (*emptypb.Empty, error) {
	userID, sessionID, device, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}

	err = s.authRepo.UpdateUserAvatar(ctx, userID, sessionID, device, req.AvatarUrl)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update user avatar: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *UserServiceServer) GetUserAvatarHistory(ctx context.Context, req *proto.GetUserAvatarHistoryRequest) (*proto.GetUserAvatarHistoryResponse, error) {
	userID, sessionID, _, err := GetUserDataFromMeta(ctx)
	if err != nil {
		return nil, err
	}
	avatarHistory, err := s.authRepo.GetUserAvatarHistory(ctx, userID, sessionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get user avatar history: %v", err)
	}

	protoAvatarHistory := make([]*proto.AvatarHistory, len(avatarHistory))
	for i, avatar := range avatarHistory {
		protoAvatarHistory[i] = &proto.AvatarHistory{
			AvatarUrl: avatar.AvatarURL,
			ChangedAt: timestamppb.New(avatar.ChangedAt),
		}
	}

	return &proto.GetUserAvatarHistoryResponse{History: protoAvatarHistory}, nil
}

// Helper functions

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func generateVerificationCode() string {
	const codeLength = 8
	return generateRandomString(codeLength)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[math.Intn(len(charset))]
	}
	return string(b)
}

func generateResetCode() string {
	const codeLength = 32 // 256 bits
	codeBytes := make([]byte, codeLength)

	_, err := rand.Read(codeBytes)
	if err != nil {
		// If we can't generate random numbers, fall back to a less secure method
		for i := range codeBytes {
			codeBytes[i] = byte(time.Now().UnixNano() & 0xff)
		}
	}

	return base64.URLEncoding.EncodeToString(codeBytes)
}

// Helper function to validate access token
func validateAccessToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.AccessTokenSecret, nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
		}
		return userID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid access token")
}

// Helper function to validate refresh token
func validateRefreshToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.RefreshTokenSecret, nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
		}
		return userID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid refresh token")
}

func getIpAddr(ctx context.Context) string {
	p, _ := peer.FromContext(ctx)
	return p.Addr.String()
}

func convertDBUserToProtoUser(dbUser *user.User) *proto.User {
	return &proto.User{
		Id:                 dbUser.ID.String(),
		Username:           dbUser.Username,
		Email:              dbUser.Email,
		Bio:                &dbUser.Bio.String,
		CurrentAvatarUrl:   &dbUser.CurrentAvatarURL.String,
		IsVerified:         dbUser.IsVerified,
		LastLogin:          timestamppb.New(dbUser.LastLogin.Time),
		CreatedAt:          timestamppb.New(dbUser.CreatedAt),
		UpdatedAt:          timestamppb.New(dbUser.UpdatedAt),
		AccountStatus:      dbUser.AccountStatus,
		TwoFactorEnabled:   dbUser.TwoFactorEnabled,
		LastPasswordChange: timestamppb.New(dbUser.LastPasswordChange.Time),
	}
}

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
