package connection

import (
	"context"
	"errors"
	"speech/infrastructure"
	"speech/internal/sessions"
	"strings"

	"github.com/google/uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	// List of methods that don't require authentication
	publicMethods = map[string]bool{
		"/auth.UserService/CreateUserTemp":       true,
		"/auth.UserService/Login":                true,
		"/auth.UserService/RefreshToken":         true,
		"/auth.UserService/RequestPasswordReset": true,
		"/auth.UserService/ResetPassword":        true,
	}
)

// AuthenticationInterceptor is a gRPC interceptor for authentication
func AuthenticationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	newCtx, err := extractDeviceInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid metadata: %v", err)
	}

	// Check if the method requires authentication
	if _, ok := publicMethods[info.FullMethod]; ok {
		return handler(newCtx, req)
	}

	token, err := extractTokenFromContext(newCtx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token: %v", err)
	}

	claims, err := infrastructure.ValidateAccessToken(token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token: %v", err)
	}

	// Add the user ID to the context
	newCtx = context.WithValue(newCtx, "user_id", claims.UserID)
	newCtx = context.WithValue(newCtx, "session_id", claims.SessionID)

	// Proceed with the request
	return handler(newCtx, req)
}

// extractTokenFromContext extracts the token from the gRPC context
func extractTokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", infrastructure.ErrMissingToken
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", infrastructure.ErrMissingToken
	}

	authHeader := values[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", infrastructure.ErrInvalidToken
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// extractTokenFromContext extracts the token from the gRPC context
func extractDeviceInfoFromContext(ctx context.Context) (context.Context, error) {
	newCtx, err := updateContextWithKey(ctx, "device_id")
	if err != nil {
		newCtx = context.WithValue(ctx, "device_id", uuid.New().String())
	}

	newCtx, err = updateContextWithKey(ctx, "device_name")
	if err != nil {
		return ctx, infrastructure.ErrMissingDeviceInfo
	}

	newCtx, err = updateContextWithKey(newCtx, "device_os")
	if err != nil {
		return ctx, infrastructure.ErrMissingDeviceInfo
	}

	newCtx, err = updateContextWithKey(newCtx, "device_os_version")
	if err != nil {
		return ctx, infrastructure.ErrMissingDeviceInfo
	}

	newCtx, err = updateContextWithKey(newCtx, "device_token")
	if err != nil {
		return ctx, infrastructure.ErrMissingDeviceInfo
	}

	return newCtx, nil
}

func updateContextWithKey(ctx context.Context, key string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, infrastructure.ErrMissingKey
	}

	values := md.Get(key)
	if len(values) == 0 {
		return ctx, infrastructure.ErrMissingKey
	}
	newCtx := context.WithValue(ctx, key, values[0])

	return newCtx, nil
}

// GetUserIDFromContext retrieves the user ID from the context
func GetUserIDFromContext(ctx context.Context) (*uuid.UUID, error) {
	id, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, errors.New("user ID not found in context")
	}
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid user ID: %v", err)
	}
	return &userID, nil
}

// GetSessionIDFromContext retrieves the session ID from the context
func GetSessionIDFromContext(ctx context.Context) (*uuid.UUID, error) {
	id, ok := ctx.Value("session_id").(string)
	if !ok {
		return nil, errors.New("session ID not found in context")
	}
	sessionID, err := uuid.Parse(id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid session ID: %v", err)
	}
	return &sessionID, nil
}

// GetDeviceInfoFromContextWithUserID retrieves the device info from the context
func GetDeviceInfoFromContextWithUserID(ctx context.Context, userID uuid.UUID) (*sessions.Device, error) {
	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		deviceID = uuid.New().String()
	}

	deviceName, ok := ctx.Value("device_name").(string)
	if !ok {
		return nil, errors.New("missing device name")
	}

	deviceOS, ok := ctx.Value("device_os").(string)
	if !ok {
		return nil, errors.New("missing device os")
	}

	deviceOSVersion, ok := ctx.Value("device_os_version").(string)
	if !ok {
		return nil, errors.New("missing device os version")
	}

	deviceToken, ok := ctx.Value("device_token").(string)
	if !ok {
		return nil, errors.New("missing device token")
	}

	return &sessions.Device{
		ID:      uuid.MustParse(deviceID),
		UserID:  userID,
		Name:    deviceName,
		Token:   deviceToken,
		OS:      sessions.DeviceOS(deviceOS),
		Version: deviceOSVersion,
	}, nil
}

// GetDeviceInfoFromContext retrieves the device info from the context
func GetDeviceInfoFromContext(ctx context.Context) (*sessions.Device, error) {
	return GetDeviceInfoFromContextWithUserID(ctx, uuid.New())
}

func GetUserDataFromMeta(ctx context.Context) (*uuid.UUID, *uuid.UUID, *sessions.Device, error) {
	userID, err := GetUserIDFromContext(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	sessionID, err := GetSessionIDFromContext(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	device, err := GetDeviceInfoFromContextWithUserID(ctx, *userID)
	if err != nil {
		return nil, nil, nil, err
	}

	return userID, sessionID, device, nil
}
