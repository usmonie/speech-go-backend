package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"speech/infrastructure"
	"speech/infrastructure/pq4"
	"speech/internal/sessions"
	"speech/internal/user"
	"time"
)

// Errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
)

type UseCase interface {
	Login(
		ctx context.Context,
		email, password string,
		device *sessions.Device,
	) (*user.User, *infrastructure.AuthTokens, error)
	Logout(ctx context.Context, token string) error
	RefreshToken(ctx context.Context, refreshToken string) (*infrastructure.AuthTokens, error)
	VerifyToken(ctx context.Context, token string) (*user.User, error)
}

// authUseCase implements the business logic for authentication
type authUseCase struct {
	usersRepository    user.Repository
	sessionsRepository sessions.Repository
}

// NewAuthUseCase creates a new AuthUseCase
func NewAuthUseCase(usersRepository user.Repository, sessionsRepository sessions.Repository) UseCase {
	return &authUseCase{
		sessionsRepository: sessionsRepository,
	}
}

// Login authenticates a user and returns tokens
func (uc *authUseCase) Login(
	ctx context.Context,
	email, password string,
	device *sessions.Device,
) (*user.User, *infrastructure.AuthTokens, error) {
	userResult, err := uc.usersRepository.GetByEmail(ctx, email)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	hmacPassword, err := pq4.HmacPassword([]byte(password), userResult.Salt)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "Failed to generate password hash: %v", err)
	}

	if !hmac.Equal(hmacPassword, userResult.PasswordHash) {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Invalid password")
	}

	if err := bcrypt.CompareHashAndPassword(userResult.PasswordHash, []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	reqIpAddr := GetIpAddr(ctx)
	accessToken, refreshToken, _, err := uc.sessionsRepository.CreateNewSession(ctx, userResult.ID, device, reqIpAddr)
	if err != nil {
		return nil, nil, err
	}

	tokens := &infrastructure.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Hour), // Assuming 1 hour expiration
	}

	return userResult, tokens, nil
}

// Logout invalidates the user's tokens
func (uc *authUseCase) Logout(ctx context.Context, token string) error {
	claims, err := infrastructure.ValidateAccessToken(token)
	if err != nil {
		return err
	}

	return uc.sessionsRepository.DeleteSessionByID(ctx, claims.SessionID)
}

// RefreshToken generates new tokens using a refresh token
func (uc *authUseCase) RefreshToken(ctx context.Context, refreshToken string) (*infrastructure.AuthTokens, error) {
	claims, err := infrastructure.ValidateAccessToken(refreshToken)
	if err != nil {
		return nil, err
	}

	_, err = uc.sessionsRepository.VerifyRefreshToken(ctx, claims.UserID, claims.SessionID)
	if err != nil {
		return nil, err
	}

	newAccessToken, newRefreshToken, _, err := uc.sessionsRepository.UpdateRefreshToken(ctx, claims.UserID, claims.SessionID)

	if err != nil {
		return nil, err
	}

	return &infrastructure.AuthTokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(time.Hour), // Assuming 1 hour expiration
	}, nil
}

// VerifyToken validates the access token and returns the associated user
func (uc *authUseCase) VerifyToken(ctx context.Context, token string) (*user.User, error) {
	claims, err := infrastructure.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	userR, err := uc.usersRepository.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	return userR, nil
}
