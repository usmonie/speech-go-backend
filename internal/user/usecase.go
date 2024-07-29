package user

import (
	"context"
	"speech/internal/sessions"
	"time"

	"speech/infrastructure"

	"github.com/google/uuid"
)

type AccountUseCase struct {
	userRepo           Repository
	sessionsRepository sessions.Repository
}

func NewUserAccountUseCase(userRepo Repository) *AccountUseCase {
	return &AccountUseCase{
		userRepo: userRepo,
	}
}

func (uc *AccountUseCase) CreateUser(
	ctx context.Context,
	email, username, bio string,
	device *sessions.Device,
	passwordHmac, salt, publicIdentityKey, publicSignedPreKey, signedPreKeySignature, publicKyberKey []byte,
	publicOneTimePreKeys [][]byte,
	encryptedPrivateKeys []byte,
) (string, string, *User, error) {
	// Validate input
	if username == "" || email == "" {
		return "", "", nil, infrastructure.ErrInvalidInput
	}

	// Check if user already exists
	existingUser, _ := uc.userRepo.GetByEmail(ctx, email)
	if existingUser != nil {
		return "", "", nil, infrastructure.ErrUserAlreadyExists
	}

	// Create user
	now := time.Now()
	user := &User{
		Username:              username,
		Email:                 email,
		Bio:                   bio,
		IsVerified:            false,
		CreatedAt:             now,
		UpdatedAt:             now,
		AccountStatus:         "active",
		PasswordHash:          passwordHmac,
		Salt:                  salt,
		PublicIdentityKey:     publicIdentityKey,
		PublicSignedPreKey:    publicSignedPreKey,
		SignedPreKeySignature: signedPreKeySignature,
		PublicKyberKey:        publicKyberKey,
		PublicOneTimePreKeys:  publicOneTimePreKeys,
		EncryptedPrivateKeys:  encryptedPrivateKeys,
	}

	user, err := uc.userRepo.Create(ctx, user)
	if err != nil {
		return "", "", nil, infrastructure.ErrInternalServer
	}

	ipAddr := GetIpAddr(ctx)
	accessToken, refreshToken, _, err := uc.sessionsRepository.CreateNewSession(ctx, user.ID, device, ipAddr)
	if err != nil {
		return "", "", nil, err
	}

	return accessToken, refreshToken, user, nil
}

func (uc *AccountUseCase) GetUserByID(ctx context.Context, id *uuid.UUID) (*User, error) {
	user, err := uc.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, infrastructure.ErrUserNotFound
	}
	return user, nil
}

func (uc *AccountUseCase) GetUsersByUsername(ctx context.Context, username string) (users []*User, err error) {
	return uc.userRepo.GetByUsername(ctx, username)
}

func (uc *AccountUseCase) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := uc.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, infrastructure.ErrUserNotFound
	}
	return user, nil
}

func (uc *AccountUseCase) UpdateUser(ctx context.Context, user *User) error {
	existingUser, err := uc.userRepo.GetByID(ctx, user.ID)
	if err != nil {
		return infrastructure.ErrUserNotFound
	}

	// Update only allowed fields
	existingUser.Username = user.Username
	existingUser.Bio = user.Bio
	existingUser.CurrentAvatarURL = user.CurrentAvatarURL
	existingUser.UpdatedAt = time.Now()

	err = uc.userRepo.Update(ctx, existingUser)
	if err != nil {
		return infrastructure.ErrInternalServer
	}

	return nil
}

func (uc *AccountUseCase) DeleteUser(ctx context.Context, id *uuid.UUID) error {
	err := uc.userRepo.Delete(ctx, id)
	if err != nil {
		return infrastructure.ErrInternalServer
	}
	return nil
}

func (uc *AccountUseCase) VerifyEmail(ctx context.Context, userID *uuid.UUID) error {
	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return infrastructure.ErrUserNotFound
	}

	user.IsVerified = true
	user.UpdatedAt = time.Now()

	err = uc.userRepo.Update(ctx, user)
	if err != nil {
		return infrastructure.ErrInternalServer
	}

	return nil
}

func (uc *AccountUseCase) ChangePassword(ctx context.Context, userID *uuid.UUID, oldPassword, newPassword string) error {
	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return infrastructure.ErrUserNotFound
	}

	// if !uc.authService.VerifyPassword(oldPassword, user.Salt, user.HashedPassword) {
	// return infrastructure.ErrUnauthorized
	// }
	//
	// salt, hashedPassword := uc.authService.HashPassword(newPassword)
	// user.Salt = salt
	// user.HashedPassword = hashedPassword
	user.LastPasswordChange = time.Now()
	user.UpdatedAt = time.Now()

	err = uc.userRepo.Update(ctx, user)
	if err != nil {
		return infrastructure.ErrInternalServer
	}

	return nil
}
