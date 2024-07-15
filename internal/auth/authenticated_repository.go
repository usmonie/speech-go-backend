package auth

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"speech/internal/auth/proto"
	"speech/internal/auth/user"
	"speech/internal/auth/verification"
	"speech/internal/sessions"
	"time"
)

type AuthenticatedRepository interface {
	UpdateUser(
		ctx context.Context,
		id *uuid.UUID,
		sessionId *uuid.UUID,
		username, email, bio *string,
		device *sessions.Device,
	) (*user.User, error)

	GetUserByUsername(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
		username string,
	) (*user.User, error)

	DeleteUser(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
	) error

	UpdateUserAvatar(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
		avatarUrl string,
	) error
	GetUserAvatarHistory(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
	) ([]*user.AvatarHistory, error)

	GetUserSessions(
		ctx context.Context,
		userID *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
	) ([]*sessions.Session, error)
	DeleteSession(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		deleteSessionId *uuid.UUID,
		device *sessions.Device,
	) error

	AddUserDevice(ctx context.Context, userId *uuid.UUID, device *sessions.Device) (*sessions.Device, error)
	GetUserDevices(ctx context.Context, userId *uuid.UUID) ([]*sessions.Device, error)
	RemoveUserDevice(ctx context.Context, userId *uuid.UUID, deviceId uuid.UUID) error

	AddUserRole(
		ctx context.Context,
		userID *uuid.UUID,
		role string,
	) error
	GetUserRoles(ctx context.Context, userID *uuid.UUID, ) ([]string, error)
	RemoveUserRole(ctx context.Context, userID *uuid.UUID, role string) error
}

type authenticatedRepository struct {
	*sql.DB
	userSaver    user.Saver
	userUpdater  user.Updater
	userDeleter  user.Deleter
	userProvider user.Provider

	verificationsSaver    verification.Saver
	verificationsDeleter  verification.Deleter
	verificationsProvider verification.Provider

	sessionsSaver    sessions.Saver
	sessionsUpdater  sessions.Updater
	sessionsDeleter  sessions.Deleter
	sessionsProvider sessions.Provider
}

func (u *authenticatedRepository) GetUserByUsername(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device, username string) (*user.User, error) {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) UpdateUserAvatar(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device, avatarUrl string) error {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) GetUserAvatarHistory(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) ([]*user.AvatarHistory, error) {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) GetUserSessions(ctx context.Context, userID *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device) ([]*sessions.Session, error) {
	return  u.sessionsProvider.GetUserSessions(userID)
}

func (u *authenticatedRepository) DeleteSession(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, deleteSessionId *uuid.UUID, device *sessions.Device) error {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) AddUserDevice(ctx context.Context, userId *uuid.UUID, device *sessions.Device) (*sessions.Device, error) {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) GetUserDevices(ctx context.Context, userId *uuid.UUID) ([]*sessions.Device, error) {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) RemoveUserDevice(ctx context.Context, userId *uuid.UUID, deviceId uuid.UUID) error {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) AddUserRole(ctx context.Context, userID *uuid.UUID, role string) error {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) GetUserRoles(ctx context.Context, userID *uuid.UUID) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (u *authenticatedRepository) RemoveUserRole(ctx context.Context, userID *uuid.UUID, role string) error {
	//TODO implement me
	panic("implement me")
}

func NewAuthenticatedRepository(
	db *sql.DB,
	userSaver user.Saver,
	userUpdater user.Updater,
	userDeleter user.Deleter,
	userProvider user.Provider,

	verificationsSaver verification.Saver,
	verificationsDeleter verification.Deleter,
	verificationsProvider verification.Provider,

	sessionsSaver sessions.Saver,
	sessionsUpdater sessions.Updater,
	sessionsDeleter sessions.Deleter,
	sessionsProvider sessions.Provider,
) AuthenticatedRepository {
	return &authenticatedRepository{
		DB:           db,
		userSaver:    userSaver,
		userUpdater:  userUpdater,
		userDeleter:  userDeleter,
		userProvider: userProvider,

		verificationsSaver:    verificationsSaver,
		verificationsDeleter:  verificationsDeleter,
		verificationsProvider: verificationsProvider,

		sessionsSaver:    sessionsSaver,
		sessionsUpdater:  sessionsUpdater,
		sessionsDeleter:  sessionsDeleter,
		sessionsProvider: sessionsProvider,
	}
}

func (u *authenticatedRepository) UpdateUser(ctx context.Context, id *uuid.UUID, sessionId *uuid.UUID, username, email, bio *string, device *sessions.Device) (*user.User, error) {
	// Start a database transaction
	tx, err := u.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to start transaction: %v", err)
	}

	defer func(tx *sql.Tx) {
		err = tx.Rollback()
		if err != nil {
			slog.Log(ctx, slog.LevelError, "Error while committing transaction", err)
		}
	}(tx) // Will be ignored if tx.Commit() is called

	dbUser, err := u.userProvider.UserByID(id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "User not found: %v", err)
	}

	if username != nil {
		dbUser.Username = *username
	}
	if email != nil {
		dbUser.Email = *email
	}
	if bio != nil {
		dbUser.Bio = sql.NullString{String: *bio, Valid: true}
	}

	dbUser.UpdatedAt = time.Now()

	err = u.userUpdater.UpdateUser(tx, dbUser)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update user: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return dbUser, nil
}

func (u *authenticatedRepository) GetUser(ctx context.Context, req *proto.GetUserRequest) (*user.User, error) {
	var dbUser *user.User
	var err error

	switch req.Identifier.(type) {
	case *proto.GetUserRequest_Id:
		userID, err := uuid.Parse(req.GetId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid user ID: %v", err)
		}
		dbUser, err = u.userProvider.UserByID(&userID)
	case *proto.GetUserRequest_Email:
		dbUser, err = u.userProvider.UserByEmail(req.GetEmail())
	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid identifier provided")
	}

	if err != nil {
		return nil, status.Errorf(codes.NotFound, "User not found: %v", err)
	}

	return dbUser, nil
}

func (u *authenticatedRepository) DeleteUser(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device) error {
	// Start a database transaction
	tx, err := u.BeginTx(ctx, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to start transaction: %v", err)
	}

	defer func(tx *sql.Tx) {
		err = tx.Rollback()
		if err != nil {
			slog.Log(ctx, slog.LevelError, "Error while committing transaction", err)
		}
	}(tx) // Will be ignored if tx.Commit() is called

	err = u.userDeleter.DeleteUser(tx, userId)
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to delete user: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (u *unauthenticatedRepository) updateSession(ctx context.Context, tx *sql.Tx, sessionID *uuid.UUID) error {
	ipAddr := getIpAddr(ctx)

	err := u.sessionsUpdater.UpdateSessionIpAddr(tx, sessionID, ipAddr)
	if err != nil {
		return err
	}

	return nil
}
