package auth

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"speech/internal/auth/user"
	"speech/internal/auth/verification"
	"speech/internal/sessions"
	"time"
)

type AuthenticatedRepository interface {
	UpdateUser(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		username, email, bio *string,
		device *sessions.Device,
	) (*user.User, error)

	GetUsersByUsername(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
		username string,
	) ([]*user.User, error)

	GetUserById(
		ctx context.Context,
		userId *uuid.UUID,
		sessionId *uuid.UUID,
		device *sessions.Device,
		requestedUserId *uuid.UUID,
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

func (u *authenticatedRepository) UpdateUser(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, username, email, bio *string, device *sessions.Device) (*user.User, error) {
	var dbUser *user.User
	var err error
	err = u.withTransaction(ctx, userId, sessionId, func(tx *sql.Tx) error {

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
			return status.Errorf(codes.Internal, "Failed to update user: %v", err)
		}
		return nil
	})

	return dbUser, err
}

func (u *authenticatedRepository) GetUsersByUsername(
	ctx context.Context,
	userId *uuid.UUID,
	sessionId *uuid.UUID,
	device *sessions.Device,
	username string,
) ([]*user.User, error) {
	var users []*user.User
	var err error
	err = u.withTransaction(ctx, userId, sessionId, func(tx *sql.Tx) error {
		users, err = u.userProvider.UserByUsername(username)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *authenticatedRepository) GetUserById(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device, requestedUserId *uuid.UUID) (*user.User, error) {
	var userDb *user.User
	var err error
	err = u.withTransaction(ctx, userId, sessionId, func(tx *sql.Tx) error {
		userDb, err = u.userProvider.UserByID(requestedUserId)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return userDb, nil
}

func (u *authenticatedRepository) GetUserByUsername(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device, username string) ([]*user.User, error) {
	err := u.withTransaction(ctx, userId, sessionId, func(tx *sql.Tx) error {
		return nil
	})
	if err != nil {
		return nil, err
	}

	return u.userProvider.UserByUsername(username)
}

func (u *authenticatedRepository) UpdateUserAvatar(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device, avatarUrl string) error {
	return nil
}

func (u *authenticatedRepository) GetUserAvatarHistory(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) ([]*user.AvatarHistory, error) {
	return nil, nil
}

func (u *authenticatedRepository) DeleteUser(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.userDeleter.DeleteUser(tx, userId)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete user: %v", err)
		}
		return nil
	})
}

func (u *authenticatedRepository) GetUserSessions(ctx context.Context, userID *uuid.UUID, sessionId *uuid.UUID, device *sessions.Device) ([]*sessions.Session, error) {
	return u.sessionsProvider.GetUserSessions(userID)
}

func (u *authenticatedRepository) DeleteSession(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID, deleteSessionId *uuid.UUID, device *sessions.Device) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.sessionsDeleter.DeleteSession(tx, deleteSessionId)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete user: %v", err)
		}
		return nil
	})
}

func (u *authenticatedRepository) AddUserRole(ctx context.Context, userID *uuid.UUID, role string) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.userSaver.AddUserRole(tx, userID, role)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete user: %v", err)
		}
		return nil
	})
}

func (u *authenticatedRepository) GetUserRoles(ctx context.Context, userID *uuid.UUID) ([]string, error) {
	return u.userProvider.UserRoles(userID)
}

func (u *authenticatedRepository) RemoveUserRole(ctx context.Context, userID *uuid.UUID, role string) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.userDeleter.RemoveUserRole(tx, userID, role)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete user: %v", err)
		}
		return nil
	})
}

func (u *authenticatedRepository) withTransaction(ctx context.Context, userID, sessionID *uuid.UUID, operation func(*sql.Tx) error) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.updateSession(ctx, tx, userID, sessionID)
		if err != nil {
			return err
		}

		return operation(tx)
	})
}

func (u *authenticatedRepository) updateSession(ctx context.Context, tx *sql.Tx, userId, sessionID *uuid.UUID) error {
	_, err := u.userProvider.UserByID(userId)
	if err != nil {
		return status.Errorf(codes.NotFound, "User not found: %v", err)
	}
	ipAddr := getIpAddr(ctx)

	err = u.sessionsUpdater.UpdateSessionIpAddr(tx, sessionID, ipAddr)
	if err != nil {
		return status.Errorf(codes.NotFound, "Error while updating session: %v", err)
	}

	return nil
}
