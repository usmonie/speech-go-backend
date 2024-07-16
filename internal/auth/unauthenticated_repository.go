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

type UnauthenticatedRepository interface {
	CreateUser(
		ctx context.Context,
		email, password, username, bio string,
		device *sessions.Device,
	) (string, string, *user.User, string, time.Time, error)

	SendVerificationEmail(ctx context.Context, userId *uuid.UUID) (*user.User, error)
	GetVerificationCode(ctx context.Context, userID *uuid.UUID, code string) (*verification.EmailVerification, error)
	VerifyEmail(ctx context.Context, userID *uuid.UUID, code string) error

	GetUserByEmail(
		ctx context.Context,
		device *sessions.Device,
		email string,
	) (*user.User, error)

	Login(
		ctx context.Context,
		email, password string,
		device *sessions.Device,
	) (string, string, *user.User, error)

	RefreshToken(ctx context.Context, token string, device *sessions.Device) (string, string, error)

	RequestPasswordReset(
		ctx context.Context,
		userID uuid.UUID,
		code string,
		expirationTime time.Time,
		device *sessions.Device,
	) error
	GetResetPasswordCode(ctx context.Context, userID *uuid.UUID, code string) (*verification.ResetCode, error)
	ResetPassword(ctx context.Context, updatedUser *user.User, device *sessions.Device) error
}

type unauthenticatedRepository struct {
	*sql.DB
	userSaver    user.Saver
	userUpdater  user.Updater
	userProvider user.Provider

	verificationsSaver    verification.Saver
	verificationsDeleter  verification.Deleter
	verificationsProvider verification.Provider

	sessionsSaver    sessions.Saver
	sessionsUpdater  sessions.Updater
	sessionsDeleter  sessions.Deleter
	sessionsProvider sessions.Provider
}

func NewUnauthenticatedRepository(
	db *sql.DB,
	userSaver user.Saver,
	userUpdater user.Updater,
	userProvider user.Provider,

	verificationsSaver verification.Saver,
	verificationsDeleter verification.Deleter,
	verificationsProvider verification.Provider,

	sessionsSaver sessions.Saver,
	sessionsUpdater sessions.Updater,
	sessionsDeleter sessions.Deleter,
	sessionsProvider sessions.Provider,
) UnauthenticatedRepository {
	return &unauthenticatedRepository{
		DB:           db,
		userSaver:    userSaver,
		userUpdater:  userUpdater,
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

func (u *unauthenticatedRepository) Login(
	ctx context.Context,
	email, password string,
	device *sessions.Device,
) (string, string, *user.User, error) {
	var accessToken, refreshToken string
	var dbUser *user.User

	var err error
	err = withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		dbUser, err = u.userProvider.UserByEmail(email)
		if err != nil {
			return status.Errorf(codes.NotFound, "User not found: %v", err)
		}

		if !verifyPassword(dbUser.PasswordHash, password) {
			return status.Errorf(codes.Unauthenticated, "Invalid password")
		}

		reqIpAddr := getIpAddr(ctx)
		accessToken, refreshToken, _, err = u.createNewSession(dbUser, device, reqIpAddr, err, tx)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", "", nil, err
	}
	return accessToken, refreshToken, dbUser, nil
}

func (u *unauthenticatedRepository) CreateUser(
	ctx context.Context,
	email, password, username, bio string,
	device *sessions.Device,
) (string, string, *user.User, string, time.Time, error) {
	var accessToken, refreshToken string
	var dbUser *user.User

	code := generateVerificationCode()
	expirationTime := time.Now().Add(15 * time.Minute)
	err := withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		hashedPassword, err := hashPassword(password)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to hash password: %v", err)
		}

		dbUser = &user.User{
			ID:               uuid.New(),
			Username:         username,
			Bio:              sql.NullString{String: bio, Valid: true},
			Email:            email,
			PasswordHash:     hashedPassword,
			IsVerified:       false,
			AccountStatus:    "active",
			TwoFactorEnabled: false,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		err = u.userSaver.SaveUser(tx, dbUser)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to create user: %v", err)
		}

		err = storeVerificationEmail(u.verificationsSaver, tx, dbUser.ID, code, expirationTime)
		if err != nil {
			return err
		}

		reqIpAddr := getIpAddr(ctx)
		accessToken, refreshToken, _, err = u.createNewSession(dbUser, device, reqIpAddr, err, tx)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", "", nil, "", time.Time{}, err
	}

	return accessToken, refreshToken, dbUser, code, expirationTime, nil
}

func (u *unauthenticatedRepository) GetUserByEmail(
	ctx context.Context,
	device *sessions.Device,
	email string,
) (*user.User, error) {
	return u.userProvider.UserByEmail(email)
}

func (u *unauthenticatedRepository) RequestPasswordReset(
	ctx context.Context,
	userID uuid.UUID,
	code string,
	expirationTime time.Time,
	device *sessions.Device,
) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		return u.verificationsSaver.StoreResetCode(
			tx,
			&verification.ResetCode{
				UserID:    userID,
				Code:      code,
				CreatedAt: time.Now(),
				ExpiresAt: expirationTime,
				Used:      false,
			},
		)
	})
}
func (u *unauthenticatedRepository) ResetPassword(ctx context.Context, updatedUser *user.User, device *sessions.Device) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		err := u.userUpdater.UpdatePassword(tx, &updatedUser.ID, updatedUser.PasswordHash)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to update password: %v", err)
		}

		err = u.verificationsDeleter.DeleteResetCode(tx, &updatedUser.ID)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete reset code: %v", err)
		}

		return nil
	})
}

func (u *unauthenticatedRepository) GetResetPasswordCode(ctx context.Context, userID *uuid.UUID, code string) (*verification.ResetCode, error) {
	return u.verificationsProvider.GetResetCode(userID, code)
}
func (u *unauthenticatedRepository) GetVerificationCode(ctx context.Context, userID *uuid.UUID, code string) (*verification.EmailVerification, error) {
	return u.verificationsProvider.GetEmailVerification(userID, code)
}

func (u *unauthenticatedRepository) SendVerificationEmail(ctx context.Context, userID *uuid.UUID) (*user.User, error) {

	return nil, nil
}
func (u *unauthenticatedRepository) VerifyEmail(ctx context.Context, userID *uuid.UUID, code string) error {
	return withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		resetCode, err := u.verificationsProvider.GetEmailVerification(userID, code)
		if err != nil {
			return status.Errorf(codes.NotFound, "Verification not found: %v", err)
		}

		if resetCode.Used {
			return status.Errorf(codes.AlreadyExists, "Verification code already used")
		}

		if resetCode.ExpiresAt.Before(time.Now()) {
			return status.Errorf(codes.DeadlineExceeded, "Verification code has expired")
		}

		err = u.userUpdater.UpdateUserVerificationStatus(tx, userID, true)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to update user code status: %v", err)
		}

		err = u.verificationsDeleter.DeleteEmailVerification(tx, userID)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete email code: %v", err)
		}

		return nil
	})
}

func (u *unauthenticatedRepository) RefreshToken(ctx context.Context, token string, device *sessions.Device) (string, string, error) {
	var newAccessToken, newRefreshToken string
	err := withTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		refreshToken, err := u.sessionsProvider.GetRefreshToken(token)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "Invalid refresh token: %v", err)
		}

		if refreshToken.ExpiresAt.Before(time.Now()) {
			return status.Errorf(codes.Unauthenticated, "Refresh token has expired")
		}

		session, err := u.sessionsProvider.GetSessionByID(&refreshToken.SessionID)
		if err != nil {
			return err
		}

		newAccessToken, newRefreshToken, err = u.createNewRefreshToken(&refreshToken.UserID, session, tx, time.Now())
		if err != nil {
			return err
		}

		err = u.sessionsDeleter.DeleteRefreshToken(tx, token)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to delete old refresh token: %v", err)
		}
		return nil
	})

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to refresh tokens: %v", err)
	}

	return newAccessToken, newRefreshToken, nil
}

func storeVerificationEmail(saver verification.Saver, tx *sql.Tx, userID uuid.UUID, code string, expirationTime time.Time) error {
	err := saver.StoreEmailVerification(tx, &verification.EmailVerification{
		UserID:    userID,
		Code:      code,
		CreatedAt: time.Now(),
		ExpiresAt: expirationTime,
		Used:      false,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to store email verification: %v", err)
	}

	return nil
}
func (u *unauthenticatedRepository) createNewSession(dbUser *user.User, device *sessions.Device, reqIpAddr string, err error, tx *sql.Tx) (string, string, *sessions.Session, error) {
	currentTime := time.Now()
	session := sessions.Session{
		ID:         uuid.New(),
		UserID:     dbUser.ID,
		DeviceInfo: device.GetName(),
		IPAddress:  reqIpAddr,
		CreatedAt:  currentTime,
		ExpiresAt:  currentTime.AddDate(1, 0, 0),
	}
	err = u.sessionsSaver.CreateSession(tx, &session)
	if err != nil {
		return "", "", nil, status.Errorf(codes.Internal, "Failed to create session: %v", err)
	}
	accessToken, refreshToken, err := u.createNewRefreshToken(&dbUser.ID, &session, tx, currentTime)
	if err != nil {
		return "", "", nil, err
	}
	return accessToken, refreshToken, &session, nil
}

func (u *unauthenticatedRepository) createNewRefreshToken(userID *uuid.UUID, session *sessions.Session, tx *sql.Tx, currentTime time.Time) (string, string, error) {
	accessToken, err := generateAccessToken(userID, &session.ID)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to generate access token: %v", err)
	}
	refreshToken, err := generateRefreshToken(userID, &session.ID)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to generate refresh token: %v", err)
	}
	err = u.sessionsSaver.StoreRefreshToken(tx, &sessions.RefreshToken{
		Token:      refreshToken,
		UserID:     *userID,
		SessionID:  session.ID,
		ExpiresAt:  currentTime.Add(7 * 24 * time.Hour),
		DeviceInfo: sql.NullString{String: session.DeviceInfo, Valid: true},
	})
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to store refresh token: %v", err)
	}

	return accessToken, refreshToken, nil
}
