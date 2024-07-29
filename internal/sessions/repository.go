package sessions

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"speech/infrastructure"
	"time"
)

type Repository interface {
	GetSessionByID(sessionId *uuid.UUID, userId *uuid.UUID) (*Session, error)
	GetSessionsByUser(userId *uuid.UUID) ([]*Session, error)

	CreateSession(ctx context.Context, session *Session) (*Session, error)
	CreateNewSession(ctx context.Context, userId *uuid.UUID, device *Device, reqIpAddr string) (string, string, *Session, error)

	DeleteSessionByID(ctx context.Context, id *uuid.UUID) error

	UpdateRefreshToken(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) (string, string, *Session, error)
	VerifyRefreshToken(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) (*Session, error)
}

type repository struct {
	*sql.DB
	provider Provider
	saver    Saver
	deleter  Deleter
}

func NewRepository(db *sql.DB, storage *PostgresStorage) Repository {
	return &repository{
		DB:       db,
		provider: storage,
		saver:    storage,
	}
}

// GetSessionByID implements Repository.
func (r *repository) GetSessionByID(sessionId *uuid.UUID, userId *uuid.UUID) (*Session, error) {
	return r.provider.GetSessionByID(sessionId, userId)
}

// GetSessionsByUser implements Repository.
func (r *repository) GetSessionsByUser(userId *uuid.UUID) ([]*Session, error) {
	return r.provider.GetUserSessions(userId)
}

func (r *repository) CreateSession(ctx context.Context, session *Session) (*Session, error) {
	err := infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		return nil
	})
	return nil, err
}

func (r *repository) CreateNewSession(ctx context.Context, userId *uuid.UUID, device *Device, reqIpAddr string) (accessToken string, refreshToken string, session *Session, err error) {
	err = infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		currentTime := time.Now()
		session := Session{
			UserID:     userId,
			DeviceInfo: device.GetName(),
			IPAddress:  reqIpAddr,
			CreatedAt:  currentTime,
			ExpiresAt:  currentTime.AddDate(1, 0, 0),
		}
		err = r.saver.CreateSession(tx, &session)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to create session: %v", err)
		}
		accessToken, refreshToken, err = r.createNewRefreshToken(userId, &session, tx, currentTime)
		if err != nil {
			return err
		}
		return nil
	})

	return accessToken, refreshToken, session, err
}

func (r *repository) DeleteSessionByID(ctx context.Context, id *uuid.UUID) error {
	return infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		return r.deleter.DeleteSession(tx, id)
	})
}

func (r *repository) UpdateRefreshToken(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) (accessToken string, refreshToken string, session *Session, err error) {
	err = infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		currentTime := time.Now()
		session, err = r.provider.GetSessionByID(sessionId, userId)
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to get session: %v", err)
		}

		accessToken, refreshToken, err = r.createNewRefreshToken(userId, session, tx, currentTime)

		return err
	})

	return accessToken, refreshToken, session, err
}

func (r *repository) VerifyRefreshToken(ctx context.Context, userId *uuid.UUID, sessionId *uuid.UUID) (*Session, error) {
	refreshToken, session, err := r.provider.GetRefreshTokenBySessionId(sessionId, userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to verify refresh token: %v", err)
	}

	claims, err := infrastructure.ValidateAccessToken(refreshToken.Token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to verify refresh token: %v", err)
	}

	if claims.UserID != userId {
		return nil, status.Errorf(codes.NotFound, "Failed to verify refresh token: this refresh token does not belong to this user")
	}
	if claims.SessionID != sessionId {
		return nil, status.Errorf(codes.NotFound, "Failed to verify refresh token: this refresh token does not belong to this session")
	}

	return session, nil
}

func (r *repository) createNewRefreshToken(userID *uuid.UUID, session *Session, tx *sql.Tx, currentTime time.Time) (string, string, error) {
	accessToken, err := infrastructure.GenerateAccessToken(userID, session.ID)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to generate access token: %v", err)
	}

	refreshToken, err := infrastructure.GenerateRefreshToken(userID, session.ID)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to generate refresh token: %v", err)
	}
	err = r.saver.StoreRefreshToken(tx, &RefreshToken{
		Token:      refreshToken,
		UserID:     userID,
		SessionID:  session.ID,
		ExpiresAt:  currentTime.Add(7 * 24 * time.Hour),
		DeviceInfo: sql.NullString{String: session.DeviceInfo, Valid: true},
	})
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "Failed to store refresh token: %v", err)
	}

	return accessToken, refreshToken, nil
}
