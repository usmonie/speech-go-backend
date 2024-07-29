package email

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"speech/infrastructure"
	"speech/internal/auth/verification"
	"time"
)

type Repository interface {
	GetVerificationCode(ctx context.Context, userID *uuid.UUID, code string) (*verification.EmailVerification, error)
	StoreVerificationEmail(ctx context.Context, email, code string, userId *uuid.UUID, expirationTime, createdAt time.Time) error
}

type repository struct {
	*sql.DB
	saver    verification.Saver
	deleter  verification.Deleter
	provider verification.Provider
}

func NewRepository(db *sql.DB, storage *verification.PostgresStorage) Repository {
	return &repository{
		DB:       db,
		saver:    storage,
		deleter:  storage,
		provider: storage,
	}
}

func (r *repository) GetVerificationCode(_ context.Context, userID *uuid.UUID, code string) (*verification.EmailVerification, error) {
	return r.provider.GetEmailVerification(userID, code)
}

func (r *repository) StoreVerificationEmail(ctx context.Context, email, code string, userId *uuid.UUID, expirationTime, createdAt time.Time) error {
	err := infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		err := r.saver.StoreEmailVerification(tx, &verification.EmailVerification{
			UserID:    userId,
			Code:      code,
			CreatedAt: createdAt,
			ExpiresAt: expirationTime,
			Used:      false,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to store email verification: %v", err)
		}
		return nil
	})
	return err
}
