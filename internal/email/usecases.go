package email

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"speech/internal/user"
	"time"
)

type UseCase interface {
	StoreEmailVerification(ctx context.Context, email, code string, userId *uuid.UUID, expirationTime, createdAt time.Time) error
	VerifyEmail(ctx context.Context, email, code string) error
}

// emailUseCase implements the business logic for authentication
type emailUseCase struct {
	usersRepository         user.Repository
	verificationsRepository Repository
}

// NewEmailUseCase creates a new EmailUseCase
func NewEmailUseCase(usersRepository user.Repository, verificationsRepository Repository) UseCase {
	return &emailUseCase{
		usersRepository:         usersRepository,
		verificationsRepository: verificationsRepository,
	}
}

func (e *emailUseCase) VerifyEmail(ctx context.Context, email, code string) error {
	userDb, err := e.usersRepository.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	verificationCode, err := e.verificationsRepository.GetVerificationCode(ctx, userDb.ID, code)
	if err != nil {
		return err
	}

	if verificationCode.Code != code {
		return errors.New("verification code does not match")
	}

	userDb.IsVerified = true
	err = e.usersRepository.Update(ctx, userDb)
	if err != nil {
		return err
	}

	return nil
}

func (e *emailUseCase) StoreEmailVerification(
	ctx context.Context,
	email, code string,
	userId *uuid.UUID,
	expirationTime, createdAt time.Time,
) error {
	return e.verificationsRepository.StoreVerificationEmail(ctx, email, code, userId, expirationTime, createdAt)
}
