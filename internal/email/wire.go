package email

import (
	"database/sql"
	"github.com/google/wire"
	"speech/config"
	"speech/internal/auth/verification"
	"speech/internal/user"
)

// ProvideEmailSender is a Wire provider function that creates a Sender
func ProvideEmailSender(cfg *config.Config) *Sender {
	return NewEmailSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPUsername)
}

func ProvideHandler(sender *Sender, useCase UseCase) *Handler {
	return NewHandler(sender, useCase)
}

func ProvideJSONHandler(useCase UseCase) *JSONHandler {
	return NewJSONHandler(useCase)
}

func ProvideUseCase(usersRepository user.Repository, verificationsRepository Repository) UseCase {
	return NewEmailUseCase(usersRepository, verificationsRepository)
}

func ProvideRepository(db *sql.DB, storage *verification.PostgresStorage) Repository {
	return NewRepository(db, storage)
}

var Set = wire.NewSet(ProvideEmailSender, ProvideRepository, ProvideUseCase, ProvideHandler, ProvideJSONHandler)
