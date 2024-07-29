package user

import (
	"database/sql"
	"github.com/google/wire"
	"speech/internal/auth/verification"
	"speech/internal/user/storage"
)

func ProvideGrpcHandler(userUseCase *AccountUseCase) *Handler {
	return NewUserHandler(userUseCase)
}

func ProvideJsonHandler(userUseCase *AccountUseCase) *JSONHandler {
	return NewJSONHandler(userUseCase)
}

func ProvideAccountUseCase(userRepo Repository) *AccountUseCase {
	return NewUserAccountUseCase(userRepo)
}

func ProvideRepository(
	db *sql.DB,
	storage *storage.PostgresStorage,
) Repository {
	return NewRepository(db, storage, storage, storage, storage)
}

// ProvideUserStorage is a Wire provider function that creates a user.PostgresStorage
func ProvideUserStorage(db *sql.DB) *storage.PostgresStorage {
	return storage.NewUserPostgresStorage(db)
}

// ProvideVerificationStorage is a Wire provider function that creates a verification.PostgresStorage
func ProvideVerificationStorage(db *sql.DB) *verification.PostgresStorage {
	return verification.NewVerificationPostgresStorage(db)
}

var Set = wire.NewSet(ProvideUserStorage, ProvideVerificationStorage, ProvideRepository, ProvideAccountUseCase, ProvideGrpcHandler, ProvideJsonHandler)
