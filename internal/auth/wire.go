package auth

import (
	"database/sql"
	"speech/internal/auth/user"
	"speech/internal/auth/verification"
	"speech/internal/email"
	"speech/internal/sessions"

	"github.com/google/wire"
)

// ProvideUserStorage is a Wire provider function that creates a user.PostgresStorage
func ProvideUserStorage(db *sql.DB) *user.PostgresStorage {
	return user.NewUserPostgresStorage(db)
}

// ProvideVerificationStorage is a Wire provider function that creates a verification.PostgresStorage
func ProvideVerificationStorage(db *sql.DB) *verification.PostgresStorage {
	return verification.NewVerificationPostgresStorage(db)
}

// ProvideAuthenticatedRepository is a Wire provider function that creates a AuthenticatedRepository
func ProvideAuthenticatedRepository(
	db *sql.DB,
	userStorage *user.PostgresStorage,
	verificationStorage *verification.PostgresStorage,
	sessionsStorage *sessions.PostgresStorage,
) AuthenticatedRepository {
	return NewAuthenticatedRepository(db, userStorage, userStorage, userStorage, userStorage, verificationStorage, verificationStorage, verificationStorage, sessionsStorage, sessionsStorage, sessionsStorage, sessionsStorage)
}

// ProvideUnauthenticatedRepository is a Wire provider function that creates a UnauthenticatedRepository
func ProvideUnauthenticatedRepository(
	db *sql.DB,
	userStorage *user.PostgresStorage,
	verificationStorage *verification.PostgresStorage,
	sessionsStorage *sessions.PostgresStorage,
) UnauthenticatedRepository {
	return NewUnauthenticatedRepository(db, userStorage, userStorage, userStorage, verificationStorage, verificationStorage, verificationStorage, sessionsStorage, sessionsStorage, sessionsStorage, sessionsStorage)
}

// ProvideUserServiceServer is a Wire provider function that creates a UserServiceServer
func ProvideUserServiceServer(authenticatedRepository AuthenticatedRepository, unauthenticatedRepository UnauthenticatedRepository, sender *email.Sender) *UserServiceServer {
	return NewUserServiceServer(authenticatedRepository, unauthenticatedRepository, sender)
}

var Set = wire.NewSet(
	ProvideUserStorage,
	ProvideVerificationStorage,
	ProvideAuthenticatedRepository,
	ProvideUnauthenticatedRepository,
	ProvideUserServiceServer,
)
