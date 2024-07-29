package sessions

import (
	"database/sql"

	"github.com/google/wire"
)

// ProvideSessionsStorage is a Wire provider function that creates a PostgresStorage
func ProvideSessionsStorage(db *sql.DB) *PostgresStorage {
	return NewSessionsPostgresStorage(db)
}

// ProvideRepository is a Wire provider function that creates a Repository
func ProvideRepository(db *sql.DB, storage *PostgresStorage) Repository {
	return NewRepository(db, storage)
}

// ProvideGetSession is a Wire provider function that creates a GetSession
func ProvideGetSession(repository Repository) GetSession {
	return NewGetSession(repository)
}

var Set = wire.NewSet(ProvideSessionsStorage, ProvideRepository, ProvideGetSession)
