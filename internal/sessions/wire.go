package sessions

import (
	"database/sql"
	"github.com/google/wire"
)

// ProvideSessionsStorage is a Wire provider function that creates a PostgresStorage
func ProvideSessionsStorage(db *sql.DB) *PostgresStorage {
	return NewSessionsPostgresStorage(db)
}

var Set = wire.NewSet(ProvideSessionsStorage)
