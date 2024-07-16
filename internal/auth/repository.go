package auth

import (
	"context"
	"database/sql"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"time"
)

// timeOperation executes an operation and logs its execution time
func timeOperation(ctx context.Context, name string, operation func() error) error {
	start := time.Now()
	err := operation()
	elapsed := time.Since(start)
	slog.Log(ctx, slog.LevelInfo, fmt.Sprintf("Operation %s took %s", name, elapsed))
	return err
}

// withTransaction handles a database transaction and executes the given operation
func withTransaction(db *sql.DB, ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to start transaction: %v", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // re-throw panic after Rollback
		} else if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				slog.Log(ctx, slog.LevelError, "Error while rolling back transaction", rbErr)
			}
		} else {
			err = tx.Commit()
		}
	}()

	err = operation(tx)
	return err
}
