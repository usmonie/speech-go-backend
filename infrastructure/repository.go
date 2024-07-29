package infrastructure

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	math "math/rand"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TimeOperation executes an operation and logs its execution time
func TimeOperation(ctx context.Context, name string, operation func() error) error {
	start := time.Now()
	err := operation()
	elapsed := time.Since(start)
	slog.Log(ctx, slog.LevelInfo, fmt.Sprintf("Operation %s took %s", name, elapsed))
	return err
}

// WithTransaction handles a database transaction and executes the given operation
func WithTransaction(db *sql.DB, ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to start transaction: %v", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // re-throw panic after Rollback
		} else if err != nil {
			if err := tx.Rollback(); err != nil {
				slog.Log(ctx, slog.LevelError, "Error while rolling back transaction", err)
			}
		} else {
			err = tx.Commit()
		}
	}()

	err = operation(tx)
	return err
}

func GenerateVerificationCode() string {
	const codeLength = 8
	return GenerateRandomString(codeLength)
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[math.Intn(len(charset))]
	}
	return string(b)
}

func GenerateResetCode() string {
	const codeLength = 32 // 256 bits
	codeBytes := make([]byte, codeLength)

	_, err := rand.Read(codeBytes)
	if err != nil {
		// If we can't generate random numbers, fall back to a less secure method
		for i := range codeBytes {
			codeBytes[i] = byte(time.Now().UnixNano() & 0xff)
		}
	}

	return base64.URLEncoding.EncodeToString(codeBytes)
}
