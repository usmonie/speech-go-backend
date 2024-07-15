package verification

import (
	"database/sql"
	"github.com/google/uuid"
)

type Saver interface {
	StoreEmailVerification(tx *sql.Tx, verification *EmailVerification) error
	StoreResetCode(tx *sql.Tx, resetCode *ResetCode) error
}

type Deleter interface {
	DeleteEmailVerification(tx *sql.Tx, userID *uuid.UUID) error
	DeleteResetCode(tx *sql.Tx, userID *uuid.UUID) error
}

type Provider interface {
	GetEmailVerification(userID *uuid.UUID, code string) (*EmailVerification, error)
	GetResetCode(userID *uuid.UUID, code string) (*ResetCode, error)
}

type PostgresStorage struct {
	db *sql.DB
}

func NewVerificationPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

func (r *PostgresStorage) StoreEmailVerification(tx *sql.Tx, verification *EmailVerification) error {
	_, err := tx.Exec(`
		INSERT INTO email_verifications (user_id, code, created_at, expires_at, used)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT ON CONSTRAINT email_verifications_pkey 
		DO UPDATE SET
		code = EXCLUDED.code, 
		created_at = EXCLUDED.created_at, 
		expires_at = EXCLUDED.expires_at, 
		used = EXCLUDED.used`,
		verification.UserID, verification.Code, verification.CreatedAt, verification.ExpiresAt, verification.Used)
	return err
}

func (r *PostgresStorage) GetEmailVerification(userID *uuid.UUID, code string) (*EmailVerification, error) {
	verification := &EmailVerification{}
	err := r.db.QueryRow(`
		SELECT user_id, code, created_at, expires_at, used
		FROM email_verifications
		WHERE user_id = $1 AND code = $2`,
		userID, code).Scan(
		&verification.UserID, &verification.Code, &verification.CreatedAt,
		&verification.ExpiresAt, &verification.Used)
	if err != nil {
		return nil, err
	}
	return verification, nil
}

func (r *PostgresStorage) DeleteEmailVerification(tx *sql.Tx, userID *uuid.UUID) error {
	_, err := tx.Exec("DELETE FROM email_verifications WHERE user_id = $1", userID)
	return err
}

func (r *PostgresStorage) StoreResetCode(tx *sql.Tx, resetCode *ResetCode) error {
	_, err := tx.Exec(`
		INSERT INTO reset_codes (user_id, code, created_at, expires_at, used)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, code) DO UPDATE SET
		created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, used = EXCLUDED.used`,
		resetCode.UserID, resetCode.Code, resetCode.CreatedAt, resetCode.ExpiresAt, resetCode.Used)
	return err
}

func (r *PostgresStorage) GetResetCode(userID *uuid.UUID, code string) (*ResetCode, error) {
	resetCode := &ResetCode{}
	err := r.db.QueryRow(`
		SELECT user_id, code, created_at, expires_at, used
		FROM reset_codes
		WHERE user_id = $1 AND code = $2`,
		userID, code,
	).Scan(
		&resetCode.UserID, &resetCode.Code, &resetCode.CreatedAt,
		&resetCode.ExpiresAt, &resetCode.Used)
	if err != nil {
		return nil, err
	}
	return resetCode, nil
}

func (r *PostgresStorage) DeleteResetCode(tx *sql.Tx, userID *uuid.UUID) error {
	_, err := tx.Exec("DELETE FROM reset_codes WHERE user_id = $1", userID)
	return err
}
