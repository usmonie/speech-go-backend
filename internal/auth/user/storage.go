package user

import (
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"time"
)

type Saver interface {
	SaveUser(tx *sql.Tx, user *User) error
	AddUserRole(tx *sql.Tx, userID *uuid.UUID, role string) error
	AddLoginAttempt(tx *sql.Tx, attempt *LoginAttempt) error
}

type Updater interface {
	UpdateUser(tx *sql.Tx, user *User) error
	UpdateLastLogin(tx *sql.Tx, userId *uuid.UUID) error
	UpdateUserVerificationStatus(tx *sql.Tx, userID *uuid.UUID, verified bool) error
	UpdatePassword(tx *sql.Tx, userID *uuid.UUID, hashedPassword string) error

	UpdateUserAvatar(tx *sql.Tx, userID *uuid.UUID, avatarURL string) error
}

type Provider interface {
	UserByEmail(email string) (*User, error)
	UserByID(id *uuid.UUID) (*User, error)

	UserAvatarHistory(userID *uuid.UUID) ([]AvatarHistory, error)
	UserRoles(userID *uuid.UUID) ([]string, error)

	LoginAttempts(userID *uuid.UUID, limit int) ([]*LoginAttempt, error)
}

type Deleter interface {
	DeleteUser(tx *sql.Tx, id *uuid.UUID) error
	DeleteUnverifiedUsers(tx *sql.Tx, expirationTime time.Time) (int64, error)

	RemoveUserRole(tx *sql.Tx, userID *uuid.UUID, role string) error
}

type PostgresStorage struct {
	db *sql.DB
}

func NewUserPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

func (r *PostgresStorage) SaveUser(tx *sql.Tx, user *User) error {
	_, err := tx.Exec(`
		INSERT INTO users (id, username, email, password_hash, bio, current_avatar_url, is_verified,
		                   last_login, created_at, updated_at, account_status, two_factor_enabled, last_password_change)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Bio, user.CurrentAvatarURL,
		user.IsVerified, user.LastLogin, user.CreatedAt, user.UpdatedAt, user.AccountStatus,
		user.TwoFactorEnabled, user.LastPasswordChange)
	return err
}

func (r *PostgresStorage) AddUserRole(tx *sql.Tx, userID *uuid.UUID, role string) error {
	_, err := tx.Exec("INSERT INTO user_roles (user_id, role) VALUES ($1, $2)", userID, role)
	return err
}

func (r *PostgresStorage) AddLoginAttempt(tx *sql.Tx, attempt *LoginAttempt) error {
	_, err := tx.Exec(`
		INSERT INTO login_attempts (user_id, ip_address, attempt_time, success)
		VALUES ($1, $2, $3, $4)`,
		attempt.UserID, attempt.IPAddress, attempt.AttemptTime, attempt.Success)
	return err
}

func (r *PostgresStorage) UpdateUser(tx *sql.Tx, user *User) error {
	_, err := tx.Exec(`
		UPDATE users SET
		username = $2, email = $3, password_hash = $4, bio = $5, current_avatar_url = $6,
		is_verified = $7, last_login = $8, updated_at = $9, account_status = $10,
		two_factor_enabled = $11, last_password_change = $12
		WHERE id = $1`,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Bio, user.CurrentAvatarURL,
		user.IsVerified, user.LastLogin, user.UpdatedAt, user.AccountStatus,
		user.TwoFactorEnabled, user.LastPasswordChange)
	return err
}

func (r *PostgresStorage) DeleteUser(tx *sql.Tx, id *uuid.UUID) error {
	_, err := tx.Exec("DELETE FROM users WHERE id = $1", id)
	return err
}

func (r *PostgresStorage) UpdateUserVerificationStatus(tx *sql.Tx, userID *uuid.UUID, verified bool) error {
	_, err := tx.Exec("UPDATE users SET is_verified = $1 WHERE id = $2", verified, userID)
	return err
}

func (r *PostgresStorage) UpdatePassword(tx *sql.Tx, userID *uuid.UUID, hashedPassword string) error {
	_, err := tx.Exec("UPDATE users SET password_hash = $1, last_password_change = $2 WHERE id = $3",
		hashedPassword, time.Now(), userID)
	return err
}

func (r *PostgresStorage) UpdateLastLogin(tx *sql.Tx, userID *uuid.UUID) error {
	_, err := tx.Exec("UPDATE users SET last_login = $1 WHERE id = $2", time.Now(), userID)
	return err
}

func (r *PostgresStorage) UpdateUserAvatar(tx *sql.Tx, userID *uuid.UUID, avatarURL string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("SELECT update_user_avatar($1, $2)", userID, avatarURL)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (r *PostgresStorage) UserByEmail(email string) (*User, error) {
	user := &User{}
	err := r.db.QueryRow(`
		SELECT id, username, email, password_hash, bio, current_avatar_url, is_verified, last_login,
		       created_at, updated_at, account_status, two_factor_enabled, last_password_change
		FROM users WHERE email = $1`, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Bio, &user.CurrentAvatarURL,
		&user.IsVerified, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt, &user.AccountStatus,
		&user.TwoFactorEnabled, &user.LastPasswordChange)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *PostgresStorage) UserByID(id *uuid.UUID) (*User, error) {
	user := &User{}
	err := r.db.QueryRow(`
		SELECT id, username, email, password_hash, bio, current_avatar_url, is_verified, last_login,
		       created_at, updated_at, account_status, two_factor_enabled, last_password_change
		FROM users WHERE id = $1`, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Bio, &user.CurrentAvatarURL,
		&user.IsVerified, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt, &user.AccountStatus,
		&user.TwoFactorEnabled, &user.LastPasswordChange)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *PostgresStorage) UserAvatarHistory(userID *uuid.UUID) ([]AvatarHistory, error) {
	rows, err := r.db.Query("SELECT * FROM get_user_avatar_history($1)", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []AvatarHistory
	for rows.Next() {
		var h AvatarHistory
		if err := rows.Scan(&h.AvatarURL, &h.ChangedAt); err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, nil
}

func (r *PostgresStorage) LoginAttempts(userID *uuid.UUID, limit int) ([]*LoginAttempt, error) {
	rows, err := r.db.Query(`
		SELECT id, user_id, ip_address, attempt_time, success
		FROM login_attempts
		WHERE user_id = $1
		ORDER BY attempt_time DESC
		LIMIT $2`,
		userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attempts []*LoginAttempt
	for rows.Next() {
		attempt := &LoginAttempt{}
		err := rows.Scan(&attempt.ID, &attempt.UserID, &attempt.IPAddress, &attempt.AttemptTime, &attempt.Success)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	return attempts, nil
}

func (r *PostgresStorage) UserRoles(userID *uuid.UUID) ([]string, error) {
	rows, err := r.db.Query("SELECT role FROM user_roles WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *PostgresStorage) RemoveUserRole(tx *sql.Tx, userID *uuid.UUID, role string) error {
	_, err := tx.Exec("DELETE FROM user_roles WHERE user_id = $1 AND role = $2", userID, role)
	return err
}

func (r *PostgresStorage) DeleteUnverifiedUsers(tx *sql.Tx, expirationTime time.Time) (int64, error) {
	result, err := tx.Exec(`
		DELETE FROM users
		WHERE is_verified = false
		AND id IN (
			SELECT u.id
			FROM users u
			LEFT JOIN email_verifications ev ON u.id = ev.user_id
			WHERE u.is_verified = false
			AND (ev.expires_at < $1 OR ev.expires_at IS NULL)
		)
	`, expirationTime)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Additional helper functions

func (r *PostgresStorage) BeginTx() (*sql.Tx, error) {
	return r.db.Begin()
}

func (r *PostgresStorage) CommitTx(tx *sql.Tx) error {
	return tx.Commit()
}

func (r *PostgresStorage) RollbackTx(tx *sql.Tx) error {
	return tx.Rollback()
}

// Error handling helper
func (r *PostgresStorage) handlePQError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505": // unique_violation
			return ErrDuplicateKey
		case "23503": // foreign_key_violation
			return ErrForeignKeyViolation
		default:
			return err
		}
	}
	return err
}

// Custom errors
var (
	ErrDuplicateKey        = errors.New("duplicate key violation")
	ErrForeignKeyViolation = errors.New("foreign key violation")
)
