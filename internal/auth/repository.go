package auth

import (
	"database/sql"
	"time"
)

type Repository interface {
	CreateUser(user *User) (string, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUserVerificationStatus(email string, verified bool) error
	StoreEmailVerification(verification *EmailVerification) error
	GetEmailVerification(email string) (*EmailVerification, error)
	DeleteEmailVerification(email string) error
	GetUserByID(id string) (*User, error)
	UpdatePassword(email, hashedPassword string) error
	StoreResetCode(email, code string) error
	GetResetCode(email string) (string, time.Time, error)
	DeleteResetCode(email string) error
	StoreRefreshToken(refreshToken *RefreshToken) error
	GetRefreshToken(token string) (*RefreshToken, error)
	DeleteRefreshToken(token string) error
	DeleteUnverifiedUsers(expirationTime time.Time) (int64, error)
}

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateUser(user *User) (string, error) {
	var userID string
	err := r.db.QueryRow(
		"INSERT INTO users (username, email, password_hash, name, about, verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		user.Username, user.Email, user.PasswordHash, user.Name, user.About, false,
	).Scan(&userID)
	return userID, err
}

func (r *PostgresRepository) UpdateUserVerificationStatus(email string, verified bool) error {
	_, err := r.db.Exec("UPDATE users SET verified = $1 WHERE email = $2", verified, email)
	return err
}

func (r *PostgresRepository) StoreEmailVerification(verification *EmailVerification) error {
	_, err := r.db.Exec(
		"INSERT INTO email_verifications (email, code, expires_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET code = $2, expires_at = $3",
		verification.Email, verification.Code, verification.ExpiresAt,
	)
	return err
}

func (r *PostgresRepository) GetEmailVerification(email string) (*EmailVerification, error) {
	verification := &EmailVerification{}
	err := r.db.QueryRow("SELECT email, code, expires_at FROM email_verifications WHERE email = $1", email).
		Scan(&verification.Email, &verification.Code, &verification.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return verification, nil
}

func (r *PostgresRepository) DeleteEmailVerification(email string) error {
	_, err := r.db.Exec("DELETE FROM email_verifications WHERE email = $1", email)
	return err
}

func (r *PostgresRepository) GetUserByEmail(email string) (*User, error) {
	user := &User{}
	err := r.db.QueryRow("SELECT id, email, password_hash, verified FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Verified)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *PostgresRepository) StoreResetCode(email, code string) error {
	_, err := r.db.Exec("INSERT INTO reset_codes (email, code, created_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET code = $2, created_at = $3",
		email, code, time.Now())
	return err
}

func (r *PostgresRepository) GetResetCode(email string) (string, time.Time, error) {
	var code string
	var createdAt time.Time
	err := r.db.QueryRow("SELECT code, created_at FROM reset_codes WHERE email = $1", email).Scan(&code, &createdAt)
	return code, createdAt, err
}

func (r *PostgresRepository) DeleteResetCode(email string) error {
	_, err := r.db.Exec("DELETE FROM reset_codes WHERE email = $1", email)
	return err
}

func (r *PostgresRepository) UpdatePassword(email, hashedPassword string) error {
	_, err := r.db.Exec("UPDATE users SET password_hash = $1 WHERE email = $2", hashedPassword, email)
	return err
}

func (r *PostgresRepository) StoreRefreshToken(refreshToken *RefreshToken) error {
	_, err := r.db.Exec("INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)",
		refreshToken.Token, refreshToken.UserID, refreshToken.ExpiresAt)
	return err
}

func (r *PostgresRepository) GetRefreshToken(token string) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	err := r.db.QueryRow("SELECT token, user_id, expires_at FROM refresh_tokens WHERE token = $1", token).
		Scan(&refreshToken.Token, &refreshToken.UserID, &refreshToken.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}

func (r *PostgresRepository) DeleteRefreshToken(token string) error {
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE token = $1", token)
	return err
}

func (r *PostgresRepository) GetUserByID(id string) (*User, error) {
	user := &User{}
	err := r.db.QueryRow("SELECT id, username, email, name, about FROM users WHERE id = $1", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Name, &user.About)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *PostgresRepository) DeleteUnverifiedUsers(expirationTime time.Time) (int64, error) {
	result, err := r.db.Exec(`
		DELETE FROM users
		WHERE verified = false
		AND id IN (
			SELECT u.id
			FROM users u
			LEFT JOIN email_verifications ev ON u.email = ev.email
			WHERE u.verified = false
			AND (ev.expires_at < $1 OR ev.expires_at IS NULL)
		)
	`, expirationTime)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
