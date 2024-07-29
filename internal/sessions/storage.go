package sessions

import (
	"database/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type Saver interface {
	StoreRefreshToken(tx *sql.Tx, refreshToken *RefreshToken) error
	CreateSession(tx *sql.Tx, session *Session) error
	AddUserDevice(tx *sql.Tx, device *Device) error
}

type Updater interface {
	UpdateSessionIpAddr(tx *sql.Tx, sessionID *uuid.UUID, ipAddr string) error
}

type Provider interface {
	GetRefreshToken(token string) (*RefreshToken, error)
	GetRefreshTokenBySessionId(sessionID *uuid.UUID, userId *uuid.UUID) (*RefreshToken, *Session, error)
	GetSessionByID(sessionID *uuid.UUID, userId *uuid.UUID) (*Session, error)
	GetUserSessions(userID *uuid.UUID) ([]*Session, error)
	GetUserDevices(userID *uuid.UUID) ([]*Device, error)
}

type Deleter interface {
	DeleteRefreshToken(tx *sql.Tx, token string) error

	DeleteSession(tx *sql.Tx, id *uuid.UUID) error

	RemoveUserDevice(tx *sql.Tx, id *uuid.UUID) error
}

type PostgresStorage struct {
	db *sql.DB
}

func NewSessionsPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

func (r *PostgresStorage) StoreRefreshToken(tx *sql.Tx, refreshToken *RefreshToken) error {
	_, err := tx.Exec(`
		INSERT INTO refresh_tokens (token, user_id, session_id, expires_at, created_at, device_info)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		refreshToken.Token, refreshToken.UserID, refreshToken.SessionID,
		refreshToken.ExpiresAt, refreshToken.CreatedAt, refreshToken.DeviceInfo)
	return err
}

func (r *PostgresStorage) GetRefreshToken(token string) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	err := r.db.QueryRow(`
		SELECT token, user_id, session_id, expires_at, created_at, device_info
		FROM refresh_tokens WHERE token = $1`, token).Scan(
		&refreshToken.Token, &refreshToken.UserID, &refreshToken.SessionID,
		&refreshToken.ExpiresAt, &refreshToken.CreatedAt, &refreshToken.DeviceInfo)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}

func (r *PostgresStorage) GetRefreshTokenBySessionId(sessionId *uuid.UUID, userId *uuid.UUID) (*RefreshToken, *Session, error) {
	session, err := r.GetSessionByID(sessionId, userId)
	if err != nil {
		return nil, nil, err
	}
	refreshToken := &RefreshToken{}
	err = r.db.QueryRow(`
		SELECT token, user_id, session_id, expires_at, created_at, device_info
		FROM refresh_tokens WHERE session_id = $1 AND user_id = $2`, sessionId, userId).Scan(
		&refreshToken.Token, &refreshToken.UserID, &refreshToken.SessionID,
		&refreshToken.ExpiresAt, &refreshToken.CreatedAt, &refreshToken.DeviceInfo)
	if err != nil {
		return nil, nil, err
	}
	return refreshToken, session, nil
}

func (r *PostgresStorage) DeleteRefreshToken(tx *sql.Tx, token string) error {
	_, err := tx.Exec("DELETE FROM refresh_tokens WHERE token = $1", token)
	return err
}

func (r *PostgresStorage) CreateSession(tx *sql.Tx, session *Session) error {
	_, err := tx.Exec(`
		INSERT INTO sessions (id, user_id, device_info, ip_address, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		session.ID, session.UserID, session.DeviceInfo, session.IPAddress, session.CreatedAt, session.ExpiresAt)
	return err
}

func (r *PostgresStorage) UpdateSessionIpAddr(tx *sql.Tx, sessionID *uuid.UUID, ipAddr string) error {
	_, err := tx.Exec("UPDATE sessions SET ip_address = $1 WHERE id = $2", ipAddr, sessionID)
	return err
}

func (r *PostgresStorage) GetSessionByID(sessionID *uuid.UUID, userId *uuid.UUID) (*Session, error) {
	session := &Session{}
	err := r.db.QueryRow(`
		SELECT id, user_id, device_info, ip_address, created_at, expires_at
		FROM sessions
		WHERE id = $1`,
		sessionID,
	).Scan(&session.ID, &session.UserID, &session.DeviceInfo, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get session: %v", err)
	}

	if session.UserID != userId {
		return nil, status.Error(codes.PermissionDenied, "User does not have access to this session")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, status.Error(codes.PermissionDenied, "Session expired")
	}

	return session, nil
}

func (r *PostgresStorage) GetUserSessions(userID *uuid.UUID) ([]*Session, error) {
	rows, err := r.db.Query(`
		SELECT id, user_id, device_info, ip_address, created_at, expires_at
		FROM sessions
		WHERE user_id = $1`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session := &Session{}
		err := rows.Scan(&session.ID, &session.UserID, &session.DeviceInfo, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (r *PostgresStorage) DeleteSession(tx *sql.Tx, id *uuid.UUID) error {
	_, err := tx.Exec("DELETE FROM sessions WHERE id = $1", id)
	return err
}

func (r *PostgresStorage) AddUserDevice(tx *sql.Tx, device *Device) error {
	_, err := tx.Exec(`
		INSERT INTO devices (id, user_id, name, token, os)
		VALUES ($1, $2, $3, $4, $5)`,
		device.ID, device.UserID, device.Name, device.Token, device.OS)
	return err
}

func (r *PostgresStorage) GetUserDevices(userID *uuid.UUID) ([]*Device, error) {
	rows, err := r.db.Query(`
		SELECT id, user_id, name, token, os
		FROM devices
		WHERE user_id = $1`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		device := &Device{}
		err := rows.Scan(&device.ID, &device.UserID, &device.Name, &device.Token, &device.OS)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (r *PostgresStorage) RemoveUserDevice(tx *sql.Tx, id *uuid.UUID) error {
	_, err := tx.Exec("DELETE FROM devices WHERE id = $1", id)
	return err
}
