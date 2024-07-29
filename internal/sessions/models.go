package sessions

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

type DeviceOS string

const (
	iOS     DeviceOS = "iOS"
	Android          = "Android"
	MacOs            = "MacOs"
	Windows          = "Windows"
	Linux            = "Linux"
	Web              = "Web"
)

type RefreshToken struct {
	Token      string
	UserID     *uuid.UUID
	SessionID  *uuid.UUID
	ExpiresAt  time.Time
	CreatedAt  time.Time
	DeviceInfo sql.NullString
}

type Session struct {
	ID               *uuid.UUID
	UserID           *uuid.UUID
	DeviceInfo       string
	IPAddress        string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	SessionSecretKey []byte
}

type Device struct {
	ID      uuid.UUID
	UserID  uuid.UUID
	Name    string
	Token   string
	OS      DeviceOS
	Version string
}

// SMTPConfig struct (if not already defined elsewhere)
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func (d *Device) GetName() string {
	return d.Name + " " + string(d.OS) + " " + d.Version
}
