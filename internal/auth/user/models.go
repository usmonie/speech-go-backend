package user

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID                 uuid.UUID
	Username           string
	Email              string
	PasswordHash       string
	Bio                sql.NullString
	CurrentAvatarURL   sql.NullString
	IsVerified         bool
	LastLogin          sql.NullTime
	CreatedAt          time.Time
	UpdatedAt          time.Time
	AccountStatus      string
	TwoFactorEnabled   bool
	LastPasswordChange sql.NullTime
}

type AvatarHistory struct {
	AvatarURL string
	ChangedAt time.Time
}

type LoginAttempt struct {
	ID          int64
	UserID      uuid.UUID
	IPAddress   string
	AttemptTime time.Time
	Success     bool
}
