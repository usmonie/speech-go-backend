package storage

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                                                                                               *uuid.UUID
	Username                                                                                         string
	Email                                                                                            string
	Bio                                                                                              sql.NullString
	CurrentAvatarURL                                                                                 sql.NullString
	IsVerified                                                                                       bool
	LastLogin                                                                                        time.Time
	CreatedAt                                                                                        time.Time
	UpdatedAt                                                                                        time.Time
	AccountStatus                                                                                    string
	TwoFactorEnabled                                                                                 bool
	LastPasswordChange                                                                               time.Time
	PasswordHash, Salt, PublicIdentityKey, PublicSignedPreKey, SignedPreKeySignature, PublicKyberKey []byte
	PublicOneTimePreKeys                                                                             [][]byte
	EncryptedPrivateKeys                                                                             []byte
}

type Status struct {
	UserID         uuid.UUID
	IsOnline       bool
	LastSeenDate   time.Time
	LastUpdateTime time.Time
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
