package verification

import (
	"github.com/google/uuid"
	"time"
)

type EmailVerification struct {
	UserID    uuid.UUID
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

type ResetCode struct {
	UserID    uuid.UUID
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}
