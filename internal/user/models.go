package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                    *uuid.UUID `json:"id"`
	Username              string     `json:"username"`
	Email                 string     `json:"email"`
	Bio                   string     `json:"bio"`
	CurrentAvatarURL      string     `json:"current_avatar_url"`
	AccountStatus         string     `json:"account_status"`
	IsVerified            bool       `json:"is_verified"`
	TwoFactorEnabled      bool       `json:"two_factor_enabled"`
	LastLogin             time.Time  `json:"last_login"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	LastPasswordChange    time.Time  `json:"last_password_change"`
	PasswordHash          []byte     `json:"password_hash"`
	Salt                  []byte     `json:"salt"`
	PublicIdentityKey     []byte     `json:"public_identity_key"`
	PublicSignedPreKey    []byte     `json:"public_signed_pre_key"`
	SignedPreKeySignature []byte     `json:"signed_pre_key_signature"`
	PublicKyberKey        []byte     `json:"public_kyber_key"`
	PublicOneTimePreKeys  [][]byte   `json:"public_one_time_pre_keys"`
	EncryptedPrivateKeys  []byte     `json:"encrypted_private_keys"`
}
