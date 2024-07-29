package auth

import "speech/internal/models"

type RegisterRequest struct {
	Username              string                         `json:"username"`
	Email                 string                         `json:"email"`
	Bio                   string                         `json:"bio"`
	PasswordHash          []byte                         `json:"password_hash"`
	Salt                  []byte                         `json:"salt"`
	PublicIdentityKey     []byte                         `json:"public_identity_key"`
	PublicSignedPreKey    []byte                         `json:"public_signed_pre_key"`
	SignedPreKeySignature []byte                         `json:"signed_pre_key_signature"`
	PublicKyberKey        []byte                         `json:"public_kyber_key"`
	PublicOneTimePreKeys  [][]byte                       `json:"public_one_time_pre_keys"`
	EncryptedPrivateKeys  []*models.EncryptedPrivateKeys `json:"encrypted_private_keys"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

type UpdateUserRequest struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Bio      *string `json:"bio"`
}

type UpdateUserAvatarRequest struct {
	AvatarUrl string `json:"avatar_url"`
}
