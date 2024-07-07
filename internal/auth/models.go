package auth

import "time"

type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	Name         string
	About        string
	Verified     bool
}

type EmailVerification struct {
	Email     string
	Code      string
	ExpiresAt time.Time
}

type Token struct {
	AccessToken  string
	RefreshToken string
}

type RefreshToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}
