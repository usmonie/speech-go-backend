package infrastructure

import "errors"

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUsersNotFound     = errors.New("users not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidInput      = errors.New("invalid input")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInternalServer    = errors.New("internal server error")

	ErrMissingDeviceInfo = errors.New("missing device info")
	ErrMissingKey        = errors.New("missing key")
	ErrMissingToken      = errors.New("missing access token")
	ErrInvalidToken      = errors.New("invalid access token")
	ErrTokenExpired      = errors.New("access token has expired")
)
