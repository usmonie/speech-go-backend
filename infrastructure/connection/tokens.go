package infrastructure

import (
	"errors"
	"fmt"
	"speech/config"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type AuthTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenClaims represents the claims in the access token
type TokenClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

// RequestParams represents the claims in the access token
type RequestParams struct {
	jwt.RegisteredClaims
	UserID    *uuid.UUID
	SessionID *uuid.UUID
}

func Map(claims *TokenClaims) (*RequestParams, error) {
	userId, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, err
	}

	sessionId, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return nil, err
	}

	return &RequestParams{claims.RegisteredClaims, &userId, &sessionId}, nil
}

// ValidateAccessToken checks if the provided token is ValidEmail
func ValidateAccessToken(tokenString string) (*RequestParams, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return config.AccessTokenSecret, nil
	})

	if err != nil {
		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrTokenExpired
			}
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return Map(claims)
	}

	return nil, ErrInvalidToken
}

func GenerateAccessToken(userID *uuid.UUID, sessionID *uuid.UUID) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID.String()
	claims["session_id"] = sessionID.String()
	claims["exp"] = time.Now().Add(time.Hour).Unix() // Token expires in 1 hour

	tokenString, err := token.SignedString(config.AccessTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return tokenString, nil
}

func GenerateRefreshToken(userID *uuid.UUID, sessionID *uuid.UUID) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID.String()
	claims["session_id"] = sessionID.String()
	claims["exp"] = time.Now().Add(time.Hour * 24 * 7).Unix() // Token expires in 7 days

	tokenString, err := token.SignedString(config.RefreshTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return tokenString, nil
}
