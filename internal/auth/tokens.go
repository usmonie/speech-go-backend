package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"speech/config"
	"time"
)

// ValidateAccessToken checks if the provided token is validEmail
func ValidateAccessToken(tokenString string) (*TokenClaims, error) {
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
		return claims, nil
	}

	return nil, ErrInvalidToken
}

func generateAccessToken(userID *uuid.UUID, sessionID *uuid.UUID) (string, error) {
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

func generateRefreshToken(userID *uuid.UUID, sessionID *uuid.UUID) (string, error) {
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
