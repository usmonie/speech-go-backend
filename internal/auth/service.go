package auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"

	"speech/internal/database"
)

type Service struct {
	db *database.Database
}

func NewService(db *database.Database) *Service {
	return &Service{db: db}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func (s *Service) Login(email, password string) (*TokenPair, error) {
	var user database.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	accessToken, err := generateToken(user.ID, "access", 15*time.Minute)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateToken(user.ID, "refresh", 7*24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func generateToken(userID uint, tokenType string, expiration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    tokenType,
		"exp":     time.Now().Add(expiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func (s *Service) RefreshToken(refreshToken string) (*TokenPair, error) {
	claims, err := validateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims["type"] != "refresh" {
		return nil, errors.New("invalid token type")
	}

	userID := uint(claims["user_id"].(float64))

	accessToken, err := generateToken(userID, "access", 15*time.Minute)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := generateToken(userID, "refresh", 7*24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *Service) Logout(refreshToken string) error {
	// In a more complex system, you would add the token to a blacklist here
	// For now, we'll just validate the token
	_, err := validateToken(refreshToken)
	return err
}
