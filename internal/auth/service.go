package auth

import (
	"fmt"
	"gopkg.in/gomail.v2"
	"log"
	"math/rand"
	"speech/config"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Register(username, email, password, name, about string) (string, error)
	VerifyEmail(email, code string) error
	Login(email, password string) (*Token, error)
	ResendVerificationEmail(email string) error
	RefreshToken(refreshToken string) (*Token, error)
	ForgotPassword(email string) error
	ResetPassword(email, code, newPassword string) error
}

type AuthService struct {
	repo                   Repository
	jwtSecret              []byte
	smtpConfig             SMTPConfig
	tokenExpiry            time.Duration
	refreshExpiry          time.Duration
	verificationCodeExpiry time.Duration
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

func NewAuthService(repo Repository, cfg *config.Config, smtpConfig SMTPConfig) Service {
	s := &AuthService{
		repo:                   repo,
		jwtSecret:              cfg.JWTSecret,
		smtpConfig:             smtpConfig,
		tokenExpiry:            time.Hour,
		refreshExpiry:          time.Hour * 24 * 7, // 1 week
		verificationCodeExpiry: time.Minute * 15,   // 15 minutes
	}

	go s.startCleanupTask()

	return s
}

func (s *AuthService) Register(username, email, password, name, about string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Name:         name,
		About:        about,
		Verified:     false,
	}

	userID, err := s.repo.CreateUser(user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %v", err)
	}

	verificationCode := s.generateVerificationCode()
	err = s.repo.StoreEmailVerification(&EmailVerification{
		Email:     email,
		Code:      verificationCode,
		ExpiresAt: time.Now().Add(s.verificationCodeExpiry),
	})
	if err != nil {
		return "", fmt.Errorf("failed to store verification code: %v", err)
	}

	err = s.sendVerificationEmail(email, verificationCode)
	if err != nil {
		return "", fmt.Errorf("failed to send verification email: %v", err)
	}

	return userID, nil
}

func (s *AuthService) VerifyEmail(email, code string) error {
	verification, err := s.repo.GetEmailVerification(email)
	if err != nil {
		return fmt.Errorf("failed to get verification code: %v", err)
	}

	if verification.Code != code {
		return fmt.Errorf("invalid verification code")
	}

	if time.Now().After(verification.ExpiresAt) {
		return fmt.Errorf("verification code has expired")
	}

	err = s.repo.UpdateUserVerificationStatus(email, true)
	if err != nil {
		return fmt.Errorf("failed to update user verification status: %v", err)
	}

	err = s.repo.DeleteEmailVerification(email)
	if err != nil {
		return fmt.Errorf("failed to delete verification code: %v", err)
	}
	
	return nil
}

func (s *AuthService) Login(email, password string) (*Token, error) {
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %v", err)
	}

	if !user.Verified {
		return nil, fmt.Errorf("email not verified")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return s.generateTokenPair(user.ID)
}

func (s *AuthService) ResendVerificationEmail(email string) error {
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	if user.Verified {
		return fmt.Errorf("email already verified")
	}

	verificationCode := s.generateVerificationCode()
	err = s.repo.StoreEmailVerification(&EmailVerification{
		Email:     email,
		Code:      verificationCode,
		ExpiresAt: time.Now().Add(s.verificationCodeExpiry),
	})
	if err != nil {
		return fmt.Errorf("failed to store verification code: %v", err)
	}

	err = s.sendVerificationEmail(email, verificationCode)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %v", err)
	}

	return nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*Token, error) {
	storedToken, err := s.repo.GetRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	err = s.repo.DeleteRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old refresh token: %v", err)
	}

	return s.generateTokenPair(storedToken.UserID)
}

func (s *AuthService) GetUserByID(userID string) (*User, error) {
	return s.repo.GetUserByID(userID)
}

func (s *AuthService) ForgotPassword(email string) error {
	// Check if the user exists
	_, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Generate a reset code
	resetCode := s.generateResetCode()

	// Store the reset code
	err = s.repo.StoreResetCode(email, resetCode)
	if err != nil {
		return fmt.Errorf("failed to store reset code: %v", err)
	}

	// Send the reset code via email
	err = s.sendResetCodeEmail(email, resetCode)
	if err != nil {
		return fmt.Errorf("failed to send reset code email: %v", err)
	}

	return nil
}

func (s *AuthService) ResetPassword(email, code, newPassword string) error {
	// Verify the reset code
	storedCode, createdAt, err := s.repo.GetResetCode(email)
	if err != nil {
		return fmt.Errorf("failed to retrieve reset code: %v", err)
	}

	if storedCode != code {
		return fmt.Errorf("invalid reset code")
	}

	if time.Since(createdAt) > 15*time.Minute {
		return fmt.Errorf("reset code has expired")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %v", err)
	}

	// Update the user's password
	err = s.repo.UpdatePassword(email, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}

	// Delete the used reset code
	err = s.repo.DeleteResetCode(email)
	if err != nil {
		return fmt.Errorf("failed to delete reset code: %v", err)
	}

	return nil
}

func (s *AuthService) generateResetCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 8)
	for i := range code {
		code[i] = charset[rand.Intn(len(charset))]
	}
	return string(code)
}

func (s *AuthService) generateVerificationCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 6)
	for i := range code {
		code[i] = charset[rand.Intn(len(charset))]
	}
	return string(code)
}

func (s *AuthService) sendVerificationEmail(email, code string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.smtpConfig.Username)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Email Verification")
	m.SetBody("text/plain", fmt.Sprintf("Your verification code is: %s\nThis code will expire in 15 minutes.", code))

	d := gomail.NewDialer(s.smtpConfig.Host, s.smtpConfig.Port, s.smtpConfig.Username, s.smtpConfig.Password)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func (s *AuthService) sendResetCodeEmail(email, code string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.smtpConfig.Username)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Password Reset Code")
	m.SetBody("text/plain", fmt.Sprintf("Your password reset code is: %s\nThis code will expire in 15 minutes.", code))

	d := gomail.NewDialer(s.smtpConfig.Host, s.smtpConfig.Port, s.smtpConfig.Username, s.smtpConfig.Password)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func (s *AuthService) generateTokenPair(userID string) (*Token, error) {
	accessToken, err := s.generateJWTToken(userID, s.tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %v", err)
	}

	refreshToken := uuid.New().String()
	err = s.repo.StoreRefreshToken(&RefreshToken{
		Token:     refreshToken,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %v", err)
	}

	return &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) generateJWTToken(userID string, expiry time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(expiry).Unix(),
	})

	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) startCleanupTask() {
	ticker := time.NewTicker(s.verificationCodeExpiry)
	defer ticker.Stop()

	for {
		<-ticker.C
		s.cleanupUnverifiedUsers()
	}
}

func (s *AuthService) cleanupUnverifiedUsers() {
	expirationTime := time.Now().Add(-s.verificationCodeExpiry)
	deletedCount, err := s.repo.DeleteUnverifiedUsers(expirationTime)
	if err != nil {
		log.Printf("Error cleaning up unverified users: %v", err)
		return
	}
	log.Printf("Cleaned up %d unverified users", deletedCount)
}
