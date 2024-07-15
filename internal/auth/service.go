package auth

//
//
//import (
//	"fmt"
//	"gopkg.in/gomail.v2"
//	"log"
//	"math/rand"
//	"speech/config"
//	"speech/internal/notifications"
//	"time"
//
//	"github.com/dgrijalva/jwt-go"
//	"github.com/google/uuid"
//	"golang.org/x/crypto/bcrypt"
//)
//
//type Service interface {
//	Register(username, email, password, name, about string) (string, error)
//	VerifyEmail(userID, code string) (*Token, error)
//	Login(email, password, ipAddress, deviceInfo, deviceType string) (*Token, error)
//	ResendVerificationEmail(email string) error
//	RefreshToken(refreshToken string) (*Token, error)
//	ForgotPassword(email string) error
//	ResetPassword(userID, code, newPassword string) error
//	GetUserByID(userID string) (*User, error)
//	UpdateUserProfile(userID string, profile *UserProfile) error
//	ChangePassword(userID, currentPassword, newPassword string) error
//	EnableTwoFactor(userID string) (string, error)
//	DisableTwoFactor(userID, verificationCode string) error
//	//	GetUserRoles(userID string) ([]string, error)
//	//	AddUserRole(userID, role string) error
//	//	RemoveUserRole(userID, role string) error
//}
//
//type AuthService struct {
//	userSaver                   OldRepository
//	jwtSecret              []byte
//	smtpConfig             SMTPConfig
//	tokenExpiry            time.Duration
//	refreshExpiry          time.Duration
//	verificationCodeExpiry time.Duration
//	notificationService    notifications.NotificationService
//}
//
//func NewAuthService(userSaver OldRepository, cfg *config.Config, smtpConfig SMTPConfig) Service {
//	s := &AuthService{
//		userSaver:                   userSaver,
//		jwtSecret:              cfg.JWTSecret,
//		smtpConfig:             smtpConfig,
//		tokenExpiry:            time.Hour,
//		refreshExpiry:          time.Hour * 24 * 7, // 1 week
//		verificationCodeExpiry: time.Hour,          // 1 hour
//	}
//
//	go s.startCleanupTask()
//
//	return s
//}
//
//func (s *AuthService) Register(username, email, password, name, about string) (string, error) {
//	hashedPassword, err := s.hashPassword(password)
//	if err != nil {
//		return "", fmt.Errorf("failed to hash password: %v", err)
//	}
//
//	user := &User{
//		Username:     username,
//		Email:        email,
//		PasswordHash: hashedPassword,
//		Name:         name,
//		About:        about,
//		Verified:     false,
//	}
//
//	userID, err := s.userSaver.CreateUser(user)
//	if err != nil {
//		return "", fmt.Errorf("failed to create user: %v", err)
//	}
//
//	verificationCode := s.generateVerificationCode()
//	err = s.userSaver.StoreEmailVerification(&EmailVerification{
//		UserID:    userID,
//		Code:      verificationCode,
//		ExpiresAt: time.Now().Add(s.verificationCodeExpiry),
//	})
//	if err != nil {
//		return "", fmt.Errorf("failed to store verification code: %v", err)
//	}
//
//	err = s.storeVerificationEmail(email, verificationCode)
//	if err != nil {
//		return "", fmt.Errorf("failed to send verification email: %v", err)
//	}
//
//	return userID, nil
//}
//
//func (s *AuthService) VerifyEmail(userID, code string) (*Token, error) {
//	verification, err := s.userSaver.GetEmailVerification(userID, code)
//	if err != nil {
//		return nil, fmt.Errorf("failed to get verification code: %v", err)
//	}
//
//	if time.Now().After(verification.ExpiresAt) {
//		return nil, fmt.Errorf("verification code has expired")
//	}
//
//	err = s.userSaver.UpdateUserVerificationStatus(userID, true)
//	if err != nil {
//		return nil, fmt.Errorf("failed to update user verification status: %v", err)
//	}
//
//	err = s.userSaver.DeleteEmailVerification(userID)
//	if err != nil {
//		return nil, fmt.Errorf("failed to delete verification code: %v", err)
//	}
//
//	return s.generateTokenPair(userID)
//}
//
//func (s *AuthService) Login(email, password, ipAddress, deviceInfo, deviceType string) (*Token, error) {
//	user, err := s.userSaver.GetUserByEmail(email)
//	if err != nil {
//		return nil, fmt.Errorf("failed to retrieve user: %v", err)
//	}
//
//	if !user.Verified {
//		return nil, fmt.Errorf("email not verified")
//	}
//
//	err = s.comparePasswords(user.PasswordHash, password)
//	if err != nil {
//		s.recordLoginAttempt(user.ID, ipAddress, false)
//		return nil, fmt.Errorf("invalid password")
//	}
//
//	err = s.userSaver.UpdateLastLogin(user.ID)
//	if err != nil {
//		log.Printf("Failed to update last login: %v", err)
//	}
//
//	s.recordLoginAttempt(user.ID, ipAddress, true)
//
//	token, err := s.generateTokenPair(user.ID)
//	if err != nil {
//		return nil, err
//	}
//
//	// Create a new session
//	session := &SessionDevice{
//		ID:         uuid.New().String(),
//		UserID:     user.ID,
//		DeviceInfo: deviceInfo,
//		IP:         ipAddress,
//		CreatedAt:  time.Now(),
//		ExpiresAt:  time.Now().Add(s.refreshExpiry),
//	}
//
//	err = s.userSaver.CreateSession(session)
//	if err != nil {
//		log.Printf("Failed to create session: %v", err)
//	}
//
//	// Notify other devices about the new session
//	go s.notifyNewSession(user.ID, session)
//
//	return token, nil
//}
//
//func (s *AuthService) recordLoginAttempt(userID, ipAddress string, success bool) {
//	attempt := &LoginAttempt{
//		UserID:      userID,
//		IPAddress:   ipAddress,
//		AttemptTime: time.Now(),
//		Success:     success,
//	}
//	err := s.userSaver.AddLoginAttempt(attempt)
//	if err != nil {
//		log.Printf("Failed to record login attempt: %v", err)
//	}
//}
//
//func (s *AuthService) ResendVerificationEmail(email string) error {
//	user, err := s.userSaver.GetUserByEmail(email)
//	if err != nil {
//		return fmt.Errorf("user not found: %v", err)
//	}
//
//	if user.Verified {
//		return fmt.Errorf("email already verified")
//	}
//
//	verificationCode := s.generateVerificationCode()
//	err = s.userSaver.StoreEmailVerification(&EmailVerification{
//		UserID:    user.ID,
//		Code:      verificationCode,
//		ExpiresAt: time.Now().Add(s.verificationCodeExpiry),
//	})
//	if err != nil {
//		return fmt.Errorf("failed to store verification code: %v", err)
//	}
//
//	return s.storeVerificationEmail(email, verificationCode)
//}
//
//func (s *AuthService) RefreshToken(refreshToken string) (*Token, error) {
//	storedToken, err := s.userSaver.GetRefreshToken(refreshToken)
//	if err != nil {
//		return nil, fmt.Errorf("invalid refresh token")
//	}
//
//	if time.Now().After(storedToken.ExpiresAt) {
//		return nil, fmt.Errorf("refresh token expired")
//	}
//
//	err = s.userSaver.DeleteRefreshToken(refreshToken)
//	if err != nil {
//		return nil, fmt.Errorf("failed to delete old refresh token: %v", err)
//	}
//
//	return s.generateTokenPair(storedToken.UserID)
//}
//
//func (s *AuthService) ForgotPassword(email string) error {
//	user, err := s.userSaver.GetUserByEmail(email)
//	if err != nil {
//		return fmt.Errorf("user not found: %v", err)
//	}
//
//	resetCode := s.generateResetCode()
//
//	err = s.userSaver.StoreResetCode(&ResetCode{
//		UserID:    user.ID,
//		Code:      resetCode,
//		ExpiresAt: time.Now().Add(15 * time.Minute),
//		Used:      false,
//	})
//	if err != nil {
//		return fmt.Errorf("failed to store reset code: %v", err)
//	}
//
//	return s.sendResetCodeEmail(email, resetCode)
//}
//
//func (s *AuthService) ResetPassword(userID, code, newPassword string) error {
//	resetCode, err := s.userSaver.GetResetCode(userID, code)
//	if err != nil {
//		return fmt.Errorf("failed to retrieve reset code: %v", err)
//	}
//
//	if resetCode.Used {
//		return fmt.Errorf("reset code has already been used")
//	}
//
//	if time.Now().After(resetCode.ExpiresAt) {
//		return fmt.Errorf("reset code has expired")
//	}
//
//	hashedPassword, err := s.hashPassword(newPassword)
//	if err != nil {
//		return fmt.Errorf("failed to hash new password: %v", err)
//	}
//
//	err = s.userSaver.UpdatePassword(userID, hashedPassword)
//	if err != nil {
//		return fmt.Errorf("failed to update password: %v", err)
//	}
//
//	err = s.userSaver.DeleteResetCode(userID)
//	if err != nil {
//		return fmt.Errorf("failed to delete reset code: %v", err)
//	}
//
//	return nil
//}
//
//func (s *AuthService) GetUserByID(userID string) (*User, error) {
//	return s.userSaver.GetUserByID(userID)
//}
//
//func (s *AuthService) UpdateUserProfile(userID string, profile *UserProfile) error {
//	user, err := s.userSaver.GetUserByID(userID)
//	if err != nil {
//		return fmt.Errorf("failed to retrieve user: %v", err)
//	}
//
//	user.Username = profile.Username
//	user.Name = profile.Name
//	user.About = profile.About
//	user.ProfilePictureURL = profile.ProfilePictureUrl
//
//	err = s.userSaver.UpdateUser(user)
//	if err != nil {
//		return fmt.Errorf("failed to update user profile: %v", err)
//	}
//
//	return nil
//}
//
//func (s *AuthService) ChangePassword(userID, currentPassword, newPassword string) error {
//	user, err := s.userSaver.GetUserByID(userID)
//	if err != nil {
//		return fmt.Errorf("failed to retrieve user: %v", err)
//	}
//
//	err = s.comparePasswords(user.PasswordHash, currentPassword)
//	if err != nil {
//		return fmt.Errorf("invalid current password")
//	}
//
//	hashedPassword, err := s.hashPassword(newPassword)
//	if err != nil {
//		return fmt.Errorf("failed to hash new password: %v", err)
//	}
//
//	err = s.userSaver.UpdatePassword(userID, hashedPassword)
//	if err != nil {
//		return fmt.Errorf("failed to update password: %v", err)
//	}
//
//	return nil
//}
//
//func (s *AuthService) EnableTwoFactor(userID string) (string, error) {
//	secret := s.generateTwoFactorSecret()
//
//	err := s.userSaver.EnableTwoFactor(userID, secret)
//	if err != nil {
//		return "", fmt.Errorf("failed to enable two-factor authentication: %v", err)
//	}
//
//	return secret, nil
//}
//
//func (s *AuthService) DisableTwoFactor(userID, verificationCode string) error {
//	user, err := s.userSaver.GetUserByID(userID)
//	if err != nil {
//		return fmt.Errorf("failed to retrieve user: %v", err)
//	}
//
//	if !user.TwoFactorEnabled {
//		return fmt.Errorf("two-factor authentication is not enabled for this user")
//	}
//
//	if !s.verifyTwoFactorCode(user.TwoFactorSecret, verificationCode) {
//		return fmt.Errorf("invalid verification code")
//	}
//
//	err = s.userSaver.DisableTwoFactor(userID)
//	if err != nil {
//		return fmt.Errorf("failed to disable two-factor authentication: %v", err)
//	}
//
//	return nil
//}
//func (s *AuthService) GetUserSessions(userID string) ([]*SessionDevice, error) {
//	return s.userSaver.GetUserSessions(userID)
//}
//
//// EndSession New method to end a session
//func (s *AuthService) EndSession(sessionID string) error {
//	return s.userSaver.DeleteSession(sessionID)
//}
//
//// AddUserDevice New method to add a user device
//func (s *AuthService) AddUserDevice(userID, deviceName, deviceToken string) error {
//	device := &Device{
//		ID:     uuid.New().String(),
//		UserID: userID,
//		Token:  deviceToken,
//		Name:   deviceName,
//	}
//	return s.userSaver.AddUserDevice(device)
//}
//
//// RemoveUserDevice New method to remove a user device
//func (s *AuthService) RemoveUserDevice(deviceID string) error {
//	return s.userSaver.RemoveUserDevice(deviceID)
//}
//
//// Helper methods...
//
//func (s *AuthService) generateResetCode() string {
//	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
//	code := make([]byte, 8)
//	for i := range code {
//		code[i] = charset[rand.Intn(len(charset))]
//	}
//	return string(code)
//}
//
//func (s *AuthService) generateVerificationCode() string {
//	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
//	code := make([]byte, 8)
//	for i := range code {
//		code[i] = charset[rand.Intn(len(charset))]
//	}
//	return string(code)
//}
//
//func (s *AuthService) generateTwoFactorSecret() string {
//	return s.generateRandomString(32)
//}
//
//func (s *AuthService) verifyTwoFactorCode(secret, code string) bool {
//	// In a real implementation, you would use a proper TOTP library to verify the code
//	// This is just a placeholder implementation
//	return len(code) == 6
//}
//
//func (s *AuthService) storeVerificationEmail(email, code string) error {
//	m := gomail.NewMessage()
//	m.SetHeader("From", s.smtpConfig.Username)
//	m.SetHeader("To", email)
//	m.SetHeader("Subject", "Email Verification")
//	m.SetBody("text/plain", fmt.Sprintf("Your verification code is: %s\nThis code will expire in 1 hour.", code))
//
//	d := gomail.NewDialer(s.smtpConfig.Host, s.smtpConfig.Port, s.smtpConfig.Username, s.smtpConfig.Password)
//
//	if err := d.DialAndSend(m); err != nil {
//		return fmt.Errorf("failed to send email: %v", err)
//	}
//
//	return nil
//}
//
//func (s *AuthService) sendResetCodeEmail(email, code string) error {
//	m := gomail.NewMessage()
//	m.SetHeader("From", s.smtpConfig.Username)
//	m.SetHeader("To", email)
//	m.SetHeader("Subject", "Password Reset Code")
//	m.SetBody("text/plain", fmt.Sprintf("Your password reset code is: %s\nThis code will expire in 15 minutes.", code))
//
//	d := gomail.NewDialer(s.smtpConfig.Host, s.smtpConfig.Port, s.smtpConfig.Username, s.smtpConfig.Password)
//
//	if err := d.DialAndSend(m); err != nil {
//		return fmt.Errorf("failed to send email: %v", err)
//	}
//
//	return nil
//}
//
//func (s *AuthService) generateTokenPair(userID string) (*Token, error) {
//	accessToken, err := s.generateJWTToken(userID, s.tokenExpiry)
//	if err != nil {
//		return nil, fmt.Errorf("failed to generate access token: %v", err)
//	}
//
//	refreshToken := uuid.New().String()
//	err = s.userSaver.StoreRefreshToken(&RefreshToken{
//		Token:     refreshToken,
//		UserID:    userID,
//		ExpiresAt: time.Now().Add(s.refreshExpiry),
//	})
//	if err != nil {
//		return nil, fmt.Errorf("failed to store refresh token: %v", err)
//	}
//
//	return &Token{
//		AccessToken:  accessToken,
//		RefreshToken: refreshToken,
//		UserID:       userID,
//	}, nil
//}
//
//func (s *AuthService) generateJWTToken(userID string, expiry time.Duration) (string, error) {
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
//		"user_id": userID,
//		"exp":     time.Now().Add(expiry).Unix(),
//	})
//
//	return token.SignedString(s.jwtSecret)
//}
//
//func (s *AuthService) startCleanupTask() {
//	ticker := time.NewTicker(s.verificationCodeExpiry)
//	defer ticker.Stop()
//
//	for {
//		<-ticker.C
//		s.cleanupUnverifiedUsers()
//	}
//}
//
//func (s *AuthService) cleanupUnverifiedUsers() {
//	expirationTime := time.Now().Add(-s.verificationCodeExpiry)
//	deletedCount, err := s.userSaver.DeleteUnverifiedUsers(expirationTime)
//	if err != nil {
//		log.Printf("Error cleaning up unverified users: %v", err)
//		return
//	}
//	log.Printf("Cleaned up %d unverified users", deletedCount)
//}
//
//func (s *AuthService) generateRandomString(length int) string {
//	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
//	b := make([]byte, length)
//	for i := range b {
//		b[i] = charset[rand.Intn(len(charset))]
//	}
//	return string(b)
//}
//
//func (s *AuthService) hashPassword(password string) (string, error) {
//	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//	if err != nil {
//		return "", fmt.Errorf("failed to hash password: %v", err)
//	}
//	return string(hashedPassword), nil
//}
//
//func (s *AuthService) comparePasswords(hashedPassword, password string) error {
//	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
//}
//
//func (s *AuthService) notifyNewSession(userID string, newSession *SessionDevice) {
//	devices, err := s.userSaver.GetUserDevices(userID)
//	if err != nil {
//		log.Printf("Failed to get user devices: %v", err)
//		return
//	}
//
//	sessionInfo := fmt.Sprintf("New login from %s on %s", newSession.IP, newSession.DeviceInfo)
//
//	for _, device := range devices {
//		err := s.notificationService.SendNewSessionNotification(userID, device.Token, sessionInfo)
//		if err != nil {
//			log.Printf("Failed to send notification to device %s: %v", device.ID, err)
//		}
//	}
//}
