package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	math "math/rand"
	"net/mail"
	"speech/config"
	"speech/internal/proto"
	"speech/internal/user/storage"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ConvertDBUserToProtoUser(dbUser *storage.User) *proto.User {
	return &proto.User{
		Id:                 dbUser.ID.String(),
		Username:           dbUser.Username,
		Email:              dbUser.Email,
		Bio:                &dbUser.Bio.String,
		CurrentAvatarUrl:   &dbUser.CurrentAvatarURL.String,
		IsVerified:         dbUser.IsVerified,
		LastLogin:          timestamppb.New(dbUser.LastLogin),
		CreatedAt:          timestamppb.New(dbUser.CreatedAt),
		UpdatedAt:          timestamppb.New(dbUser.UpdatedAt),
		AccountStatus:      dbUser.AccountStatus,
		TwoFactorEnabled:   dbUser.TwoFactorEnabled,
		LastPasswordChange: timestamppb.New(dbUser.LastPasswordChange),
	}
}

func ConvertUserToProtoUser(dbUser *User) *proto.User {
	return &proto.User{
		Id:                 dbUser.ID.String(),
		Username:           dbUser.Username,
		Email:              dbUser.Email,
		Bio:                &dbUser.Bio,
		CurrentAvatarUrl:   &dbUser.CurrentAvatarURL,
		IsVerified:         dbUser.IsVerified,
		LastLogin:          timestamppb.New(dbUser.LastLogin),
		CreatedAt:          timestamppb.New(dbUser.CreatedAt),
		UpdatedAt:          timestamppb.New(dbUser.UpdatedAt),
		AccountStatus:      dbUser.AccountStatus,
		TwoFactorEnabled:   dbUser.TwoFactorEnabled,
		LastPasswordChange: timestamppb.New(dbUser.LastPasswordChange),
	}
}

func ConvertUserToDbUser(dbUser *User) *storage.User {
	return &storage.User{
		ID:                    dbUser.ID,
		Username:              dbUser.Username,
		Email:                 dbUser.Email,
		Bio:                   sql.NullString{String: dbUser.Bio, Valid: true},
		CurrentAvatarURL:      sql.NullString{String: dbUser.CurrentAvatarURL, Valid: true},
		IsVerified:            dbUser.IsVerified,
		LastLogin:             dbUser.LastLogin,
		CreatedAt:             dbUser.CreatedAt,
		UpdatedAt:             dbUser.UpdatedAt,
		AccountStatus:         dbUser.AccountStatus,
		TwoFactorEnabled:      dbUser.TwoFactorEnabled,
		LastPasswordChange:    dbUser.LastPasswordChange,
		PasswordHash:          dbUser.PasswordHash,
		Salt:                  dbUser.Salt,
		PublicIdentityKey:     dbUser.PublicIdentityKey,
		PublicSignedPreKey:    dbUser.PublicSignedPreKey,
		SignedPreKeySignature: dbUser.SignedPreKeySignature,
		PublicKyberKey:        dbUser.PublicKyberKey,
		PublicOneTimePreKeys:  dbUser.PublicOneTimePreKeys,
		EncryptedPrivateKeys:  dbUser.EncryptedPrivateKeys,
	}
}

func ConvertDBUserToUser(dbUser *storage.User) *User {
	return &User{
		ID:                    dbUser.ID,
		Username:              dbUser.Username,
		Email:                 dbUser.Email,
		Bio:                   dbUser.Bio.String,
		CurrentAvatarURL:      dbUser.CurrentAvatarURL.String,
		IsVerified:            dbUser.IsVerified,
		LastLogin:             dbUser.LastLogin,
		CreatedAt:             dbUser.CreatedAt,
		UpdatedAt:             dbUser.UpdatedAt,
		AccountStatus:         dbUser.AccountStatus,
		TwoFactorEnabled:      dbUser.TwoFactorEnabled,
		LastPasswordChange:    dbUser.LastPasswordChange,
		PasswordHash:          dbUser.PasswordHash,
		Salt:                  dbUser.Salt,
		PublicIdentityKey:     dbUser.PublicIdentityKey,
		PublicSignedPreKey:    dbUser.PublicSignedPreKey,
		SignedPreKeySignature: dbUser.SignedPreKeySignature,
		PublicKyberKey:        dbUser.PublicKyberKey,
		PublicOneTimePreKeys:  dbUser.PublicOneTimePreKeys,
		EncryptedPrivateKeys:  dbUser.EncryptedPrivateKeys,
	}
}

const (
	PasswordMinEntropyBits = 30
)

var (
	ErrInvalidEmail = errors.New("invalid email")
)

func CheckCredentials(email, password string) error {
	if !ValidEmail(email) {
		return ErrInvalidEmail
	}

	err := passwordvalidator.Validate(password, PasswordMinEntropyBits)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "Password is not strong enough: %v", err)
	}
	return nil
}

func GetIpAddr(ctx context.Context) string {
	p, _ := peer.FromContext(ctx)
	return p.Addr.String()
}

func ValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[math.Intn(len(charset))]
	}
	return string(b)
}

func GenerateResetCode() string {
	const codeLength = 32 // 256 bits
	codeBytes := make([]byte, codeLength)

	_, err := rand.Read(codeBytes)
	if err != nil {
		// If we can't generate random numbers, fall back to a less secure method
		for i := range codeBytes {
			codeBytes[i] = byte(time.Now().UnixNano() & 0xff)
		}
	}

	return base64.URLEncoding.EncodeToString(codeBytes)
}

// Helper function to validate access token
func validateAccessToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.AccessTokenSecret, nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
		}
		return userID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid access token")
}

// ValidateRefreshToken Helper function to validate refresh token
func ValidateRefreshToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.RefreshTokenSecret, nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
		}
		return userID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid refresh token")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
