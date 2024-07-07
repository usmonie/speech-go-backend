package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthMiddleware struct {
	jwtSecret []byte
}

func NewAuthMiddleware(jwtSecret []byte) *AuthMiddleware {
	return &AuthMiddleware{jwtSecret: jwtSecret}
}

func (am *AuthMiddleware) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Skip token validation for authentication methods
	if info.FullMethod == "/auth.AuthService/Login" || info.FullMethod == "/auth.AuthService/Register" ||
		info.FullMethod == "/auth.AuthService/ForgotPassword" || info.FullMethod == "/auth.AuthService/ResetPassword" ||
		info.FullMethod == "/auth.AuthService/VerifyEmail" || info.FullMethod == "/auth.AuthService/RefreshToken" {
		return handler(ctx, req)
	}

	userID, err := am.validateToken(ctx)
	if err != nil {
		return nil, err
	}

	// Add the user ID to the context
	newCtx := context.WithValue(ctx, "user_id", userID)

	// Call the handler with the new context
	return handler(newCtx, req)
}

func (am *AuthMiddleware) validateToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	bearerToken := authHeader[0]
	token := strings.TrimPrefix(bearerToken, "Bearer ")

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	if !parsedToken.Valid {
		return "", status.Errorf(codes.Unauthenticated, "invalid token")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "invalid token claims")
	}

	return userID, nil
}
