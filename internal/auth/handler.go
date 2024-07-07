package auth

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandler struct {
	UnimplementedAuthServiceServer
	service Service
}

func NewAuthHandler(service Service) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	userID, err := h.service.Register(req.Username, req.Email, req.Password, req.Name, req.About)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to register user: %v", err)
	}

	return &RegisterResponse{
		Success: true,
		Message: "User registered successfully. Please check your email for verification code.",
		UserId:  userID,
	}, nil
}

func (h *AuthHandler) VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	err := h.service.VerifyEmail(req.Email, req.Code)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to verify email: %v", err)
	}

	return &VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully",
	}, nil
}

func (h *AuthHandler) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	token, err := h.service.Login(req.Email, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Login failed: %v", err)
	}

	return &LoginResponse{
		Success:      true,
		Message:      "Login successful",
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

func (h *AuthHandler) ResendVerificationEmail(ctx context.Context, req *ResendVerificationEmailRequest) (*ResendVerificationEmailResponse, error) {
	err := h.service.ResendVerificationEmail(req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to resend verification email: %v", err)
	}

	return &ResendVerificationEmailResponse{
		Success: true,
		Message: "Verification email sent successfully",
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	token, err := h.service.RefreshToken(req.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Failed to refresh token: %v", err)
	}

	return &RefreshTokenResponse{
		Success:      true,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

func (h *AuthHandler) ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	err := h.service.ForgotPassword(req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to process forgot password request: %v", err)
	}

	return &ForgotPasswordResponse{
		Success: true,
		Message: "Reset code sent to email",
	}, nil
}

func (h *AuthHandler) ResetPassword(ctx context.Context, req *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	err := h.service.ResetPassword(req.Email, req.Code, req.NewPassword)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to reset password: %v", err)
	}

	return &ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}, nil
}

//func (h *AuthHandler) GetUserInfo(ctx context.Context, req *GetUserInfoRequest) (*GetUserInfoResponse, error) {
//	userID, ok := ctx.Value("user_id").(string)
//	if !ok {
//		return nil, status.Errorf(codes.Internal, "Failed to get user ID from context")
//	}
//
//	user, err := h.service.GetUserByID(userID)
//	if err != nil {
//		return nil, status.Errorf(codes.Internal, "Failed to get user info: %v", err)
//	}
//
//	return &GetUserInfoResponse{
//		Username: user.Username,
//		Email:    user.Email,
//		Name:     user.Name,
//		About:    user.About,
//	}, nil
//}
