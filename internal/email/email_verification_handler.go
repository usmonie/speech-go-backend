package email

import (
	"context"
	"errors"
	"google.golang.org/protobuf/types/known/emptypb"
	"speech/internal/proto"
)

var (
	ErrTokenExpired        = errors.New("verification token has expired")
	ErrTokenNotFound       = errors.New("verification token not found")
	ErrUserAlreadyVerified = errors.New("user is already verified")
)

type Handler struct {
	proto.UnimplementedEmailServiceServer
	emailSender  *Sender
	emailUseCase UseCase
}

func NewHandler(emailSender *Sender, emailUseCase UseCase) *Handler {
	return &Handler{
		emailSender:  emailSender,
		emailUseCase: emailUseCase,
	}
}

func (s *Handler) VerifyEmail(ctx context.Context, request *proto.VerifyEmailRequest) (*emptypb.Empty, error) {
	err := s.emailUseCase.VerifyEmail(ctx, request.GetEmail(), request.GetCode())

	return &emptypb.Empty{}, err
}
