package auth

import (
	"github.com/google/wire"
	"speech/internal/sessions"
	"speech/internal/user"
)

func ProvideUseCase(
	usersRepository user.Repository,
	sessionsRepository sessions.Repository,
) UseCase {
	return NewAuthUseCase(usersRepository, sessionsRepository)
}

func ProvideAuthHandler(useCase UseCase) *Handler {
	return NewAuthHandler(useCase)
}

func ProvideJSONHandler(useCase UseCase) *JSONHandler {
	return NewJSONAuthHandler(useCase)
}

var Set = wire.NewSet(ProvideUseCase, ProvideAuthHandler, ProvideJSONHandler)
