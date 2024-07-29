//go:build wireinject
// +build wireinject

package main

import (
	"database/sql"
	"speech/config"
	"speech/infrastructure/connection"
	"speech/internal/auth"
	"speech/internal/email"
	"speech/internal/sessions"
	"speech/internal/user"

	"github.com/google/wire"

	"google.golang.org/grpc/credentials"
)

var AppSet = wire.NewSet(sessions.Set, email.Set, user.Set, auth.Set, ProvideCreds, ProvideAppServices)

func InitializeAppWire(db *sql.DB, cfg *config.Config) *AppServices {
	wire.Build(AppSet)

	return &AppServices{}
}

func ProvideAppServices(
	credentials credentials.TransportCredentials,
	userHandler *user.Handler,
	userJsonHandler *user.JSONHandler,
	emailHandler *email.Handler,
	emailJsonHandler *email.JSONHandler,
	authHandler *auth.Handler,
	authJSONHandler *auth.JSONHandler,
) *AppServices {
	return &AppServices{
		credentials,
		authHandler,
		authJSONHandler,
		emailHandler,
		emailJsonHandler,
		userHandler,
		userJsonHandler,
	}
}

func ProvideCreds(getSession sessions.GetSession) credentials.TransportCredentials {
	return connection.NewDynamicCreds(getSession, nil)
}
