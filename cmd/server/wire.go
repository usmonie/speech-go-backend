//go:build wireinject
// +build wireinject

package main

//import (
//	"database/sql"
//	"github.com/google/wire"
//	"speech/config"
//	"speech/internal/auth"
//	"speech/internal/email"
//	"speech/internal/sessions"
//)
//
//var AppSet = wire.NewSet(sessions.Set, email.Set, auth.Set)
//
//func InitializeAppWire(db *sql.DB, cfg *config.Config) *auth.UserServiceServer {
//	wire.Build(AppSet)
//
//	return &auth.UserServiceServer{}
//}
