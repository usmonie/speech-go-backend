package di

//import (
//	"database/sql"
//
//	"github.com/google/wire"
//	"speech/internal/auth"
//	"speech/config"
//)

//func InitializeAuthHandler(cfg *config.Config, db *sql.DB) (*auth.AuthHandler, error) {
//	wire.Build(
//		auth.NewPostgresRepository,
//		provideSMTPConfig,
//		auth.NewAuthService,
//		auth.NewAuthHandler,
//	)
//	return &auth.AuthHandler{}, nil
//}
//
//func provideSMTPConfig(cfg *config.Config) auth.SMTPConfig {
//	return auth.SMTPConfig{
//		Host:     cfg.SMTPHost,
//		Port:     cfg.SMTPPort,
//		Username: cfg.SMTPUsername,
//		Password: cfg.SMTPPassword,
//	}
//}
