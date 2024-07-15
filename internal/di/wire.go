package di
//
//import (
//	"database/sql"
//	"github.com/google/wire"
//	"speech/config"
//	"speech/internal/auth"
//	"speech/internal/chat"
//	"speech/internal/email"
//)
//
//// ProvideRepository is a Wire provider function that creates a chat.Repository
//func ProvideRepository(db *sql.DB) chat.Repository {
//	return chat.NewPostgresRepository(db)
//}
//
//// ProvideAuthRepository is a Wire provider function that creates an auth.Repository
//func ProvideAuthRepository(db *sql.DB) auth.Repository {
//	return auth.NewPostgresRepository(db)
//}
//
//// ProvideNotificationService is a Wire provider function that creates a NotificationService
////func ProvideNotificationService() auth.NotificationService {
////	return auth.NewMockNotificationService() // For now, we're using the mock service
////}
//
////func InitializeAuthHandler(cfg *config.Config, db *sql.DB) {
////	wire.Build(
////		ProvideAuthRepository,
////		provideSMTPConfig,
////		provideEmailSender,
////		//		ProvideNotificationService,
////		//		wire.Bind(new(auth.NotificationService), new(*auth.MockNotificationService)),
////		auth.NewUserServiceServer,
////		//		auth.NewAuthHandler,
////	)
////	//	return &auth.AuthHandler{}, nil
////}
//
//func InitializeUserService(cfg *config.Config, db *sql.DB) *auth.UserServiceServer {
//	wire.Build(
//		ProvideAuthRepository,
//		provideSMTPConfig,
//		ProvideEmailSender,
//		//		ProvideNotificationService,
//		//		wire.Bind(new(auth.NotificationService), new(*auth.MockNotificationService)),
//		auth.NewUserServiceServer,
//		//		auth.NewAuthHandler,
//	)
//	return &auth.UserServiceServer{}
//}
//
//func InitializeChatHandler(cfg *config.Config, db *sql.DB) (*chat.ChatHandler, error) {
//	wire.Build(
//		ProvideRepository,
//		chat.NewChatService,
//		chat.NewChatHandler,
//	)
//	return &chat.ChatHandler{}, nil
//}
//
//func provideSMTPConfig(cfg *config.Config) auth.SMTPConfig {
//	return auth.SMTPConfig{
//		Host:     cfg.SMTPHost,
//		Port:     cfg.SMTPPort,
//		Username: cfg.SMTPUsername,
//		Password: cfg.SMTPPassword,
//		From:     "speech WTF",
//	}
//}
//
//func ProvideEmailSender(smtpCfg auth.SMTPConfig) *email.Sender {
//	return email.NewEmailSender(smtpCfg.Host, smtpCfg.Port, smtpCfg.Username, smtpCfg.Password, smtpCfg.From)
//}
