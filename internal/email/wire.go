package email

import (
	"github.com/google/wire"
	"speech/config"
)

// ProvideEmailSender is a Wire provider function that creates a Sender
func ProvideEmailSender(cfg *config.Config) *Sender {
	return NewEmailSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPUsername)
}

var Set = wire.NewSet(ProvideEmailSender)
