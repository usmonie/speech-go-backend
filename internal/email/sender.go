package email

import (
	"bytes"
	"fmt"
	"gopkg.in/gomail.v2"
	"html/template"
	"path/filepath"
)

type Sender struct {
	dialer *gomail.Dialer
	from   string
}

func NewEmailSender(host string, port int, username, password, from string) *Sender {
	dialer := gomail.NewDialer(host, port, username, password)
	return &Sender{
		dialer: dialer,
		from:   from,
	}
}

func (s *Sender) sendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return s.dialer.DialAndSend(m)
}

func (s *Sender) SendVerificationEmail(to, username, verificationCode string) error {
	subject := "Verify Your Email Address"
	body, err := s.parseTemplate("verification_email.html", map[string]string{
		"Username":         username,
		"VerificationCode": verificationCode,
	})
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	return s.sendEmail(to, subject, body)
}

func (s *Sender) Send2FACode(to, username, twoFactorCode string) error {
	subject := "Your Two-Factor Authentication Code"
	body, err := s.parseTemplate("2fa_email.html", map[string]string{
		"Username":      username,
		"TwoFactorCode": twoFactorCode,
	})
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	return s.sendEmail(to, subject, body)
}

func (s *Sender) SendPasswordResetEmail(to, username, resetCode string, deviceInfo string, ipAddr string) error {
	subject := "Password Reset Request"
	body, err := s.parseTemplate("password_reset_email.html", map[string]string{
		"Username":  username,
		"ResetCode": resetCode,
		"Device":    deviceInfo,
		"IP":        ipAddr,
	})
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	return s.sendEmail(to, subject, body)
}

func (s *Sender) SendWelcomeEmail(to, username string) error {
	subject := "Welcome to Our Platform"
	body, err := s.parseTemplate("welcome_email.html", map[string]string{
		"Username": username,
	})
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	return s.sendEmail(to, subject, body)
}

func (s *Sender) SendPasswordChangedEmail(to, username string) error {
	subject := "Your Password Has Been Changed"
	body, err := s.parseTemplate("password_changed_email.html", map[string]string{
		"Username": username,
	})
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	return s.sendEmail(to, subject, body)
}

func (s *Sender) parseTemplate(templateFileName string, data interface{}) (string, error) {
	templatePath := filepath.Join("/Users/usmanakhmedov/FleetProjects/speech/templates", templateFileName)
	t, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", templateFileName, err)
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateFileName, err)
	}
	return buf.String(), nil
}
