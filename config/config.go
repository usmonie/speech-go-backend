package config

import (
	"os"
	//	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL    string
	JWTSecret      []byte
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	Port           string
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	ClientKeyPath  string
}

func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	//	err := godotenv.Load()
	//	if err != nil {
	//		return nil, err
	//	}

	//	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))

	return &Config{
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		JWTSecret:    []byte(os.Getenv("JWT_SECRET")),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     587,
		SMTPUsername: os.Getenv("SMTP_USERNAME"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		Port:         "8443",
	}, nil
}

var (
	AccessTokenSecret  = []byte("eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJVc21hbiBBa2htZWRvdiBOaWUgIiwiVXNlcm5hbWUiOiJuaWUiLCJleHAiOjU2OTY3ODAxODYsImlhdCI6MTcyMDY1MjE4Nn0.Lygnb2EL5g_syyksTNjDbSlrfGvoEYqciCUHRzJBPog") // Replace with a secure secret
	RefreshTokenSecret = []byte("eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJVc21hbiBBa2htZWRvdiBOaWUgIiwiVXNlcm5hbWUiOiJuaWUiLCJleHAiOjU2OTY3ODAxODYsImlhdCI6MTcyMDY1MjE4Nn0.VcPlihowGDCC_db7dgHXvp2zVs9c8bNP_bRICUhA6xc") // Replace with a secure secret
)
