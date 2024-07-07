package config

import (
	"os"

	//	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL  string
	JWTSecret    []byte
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	Port         string
}

func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	//	err := godotenv.Load()
	//	if err != nil {
	//		return nil, err
	//	}

	//	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))

	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   []byte(os.Getenv("JWT_SECRET")),
		// TODO: ADD neccessary params
		Port: "50051",
	}, nil
}
