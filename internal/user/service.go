package user

import (
	"golang.org/x/crypto/bcrypt"

	"speech/internal/database"
)

type Service struct {
	db *database.Database
}

func NewService(db *database.Database) *Service {
	return &Service{db: db}
}

type CreateUserInput struct {
	Username string
	Email    string
	Password string
}

func (s *Service) CreateUser(input CreateUserInput) (*database.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &database.User{
		Username: input.Username,
		Email:    input.Email,
		Password: string(hashedPassword),
	}

	result := s.db.Create(user)
	if result.Error != nil {
		return nil, result.Error
	}

	return user, nil
}
