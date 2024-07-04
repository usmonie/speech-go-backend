package messaging

import (
	"speech/internal/database"
)

type Service struct {
	db *database.Database
}

func NewService(db *database.Database) *Service {
	return &Service{db: db}
}

type SendMessageInput struct {
	SenderID    uint
	RecipientID uint
	Content     string
}

func (s *Service) SendMessage(input SendMessageInput) (*database.Message, error) {
	message := &database.Message{
		SenderID:    input.SenderID,
		RecipientID: input.RecipientID,
		Content:     input.Content,
	}

	result := s.db.Create(message)
	if result.Error != nil {
		return nil, result.Error
	}

	return message, nil
}
