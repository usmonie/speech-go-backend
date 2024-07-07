package profile

import (
	"errors"

	"speech/internal/models"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) GetProfile(userID uint) (*models.User, error) {
	return s.repo.GetUserByID(userID)
}

func (s *Service) UpdateProfile(userID uint, updates map[string]interface{}) error {
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Only allow updating certain fields
	allowedFields := map[string]bool{
		"username": true,
		"about":    true,
		"name":     true,
	}

	for field, value := range updates {
		if allowed := allowedFields[field]; allowed {
			switch field {
			case "username":
				user.Username = value.(string)
			case "about":
				user.About = value.(string)
			case "name":
				user.Name = value.(string)
			}
		} else {
			return errors.New("attempt to update restricted field")
		}
	}

	return s.repo.UpdateUser(user)
}
