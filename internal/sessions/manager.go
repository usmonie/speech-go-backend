package sessions

import "github.com/google/uuid"

type GetSession interface {
	Get(sessionID *uuid.UUID) (*Session, error)
}

type getSession struct {
	repository Repository
}

func NewGetSession(repository Repository) GetSession {
	return &getSession{repository: repository}
}

func (s *getSession) Get(sessionID *uuid.UUID) (*Session, error) {
	return s.repository.GetSessionByID(sessionID, nil)
}
