package persistence

import (
	"github.com/eldelto/zerberus/authentication"
)

// InMemoryRepository is an in-memory implementation of authentication.Repository.
type InMemoryRepository struct {
	store map[string]authentication.Session
}

// NewInMemoryRepository returns a new instance of InMemoryRepository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{make(map[string]authentication.Session)}
}

// StoreSession persists the given Session in an in-memory map.
func (r *InMemoryRepository) StoreSession(session authentication.Session) error {
	r.store[session.ID()] = session
	return nil
}

// FetchSession returns the Session with the given sessionID if it exists
// otherwise it returns an InvalidSessionError.
func (r *InMemoryRepository) FetchSession(sessionID string) (authentication.Session, error) {
	session, ok := r.store[sessionID]
	if !ok {
		err := &authentication.InvalidSessionError{SessionID: sessionID}
		return session, err
	}

	return session, nil
}

func (r *InMemoryRepository) StoreAuthenticationRequest(request authentication.AuthenticationRequest) error {
	// TODO: Implement
	return nil
}
