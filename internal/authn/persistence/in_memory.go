package persistence

import (
	"github.com/eldelto/zerberus/internal/authn"
)

// InMemoryRepository is an in-memory implementation of authn.Repository.
type InMemoryRepository struct {
	store map[string]authn.Session
}

// NewInMemoryRepository returns a new instance of InMemoryRepository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{make(map[string]authn.Session)}
}

// StoreSession persists the given Session in an in-memory map.
func (r *InMemoryRepository) StoreSession(session authn.Session) error {
	r.store[session.ID()] = session
	return nil
}

// FetchSession returns the Session with the given sessionID if it exists
// otherwise it returns an InvalidSessionError.
func (r *InMemoryRepository) FetchSession(sessionID string) (authn.Session, error) {
	session, ok := r.store[sessionID]
	if !ok {
		err := &authn.InvalidSessionError{SessionID: sessionID}
		return session, err
	}

	return session, nil
}

// StoreRequest persists the given Request in an in-memory map.
func (r *InMemoryRepository) StoreRequest(request authn.Request) error {
	// TODO: Implement
	return nil
}

func (r *InMemoryRepository) FetchRequest(requestID string) (authn.Request, error) {
	// TODO: Implement
	return authn.Request{}, nil
}
