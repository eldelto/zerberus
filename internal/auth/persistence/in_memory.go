package persistence

import (
	"github.com/eldelto/zerberus/internal/auth"
)

// InMemoryRepository is an in-memory implementation of auth.Repository.
type InMemoryRepository struct {
	store map[string]auth.ClientConfiguration
}

// NewInMemoryRepository returns anew instance of InMemoryRepository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{make(map[string]auth.ClientConfiguration)}
}

// StoreClientConfiguration stores the given ClientConfiguration in an in-memory map.
func (r *InMemoryRepository) StoreClientConfiguration(config auth.ClientConfiguration) error {
	r.store[config.ClientID] = config

	return nil
}

// FetchClientConfiguration returns the ClientConfiguration for the given client ID
// otherwise it returns an NotFoundError.
func (r *InMemoryRepository) FetchClientConfiguration(clientID string) (auth.ClientConfiguration, error) {
	config, ok := r.store[clientID]
	if !ok {
		return config, auth.NewNotFoundError(clientID)
	}

	return config, nil
}

// StoreResponse stores the given Response in an in-memory map.
func (*InMemoryRepository) StoreResponse(response auth.Response) error {
	// TODO: Implement

	return nil
}
