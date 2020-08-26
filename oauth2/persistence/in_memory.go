package persistence

import (
	"github.com/eldelto/zerberus/oauth2"
)

type InMemoryRepository struct{
	store map[string]oauth2.ClientConfiguration
}

func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{make(map[string]oauth2.ClientConfiguration)}
}

func (r *InMemoryRepository) StoreClientConfiguration(config oauth2.ClientConfiguration) error {
	r.store[config.ClientID] = config

	return nil
}

func (r *InMemoryRepository) FetchClientConfiguration(clientID string) (oauth2.ClientConfiguration, error) {
	config, ok := r.store[clientID]
	if !ok {
		return config, oauth2.NewNotFoundError(clientID)
	}

	return config, nil
}

func (*InMemoryRepository) StoreAuthorizationResponse(response oauth2.AuthorizationResponse) error {
	return nil
}
