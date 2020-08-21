package persistence

import (
	"github.com/eldelto/zerberus/oauth2"
)

type InMemoryRepository struct{}

func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{}
}

func (r *InMemoryRepository) FetchClientConfiguration(clientID string) (oauth2.ClientConfiguration, error) {
	return oauth2.ClientConfiguration{}, nil
}

func (*InMemoryRepository) StoreAuthorizationResponse(response oauth2.AuthorizationResponse) error {
	return nil
}
