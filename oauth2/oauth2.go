package oauth2

import (
	"fmt"
)

type AuthorizationRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scopes       []string
	State        string
}

type AuthorizationResponse struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scopes       []string
	State        string
	Code         string
}

type ClientConfiguration struct {
	ClientID     string
	RedirectURI  string
	Scopes       []string
	ClientSecret string
}

type Repository interface {
	FetchClientConfiguration(clientID string) (ClientConfiguration, error)
	StoreAuthorizationResponse(response AuthorizationResponse) error
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{repository}
}

func (s *Service) Authorize(request AuthorizationRequest) (AuthorizationResponse, error) {
	err := validateAuthorizationRequest(request, s.repository)

	return AuthorizationResponse{}, err
}

func validateAuthorizationRequest(request AuthorizationRequest, repository Repository) error {
	config, err := repository.FetchClientConfiguration(request.ClientID)
	if err != nil {
		// TODO: Wrap with custom error
		return err
	}

	if request.RedirectURI != config.RedirectURI {
		return newClientValidationError(request.ClientID, "Invalid redirect URI")
	}

	// TODO: Check if clientID exists
	//       Check if RedirectURI matches
	//       Check if scopes exist?
	//       Check if client is allowed to obtain requested scopes?

	return nil
}

type ClientValidationError struct {
	ClientID string
	message  string
}

func newClientValidationError(clientID, message string) *ClientValidationError {
	// TODO: Include clientID in error message
	return &ClientValidationError{
		ClientID: clientID,
		message:  fmt.Sprintf("%s: %s", clientID, message),
	}
}

func (e *ClientValidationError) Error() string {
	return e.message
}
