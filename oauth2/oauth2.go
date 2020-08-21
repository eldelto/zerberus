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

	// TODO: generate & store authorization code

	return AuthorizationResponse{}, err
}

func validateAuthorizationRequest(request AuthorizationRequest, repository Repository) error {
	config, err := repository.FetchClientConfiguration(request.ClientID)
	if err != nil {
		// TODO: Check for NotFoundError otherwise return wrapped error
		return err
	}

	if request.RedirectURI != config.RedirectURI {
		return NewClientValidationError(request.ClientID, "invalid redirect URI")
	}

	return validateScopes(request, config)
}

func validateScopes(request AuthorizationRequest, config ClientConfiguration) error {
	validScopes := config.Scopes
	for scope := range request.Scopes {
		valid := false
		for validScope := range validScopes {
			if scope == validScope {
				valid = true
				break
			}
		}

		if !valid {
			return NewClientValidationError(request.ClientID, fmt.Sprintf("invalid scope set"))
		}
	}

	return nil
}

type ClientValidationError struct {
	ClientID string
	message  string
}

func NewClientValidationError(clientID, message string) *ClientValidationError {
	return &ClientValidationError{
		ClientID: clientID,
		message:  fmt.Sprintf("%s: %s", clientID, message),
	}
}

func (e *ClientValidationError) Error() string {
	return e.message
}
