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
		message: message,
	}
}

func (e *ClientValidationError) Error() string {
		return fmt.Sprintf("%s: %s", e.ClientID, e.message)
}

type NotFoundError struct {
	*ClientValidationError
}

func NewNotFoundError(clientId string) error {
	err := NewClientValidationError(clientId, "client could not be found")

	return &NotFoundError{
			ClientValidationError: err,
	}
}


type UnknownError struct {
	ClientID string
	err error
}

func NewUnknownError(clientId string, err error) error {
	return &UnknownError{
		ClientID: clientId,
		err: err,
	}
}

func (e *UnknownError) Error() string {
	return fmt.Sprintf("%s: %s", e.ClientID, e.err.Error());
}

func (e *UnknownError) Unwrap() error {
	return e.err;
}
