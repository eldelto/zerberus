package oauth2

import (
	"fmt"

	"github.com/google/uuid"
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
	StoreClientConfiguration(config ClientConfiguration) error
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
	err := s.ValidateAuthorizationRequest(request)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	return generateAuthorizationCode(request, s.repository)
}

func (s *Service) ValidateAuthorizationRequest(request AuthorizationRequest) error {
	config, err := s.repository.FetchClientConfiguration(request.ClientID)
	if err != nil {
		return err
	}

	if request.RedirectURI != config.RedirectURI {
		return NewClientValidationError(request.ClientID, "invalid redirect URI")
	}

	return validateScopes(request, config)
}

func generateAuthorizationCode(request AuthorizationRequest, repository Repository) (AuthorizationResponse, error) {
	code, err := uuid.NewRandom()
	if err != nil {
		return AuthorizationResponse{}, NewUnknownError(request.ClientID, err)
	}

	response := AuthorizationResponse{
		ClientID:     request.ClientID,
		RedirectURI:  request.RedirectURI,
		ResponseType: request.ResponseType,
		Scopes:       request.Scopes,
		State:        request.State,
		Code:         code.String(),
	}

	err = repository.StoreAuthorizationResponse(response)

	return response, err
}

func validateScopes(request AuthorizationRequest, config ClientConfiguration) error {
	validScopes := config.Scopes
	for _, scope := range request.Scopes {
		valid := false
		for _, validScope := range validScopes {
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
		message:  message,
	}
}

func (e *ClientValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.ClientID, e.message)
}

type NotFoundError struct {
	ClientID string
}

func NewNotFoundError(clientID string) error {
	return &NotFoundError{
		ClientID: clientID,
	}
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s: could not be found", e.ClientID)
}

type UnknownError struct {
	ClientID string
	err      error
}

func NewUnknownError(clientId string, err error) error {
	return &UnknownError{
		ClientID: clientId,
		err:      err,
	}
}

func (e *UnknownError) Error() string {
	return fmt.Sprintf("%s: %s", e.ClientID, e.err.Error())
}

func (e *UnknownError) Unwrap() error {
	return e.err
}
