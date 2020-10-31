package auth

import (
	"fmt"

	"github.com/google/uuid"
)

// Request represents a client's authorization request to the server.
type Request struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scopes       []string
	State        string
}

// Response represents the server's authorization response to the client.
type Response struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scopes       []string
	State        string
	Code         string
}

// ClientConfiguration contains the stored settings for a client.
type ClientConfiguration struct {
	ClientID     string
	RedirectURI  string
	Scopes       []string
	ClientSecret string
}

// Repository handles persistence for authorization related data.
type Repository interface {
	StoreClientConfiguration(config ClientConfiguration) error
	FetchClientConfiguration(clientID string) (ClientConfiguration, error)
	StoreResponse(response Response) error
}

// Service is the entrypoint for all authorization related operations.
type Service struct {
	repository Repository
}

// NewService returns a new instance of Service using the given Repository implementation.
func NewService(repository Repository) *Service {
	return &Service{repository}
}

// Authorize validates the given Request, generates and authorization code
// and returns the Response.
func (s *Service) Authorize(request Request) (Response, error) {
	err := s.ValidateRequest(request)
	if err != nil {
		return Response{}, err
	}

	return generateAuthorizationCode(request, s.repository)
}

// ValidateRequest validates the given Request and returns
// an error if it does not match the configured ClientConfiguration.
func (s *Service) ValidateRequest(request Request) error {
	config, err := s.repository.FetchClientConfiguration(request.ClientID)
	if err != nil {
		return err
	}

	if request.RedirectURI != config.RedirectURI {
		return NewClientValidationError(request.ClientID, "invalid redirect URI")
	}

	return validateScopes(request, config)
}

func generateAuthorizationCode(request Request, repository Repository) (Response, error) {
	code, err := uuid.NewRandom()
	if err != nil {
		return Response{}, NewUnknownError(request.ClientID, err)
	}

	response := Response{
		ClientID:     request.ClientID,
		RedirectURI:  request.RedirectURI,
		ResponseType: request.ResponseType,
		Scopes:       request.Scopes,
		State:        request.State,
		Code:         code.String(),
	}

	err = repository.StoreResponse(response)

	return response, err
}

func validateScopes(request Request, config ClientConfiguration) error {
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

// ClientValidationError indicates that the validation against the stored
// ClientConfiguration failed.
type ClientValidationError struct {
	ClientID string
	message  string
}

// NewClientValidationError returns a new ClientValidationError containing the given
// clientID and message.
func NewClientValidationError(clientID, message string) *ClientValidationError {
	return &ClientValidationError{
		ClientID: clientID,
		message:  message,
	}
}

func (e *ClientValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.ClientID, e.message)
}

// NotFoundError indicates that a ClientConfiguration for the given clientID could
// not be found.
type NotFoundError struct {
	ClientID string
}

// NewNotFoundError returns a new NotFoundError for the given clientID.
func NewNotFoundError(clientID string) error {
	return &NotFoundError{
		ClientID: clientID,
	}
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s: could not be found", e.ClientID)
}

// UnknownError indicates that an unexpected error has occured that could not be handled
// by the business logic (e.g. database unavailable).
type UnknownError struct {
	ClientID string
	err      error
}

// NewUnknownError returns a new UnknownError wrapping the given error and containing
// the passed clientID.
func NewUnknownError(clientID string, err error) error {
	return &UnknownError{
		ClientID: clientID,
		err:      err,
	}
}

func (e *UnknownError) Error() string {
	return fmt.Sprintf("%s: %s", e.ClientID, e.err.Error())
}

func (e *UnknownError) Unwrap() error {
	return e.err
}
