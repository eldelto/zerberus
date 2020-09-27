package authentication

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Session represents a user's session on the server.
type Session struct {
	id              string
	createdAt       time.Time
	lifetime        time.Duration
	isAuthenticated bool
}

// ID returns the ID of the session.
func (s *Session) ID() string {
	return s.id
}

// CreatedAt returns the time the session has been created at.
func (s *Session) CreatedAt() time.Time {
	return s.createdAt
}

// Lifetime returns the lifetime of the session.
func (s *Session) Lifetime() time.Duration {
	return s.lifetime
}

// IsAuthenticated returns true if the session belongs to an authenticated user
// otherwise false.
func (s *Session) IsAuthenticated() bool {
	return s.isAuthenticated
}

// IsValid return true if the Session has not yet expired otherwise false.
func (s *Session) IsValid() bool {
	expirationTime := s.createdAt.Add(s.lifetime)
	return expirationTime.After(time.Now())
}

// Repository handles session persistance.
type Repository interface {
	StoreSession(session Session) error
	FetchSession(sessionID string) (Session, error)
}

/* DRAFT
func (s *Service) InitAuth(request AuthenticationRequest,  w http.ResponseWriter) error {
	session, err := s.repository.FetchSession(request.SessionID)
	if err != nil {
		return InvalidSessionError
	}

	s.ValidateAuthentication(session) == nil {
		w.Header().Add("Location", request.RedirectURI)
		return nil
	}

	provider, ok := s.loginProviders[request.Provider]
	if !ok {
		return ValidationError
	}

	err = s.repository.StoreAuthenticationRequest(request); err != nil {
		return err
	}

	return provider.InitLogin(w)
}

func (s *Service) HandleCallback(session Session, response AuthenticationResponse) (Session, error)

var loginProviderMapping [string]LoginProvider

func RegisterLoginProvider(key string, provider LoginProvider) error
	=> Returns an error if a provider with the same key already exists
}
*/

type LoginProvider interface {
	InitLogin(w http.ResponseWriter) error
	HandleCallback(authorizationCode string) error
}


// Service is the entrypoint for all authentication related operations.
type Service struct {
	repository Repository
}

// NewService return a new instance of Service using the given Repository implementation.
func NewService(repository Repository) *Service {
	return &Service{repository}
}

// CreateSession creates a new anonymous session and stores it in the repository.
// It will return an error if the session could not be created.
func (s *Service) CreateSession() (*Session, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return nil, NewUnknownError(err, "error while generating a new session ID")
	}

	session := Session{
		id:              uuid.String(),
		createdAt:       time.Now(),
		lifetime:        time.Hour * 24,
		isAuthenticated: false,
	}

	if err = s.repository.StoreSession(session); err != nil {
		return nil, err
	}

	return &session, nil
}

// ValidateSession validates the given sessionID.
// It returns nil if the session is valid otherwise the respective error is returned.
func (s *Service) ValidateSession(sessionID string) error {
	session, err := s.repository.FetchSession(sessionID)
	if err != nil {
		return err
	}

	if !session.IsValid() {
		return &InvalidSessionError{sessionID}
	}

	return nil
}

// ValidateAuthentication validates the given sessionID and ensures that the session
// has a valid authentication.
// It returns nil if the session is valid otherwise the respective error is returned.
func (s *Service) ValidateAuthentication(sessionID string) error {
	session, err := s.repository.FetchSession(sessionID)
	if err != nil {
		return err
	}

	if !session.IsValid() {
		return &InvalidSessionError{sessionID}
	}

	if !session.isAuthenticated {
		return &NotAuthenticatedError{sessionID}
	}

	return nil
}

// InvalidSessionError indicates that the given session does not exist, has expired
// or is invalid in any other way.
type InvalidSessionError struct {
	SessionID string
}

func (e *InvalidSessionError) Error() string {
	return fmt.Sprintf("session '%s' is not valid", e.SessionID)
}

// NotAuthenticatedError indicates that the given session is not authenticated
// but anonymous.
type NotAuthenticatedError struct {
	SessionID string
}

func (e *NotAuthenticatedError) Error() string {
	return fmt.Sprintf("session '%s' is not authenticated", e.SessionID)
}

// CallbackError indicates that the given LoginProvider encountered a problem while
// processing the callback request.
type CallbackError struct {
	Provider LoginProvider
	message string
}

// NewCallbackError returns a new CallbackError for the given LoginProvider with the
// specified message.
func NewCallbackError(provider LoginProvider, message string) error {
	return &CallbackError{
		Provider: provider,
		message: message,
	}
}

func (e *CallbackError) Error() string {
	return fmt.Sprintf("error while handling callback: %s", e.message)
}

// UnknownError indicates that an unexpected error has occured that could not be handled
// by the business logic (e.g. database unavailable).
type UnknownError struct {
	err     error
	message string
}

// NewUnknownError returns a new UnknownError wrapping the given error and containing
// the passed message.
func NewUnknownError(err error, message string) error {
	return &UnknownError{
		err:     err,
		message: message,
	}
}

func (e *UnknownError) Error() string {
	return fmt.Sprintf("%s: %s", e.message, e.err.Error())
}

func (e *UnknownError) Unwrap() error {
	return e.err
}
