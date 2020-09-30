package authn

import (
	"fmt"
	"net/http"
	"net/url"
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

// Request holds all information for initiating a new authentication flow.
type Request struct {
	id          string
	state       string
	sessionID   string
	redirectURL url.URL
	provider    string
	createdAt   time.Time
	lifetime    time.Duration
}

// NewRequest returns a new Request containing the given parameters.
func NewRequest(sessionID string, redirectURL url.URL, provider string) (Request, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return Request{}, NewUnknownError(err, "error while generating a new Request ID")
	}

	state, err := uuid.NewRandom()
	if err != nil {
		return Request{}, NewUnknownError(err, "error while generating a new Request state")
	}

	request := Request{
		id:          id.String(),
		state:       state.String(),
		sessionID:   sessionID,
		redirectURL: redirectURL,
		provider:    provider,
		createdAt:   time.Now(),
		lifetime:    time.Minute * 5,
	}

	return request, nil
}

// Repository handles session persistance.
type Repository interface {
	StoreSession(session Session) error
	FetchSession(sessionID string) (Session, error)
	StoreRequest(request Request) error
}

/* DRAFT
type Response struct {
	ID string
	SessionID string
	State string
	AuthorizationCode string
}

// TODO: How to handle the redirect and setting of the session cookie?

func (s *Service) HandleCallback(response Response) (Session, error) {
	// Checks session, id, state & type against stored Request
	provider, err := s.validateAuthnResponse(response)
	if err != nil {
		return Session{}, err
	}

	if err = provider.HandleCallback(reponse.AuthnCode); err != nil {
		return Session{}, err
	}

	return s.createAuthenticatedSession
}
*/

// LoginProvider handles the custom logic used to provide authentication via a
// third party service (e.g. Google, Facebook, etc.).
type LoginProvider interface {
	InitLogin(w http.ResponseWriter) error
	HandleCallback(authorizationCode string) error
}

// Service is the entrypoint for all authentication related operations.
type Service struct {
	repository     Repository
	loginProviders map[string]LoginProvider
}

// NewService return a new instance of Service using the given Repository implementation.
func NewService(repository Repository) *Service {
	return &Service{
		repository:     repository,
		loginProviders: map[string]LoginProvider{},
	}
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

// ValidateAuthn validates the given sessionID and ensures that the session
// has a valid authentication.
// It returns nil if the session is valid otherwise the respective error is returned.
func (s *Service) ValidateAuthn(sessionID string) error {
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

// RegisterLoginProvider registers the given LoginProvider under the given key.
// If a LoginProvider for the given key is already registered a ConfigurationError
// is returned otherwise nil.
func (s *Service) RegisterLoginProvider(provider LoginProvider, key string) error {
	_, ok := s.loginProviders[key]
	if ok {
		msg := fmt.Sprintf("LoginProvider with key '%s' is already registered", key)
		return &ConfigurationError{msg}
	}

	s.loginProviders[key] = provider

	return nil
}

// InitAuthn initiates a new Authentication flow via a third party identity provider.
func (s *Service) InitAuthn(request Request, w http.ResponseWriter) error {
	session, err := s.repository.FetchSession(request.sessionID)
	if err != nil {
		return &InvalidSessionError{request.sessionID}
	}

	if s.ValidateAuthn(session.id) == nil {
		w.Header().Add("Location", request.redirectURL.String())
		return nil
	}

	provider, ok := s.loginProviders[request.provider]
	if !ok {
		msg := fmt.Sprintf("provider with key '%s' is not registered", request.provider)
		return &ConfigurationError{msg}
	}

	if err = s.repository.StoreRequest(request); err != nil {
		return err
	}

	return provider.InitLogin(w)
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
	message  string
}

// NewCallbackError returns a new CallbackError for the given LoginProvider with the
// specified message.
func NewCallbackError(provider LoginProvider, message string) error {
	return &CallbackError{
		Provider: provider,
		message:  message,
	}
}

func (e *CallbackError) Error() string {
	return fmt.Sprintf("error while handling callback: %s", e.message)
}

// ConfigurationError indicates that an invalid configuration has been provided
// or the current configuration is in an invalid state.
type ConfigurationError struct {
	message string
}

func (e *ConfigurationError) Error() string {
	return e.message
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
