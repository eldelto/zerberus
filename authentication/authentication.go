package authentication

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Session represents a user's session on the server.
type Session struct {
	id          string
	createdAt   time.Time
	lifetime    time.Duration
	isAnonymous bool
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

// IsAnonymous returns true if the session belongs to an anonymous user otherwise false.
func (s *Session) IsAnonymous() bool {
	return s.isAnonymous
}

// IsValid return true if the Session has not yet expired otherwise false.
func (s *Session) IsValid() bool {
	expirationTime := s.createdAt.Add(s.lifetime)
	return expirationTime.After(time.Now())
}

// Repository handles session persistance.
type Repository interface {
	StoreSession(session *Session) error
	FetchSession(sessionID string) (*Session, error)
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

	session := &Session{
		id:          uuid.String(),
		createdAt:   time.Now(),
		lifetime:    time.Hour * 24,
		isAnonymous: true,
	}

	if err = s.repository.StoreSession(session); err != nil {
		return nil, err
	}

	return session, nil
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

/* DRAFT
func (s *Service) Authenticate(session *Session) (*Session, error)
*/

// InvalidSessionError indicates that the given session does not exist, has expired
// or is invalid in any other way.
type InvalidSessionError struct {
	SessionID string
}

func (e *InvalidSessionError) Error() string {
	return fmt.Sprintf("session '%s' is not valid", e.SessionID)
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
