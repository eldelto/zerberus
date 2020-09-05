package authentication

import (
	"fmt"
	"time"
)

// Session represents a user's session on the server.
type Session struct {
	ID        string
	CreatedAt time.Time
	Lifetime  time.Duration
}

// IsValid return true if the Session has not yet expired otherwise false.
func (s *Session) IsValid() bool {
	expirationTime := s.CreatedAt.Add(s.Lifetime)
	return expirationTime.After(time.Now())
}

// Repository handles session persistance.
type Repository interface {
	StoreSession(session Session) error
	FetchSession(sessionID string) (Session, error)
}

// Service is the entrypoint for all authentication related operations.
type Service struct {
	repository Repository
}

// NewService return a new instance of Service using the given Repository implementation.
func NewService(repository Repository) *Service {
	return &Service{repository}
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
