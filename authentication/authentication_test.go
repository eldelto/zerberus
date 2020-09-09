package authentication

import (
	"testing"
	"time"

	. "github.com/eldelto/zerberus/internal/testutils"
)

const validSessionID = "111"
const invalidSessionID = "666"
const nonExistentSessionID = "000"

var validSession = &Session{
	id:        validSessionID,
	createdAt: time.Now(),
	lifetime:  100 * time.Minute,
}

var invalidSession = &Session{
	id:        validSessionID,
	createdAt: time.Now().AddDate(0, 0, -1),
	lifetime:  1 * time.Nanosecond,
}

var service = NewService(&StubRepository{})

func TestService_ValidateSession(t *testing.T) {

	tests := []struct {
		name      string
		sessionID string
		wantErr   error
	}{
		{"valid sessionID", validSessionID, nil},
		{"invalid sessionID", invalidSessionID, &InvalidSessionError{}},
		{"non-existent sessionID", nonExistentSessionID, &InvalidSessionError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateSession(tt.sessionID)
			AssertTypeEquals(t, tt.wantErr, err, "service.Authorize error")
		})
	}
}

type StubRepository struct{}

func (r *StubRepository) StoreSession(session *Session) error {
	return nil
}

func (r *StubRepository) FetchSession(sessionID string) (*Session, error) {
	switch sessionID {
	case "111":
		return validSession, nil
	case "666":
		return invalidSession, nil
	default:
		return nil, &InvalidSessionError{SessionID: sessionID}
	}
}
