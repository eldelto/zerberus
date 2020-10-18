package authn

import (
	"net/url"
	"testing"
	"time"

	"github.com/eldelto/zerberus/internal/testutils"
)

const validSessionID = "111"
const validAnonymousSessionID = "222"
const invalidSessionID = "666"
const nonExistentSessionID = "000"

var validSession = Session{
	id:              validSessionID,
	createdAt:       time.Now(),
	lifetime:        100 * time.Minute,
	isAuthenticated: true,
}

var validAnonymousSession = Session{
	id:              validAnonymousSessionID,
	createdAt:       time.Now(),
	lifetime:        100 * time.Minute,
	isAuthenticated: false,
}

var invalidSession = Session{
	id:              invalidSessionID,
	createdAt:       time.Now().AddDate(0, 0, -1),
	lifetime:        1 * time.Nanosecond,
	isAuthenticated: true,
}

var service = NewService(&stubRepository{})

func init() {
	service.RegisterLoginProvider(&stubLoginProvider{}, providerKey)
}

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
			testutils.AssertTypeEquals(t, tt.wantErr, err, "service.ValidateSession error")
		})
	}
}

func TestService_ValidateAuthn(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		wantErr   error
	}{
		{"valid sessionID", validSessionID, nil},
		{"valid anonymous sessionID", validAnonymousSessionID, &NotAuthenticatedError{}},
		{"invalid sessionID", invalidSessionID, &InvalidSessionError{}},
		{"non-existent sessionID", nonExistentSessionID, &InvalidSessionError{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateAuthn(tt.sessionID)
			testutils.AssertTypeEquals(t, tt.wantErr, err, "service.ValidateAuthn error")
		})
	}
}

const redirectString = "https://loginprovider.com/login"

var redirectURL, _ = url.Parse(redirectString)

const providerKey = "stubProvider"

var authenticatedRequest, _ = NewRequest(validSessionID, *redirectURL, providerKey)
var invalidSessionRequest, _ = NewRequest(nonExistentSessionID, *redirectURL, providerKey)
var anonymousRequest, _ = NewRequest(validAnonymousSessionID, *redirectURL, providerKey)
var badProviderRequest, _ = NewRequest(validAnonymousSessionID, *redirectURL, "badProvider")
var nonExistentRequest, _ = NewRequest(nonExistentSessionID, *redirectURL, "badProvider")

func TestService_InitAuthn(t *testing.T) {
	tests := []struct {
		name         string
		request      Request
		wantLocation string
		wantErr      error
	}{
		{"authenticatedRequest", authenticatedRequest, redirectString, nil},
		{"invalidSessionRequest", invalidSessionRequest, "", &InvalidSessionError{}},
		{"anonymousRequest", anonymousRequest, redirectString, nil},
		{"badProviderRequest", badProviderRequest, "", &ConfigurationError{}},
		{"nonExistentRequest", nonExistentRequest, "", &InvalidSessionError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := service.InitAuthn(tt.request)
			testutils.AssertEquals(t, tt.wantLocation, url.String(), "service.InitAuthn url")
			testutils.AssertTypeEquals(t, tt.wantErr, err, "service.InitAuthn error")
		})
	}
}

func TestService_HandleCallback(t *testing.T) {
	tests := []struct {
		name           string
		response       Response
		wantNewSession bool
		wantErr        error
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := service.HandleCallback(tt.response)
			testutils.AssertTypeEquals(t, tt.wantErr, err, "service.HandleCallback error")
			if tt.wantNewSession {
				testutils.AssertNotEquals(t, tt.response.SessionID, session.ID(), "service.HandleCallback session ID")
			} else {
				testutils.AssertEquals(t, tt.response.SessionID, session.ID(), "service.HandleCallback session ID")
			}
		})
	}
}

type stubRepository struct{}

func (r *stubRepository) StoreSession(session Session) error {
	return nil
}

func (r *stubRepository) FetchSession(sessionID string) (Session, error) {
	switch sessionID {
	case "111":
		return validSession, nil
	case "222":
		return validAnonymousSession, nil
	case "666":
		return invalidSession, nil
	default:
		return Session{}, &InvalidSessionError{SessionID: sessionID}
	}
}

func (r *stubRepository) StoreRequest(request Request) error {
	return nil
}

type stubLoginProvider struct{}

func (lp *stubLoginProvider) InitLogin() (url.URL, error) {
	url, err := url.Parse(redirectString)

	return *url, err
}

func (lp *stubLoginProvider) HandleCallback(authorizationCode string) error {
	return nil
}
