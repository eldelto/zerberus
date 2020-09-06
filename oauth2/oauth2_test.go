package oauth2

import (
	"fmt"
	"testing"

	. "github.com/eldelto/zerberus/internal/testutils"
)

const scope0 = "scope0"
const scope1 = "scope1"
const clientID0 = "client_id0"
const clientSecret0 = "client_secret"
const redirectURI0 = "http://fakeurl.fake/login"

var scopes0 = []string{scope0, scope1}

const state = "123"

const notFoundClientID = "not_found"
const errorClientID = "error"

var errorUnkown = fmt.Errorf("error")

var service = NewService(&StubRepository{})

func TestService_Authorize(t *testing.T) {
	validRequest := validAuthorizationRequest()

	requestWithUnkownClientID := validAuthorizationRequest()
	requestWithUnkownClientID.ClientID = notFoundClientID

	requestWithBadRedirectURI := validAuthorizationRequest()
	requestWithBadRedirectURI.RedirectURI = "http://wrong.url"

	requestWithBadScope := validAuthorizationRequest()
	requestWithBadScope.Scopes = []string{scope0, "bad_scope"}

	validResponse := AuthorizationResponse{
		ClientID:     clientID0,
		RedirectURI:  redirectURI0,
		ResponseType: "code",
		Scopes:       scopes0,
		State:        state,
		Code:         "",
	}

	type test struct {
		input   AuthorizationRequest
		want    AuthorizationResponse
		wantErr error
	}

	tests := []test{
		{validRequest, validResponse, nil},
		{requestWithUnkownClientID, AuthorizationResponse{}, &NotFoundError{}},
		{requestWithBadRedirectURI, AuthorizationResponse{}, &ClientValidationError{}},
		{requestWithBadScope, AuthorizationResponse{}, &ClientValidationError{}},
	}

	for _, tt := range tests {
		result, err := service.Authorize(tt.input)
		AssertTypeEquals(t, tt.wantErr, err, "service.Authorize error")
		if err == nil {
			AssertNotEquals(t, "", result.Code, "result.Code")
			tt.want.Code = result.Code
			AssertEquals(t, tt.want, result, "service.Authorize result")
		}
	}
}

func validAuthorizationRequest() AuthorizationRequest {
	return AuthorizationRequest{
		ClientID:     clientID0,
		RedirectURI:  redirectURI0,
		ResponseType: "code",
		Scopes:       scopes0,
		State:        state,
	}
}

type StubRepository struct{}

func (r *StubRepository) StoreClientConfiguration(config ClientConfiguration) error {
	return nil
}

func (r *StubRepository) FetchClientConfiguration(clientID string) (ClientConfiguration, error) {
	switch clientID {
	case notFoundClientID:
		return ClientConfiguration{}, NewNotFoundError(clientID)
	case errorClientID:
		return ClientConfiguration{}, NewUnknownError(clientID, errorUnkown)
	default:
		config := ClientConfiguration{
			ClientID:     clientID0,
			ClientSecret: clientSecret0,
			RedirectURI:  redirectURI0,
			Scopes:       []string{scope0, scope1},
		}
		return config, nil
	}
}

func (r *StubRepository) StoreAuthorizationResponse(response AuthorizationResponse) error {
	switch response.ClientID {
	case errorClientID:
		return NewUnknownError(response.ClientID, errorUnkown)
	default:
		return nil
	}
}
