package loginprovider

import (
	"net/http"
	"github.com/google/uuid"

	"github.com/eldelto/zerberus/authn"
)

// FakeLoginProvider doesn't actually use any third party identity provider but
// just returns a valid authentication in any case.
type FakeLoginProvider struct {}

// NewFakeLoginProvider return a new FakeLoginProvider.
func NewFakeLoginProvider() *FakeLoginProvider {
	return &FakeLoginProvider{}
}

// InitLogin immediately redirects the client to the callback URL with a
// hardcoded authorization code.
func (lp *FakeLoginProvider) InitLogin(w http.ResponseWriter) error {
	authorizationCode := uuid.Nil
	w.Header().Add("Location", "/v1/callback#" + authorizationCode.String())

	return nil
}

// HandleCallback only checks if the hardcoded authorization code is present
// and confirms the authentication. Otherwise it returns a CallbackError.
func (lp *FakeLoginProvider) HandleCallback(authorizationCode string) error {
	if authorizationCode != uuid.Nil.String() {
		return authn.NewCallbackError(lp, "invalid authorization code: " + authorizationCode)
	}

	return nil
}