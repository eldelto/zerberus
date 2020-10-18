package loginprovider

import (
	"github.com/google/uuid"
	"net/url"

	"github.com/eldelto/zerberus/authn"
)

// FakeLoginProvider doesn't actually use any third party identity provider but
// just returns a valid authentication in any case.
type FakeLoginProvider struct{}

// NewFakeLoginProvider return a new FakeLoginProvider.
func NewFakeLoginProvider() *FakeLoginProvider {
	return &FakeLoginProvider{}
}

// InitLogin immediately returns the callback URL with a hardcoded authorization code.
func (lp *FakeLoginProvider) InitLogin() (url.URL, error) {
	authorizationCode := uuid.Nil
	url, err := url.Parse("/v1/callback#" + authorizationCode.String())

	return *url, err
}

// HandleCallback only checks if the hardcoded authorization code is present
// and confirms the authentication. Otherwise it returns a CallbackError.
func (lp *FakeLoginProvider) HandleCallback(authorizationCode string) error {
	if authorizationCode != uuid.Nil.String() {
		return authn.NewCallbackError(lp, "invalid authorization code: "+authorizationCode)
	}

	return nil
}
