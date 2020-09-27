package loginprovider

import (
	"net/http"
	"github.com/google/uuid"

	"github.com/eldelto/zerberus/authentication"
)

type FakeLoginProvider struct {}

func NewFakeLoginProvider() *FakeLoginProvider {
	return &FakeLoginProvider{}
}

func (lp *FakeLoginProvider) InitLogin(w http.ResponseWriter) error {
	authorizationCode := uuid.Nil
	w.Header().Add("Location", "/v1/callback#" + authorizationCode.String())

	return nil
}

func (lp *FakeLoginProvider) HandleCallback(authorizationCode string) error {
	if authorizationCode != uuid.Nil.String() {
		return authentication.NewCallbackError(lp, "invalid authorization code: " + authorizationCode)
	}

	return nil
}