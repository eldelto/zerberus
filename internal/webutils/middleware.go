package webutils

import (
	"net/http"
	"strings"

	"github.com/eldelto/zerberus/authentication"
)

// SessionCookieKey is the name of the session cookie used by Zerberus.
const SessionCookieKey = "ZSC"

// SessionMiddleware represents a middleware to check for a valid session and otherwise
// create a new one.
type SessionMiddleware struct {
	service *authentication.Service
}

// NewSessionMiddleware returns a new instance of SessionMiddleware with the given
// authentication.Service.
func NewSessionMiddleware(service *authentication.Service) *SessionMiddleware {
	return &SessionMiddleware{service}
}

// Wrap wraps a given http.Handler and validates the session cookie of the request
// before executing the passed in handler.
func (m *SessionMiddleware) Wrap(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(SessionCookieKey); err == nil {
			// Validate session if cookie is set
			if err = m.service.ValidateSession(cookie.Value); err == nil {
				handler.ServeHTTP(w, r)
				return
			}
		}

		// Otherwise create a new session
		session, err := m.service.CreateSession()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		cookie := http.Cookie{
			Name:     "ZSC",
			Value:    session.ID(),
			MaxAge:   int(session.Lifetime().Seconds()),
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
			//Secure:   true,	// Disabled because localy we don't use TLS
		}
		http.SetCookie(w, &cookie)
		handler.ServeHTTP(w, r)
	}
}

// ReferrerHeaderKey is the name of the header which stores the original URI before
// being redirected to the authentication URI.
const ReferrerHeaderKey = "Z-Referrer"

// AuthnMiddleware represents a middleware to check for a valid authenticated session
// and otherwise redirects to the authenURI.
type AuthnMiddleware struct {
	service  *authentication.Service
	authnURI string
}

// NewAuthnMiddleware returns a new instance of AuthnMiddleware with the given
// authentication.Service and authnURI.
func NewAuthnMiddleware(service *authentication.Service, authnURI string) *AuthnMiddleware {
	return &AuthnMiddleware{
		service:  service,
		authnURI: authnURI,
	}
}

// Wrap wraps a given http.Handler and validates the session for a valid authentication
// before executing the passed in handler.
func (m *AuthnMiddleware) Wrap(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, m.authnURI) {
			handler.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(SessionCookieKey)
		if err != nil {
			redirect(m.authnURI, w, r)
			return
		}

		if err = m.service.ValidateAuthentication(cookie.Value); err != nil {
			redirect(m.authnURI, w, r)
			return
		}

		handler.ServeHTTP(w, r)
	}
}

func redirect(location string, w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Content-Type") //Remove Content-Type on empty responses
	w.Header().Add("Location", location)
	w.Header().Add(ReferrerHeaderKey, r.RequestURI)
	w.WriteHeader(302)
}
