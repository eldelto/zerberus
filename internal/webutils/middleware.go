package webutils

import (
	"github.com/eldelto/zerberus/authentication"
	"net/http"
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
