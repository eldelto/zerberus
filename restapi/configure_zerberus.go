// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/eldelto/zerberus/internal/auth"
	authPersistence "github.com/eldelto/zerberus/internal/auth/persistence"
	"github.com/eldelto/zerberus/internal/authn"
	authnPersistence "github.com/eldelto/zerberus/internal/authn/persistence"
	"github.com/eldelto/zerberus/internal/webutils"
	"github.com/eldelto/zerberus/restapi/operations"
	"github.com/eldelto/zerberus/restapi/operations/o_auth2"
)

//go:generate swagger generate server --target ../../zerberus --name Zerberus --spec ../api/swagger.yml --principal interface{}

func configureFlags(api *operations.ZerberusAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.ZerberusAPI) http.Handler {
	authRepository.StoreClientConfiguration(testConfig)

	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.UrlformConsumer = runtime.DiscardConsumer

	api.HTMLProducer = webutils.HTMLProducer

	api.JSONProducer = runtime.JSONProducer()

	api.OAuth2AuthorizeHandler = o_auth2.AuthorizeHandlerFunc(func(params o_auth2.AuthorizeParams) middleware.Responder {
		request := auth.Request{
			ClientID:     params.ClientID,
			RedirectURI:  params.RedirectURI,
			ResponseType: params.ResponseType,
			Scopes:       extractScopes(*params.Scope),
			State:        params.State,
		}

		if err := authService.ValidateRequest(request); err != nil {
			// TODO: Return the error as URL parameter
			//       Will probably need a custom Responder implementation => overwrite ServeError
			//			 Don't redirect if the redirect_uri isn't valid
			return newRedirect(request.RedirectURI)
		}

		return webutils.NewTemplateProvider("assets/templates/authorize.html", request)
	})

	api.OAuth2CreateAuthorizationHandler = o_auth2.CreateAuthorizationHandlerFunc(func(params o_auth2.CreateAuthorizationParams) middleware.Responder {
		// TODO: Generate the authorization code here
		// TODO: Disable trailing slash rewrite in Caddy

		return newRedirect(params.RedirectURI + "?code=123-123-123-123-123")
	})

	api.OAuth2AuthenticateHandler = o_auth2.AuthenticateHandlerFunc(func(params o_auth2.AuthenticateParams) middleware.Responder {
		sessionCookie, err := params.HTTPRequest.Cookie("ZSC")
		if err == nil {
			if err = authnService.ValidateAuthn(sessionCookie.Value); err == nil {
				return newRedirect("/v1/logout")
			}
		}

		// TODO: Pass URL from referrer header to template so it post it to the provider.

		return webutils.NewTemplateProvider("assets/templates/authenticate.html", nil)
	})

	api.OAuth2CreateAuthenticationHandler = o_auth2.CreateAuthenticationHandlerFunc(func(params o_auth2.CreateAuthenticationParams) middleware.Responder {
		// TODO: Create a new authn.Request and redirect to the authentication provider URL

		return middleware.NotImplemented("operation o_auth2.CreateAuthentication has not yet been implemented")
	})

	if api.OAuth2CreateTokenHandler == nil {
		api.OAuth2CreateTokenHandler = o_auth2.CreateTokenHandlerFunc(func(params o_auth2.CreateTokenParams, principal interface{}) middleware.Responder {
			return middleware.NotImplemented("operation o_auth2.Token has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return sessionMiddleware.Wrap(
		authnMiddleware.Wrap(handler))
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}

func extractScopes(scopeString string) []string {
	scopes := strings.Split(scopeString, ",")
	for i, scope := range scopes {
		scopes[i] = strings.TrimSpace(scope)
	}

	return scopes
}

type Redirect struct {
	location string
}

func newRedirect(location string) *Redirect {
	return &Redirect{location}
}

func (r *Redirect) WriteResponse(w http.ResponseWriter, producer runtime.Producer) {
	w.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses
	w.Header().Add("Location", r.location)
	w.WriteHeader(302)
}

var testConfig = auth.ClientConfiguration{
	ClientID:     "solvent",
	RedirectURI:  "https://www.eldelto.net/solvent",
	Scopes:       []string{"read", "write"},
	ClientSecret: "secret",
}

var authRepository = authPersistence.NewInMemoryRepository()
var authService = auth.NewService(authRepository)

var authnRepository = authnPersistence.NewInMemoryRepository()
var authnService = authn.NewService(authnRepository)

var sessionMiddleware = webutils.NewSessionMiddleware(authnService)
var authnMiddleware = webutils.NewAuthnMiddleware(authnService, "/v1/authenticate")
