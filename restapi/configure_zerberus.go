// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/eldelto/zerberus/internal/html"
	"github.com/eldelto/zerberus/oauth2"
	"github.com/eldelto/zerberus/oauth2/persistence"
	"github.com/eldelto/zerberus/restapi/operations"
	"github.com/eldelto/zerberus/restapi/operations/o_auth2"
)

//go:generate swagger generate server --target ../../zerberus --name Zerberus --spec ../api/swagger.yml --principal interface{}

func configureFlags(api *operations.ZerberusAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.ZerberusAPI) http.Handler {
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

	api.HTMLProducer = html.HTMLProducer

	api.JSONProducer = runtime.JSONProducer()

	api.OAuth2AuthorizeHandler = o_auth2.AuthorizeHandlerFunc(func(params o_auth2.AuthorizeParams) middleware.Responder {
		request := oauth2.AuthorizationRequest{
			ClientID:    params.ClientID,
			RedirectURI: params.RedirectURI,
			Scopes:      extractScopes(*params.Scope),
			State:       params.State,
		}

		// TODO: Return the error as URL parameter
		response, _ := service.Authorize(request)

		return html.NewTemplateProvider("assets/templates/authorize.html", response)
	})

	if api.OAuth2TokenHandler == nil {
		api.OAuth2TokenHandler = o_auth2.TokenHandlerFunc(func(params o_auth2.TokenParams, principal interface{}) middleware.Responder {
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
	return handler
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

var repo = persistence.NewInMemoryRepository()
var service = oauth2.NewService(repo)
