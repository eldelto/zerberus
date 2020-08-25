// Code generated by go-swagger; DO NOT EDIT.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "This is the public API of the Zerberus authorization server.",
    "title": "Zerberus",
    "termsOfService": "TBD",
    "contact": {
      "email": "eldelto77@gmail.com"
    },
    "license": {
      "name": "Apache 2.0",
      "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
    },
    "version": "0.1.0"
  },
  "host": "TBD",
  "basePath": "/v1",
  "paths": {
    "/authenticate": {
      "get": {
        "description": "Presents the user a selection of authentication providers.",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Authentication entry point",
        "operationId": "authenticate",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "The authentication page."
          }
        }
      }
    },
    "/authorize": {
      "get": {
        "description": "Entrypoint for most OAuth2 flows (currently only the code grant flow is supported).",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Authorization endpoint",
        "operationId": "authorize",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "The authorization page."
          }
        }
      },
      "post": {
        "description": "Authorizes an application on behalf of the user.",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Create authorization endpoint",
        "operationId": "create_authorization",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "302": {
            "description": "Redirect to the given redirect_uri."
          }
        }
      }
    },
    "/token": {
      "post": {
        "security": [
          {
            "basicAuth": []
          }
        ],
        "description": "Endpoint to exchange an authorization code for an access token.",
        "consumes": [
          "application/x-www-form-urlencoded"
        ],
        "produces": [
          "application/json"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Token endpoint",
        "operationId": "create_token",
        "parameters": [
          {
            "type": "string",
            "description": "The requested grant type (currently only authorization_code is supported).",
            "name": "grant_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The authorization code that has been obtained from the authorization server.",
            "name": "code",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Successful token response.",
            "schema": {
              "type": "object",
              "required": [
                "access_token",
                "token_type",
                "expires_in"
              ],
              "properties": {
                "access_token": {
                  "description": "The generated access token.",
                  "type": "string",
                  "example": "123-123-123-123"
                },
                "expires_in": {
                  "description": "The lifetime of the token in seconds.",
                  "type": "integer",
                  "example": 3600
                },
                "refresh_token": {
                  "description": "The optional refresh token.",
                  "type": "string",
                  "example": "456-456-456-456"
                },
                "token_type": {
                  "description": "The type of the returned token.",
                  "type": "string",
                  "example": "Bearer"
                }
              }
            }
          }
        }
      }
    }
  },
  "securityDefinitions": {
    "BasicAuth": {
      "type": "basic"
    }
  },
  "tags": [
    {
      "description": "OAuth2 related endpoints",
      "name": "OAuth2"
    }
  ]
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "This is the public API of the Zerberus authorization server.",
    "title": "Zerberus",
    "termsOfService": "TBD",
    "contact": {
      "email": "eldelto77@gmail.com"
    },
    "license": {
      "name": "Apache 2.0",
      "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
    },
    "version": "0.1.0"
  },
  "host": "TBD",
  "basePath": "/v1",
  "paths": {
    "/authenticate": {
      "get": {
        "description": "Presents the user a selection of authentication providers.",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Authentication entry point",
        "operationId": "authenticate",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "The authentication page."
          }
        }
      }
    },
    "/authorize": {
      "get": {
        "description": "Entrypoint for most OAuth2 flows (currently only the code grant flow is supported).",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Authorization endpoint",
        "operationId": "authorize",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "The authorization page."
          }
        }
      },
      "post": {
        "description": "Authorizes an application on behalf of the user.",
        "produces": [
          "text/html"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Create authorization endpoint",
        "operationId": "create_authorization",
        "parameters": [
          {
            "type": "string",
            "description": "The expected response type (currently only code is supported).",
            "name": "response_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The unique identifier of the client that has been registered with the auth server.",
            "name": "client_id",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "Comma-separated list of scopes the client wants to request.",
            "name": "scope",
            "in": "query"
          },
          {
            "type": "string",
            "description": "Opage value that will be returned unmodified after the redirect.",
            "name": "state",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "302": {
            "description": "Redirect to the given redirect_uri."
          }
        }
      }
    },
    "/token": {
      "post": {
        "security": [
          {
            "basicAuth": []
          }
        ],
        "description": "Endpoint to exchange an authorization code for an access token.",
        "consumes": [
          "application/x-www-form-urlencoded"
        ],
        "produces": [
          "application/json"
        ],
        "tags": [
          "OAuth2"
        ],
        "summary": "Token endpoint",
        "operationId": "create_token",
        "parameters": [
          {
            "type": "string",
            "description": "The requested grant type (currently only authorization_code is supported).",
            "name": "grant_type",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The authorization code that has been obtained from the authorization server.",
            "name": "code",
            "in": "query",
            "required": true
          },
          {
            "type": "string",
            "description": "The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).",
            "name": "redirect_uri",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Successful token response.",
            "schema": {
              "type": "object",
              "required": [
                "access_token",
                "token_type",
                "expires_in"
              ],
              "properties": {
                "access_token": {
                  "description": "The generated access token.",
                  "type": "string",
                  "example": "123-123-123-123"
                },
                "expires_in": {
                  "description": "The lifetime of the token in seconds.",
                  "type": "integer",
                  "example": 3600
                },
                "refresh_token": {
                  "description": "The optional refresh token.",
                  "type": "string",
                  "example": "456-456-456-456"
                },
                "token_type": {
                  "description": "The type of the returned token.",
                  "type": "string",
                  "example": "Bearer"
                }
              }
            }
          }
        }
      }
    }
  },
  "securityDefinitions": {
    "BasicAuth": {
      "type": "basic"
    }
  },
  "tags": [
    {
      "description": "OAuth2 related endpoints",
      "name": "OAuth2"
    }
  ]
}`))
}
