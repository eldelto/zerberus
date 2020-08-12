// Code generated by go-swagger; DO NOT EDIT.

package o_auth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// NewAuthorizeParams creates a new AuthorizeParams object
// no default values defined in spec.
func NewAuthorizeParams() AuthorizeParams {

	return AuthorizeParams{}
}

// AuthorizeParams contains all the bound params for the authorize operation
// typically these are obtained from a http.Request
//
// swagger:parameters authorize
type AuthorizeParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*The unique identifier of the client that has been registered with the auth server.
	  Required: true
	  In: query
	*/
	ClientID string
	/*The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).
	  Required: true
	  In: query
	*/
	RedirectURI string
	/*The expected response type (currently only code is supported).
	  Required: true
	  In: query
	*/
	ResponseType string
	/*Comma-separated list of scopes the client wants to request.
	  In: query
	*/
	Scope *string
	/*Opage value that will be returned unmodified after the redirect.
	  Required: true
	  In: query
	*/
	State string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewAuthorizeParams() beforehand.
func (o *AuthorizeParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qClientID, qhkClientID, _ := qs.GetOK("client_id")
	if err := o.bindClientID(qClientID, qhkClientID, route.Formats); err != nil {
		res = append(res, err)
	}

	qRedirectURI, qhkRedirectURI, _ := qs.GetOK("redirect_uri")
	if err := o.bindRedirectURI(qRedirectURI, qhkRedirectURI, route.Formats); err != nil {
		res = append(res, err)
	}

	qResponseType, qhkResponseType, _ := qs.GetOK("response_type")
	if err := o.bindResponseType(qResponseType, qhkResponseType, route.Formats); err != nil {
		res = append(res, err)
	}

	qScope, qhkScope, _ := qs.GetOK("scope")
	if err := o.bindScope(qScope, qhkScope, route.Formats); err != nil {
		res = append(res, err)
	}

	qState, qhkState, _ := qs.GetOK("state")
	if err := o.bindState(qState, qhkState, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindClientID binds and validates parameter ClientID from query.
func (o *AuthorizeParams) bindClientID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("client_id", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("client_id", "query", raw); err != nil {
		return err
	}

	o.ClientID = raw

	return nil
}

// bindRedirectURI binds and validates parameter RedirectURI from query.
func (o *AuthorizeParams) bindRedirectURI(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("redirect_uri", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("redirect_uri", "query", raw); err != nil {
		return err
	}

	o.RedirectURI = raw

	return nil
}

// bindResponseType binds and validates parameter ResponseType from query.
func (o *AuthorizeParams) bindResponseType(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("response_type", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("response_type", "query", raw); err != nil {
		return err
	}

	o.ResponseType = raw

	return nil
}

// bindScope binds and validates parameter Scope from query.
func (o *AuthorizeParams) bindScope(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Scope = &raw

	return nil
}

// bindState binds and validates parameter State from query.
func (o *AuthorizeParams) bindState(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("state", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("state", "query", raw); err != nil {
		return err
	}

	o.State = raw

	return nil
}
