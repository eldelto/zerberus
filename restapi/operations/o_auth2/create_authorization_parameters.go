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

// NewCreateAuthorizationParams creates a new CreateAuthorizationParams object
// no default values defined in spec.
func NewCreateAuthorizationParams() CreateAuthorizationParams {

	return CreateAuthorizationParams{}
}

// CreateAuthorizationParams contains all the bound params for the create authorization operation
// typically these are obtained from a http.Request
//
// swagger:parameters create_authorization
type CreateAuthorizationParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*The unique identifier of the client that has been registered with the auth server.
	  Required: true
	  In: formData
	*/
	ClientID string
	/*The URI the client will be redirected to after a successful authorization (has to bee the same URI that has been registered with the auth server).
	  Required: true
	  In: formData
	*/
	RedirectURI string
	/*The expected response type (currently only code is supported).
	  Required: true
	  In: formData
	*/
	ResponseType string
	/*Comma-separated list of scopes the client wants to request.
	  In: formData
	*/
	Scope *string
	/*Opage value that will be returned unmodified after the redirect.
	  Required: true
	  In: formData
	*/
	State string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewCreateAuthorizationParams() beforehand.
func (o *CreateAuthorizationParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err != http.ErrNotMultipart {
			return errors.New(400, "%v", err)
		} else if err := r.ParseForm(); err != nil {
			return errors.New(400, "%v", err)
		}
	}
	fds := runtime.Values(r.Form)

	fdClientID, fdhkClientID, _ := fds.GetOK("client_id")
	if err := o.bindClientID(fdClientID, fdhkClientID, route.Formats); err != nil {
		res = append(res, err)
	}

	fdRedirectURI, fdhkRedirectURI, _ := fds.GetOK("redirect_uri")
	if err := o.bindRedirectURI(fdRedirectURI, fdhkRedirectURI, route.Formats); err != nil {
		res = append(res, err)
	}

	fdResponseType, fdhkResponseType, _ := fds.GetOK("response_type")
	if err := o.bindResponseType(fdResponseType, fdhkResponseType, route.Formats); err != nil {
		res = append(res, err)
	}

	fdScope, fdhkScope, _ := fds.GetOK("scope")
	if err := o.bindScope(fdScope, fdhkScope, route.Formats); err != nil {
		res = append(res, err)
	}

	fdState, fdhkState, _ := fds.GetOK("state")
	if err := o.bindState(fdState, fdhkState, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindClientID binds and validates parameter ClientID from formData.
func (o *CreateAuthorizationParams) bindClientID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("client_id", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("client_id", "formData", raw); err != nil {
		return err
	}

	o.ClientID = raw

	return nil
}

// bindRedirectURI binds and validates parameter RedirectURI from formData.
func (o *CreateAuthorizationParams) bindRedirectURI(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("redirect_uri", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("redirect_uri", "formData", raw); err != nil {
		return err
	}

	o.RedirectURI = raw

	return nil
}

// bindResponseType binds and validates parameter ResponseType from formData.
func (o *CreateAuthorizationParams) bindResponseType(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("response_type", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("response_type", "formData", raw); err != nil {
		return err
	}

	o.ResponseType = raw

	return nil
}

// bindScope binds and validates parameter Scope from formData.
func (o *CreateAuthorizationParams) bindScope(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Scope = &raw

	return nil
}

// bindState binds and validates parameter State from formData.
func (o *CreateAuthorizationParams) bindState(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("state", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("state", "formData", raw); err != nil {
		return err
	}

	o.State = raw

	return nil
}
