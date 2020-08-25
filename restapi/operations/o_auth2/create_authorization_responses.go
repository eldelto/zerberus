// Code generated by go-swagger; DO NOT EDIT.

package o_auth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// CreateAuthorizationFoundCode is the HTTP code returned for type CreateAuthorizationFound
const CreateAuthorizationFoundCode int = 302

/*CreateAuthorizationFound Redirect to the given redirect_uri.

swagger:response createAuthorizationFound
*/
type CreateAuthorizationFound struct {
}

// NewCreateAuthorizationFound creates CreateAuthorizationFound with default headers values
func NewCreateAuthorizationFound() *CreateAuthorizationFound {

	return &CreateAuthorizationFound{}
}

// WriteResponse to the client
func (o *CreateAuthorizationFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(302)
}
