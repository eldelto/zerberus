// Code generated by go-swagger; DO NOT EDIT.

package o_auth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// CreateAuthenticationFoundCode is the HTTP code returned for type CreateAuthenticationFound
const CreateAuthenticationFoundCode int = 302

/*CreateAuthenticationFound Redirect to the selected authentication provider's authorization page.

swagger:response createAuthenticationFound
*/
type CreateAuthenticationFound struct {
}

// NewCreateAuthenticationFound creates CreateAuthenticationFound with default headers values
func NewCreateAuthenticationFound() *CreateAuthenticationFound {

	return &CreateAuthenticationFound{}
}

// WriteResponse to the client
func (o *CreateAuthenticationFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(302)
}
