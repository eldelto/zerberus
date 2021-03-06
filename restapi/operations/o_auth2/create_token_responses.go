// Code generated by go-swagger; DO NOT EDIT.

package o_auth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// CreateTokenOKCode is the HTTP code returned for type CreateTokenOK
const CreateTokenOKCode int = 200

/*CreateTokenOK Successful token response.

swagger:response createTokenOK
*/
type CreateTokenOK struct {

	/*
	  In: Body
	*/
	Payload *CreateTokenOKBody `json:"body,omitempty"`
}

// NewCreateTokenOK creates CreateTokenOK with default headers values
func NewCreateTokenOK() *CreateTokenOK {

	return &CreateTokenOK{}
}

// WithPayload adds the payload to the create token o k response
func (o *CreateTokenOK) WithPayload(payload *CreateTokenOKBody) *CreateTokenOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create token o k response
func (o *CreateTokenOK) SetPayload(payload *CreateTokenOKBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateTokenOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
