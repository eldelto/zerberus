package html

import (
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/go-openapi/runtime"
)

var HTMLProducer = runtime.ProducerFunc(htmlProducerFunc)

type TemplateProvider struct {
	templatePath string
	data         interface{}
}

func NewTemplateProvider(templatePath string, data interface{}) *TemplateProvider {
	return &TemplateProvider{
		templatePath: templatePath,
		data:         data,
	}
}

func (t *TemplateProvider) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.Header().Del(runtime.HeaderContentType)
	rw.WriteHeader(200)

	if err := producer.Produce(rw, t); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

func htmlProducerFunc(w io.Writer, data interface{}) error {
	provider, ok := data.(*TemplateProvider)
	if !ok {
		return newNoTemplateProviderError(fmt.Sprintf("data must by of type '*TemplateProvider' but was '%T'", data))
	}

	templ, err := template.ParseFiles(provider.templatePath)
	if err != nil {
		return newTemplateError(fmt.Sprintf("Error while parsing template from '%s'", provider.templatePath), err)
	}

	err = templ.Execute(w, provider.data)
	if err != nil {
		return newTemplateError(fmt.Sprintf("Error while executing template '%s'", provider.templatePath), err)
	}

	return nil
}

type NoTemplateProviderError struct {
	message string
}

func newNoTemplateProviderError(message string) *NoTemplateProviderError {
	return &NoTemplateProviderError{message}
}

func (e *NoTemplateProviderError) Error() string {
	return e.message
}

type TemplateError struct {
	message string
	err     error
}

func newTemplateError(message string, err error) *TemplateError {
	return &TemplateError{
		message: message,
		err:     err,
	}
}

func (e *TemplateError) Error() string {
	return e.message
}

func (e *TemplateError) Unwrap() error {
	return e.err
}
