package godoauth

import (
	"fmt"
	"net/http"
)

type HttpAuthError struct {
	error string
	Code  int
}

// Predefined internal error
var ErrorUnauthorized *HttpAuthError = NewHttpError("Unauthorized Access", http.StatusUnauthorized)
var ErrorForbidden *HttpAuthError = NewHttpError("Forbiden Access", http.StatusForbidden)
var ErrorInternal *HttpAuthError = NewHttpError("Internal server error", http.StatusInternalServerError)

// HttpBadRequest returns *HttpError with supplied informative string and error code 400.
func HttpBadRequest(error string) (err *HttpAuthError) {
	return NewHttpError(error, http.StatusBadRequest)
}

// NewHttpError creates new HttpError with supplied error message and code.
// The message is displayed to the end user, so please be careful.
func NewHttpError(error string, code int) (err *HttpAuthError) {
	return &HttpAuthError{error, code}
}

func (e HttpAuthError) Error() string {
	return fmt.Sprintf("%d: %v", e.Code, e.error)
}

// Respond sends the error code and message to the supplied ResponseWriter
func (e *HttpAuthError) Respond(w http.ResponseWriter) {
	http.Error(w, e.error, e.Code)
}
