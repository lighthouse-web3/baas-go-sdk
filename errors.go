package backup

import "fmt"

// ApiError represents an HTTP error response from the backup service.
type ApiError struct {
	StatusCode int
	Body       interface{}
	Msg        string
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("ApiError %d: %s", e.StatusCode, e.Msg)
}

// NewApiError creates a new ApiError.
func NewApiError(msg string, status int, body interface{}) *ApiError {
	return &ApiError{StatusCode: status, Body: body, Msg: msg}
}

// IsApiError checks whether an error is an *ApiError.
func IsApiError(err error) (*ApiError, bool) {
	if ae, ok := err.(*ApiError); ok {
		return ae, true
	}
	return nil, false
}
