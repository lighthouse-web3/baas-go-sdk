package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// Error code constants returned by the backend in structured error bodies.
// SDK callers should prefer the helper functions below over string comparison.
const (
	ErrCodeInvalidCredentials   = "invalid_credentials"
	ErrCodeUnauthorized         = "unauthorized"
	ErrCodeForbidden            = "forbidden"
	ErrCodeNotFound             = "not_found"
	ErrCodeConflict             = "conflict"
	ErrCodePayloadTooLarge      = "payload_too_large"
	ErrCodeStorageQuotaExceeded = "storage_quota_exceeded"

	ErrCodeInvalidAPIKey    = "invalid_api_key"
	ErrCodeRevokedAPIKey    = "revoked_api_key"
	ErrCodeExpiredAPIKey    = "expired_api_key"
	ErrCodeMissingWorkspace = "missing_workspace_membership"
	ErrCodeMissingScope     = "missing_scope"
)

// ApiError represents an HTTP error response from the Lighthouse backend.
// It carries both the HTTP status and, when present, the structured error
// body so callers can surface a precise cause to users.
type ApiError struct {
	StatusCode int
	// Code is the machine-readable error code returned by the backend
	// (e.g. "invalid_api_key"). May be empty if the backend did not
	// provide a structured error.
	Code string
	// Msg is the human-readable message.
	Msg string
	// Body is the full parsed error body (best-effort).
	Body map[string]any
}

func (e *ApiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ApiError %d [%s]: %s", e.StatusCode, e.Code, e.Msg)
	}
	return fmt.Sprintf("ApiError %d: %s", e.StatusCode, e.Msg)
}

// NewApiError creates a new ApiError from a status, message and optional body.
// If body is a map[string]any the Code is populated from common fields.
func NewApiError(msg string, status int, body any) *ApiError {
	e := &ApiError{StatusCode: status, Msg: msg}
	if m, ok := body.(map[string]any); ok {
		e.Body = m
		if c, ok := m["code"].(string); ok {
			e.Code = c
		} else if c, ok := m["errorCode"].(string); ok {
			e.Code = c
		} else if c, ok := m["error"].(string); ok && !strings.Contains(c, " ") {
			// Some backends return a short slug in the "error" field.
			e.Code = c
		}
	}
	return e
}

// IsApiError unwraps an error chain and returns the underlying ApiError if any.
func IsApiError(err error) (*ApiError, bool) {
	var ae *ApiError
	if stderrors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// IsUnauthorized reports whether err is an HTTP 401 response.
func IsUnauthorized(err error) bool { return statusEquals(err, 401) }

// IsForbidden reports whether err is an HTTP 403 response.
func IsForbidden(err error) bool { return statusEquals(err, 403) }

// IsNotFound reports whether err is an HTTP 404 response.
func IsNotFound(err error) bool { return statusEquals(err, 404) }

// IsConflict reports whether err is an HTTP 409 response.
func IsConflict(err error) bool { return statusEquals(err, 409) }

// IsPayloadTooLarge reports whether err is an HTTP 413 response.
func IsPayloadTooLarge(err error) bool { return statusEquals(err, 413) }

// IsInvalidAPIKey reports whether the error is an auth failure caused by
// an invalid, revoked or expired API key.
func IsInvalidAPIKey(err error) bool {
	ae, ok := IsApiError(err)
	if !ok {
		return false
	}
	switch ae.Code {
	case ErrCodeInvalidAPIKey, ErrCodeRevokedAPIKey, ErrCodeExpiredAPIKey:
		return true
	}
	return false
}

// IsMissingWorkspaceMembership reports whether the error indicates the caller
// is not a member of the target workspace.
func IsMissingWorkspaceMembership(err error) bool {
	ae, ok := IsApiError(err)
	if !ok {
		return false
	}
	return ae.Code == ErrCodeMissingWorkspace
}

// IsMissingScope reports whether the error indicates the caller lacks a
// required scope/permission.
func IsMissingScope(err error) bool {
	ae, ok := IsApiError(err)
	if !ok {
		return false
	}
	return ae.Code == ErrCodeMissingScope
}

// IsStorageQuotaExceeded reports whether the error is a quota violation.
func IsStorageQuotaExceeded(err error) bool {
	ae, ok := IsApiError(err)
	if !ok {
		return false
	}
	if ae.StatusCode == 413 {
		return true
	}
	return ae.Code == ErrCodeStorageQuotaExceeded
}

func statusEquals(err error, status int) bool {
	ae, ok := IsApiError(err)
	if !ok {
		return false
	}
	return ae.StatusCode == status
}
