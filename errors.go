package vulners

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error conditions.
var (
	// ErrAPIKeyRequired is returned when an API key is required but not provided.
	ErrAPIKeyRequired = errors.New("vulners: API key is required")

	// ErrInvalidInput is returned when a required parameter is missing or invalid.
	ErrInvalidInput = errors.New("vulners: invalid input")

	// ErrNotFound is returned when a requested resource is not found.
	ErrNotFound = errors.New("vulners: resource not found")

	// ErrRateLimited is returned when the rate limit has been exceeded.
	ErrRateLimited = errors.New("vulners: rate limit exceeded")

	// ErrUnauthorized is returned when the API key is invalid or expired.
	ErrUnauthorized = errors.New("vulners: unauthorized - invalid or expired API key")

	// ErrBadRequest is returned when the request is malformed.
	ErrBadRequest = errors.New("vulners: bad request")

	// ErrServerError is returned when the server returns a 5xx error.
	ErrServerError = errors.New("vulners: server error")
)

// APIError represents an error response from the Vulners API.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int `json:"statusCode,omitempty"`

	// Message is the error message from the API.
	Message string `json:"error,omitempty"`

	// ErrorCode is an optional error code from the API.
	ErrorCode string `json:"errorCode,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("vulners: API error (status %d, code %s): %s", e.StatusCode, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("vulners: API error (status %d): %s", e.StatusCode, e.Message)
}

// Is implements errors.Is for APIError.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == 404
	case ErrRateLimited:
		return e.StatusCode == 429
	case ErrUnauthorized:
		return e.StatusCode == 401 || e.StatusCode == 403
	case ErrBadRequest:
		return e.StatusCode == 400
	case ErrServerError:
		return e.StatusCode >= 500 && e.StatusCode < 600
	}
	return false
}

// NewAPIError creates a new APIError with the given parameters.
func NewAPIError(statusCode int, message, errorCode string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
		ErrorCode:  errorCode,
	}
}

// validateRequired validates that the given string is not empty.
func validateRequired(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
	}
	return nil
}
