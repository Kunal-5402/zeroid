package domain

import (
	"net/http"
	"time"
)

// ErrorResponse is the standard structured error envelope.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail holds the details of a structured error.
type ErrorDetail struct {
	Code         int    `json:"code"`
	InternalCode string `json:"internalCode"`
	Message      string `json:"message"`
	Status       string `json:"status"`
	Timestamp    string `json:"timestamp"`
	RequestID    string `json:"requestId,omitempty"`
}

// NewErrorResponse creates a structured error response.
func NewErrorResponse(code int, internalCode, message string) *ErrorResponse {
	return &ErrorResponse{
		Error: ErrorDetail{
			Code:         code,
			InternalCode: internalCode,
			Message:      message,
			Status:       http.StatusText(code),
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// WithRequestID adds a request ID to the error response.
func (e *ErrorResponse) WithRequestID(reqID string) *ErrorResponse {
	e.Error.RequestID = reqID
	return e
}

// Standard ZeroID error codes.
const (
	ErrCodeBadRequest     = "ZEROID-40001"
	ErrCodeUnauthorized   = "ZEROID-40101"
	ErrCodeForbidden      = "ZEROID-40301"
	ErrCodeNotFound       = "ZEROID-40401"
	ErrCodeConflict       = "ZEROID-40901"
	ErrCodeInternal       = "ZEROID-50001"
	ErrCodeNotImplemented = "ZEROID-50101"
)
