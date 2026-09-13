package atlas

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorItem is one entry in the Atlas §9.1 error envelope. Code is the stable,
// machine-readable part of the contract integrators branch on
// (LAST_ADMIN, NOT_FOUND, FORM_IDENTIFIER_EXISTS, …). Param names the offending
// input field; Meta carries extras such as a rate limit's retry_after.
type ErrorItem struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Param   string                 `json:"param,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// APIError is returned by every SDK method on a non-2xx response. It carries the
// HTTP status and the full, ordered error envelope. Recover it with errors.As:
//
//	var apiErr *atlas.APIError
//	if errors.As(err, &apiErr) {
//	        log.Printf("status=%d code=%s param=%s", apiErr.Status, apiErr.Code(), apiErr.Errors[0].Param)
//	}
type APIError struct {
	// Status is the HTTP status of the failed response.
	Status int
	// Errors is the full envelope, in the order the server returned it.
	Errors []ErrorItem
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		first := e.Errors[0]
		if first.Param != "" {
			return fmt.Sprintf("atlas: %s: %s (%s) [param=%s]", first.Code, first.Message, statusText(e.Status), first.Param)
		}
		return fmt.Sprintf("atlas: %s: %s (%s)", first.Code, first.Message, statusText(e.Status))
	}
	return fmt.Sprintf("atlas: API request failed with status %d", e.Status)
}

// Code returns the first error's stable code — the field callers branch on most.
func (e *APIError) Code() string {
	if len(e.Errors) > 0 {
		return e.Errors[0].Code
	}
	return ""
}

// HasCode reports whether any error in the envelope carries the given code.
func (e *APIError) HasCode(code string) bool {
	for _, item := range e.Errors {
		if item.Code == code {
			return true
		}
	}
	return false
}

// IsNotFound reports whether the error represents a missing object (404 /
// NOT_FOUND).
func (e *APIError) IsNotFound() bool {
	return e.Status == http.StatusNotFound || e.HasCode("NOT_FOUND")
}

func statusText(status int) string {
	if t := http.StatusText(status); t != "" {
		return fmt.Sprintf("HTTP %d %s", status, t)
	}
	return fmt.Sprintf("HTTP %d", status)
}

// parseError turns a non-2xx body into an *APIError, tolerating a non-JSON body
// (e.g. an upstream proxy) by keeping it as the message.
func parseError(status int, raw []byte) error {
	apiErr := &APIError{Status: status}
	if len(raw) > 0 {
		var envelope struct {
			Errors []ErrorItem `json:"errors"`
		}
		if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Errors) > 0 {
			apiErr.Errors = envelope.Errors
			return apiErr
		}
		msg := string(raw)
		if len(msg) > 500 {
			msg = msg[:500]
		}
		apiErr.Errors = []ErrorItem{{Code: "UNKNOWN", Message: msg}}
		return apiErr
	}
	apiErr.Errors = []ErrorItem{{
		Code:    "UNKNOWN",
		Message: fmt.Sprintf("atlas API request failed with status %d", status),
	}}
	return apiErr
}
