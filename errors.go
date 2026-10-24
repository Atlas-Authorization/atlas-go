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
	// DocsURL is the code's page in the error reference
	// (https://atlasauth.net/errors/<code>).
	DocsURL string `json:"docs_url,omitempty"`
	// DidYouMean is, on ROUTE_NOT_FOUND only, the closest documented paths.
	DidYouMean []string `json:"did_you_mean,omitempty"`
	// AllowedMethods is, on ROUTE_NOT_FOUND only, the methods the path does
	// support.
	AllowedMethods []string `json:"allowed_methods,omitempty"`
}

// Stable error codes worth branching on with APIError.HasCode / Code.
const (
	// ErrCodeEmailDeliveryNotConfigured: the instance has no working email
	// sender for a flow that must send mail.
	ErrCodeEmailDeliveryNotConfigured = "EMAIL_DELIVERY_NOT_CONFIGURED"
	// ErrCodeEmailProviderRequired: the change needs an email provider to be
	// configured first.
	ErrCodeEmailProviderRequired = "EMAIL_PROVIDER_REQUIRED"
	// ErrCodeEmailProviderInUse: the email provider cannot be removed while
	// email-dependent features are on and nothing else would deliver email;
	// Meta["features"] lists them. Delete with Force to remove it anyway.
	ErrCodeEmailProviderInUse = "EMAIL_PROVIDER_IN_USE"
	// ErrCodeCaptchaKeysRequired: captcha is bring-your-own-keys; turning it on
	// (or switching provider) needs that provider's site key and secret stored.
	ErrCodeCaptchaKeysRequired = "CAPTCHA_KEYS_REQUIRED"
	// ErrCodeCaptchaInUse: a captcha key a live flow uses cannot be removed;
	// Meta["flows"] lists them. Delete with Force to remove it anyway.
	ErrCodeCaptchaInUse = "CAPTCHA_IN_USE"
	// ErrCodeUnknownField: a strict write (Atlas-Strict: true) carried a body
	// field the endpoint does not accept; Param names it.
	ErrCodeUnknownField = "UNKNOWN_FIELD"
	// ErrCodeReadOnlyField: the body set a field that is not writable on this
	// endpoint; Param names it and the message names the call that changes it.
	ErrCodeReadOnlyField = "READ_ONLY_FIELD"
	// ErrCodeDevelopmentEmailNotAllowed: the development email sender is not
	// available on a production instance (409).
	ErrCodeDevelopmentEmailNotAllowed = "DEVELOPMENT_EMAIL_NOT_ALLOWED"
	// ErrCodeDevelopmentEmailUnavailable: the development email sender is not
	// available on this deployment (503).
	ErrCodeDevelopmentEmailUnavailable = "DEVELOPMENT_EMAIL_UNAVAILABLE"
	// ErrCodeDevelopmentEmailLimitReached: the development sender's daily or
	// per-recipient hourly cap is spent (429; Meta["window"],
	// Meta["retry_after_seconds"]).
	ErrCodeDevelopmentEmailLimitReached = "DEVELOPMENT_EMAIL_LIMIT_REACHED"
	// ErrCodeDevelopmentEmailTemplateNotAllowed: the development sender sends
	// only Atlas's own sign-in emails (422).
	ErrCodeDevelopmentEmailTemplateNotAllowed = "DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED"
	// ErrCodeReferralsNotConfigured: referrals cannot be enabled until the
	// provider's needs are set (422; meta names what is missing).
	ErrCodeReferralsNotConfigured = "REFERRALS_NOT_CONFIGURED"
	// ErrCodeReferralCodeTaken: another user on the instance already holds that
	// referral code (409).
	ErrCodeReferralCodeTaken = "REFERRAL_CODE_TAKEN"
	// ErrCodePlanInUse: a billing plan cannot be removed while subscriptions
	// still use it.
	ErrCodePlanInUse = "PLAN_IN_USE"
	// ErrCodeWrongKeySurface: the key is valid but for a different API surface
	// (for example a platform key on a secret-key route).
	ErrCodeWrongKeySurface = "WRONG_KEY_SURFACE"
	// ErrCodeInvalidKey: the key is malformed, unknown or revoked.
	ErrCodeInvalidKey = "INVALID_KEY"
	// ErrCodeLimitExceeded: a usage debit would exceed an API key's spend cap.
	// RecordUsage reports it as APIKeyUsageDebit.Code (Allowed=false), not as
	// an error.
	ErrCodeLimitExceeded = "LIMIT_EXCEEDED"
	// ErrCodeIdempotencyConflict: an idempotency key was reused with a
	// different request (for example another unit or amount).
	ErrCodeIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	// ErrCodeSessionRevoked, ErrCodeSessionIdleExpired, ErrCodeSessionExpired:
	// the session has ended (signed out, timed out from inactivity, or past
	// its absolute expiry) and cannot be kept alive.
	ErrCodeSessionRevoked     = "SESSION_REVOKED"
	ErrCodeSessionIdleExpired = "SESSION_IDLE_EXPIRED"
	ErrCodeSessionExpired     = "SESSION_EXPIRED"
	// ErrCodeInsufficientScope: the key lacks a scope the call needs;
	// Meta["required_scope"] names it (403). It replaces ErrCodeScopeMissing;
	// use APIError.IsInsufficientScope, which accepts both.
	ErrCodeInsufficientScope = "INSUFFICIENT_SCOPE"
	// ErrCodeScopeMissing is the former spelling of ErrCodeInsufficientScope
	// (the new envelope carries it as Meta["legacy_code"]); still tolerated.
	ErrCodeScopeMissing = "SCOPE_MISSING"
	// ErrCodeOriginNotAllowed: a key locked to allowed_origins was used from
	// another browser origin (403). See APIError.IsOriginNotAllowed.
	ErrCodeOriginNotAllowed = "ORIGIN_NOT_ALLOWED"
	// ErrCodeStepUpRequired: a root action (create an app or instance, mint a
	// key) needs a multi-factor sign-in within the last five minutes (403).
	ErrCodeStepUpRequired = "STEP_UP_REQUIRED"
	// ErrCodeRouteNotFound: no endpoint matches the method and path (a typo
	// or a guessed route); see ErrorItem.DidYouMean and AllowedMethods.
	ErrCodeRouteNotFound = "ROUTE_NOT_FOUND"
	// ErrCodeNotALiveInstance, ErrCodeTestModeOnly, ErrCodeTestingUnavailable:
	// the call is for (or refused on) a live or test-mode instance only.
	ErrCodeNotALiveInstance   = "NOT_A_LIVE_INSTANCE"
	ErrCodeTestModeOnly       = "TEST_MODE_ONLY"
	ErrCodeTestingUnavailable = "TESTING_UNAVAILABLE"
	// ErrCodePartnerLinkUnavailable: the partner-link credential an
	// integration needs is not available on this instance.
	ErrCodePartnerLinkUnavailable = "PARTNER_LINK_UNAVAILABLE"
)

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

// IsInsufficientScope reports whether the key lacked a required scope. It
// accepts INSUFFICIENT_SCOPE and the former SCOPE_MISSING.
func (e *APIError) IsInsufficientScope() bool {
	return e.HasCode(ErrCodeInsufficientScope) || e.HasCode(ErrCodeScopeMissing)
}

// RequiredScope returns the scope an INSUFFICIENT_SCOPE (or SCOPE_MISSING)
// error says the call needed, or "".
func (e *APIError) RequiredScope() string {
	for _, item := range e.Errors {
		if item.Code == ErrCodeInsufficientScope || item.Code == ErrCodeScopeMissing {
			if s, ok := item.Meta["required_scope"].(string); ok {
				return s
			}
		}
	}
	return ""
}

// IsOriginNotAllowed reports whether a browser-origin-locked key was used from
// another origin (ORIGIN_NOT_ALLOWED).
func (e *APIError) IsOriginNotAllowed() bool { return e.HasCode(ErrCodeOriginNotAllowed) }

// IsStepUpRequired reports whether a multi-factor sign-in is needed first.
func (e *APIError) IsStepUpRequired() bool { return e.HasCode(ErrCodeStepUpRequired) }

// IsRouteNotFound reports whether no endpoint matched the method and path.
func (e *APIError) IsRouteNotFound() bool { return e.HasCode(ErrCodeRouteNotFound) }

// DidYouMean returns the closest documented paths of a ROUTE_NOT_FOUND error.
func (e *APIError) DidYouMean() []string {
	for _, item := range e.Errors {
		if item.Code == ErrCodeRouteNotFound {
			return item.DidYouMean
		}
	}
	return nil
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
