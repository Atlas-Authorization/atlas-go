package atlas

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

// APIKeysService is the /v1/api_keys namespace — end-user API keys (Clerk
// api_keys parity). A tenant mints these for its own users/organizations and
// later asks Atlas to Verify one a subject presented. Only a hash is stored, so
// the ak_ secret is shown exactly once at mint; a read reports only Prefix.
type APIKeysService struct{ client *Client }

// APIKey is an end-user API key as read back (no secret).
type APIKey struct {
	Object      string                 `json:"object"`
	ID          string                 `json:"id"`
	SubjectType string                 `json:"subject_type"`
	SubjectID   string                 `json:"subject_id"`
	Name        *string                `json:"name"`
	Prefix      string                 `json:"prefix"`
	Claims      map[string]interface{} `json:"claims"`
	// Limits are the key's spend caps; nil when it has none.
	Limits []APIKeyLimit `json:"limits"`
	// Usage is each cap with its current-window usage (empty without caps).
	Usage []APIKeyLimitState `json:"usage"`
	// Enabled is false for a key that was disabled (it verifies as invalid
	// until re-enabled). Nil from a server that predates key controls.
	Enabled *bool `json:"enabled,omitempty"`
	// RateLimit is the per-key verify throttle, nil when the key has none.
	RateLimit *APIKeyRateLimit `json:"rate_limit,omitempty"`
	// Remaining is the use budget left (each successful verify spends one);
	// nil means unlimited.
	Remaining  *int64 `json:"remaining,omitempty"`
	LastUsedAt *int64 `json:"last_used_at"`
	ExpiresAt  *int64 `json:"expires_at"`
	RevokedAt  *int64 `json:"revoked_at"`
	CreatedAt  int64  `json:"created_at"`
}

// APIKeyRateLimit throttles verifies of one key: at most Max per
// WindowSeconds. A throttled verify answers Code=rate_limited.
type APIKeyRateLimit struct {
	Max           int64 `json:"max"`
	WindowSeconds int64 `json:"window_seconds"`
}

// Coded refusals of a live key by its own policy (APIKeyVerification.Code).
const (
	APIKeyRefusalInsufficientScope = "insufficient_scope"
	APIKeyRefusalRateLimited       = "rate_limited"
	APIKeyRefusalUsageExhausted    = "usage_exhausted"
)

// API key spend-cap periods. Request caps a single debit; day and month are
// UTC calendar windows; total never resets.
const (
	APIKeyLimitPeriodRequest = "request"
	APIKeyLimitPeriodDay     = "day"
	APIKeyLimitPeriodMonth   = "month"
	APIKeyLimitPeriodTotal   = "total"
)

// APIKeyLimit is a per-key spend cap, metered with APIKeysService.RecordUsage.
type APIKeyLimit struct {
	// Unit is app-defined, e.g. "requests" or "usd_cents".
	Unit string `json:"unit"`
	// Amount is the cap, in Unit.
	Amount int64 `json:"amount"`
	// Period is request, day, month or total.
	Period string `json:"period"`
}

// APIKeyLimitState is a spend cap with its current-window usage.
type APIKeyLimitState struct {
	Unit   string `json:"unit"`
	Period string `json:"period"`
	Amount int64  `json:"amount"`
	// Used in the current window (always 0 for a per-request cap).
	Used int64 `json:"used"`
	// Remaining is Amount - Used, never below 0.
	Remaining int64 `json:"remaining"`
	// WindowStart is epoch ms; nil for a per-request cap.
	WindowStart *int64 `json:"window_start"`
	// ResetsAt is epoch ms; nil for per-request and total caps.
	ResetsAt *int64 `json:"resets_at"`
}

// APIKeyUsageCounter is a raw usage counter for one unit in its current window.
type APIKeyUsageCounter struct {
	Unit string `json:"unit"`
	// Period is day, month or total.
	Period      string `json:"period"`
	Used        int64  `json:"used"`
	WindowStart int64  `json:"window_start"`
	// ResetsAt is epoch ms; nil for total.
	ResetsAt *int64 `json:"resets_at"`
}

// RecordAPIKeyUsageParams is the body of POST /v1/api_keys/:id/usage.
type RecordAPIKeyUsageParams struct {
	// Amount to debit, in Unit (a positive integer).
	Amount int64 `json:"amount"`
	// Unit to debit, matching the unit of the caps it should count against.
	Unit string `json:"unit"`
	// IdempotencyKey makes a retry return the first outcome without counting
	// again (kept 24 hours).
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// APIKeyUsageDebit is the outcome of a usage debit. A refusal is not an error:
// Allowed is false, Code is "LIMIT_EXCEEDED", and nothing was recorded.
type APIKeyUsageDebit struct {
	Object  string `json:"object"`
	KeyID   string `json:"key_id"`
	Unit    string `json:"unit"`
	Amount  int64  `json:"amount"`
	Allowed bool   `json:"allowed"`
	// Code is set only when Allowed is false.
	Code string `json:"code,omitempty"`
	// Exceeded lists the caps that refused the debit (empty when allowed).
	Exceeded []APIKeyLimitState `json:"exceeded"`
	// Usage is every cap on the key after this call.
	Usage []APIKeyLimitState `json:"usage"`
	// Counters are the debited unit's day, month and total counters.
	Counters []APIKeyUsageCounter `json:"counters"`
	// IdempotentReplay is true when this is the stored outcome of an earlier
	// call with the same idempotency key.
	IdempotentReplay bool `json:"idempotent_replay"`
}

// APIKeyUsage is a key's current-window usage.
type APIKeyUsage struct {
	Object string             `json:"object"`
	KeyID  string             `json:"key_id"`
	Limits []APIKeyLimit      `json:"limits"`
	Usage  []APIKeyLimitState `json:"usage"`
	// Counters cover every unit the key has been debited in, capped or not.
	Counters []APIKeyUsageCounter `json:"counters"`
}

// APIKeyWithSecret is the mint response: the key plus its secret, revealed once.
type APIKeyWithSecret struct {
	APIKey
	Secret string `json:"secret"`
	Note   string `json:"note"`
}

// CreateAPIKeyParams is the body of POST /v1/api_keys.
type CreateAPIKeyParams struct {
	SubjectType string                 `json:"subject_type"`
	SubjectID   string                 `json:"subject_id"`
	Name        string                 `json:"name,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	// ExpiresAt is epoch ms; a nil pointer never expires.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	// ExpiresInSeconds is an alternative to ExpiresAt. Without either the
	// instance expiry policy's default lifetime applies (if one is set).
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
	// Prefix is a custom secret prefix (e.g. "acme" gives acme_<id>_<secret>).
	Prefix string `json:"prefix,omitempty"`
	// Enabled=false mints the key disabled.
	Enabled *bool `json:"enabled,omitempty"`
	// RateLimit is a per-key verify throttle.
	RateLimit *APIKeyRateLimit `json:"rate_limit,omitempty"`
	// Remaining is a use budget each successful verify spends.
	Remaining *int64 `json:"remaining,omitempty"`
	// Scopes the key carries (checked by Verify's RequiredScopes).
	Scopes []string `json:"scopes,omitempty"`
	// Limits are per-key spend caps, metered with RecordUsage.
	Limits []APIKeyLimit `json:"limits,omitempty"`
}

// UpdateAPIKeyParams is the body of PATCH /v1/api_keys/:id. Set Limits to
// replace the spend caps, or ClearLimits to send limits: null and remove them
// (usage counters are kept).
//
// Enabled disables (false) or re-enables (true) the key without revoking it.
// RateLimit sets the verify throttle (ClearRateLimit removes it); Remaining
// sets the use budget (ClearRemaining makes it unlimited).
type UpdateAPIKeyParams struct {
	Name           *string                `json:"name,omitempty"`
	Claims         map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt      *int64                 `json:"expires_at,omitempty"`
	Scopes         []string               `json:"scopes,omitempty"`
	Limits         []APIKeyLimit          `json:"limits,omitempty"`
	ClearLimits    bool                   `json:"-"`
	Enabled        *bool                  `json:"enabled,omitempty"`
	RateLimit      *APIKeyRateLimit       `json:"rate_limit,omitempty"`
	ClearRateLimit bool                   `json:"-"`
	Remaining      *int64                 `json:"remaining,omitempty"`
	ClearRemaining bool                   `json:"-"`
}

// MarshalJSON renders limits / rate_limit / remaining as null when their
// Clear* flag is set.
func (p UpdateAPIKeyParams) MarshalJSON() ([]byte, error) {
	type alias UpdateAPIKeyParams
	raw, err := json.Marshal(alias(p))
	if err != nil || !(p.ClearLimits || p.ClearRateLimit || p.ClearRemaining) {
		return raw, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if p.ClearLimits {
		m["limits"] = nil
	}
	if p.ClearRateLimit {
		m["rate_limit"] = nil
	}
	if p.ClearRemaining {
		m["remaining"] = nil
	}
	return json.Marshal(m)
}

// APIKeyVerification is the verify verdict. Every negative — unknown, malformed,
// revoked, expired, or a key whose subject was since deleted — resolves to the
// same Valid=false, so a caller learns nothing about which keys exist.
//
// A LIVE key refused by its own policy is also Valid=false, but carries Code
// (APIKeyRefusalInsufficientScope with MissingScopes, APIKeyRefusalRateLimited
// with RetryAfterMS, or APIKeyRefusalUsageExhausted) so you can tell the
// holder what to do.
type APIKeyVerification struct {
	Object        string   `json:"object"`
	Valid         bool     `json:"valid"`
	Code          string   `json:"code,omitempty"`
	MissingScopes []string `json:"missing_scopes,omitempty"`
	RetryAfterMS  *int64   `json:"retry_after_ms,omitempty"`
	// Remaining is the use budget left after this verify (nil = unlimited).
	Remaining   *int64                 `json:"remaining,omitempty"`
	ID          string                 `json:"id,omitempty"`
	SubjectType string                 `json:"subject_type,omitempty"`
	SubjectID   string                 `json:"subject_id,omitempty"`
	Name        *string                `json:"name,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Constraints map[string]interface{} `json:"constraints,omitempty"`
	// Limits are the key's spend caps (nil when none).
	Limits []APIKeyLimit `json:"limits,omitempty"`
	// Usage is each cap with its current-window usage.
	Usage      []APIKeyLimitState `json:"usage,omitempty"`
	LastUsedAt *int64             `json:"last_used_at,omitempty"`
	ExpiresAt  *int64             `json:"expires_at,omitempty"`
}

// ListAPIKeysParams optionally narrows the listing to one subject.
type ListAPIKeysParams struct {
	SubjectType string
	SubjectID   string
}

func (p ListAPIKeysParams) values() url.Values {
	v := url.Values{}
	if p.SubjectType != "" {
		v.Set("subject_type", p.SubjectType)
	}
	if p.SubjectID != "" {
		v.Set("subject_id", p.SubjectID)
	}
	return v
}

// List returns API keys, optionally narrowed to one subject. GET /v1/api_keys.
func (s *APIKeysService) List(ctx context.Context, params ListAPIKeysParams) (*ListPage[APIKey], error) {
	out := &ListPage[APIKey]{}
	return out, s.client.get(ctx, "/v1/api_keys", params.values(), out)
}

// Create mints a key. The secret is returned once, here. POST /v1/api_keys.
func (s *APIKeysService) Create(ctx context.Context, params CreateAPIKeyParams, opts ...RequestOption) (*APIKeyWithSecret, error) {
	out := &APIKeyWithSecret{}
	return out, s.client.post(ctx, "/v1/api_keys", params, out, opts...)
}

// Verify checks a presented secret. Rate-limited — an online credential check.
// POST /v1/api_keys/verify.
func (s *APIKeysService) Verify(ctx context.Context, secret string, opts ...RequestOption) (*APIKeyVerification, error) {
	out := &APIKeyVerification{}
	body := map[string]string{"secret": secret}
	return out, s.client.post(ctx, "/v1/api_keys/verify", body, out, opts...)
}

// VerifyAPIKeyParams is the body of POST /v1/api_keys/verify with options.
// RequiredScopes must all be on the key, else the verdict is Valid=false with
// Code=insufficient_scope and the MissingScopes.
type VerifyAPIKeyParams struct {
	Secret         string   `json:"secret"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

// VerifyWithParams is Verify with required scopes. POST /v1/api_keys/verify.
func (s *APIKeysService) VerifyWithParams(ctx context.Context, params VerifyAPIKeyParams, opts ...RequestOption) (*APIKeyVerification, error) {
	out := &APIKeyVerification{}
	return out, s.client.post(ctx, "/v1/api_keys/verify", params, out, opts...)
}

// Get returns one key. GET /v1/api_keys/:id.
func (s *APIKeysService) Get(ctx context.Context, id string) (*APIKey, error) {
	out := &APIKey{}
	return out, s.client.get(ctx, "/v1/api_keys/"+url.PathEscape(id), nil, out)
}

// Update patches a key. PATCH /v1/api_keys/:id.
func (s *APIKeysService) Update(ctx context.Context, id string, params UpdateAPIKeyParams, opts ...RequestOption) (*APIKey, error) {
	out := &APIKey{}
	return out, s.client.patch(ctx, "/v1/api_keys/"+url.PathEscape(id), params, out, opts...)
}

// Delete revokes a key. It stays queryable but never authenticates again.
// DELETE /v1/api_keys/:id.
func (s *APIKeysService) Delete(ctx context.Context, id string, opts ...RequestOption) (*APIKeyRevokeResult, error) {
	out := &APIKeyRevokeResult{}
	return out, s.client.del(ctx, "/v1/api_keys/"+url.PathEscape(id), out, opts...)
}

// RecordUsage meters usage against a key's spend caps, atomically. When the
// debit fits every cap for the unit it is recorded and Allowed is true; when it
// would exceed one, nothing is recorded and the call returns (without an error)
// Allowed=false and Code "LIMIT_EXCEEDED". Reusing an idempotency key with a
// different unit or amount is a 409 IDEMPOTENCY_CONFLICT; a revoked or expired
// key is a 409 CONFLICT. POST /v1/api_keys/:id/usage.
func (s *APIKeysService) RecordUsage(ctx context.Context, id string, params RecordAPIKeyUsageParams, opts ...RequestOption) (*APIKeyUsageDebit, error) {
	out := &APIKeyUsageDebit{}
	return out, s.client.post(ctx, "/v1/api_keys/"+url.PathEscape(id)+"/usage", params, out, opts...)
}

// GetUsage returns a key's current-window usage: each cap's state plus every
// unit's counters. GET /v1/api_keys/:id/usage.
func (s *APIKeysService) GetUsage(ctx context.Context, id string) (*APIKeyUsage, error) {
	out := &APIKeyUsage{}
	return out, s.client.get(ctx, "/v1/api_keys/"+url.PathEscape(id)+"/usage", nil, out)
}

// APIKeyRevokeResult acknowledges a key revoke.
type APIKeyRevokeResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// RevokedAPIKey is one entry of the revocation feed.
type RevokedAPIKey struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	RevokedAt *int64 `json:"revoked_at"`
}

// ListRevokedAPIKeysParams pages the revocation feed. Since is an ISO-8601
// timestamp, epoch milliseconds, or a NextCursor from a prior page.
type ListRevokedAPIKeysParams struct {
	Since string
	Limit int
}

// MintAPIKeyTokenParams is the body of POST /v1/api_keys/token. Audience is a
// string or a []string.
type MintAPIKeyTokenParams struct {
	Secret     string      `json:"secret"`
	TTLSeconds int         `json:"ttl_seconds,omitempty"`
	Audience   interface{} `json:"audience,omitempty"`
}

// APIKeyTokenConfirmation binds a token to the key's registered public key.
type APIKeyTokenConfirmation struct {
	JKT string `json:"jkt"`
}

// APIKeyToken is a short-lived, JWKS-signed access JWT minted from an API key.
// Cnf is set when the key registered a public key (sender-constrained).
type APIKeyToken struct {
	Object      string                   `json:"object"`
	Token       string                   `json:"token"`
	TokenType   string                   `json:"token_type"`
	JTI         string                   `json:"jti"`
	KeyID       string                   `json:"key_id"`
	SubjectType string                   `json:"subject_type,omitempty"`
	SubjectID   string                   `json:"subject_id,omitempty"`
	Scopes      []string                 `json:"scopes"`
	Constraints map[string]interface{}   `json:"constraints"`
	Cnf         *APIKeyTokenConfirmation `json:"cnf,omitempty"`
	ExpiresIn   int64                    `json:"expires_in"`
	ExpiresAt   int64                    `json:"expires_at"`
	Issuer      string                   `json:"issuer"`
}

// ListRevoked returns keys revoked since a cursor, so a resource server can
// deny-list them while their short-lived tokens are still live.
// GET /v1/api_keys/revoked.
func (s *APIKeysService) ListRevoked(ctx context.Context, params ListRevokedAPIKeysParams) (*CursorPage[RevokedAPIKey], error) {
	q := url.Values{}
	if params.Since != "" {
		q.Set("since", params.Since)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	out := &CursorPage[RevokedAPIKey]{}
	return out, s.client.get(ctx, "/v1/api_keys/revoked", q, out)
}

// MintToken exchanges an API key secret for a short-lived signed access JWT
// that a resource verifies offline against the instance JWKS.
// POST /v1/api_keys/token.
func (s *APIKeysService) MintToken(ctx context.Context, params MintAPIKeyTokenParams, opts ...RequestOption) (*APIKeyToken, error) {
	out := &APIKeyToken{}
	return out, s.client.post(ctx, "/v1/api_keys/token", params, out, opts...)
}
