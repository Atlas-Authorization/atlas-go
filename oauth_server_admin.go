package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// --- Instance signing keys ---------------------------------------------------

// SigningKey is one published token-signing key. Status is "current" (signs
// every new token) or "previous" (still in the JWKS until RetiresAt, epoch ms,
// after a rotation). Role is "main" or "secondary" (the key of the other
// algorithm, for APIs set to it).
type SigningKey struct {
	Object    string `json:"object"`
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	Status    string `json:"status"`
	Role      string `json:"role,omitempty"`
	RetiresAt *int64 `json:"retires_at"`
}

// SigningKeyList is GET /v1/instance/signing_keys.
type SigningKeyList struct {
	Object string       `json:"object"`
	Data   []SigningKey `json:"data"`
}

// RotateSigningKeyParams is the body of POST /v1/instance/signing_keys/rotate.
// Alg switches the instance key's algorithm ("RS256" or "ES256");
// GracePeriodSeconds keeps the previous key published (default 86400, at most
// 2592000); Emergency publishes ONLY the new key (old tokens stop verifying at
// once) and is required for a second rotation inside a grace window.
type RotateSigningKeyParams struct {
	Alg                string `json:"alg,omitempty"`
	GracePeriodSeconds *int64 `json:"grace_period_seconds,omitempty"`
	Emergency          bool   `json:"emergency,omitempty"`
}

// SigningKeyRotation is the result of a rotation.
type SigningKeyRotation struct {
	Object            string  `json:"object"`
	Kid               string  `json:"kid"`
	Alg               string  `json:"alg"`
	PreviousKid       *string `json:"previous_kid"`
	PreviousRetiresAt *int64  `json:"previous_retires_at"`
	Emergency         bool    `json:"emergency"`
}

// ListSigningKeys lists the published signing keys, newest first.
// GET /v1/instance/signing_keys.
func (s *InstanceSecurityService) ListSigningKeys(ctx context.Context) (*SigningKeyList, error) {
	out := &SigningKeyList{}
	return out, s.client.get(ctx, "/v1/instance/signing_keys", nil, out)
}

// RotateSigningKey rotates the instance signing key, optionally switching its
// algorithm. POST /v1/instance/signing_keys/rotate.
func (s *InstanceSecurityService) RotateSigningKey(ctx context.Context, params RotateSigningKeyParams, opts ...RequestOption) (*SigningKeyRotation, error) {
	out := &SigningKeyRotation{}
	return out, s.client.post(ctx, "/v1/instance/signing_keys/rotate", params, out, opts...)
}

// --- OAuth initial access tokens (RFC 7591 §3) -------------------------------

// OAuthInitialAccessTokensService is /v1/oauth_initial_access_tokens: tokens
// that gate dynamic client registration once
// oauthProvider.requireInitialAccessToken is on.
type OAuthInitialAccessTokensService struct{ client *Client }

// InitialAccessToken is a DCR initial access token. Token is set only on
// create (shown once, stored hashed). Status is active, expired, used_up or
// revoked.
type InitialAccessToken struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	TokenPrefix string  `json:"token_prefix"`
	Description *string `json:"description"`
	Status      string  `json:"status"`
	MaxUses     *int64  `json:"max_uses"`
	UseCount    int64   `json:"use_count"`
	ExpiresAt   *int64  `json:"expires_at"`
	RevokedAt   *int64  `json:"revoked_at"`
	LastUsedAt  *int64  `json:"last_used_at"`
	CreatedAt   int64   `json:"created_at"`
	Token       string  `json:"token,omitempty"`
}

// CreateInitialAccessTokenParams is the body of
// POST /v1/oauth_initial_access_tokens.
type CreateInitialAccessTokenParams struct {
	Description      string `json:"description,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
	MaxUses          int64  `json:"max_uses,omitempty"`
}

// List lists the tokens, newest first (the tokens themselves never).
// GET /v1/oauth_initial_access_tokens.
func (s *OAuthInitialAccessTokensService) List(ctx context.Context) (*CursorPage[InitialAccessToken], error) {
	out := &CursorPage[InitialAccessToken]{}
	return out, s.client.get(ctx, "/v1/oauth_initial_access_tokens", nil, out)
}

// Create mints a token; Token is returned exactly once.
// POST /v1/oauth_initial_access_tokens.
func (s *OAuthInitialAccessTokensService) Create(ctx context.Context, params CreateInitialAccessTokenParams, opts ...RequestOption) (*InitialAccessToken, error) {
	out := &InitialAccessToken{}
	return out, s.client.post(ctx, "/v1/oauth_initial_access_tokens", params, out, opts...)
}

// Revoke revokes a token at once. DELETE /v1/oauth_initial_access_tokens/:id.
func (s *OAuthInitialAccessTokensService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*InitialAccessToken, error) {
	out := &InitialAccessToken{}
	return out, s.client.del(ctx, "/v1/oauth_initial_access_tokens/"+url.PathEscape(id), out, opts...)
}

// --- Delivery logs -------------------------------------------------------------

// BeforeUserCreateHookCall is one entry of the hook's delivery log.
type BeforeUserCreateHookCall struct {
	Object     string                 `json:"object"`
	ID         string                 `json:"id"`
	UserID     *string                `json:"user_id"`
	Test       bool                   `json:"test"`
	Status     string                 `json:"status"`
	HTTPStatus *int                   `json:"http_status"`
	LatencyMS  *int                   `json:"latency_ms"`
	Error      *string                `json:"error"`
	Answer     map[string]interface{} `json:"answer"`
	CreatedAt  int64                  `json:"created_at"`
}

// ListBeforeUserCreateCallsParams filters the hook's delivery log. Status is
// ok, failed, timeout, error or invalid_response; Test filters test calls.
type ListBeforeUserCreateCallsParams struct {
	Limit         int
	Status        string
	Test          *bool
	StartingAfter string
}

// ListBeforeUserCreateCalls returns the hook's delivery log, newest first
// (kept 30 days). GET /v1/instance/hooks/before_user_create/calls.
func (s *UserHooksService) ListBeforeUserCreateCalls(ctx context.Context, params ListBeforeUserCreateCallsParams) (*CursorPage[BeforeUserCreateHookCall], error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	if params.Test != nil {
		q.Set("test", strconv.FormatBool(*params.Test))
	}
	if params.StartingAfter != "" {
		q.Set("starting_after", params.StartingAfter)
	}
	out := &CursorPage[BeforeUserCreateHookCall]{}
	return out, s.client.get(ctx, "/v1/instance/hooks/before_user_create/calls", q, out)
}

// GetCall fetches one call of the referral delivery log, by its id or by the
// platform's request id. GET /v1/instance/referrals/calls/:id.
func (s *ReferralsService) GetCall(ctx context.Context, id string) (*ReferralCall, error) {
	out := &ReferralCall{}
	return out, s.client.get(ctx, "/v1/instance/referrals/calls/"+url.PathEscape(id), nil, out)
}
