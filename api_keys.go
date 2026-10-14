package atlas

import (
	"context"
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
	LastUsedAt  *int64                 `json:"last_used_at"`
	ExpiresAt   *int64                 `json:"expires_at"`
	RevokedAt   *int64                 `json:"revoked_at"`
	CreatedAt   int64                  `json:"created_at"`
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
}

// UpdateAPIKeyParams is the body of PATCH /v1/api_keys/:id.
type UpdateAPIKeyParams struct {
	Name      *string                `json:"name,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt *int64                 `json:"expires_at,omitempty"`
}

// APIKeyVerification is the verify verdict. Every negative — unknown, malformed,
// revoked, expired, or a key whose subject was since deleted — resolves to the
// same Valid=false, so a caller learns nothing about which keys exist.
type APIKeyVerification struct {
	Object      string                 `json:"object"`
	Valid       bool                   `json:"valid"`
	ID          string                 `json:"id,omitempty"`
	SubjectType string                 `json:"subject_type,omitempty"`
	SubjectID   string                 `json:"subject_id,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	LastUsedAt  *int64                 `json:"last_used_at,omitempty"`
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
