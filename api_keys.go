package atlas

import (
	"context"
	"net/url"
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
func (s *APIKeysService) Verify(ctx context.Context, secret string) (*APIKeyVerification, error) {
	out := &APIKeyVerification{}
	body := map[string]string{"secret": secret}
	return out, s.client.post(ctx, "/v1/api_keys/verify", body, out)
}

// Get returns one key. GET /v1/api_keys/:id.
func (s *APIKeysService) Get(ctx context.Context, id string) (*APIKey, error) {
	out := &APIKey{}
	return out, s.client.get(ctx, "/v1/api_keys/"+url.PathEscape(id), nil, out)
}

// Update patches a key. PATCH /v1/api_keys/:id.
func (s *APIKeysService) Update(ctx context.Context, id string, params UpdateAPIKeyParams) (*APIKey, error) {
	out := &APIKey{}
	return out, s.client.patch(ctx, "/v1/api_keys/"+url.PathEscape(id), params, out)
}

// Delete revokes a key. It stays queryable but never authenticates again.
// DELETE /v1/api_keys/:id.
func (s *APIKeysService) Delete(ctx context.Context, id string) (*APIKeyRevokeResult, error) {
	out := &APIKeyRevokeResult{}
	return out, s.client.del(ctx, "/v1/api_keys/"+url.PathEscape(id), out)
}

// APIKeyRevokeResult acknowledges a key revoke.
type APIKeyRevokeResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}
