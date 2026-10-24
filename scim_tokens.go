package atlas

import (
	"context"
	"net/url"
)

// SCIMTokensService is the /v1/scim_tokens namespace.
type SCIMTokensService struct{ client *Client }

// ScimToken is a SCIM bearer token record. The usable secret is never returned
// after create.
type ScimToken struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Name           *string `json:"name"`
	OrganizationID string  `json:"organization_id"`
	ConnectionID   *string `json:"connection_id"`
	Prefix         string  `json:"prefix"`
	// Scopes is nil for a read-write token, ["read"] for a read-only one.
	Scopes []string `json:"scopes"`
	// RoleMappings map SCIM roles values to organization role keys.
	RoleMappings []ScimRoleMapping `json:"role_mappings,omitempty"`
	LastUsedAt   *int64            `json:"last_used_at"`
	ExpiresAt    *int64            `json:"expires_at"`
	RevokedAt    *int64            `json:"revoked_at"`
	CreatedAt    int64             `json:"created_at"`
}

// ScimTokenWithSecret reveals the usable secret once, on create.
type ScimTokenWithSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	ScimToken
	Secret string `json:"secret"`
	Note   string `json:"note"`
}

// CreateScimTokenParams is the body of POST /v1/scim_tokens.
type CreateScimTokenParams struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name,omitempty"`
	ConnectionID   string `json:"connection_id,omitempty"`
	// Scopes ["read"] makes the token read-only; omit for read and write.
	Scopes []string `json:"scopes,omitempty"`
	// RoleMappings map SCIM roles values to organization role keys.
	RoleMappings []ScimRoleMapping `json:"role_mappings,omitempty"`
}

// ScimRoleMapping maps one SCIM roles value to an organization role key.
type ScimRoleMapping struct {
	Value string `json:"value"`
	Role  string `json:"role"`
}

// UpdateScimTokenParams is the body of PATCH /v1/scim_tokens/:id. Nil fields
// are left alone.
type UpdateScimTokenParams struct {
	Name         *string           `json:"name,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	RoleMappings []ScimRoleMapping `json:"role_mappings,omitempty"`
}

// Update changes a SCIM token's name, scopes or role mappings (the secret is
// unchanged). PATCH /v1/scim_tokens/:id.
func (s *SCIMTokensService) Update(ctx context.Context, id string, params UpdateScimTokenParams, opts ...RequestOption) (*ScimToken, error) {
	out := &ScimToken{}
	return out, s.client.patch(ctx, "/v1/scim_tokens/"+url.PathEscape(id), params, out, opts...)
}

// ScimTokenRevokeResult is the acknowledgement of a revoke.
type ScimTokenRevokeResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
	Note    string `json:"note"`
}

// List returns all SCIM tokens. GET /v1/scim_tokens.
func (s *SCIMTokensService) List(ctx context.Context) (*ListPage[ScimToken], error) {
	out := &ListPage[ScimToken]{}
	return out, s.client.get(ctx, "/v1/scim_tokens", nil, out)
}

// Create mints a SCIM token; the response reveals the secret once.
// POST /v1/scim_tokens.
func (s *SCIMTokensService) Create(ctx context.Context, params CreateScimTokenParams, opts ...RequestOption) (*ScimTokenWithSecret, error) {
	out := &ScimTokenWithSecret{}
	return out, s.client.post(ctx, "/v1/scim_tokens", params, out, opts...)
}

// Revoke revokes a SCIM token. POST /v1/scim_tokens/:id/revoke.
func (s *SCIMTokensService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*ScimTokenRevokeResult, error) {
	out := &ScimTokenRevokeResult{}
	return out, s.client.post(ctx, "/v1/scim_tokens/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}
