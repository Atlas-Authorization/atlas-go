package atlas

import (
	"context"
	"net/url"
)

// NetworkACLsService is the /v1/network_acls namespace — §11.2 per-instance IP
// allow/deny rules, evaluated in priority order (lower first), first match wins.
type NetworkACLsService struct{ client *Client }

// NetworkACL is a single IP allow/deny rule.
type NetworkACL struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Action      string  `json:"action"`
	CIDR        string  `json:"cidr"`
	Description *string `json:"description"`
	Priority    int     `json:"priority"`
	Enabled     bool    `json:"enabled"`
	CreatedAt   int64   `json:"created_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// CreateNetworkACLParams is the body of POST /v1/network_acls.
type CreateNetworkACLParams struct {
	Action      string  `json:"action"`
	CIDR        string  `json:"cidr"`
	Description *string `json:"description,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// UpdateNetworkACLParams is the body of PATCH /v1/network_acls/:id.
type UpdateNetworkACLParams struct {
	Action      string  `json:"action,omitempty"`
	CIDR        string  `json:"cidr,omitempty"`
	Description *string `json:"description,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// List returns all rules, in priority order. GET /v1/network_acls.
func (s *NetworkACLsService) List(ctx context.Context) (*ListPage[NetworkACL], error) {
	out := &ListPage[NetworkACL]{}
	return out, s.client.get(ctx, "/v1/network_acls", nil, out)
}

// Get returns one rule. GET /v1/network_acls/:id.
func (s *NetworkACLsService) Get(ctx context.Context, id string) (*NetworkACL, error) {
	out := &NetworkACL{}
	return out, s.client.get(ctx, "/v1/network_acls/"+url.PathEscape(id), nil, out)
}

// Create adds a rule. POST /v1/network_acls.
func (s *NetworkACLsService) Create(ctx context.Context, params CreateNetworkACLParams, opts ...RequestOption) (*NetworkACL, error) {
	out := &NetworkACL{}
	return out, s.client.post(ctx, "/v1/network_acls", params, out, opts...)
}

// Update patches a rule. PATCH /v1/network_acls/:id.
func (s *NetworkACLsService) Update(ctx context.Context, id string, params UpdateNetworkACLParams) (*NetworkACL, error) {
	out := &NetworkACL{}
	return out, s.client.patch(ctx, "/v1/network_acls/"+url.PathEscape(id), params, out)
}

// Delete removes a rule. DELETE /v1/network_acls/:id.
func (s *NetworkACLsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/network_acls/"+url.PathEscape(id), out)
}
