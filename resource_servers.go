package atlas

import (
	"context"
	"net/url"
)

// ResourceServersService is the /v1/resource_servers namespace (API audiences).
type ResourceServersService struct{ client *Client }

// ResourceServerScope is one scope a resource server exposes.
type ResourceServerScope struct {
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// ResourceServer is an API audience with its scopes and token settings.
type ResourceServer struct {
	Object          string                `json:"object"`
	ID              string                `json:"id"`
	Identifier      string                `json:"identifier"`
	Name            string                `json:"name"`
	Scopes          []ResourceServerScope `json:"scopes"`
	TokenTTLSeconds int                   `json:"token_ttl_seconds"`
	SigningAlg      string                `json:"signing_alg"`
	CreatedAt       int64                 `json:"created_at"`
	UpdatedAt       int64                 `json:"updated_at"`
}

// CreateResourceServerParams is the body of POST /v1/resource_servers. Each
// scope may be a bare string or a {value, description}; pass the latter as
// ResourceServerScope. Scopes accepts []interface{} for that flexibility.
type CreateResourceServerParams struct {
	Identifier      string        `json:"identifier"`
	Name            string        `json:"name"`
	Scopes          []interface{} `json:"scopes,omitempty"`
	TokenTTLSeconds *int          `json:"token_ttl_seconds,omitempty"`
	SigningAlg      string        `json:"signing_alg,omitempty"`
}

// UpdateResourceServerParams is the body of PATCH /v1/resource_servers/:id. The
// identifier is immutable.
type UpdateResourceServerParams struct {
	Name            string        `json:"name,omitempty"`
	Scopes          []interface{} `json:"scopes,omitempty"`
	TokenTTLSeconds *int          `json:"token_ttl_seconds,omitempty"`
	SigningAlg      string        `json:"signing_alg,omitempty"`
	Identifier      string        `json:"identifier,omitempty"`
}

// List returns all resource servers. GET /v1/resource_servers.
func (s *ResourceServersService) List(ctx context.Context) (*ListPage[ResourceServer], error) {
	out := &ListPage[ResourceServer]{}
	return out, s.client.get(ctx, "/v1/resource_servers", nil, out)
}

// Get fetches a resource server. GET /v1/resource_servers/:id.
func (s *ResourceServersService) Get(ctx context.Context, id string) (*ResourceServer, error) {
	out := &ResourceServer{}
	return out, s.client.get(ctx, "/v1/resource_servers/"+url.PathEscape(id), nil, out)
}

// Create creates a resource server. POST /v1/resource_servers.
func (s *ResourceServersService) Create(ctx context.Context, params CreateResourceServerParams, opts ...RequestOption) (*ResourceServer, error) {
	out := &ResourceServer{}
	return out, s.client.post(ctx, "/v1/resource_servers", params, out, opts...)
}

// Update patches a resource server. PATCH /v1/resource_servers/:id.
func (s *ResourceServersService) Update(ctx context.Context, id string, params UpdateResourceServerParams) (*ResourceServer, error) {
	out := &ResourceServer{}
	return out, s.client.patch(ctx, "/v1/resource_servers/"+url.PathEscape(id), params, out)
}

// Delete removes a resource server. DELETE /v1/resource_servers/:id.
func (s *ResourceServersService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/resource_servers/"+url.PathEscape(id), out)
}
