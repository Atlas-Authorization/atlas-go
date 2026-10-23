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
	// PublishResourceMetadata is true when Atlas serves the API's RFC 9728
	// protected-resource metadata document.
	PublishResourceMetadata bool `json:"publish_resource_metadata"`
	// AccessTokenFormat is "jwt" or "opaque"; nil inherits from the client /
	// instance.
	AccessTokenFormat *string `json:"access_token_format,omitempty"`
	// RefreshTokenAbsoluteTTLSeconds / RefreshTokenIdleTTLSeconds are the
	// refresh-token lifetimes for grants issued for this API; nil inherits.
	RefreshTokenAbsoluteTTLSeconds *int64 `json:"refresh_token_absolute_ttl_seconds,omitempty"`
	RefreshTokenIdleTTLSeconds     *int64 `json:"refresh_token_idle_ttl_seconds,omitempty"`
	// IntrospectionClientIDs are the confidential clients allowed to introspect
	// this API's tokens.
	IntrospectionClientIDs []string `json:"introspection_client_ids,omitempty"`
	CreatedAt              int64    `json:"created_at"`
	UpdatedAt              int64    `json:"updated_at"`
}

// CreateResourceServerParams is the body of POST /v1/resource_servers. Each
// scope may be a bare string or a {value, description}; pass the latter as
// ResourceServerScope. Scopes accepts []interface{} for that flexibility.
type CreateResourceServerParams struct {
	Identifier      string        `json:"identifier"`
	Name            string        `json:"name"`
	Scopes          []interface{} `json:"scopes,omitempty"`
	TokenTTLSeconds *int          `json:"token_ttl_seconds,omitempty"`
	// SigningAlg is RS256 or ES256: the algorithm of this API's access tokens.
	SigningAlg string `json:"signing_alg,omitempty"`
	// PublishResourceMetadata makes Atlas serve the RFC 9728 metadata document.
	PublishResourceMetadata *bool `json:"publish_resource_metadata,omitempty"`
	// AccessTokenFormat is "jwt" or "opaque"; ClearAccessTokenFormat sends
	// null (inherit).
	AccessTokenFormat      string `json:"access_token_format,omitempty"`
	ClearAccessTokenFormat bool   `json:"-"`
	// RefreshTokenAbsoluteTTLSeconds (300–31536000) and
	// RefreshTokenIdleTTLSeconds (at most the absolute lifetime); the Clear*
	// flags send null (inherit).
	RefreshTokenAbsoluteTTLSeconds      *int64 `json:"refresh_token_absolute_ttl_seconds,omitempty"`
	ClearRefreshTokenAbsoluteTTLSeconds bool   `json:"-"`
	RefreshTokenIdleTTLSeconds          *int64 `json:"refresh_token_idle_ttl_seconds,omitempty"`
	ClearRefreshTokenIdleTTLSeconds     bool   `json:"-"`
	// IntrospectionClientIDs are client_ids of confidential clients (e.g. this
	// API's backend) that may introspect its tokens.
	IntrospectionClientIDs []string `json:"introspection_client_ids,omitempty"`
}

// UpdateResourceServerParams is the body of PATCH /v1/resource_servers/:id. The
// identifier is immutable.
type UpdateResourceServerParams struct {
	Name            string        `json:"name,omitempty"`
	Scopes          []interface{} `json:"scopes,omitempty"`
	TokenTTLSeconds *int          `json:"token_ttl_seconds,omitempty"`
	SigningAlg      string        `json:"signing_alg,omitempty"`
	Identifier      string        `json:"identifier,omitempty"`
	// PublishResourceMetadata turns the RFC 9728 metadata document on or off.
	PublishResourceMetadata *bool `json:"publish_resource_metadata,omitempty"`
	// AccessTokenFormat is "jwt" or "opaque"; ClearAccessTokenFormat sends
	// null (inherit).
	AccessTokenFormat      string `json:"access_token_format,omitempty"`
	ClearAccessTokenFormat bool   `json:"-"`
	// RefreshTokenAbsoluteTTLSeconds (300–31536000) and
	// RefreshTokenIdleTTLSeconds (at most the absolute lifetime); the Clear*
	// flags send null (inherit).
	RefreshTokenAbsoluteTTLSeconds      *int64 `json:"refresh_token_absolute_ttl_seconds,omitempty"`
	ClearRefreshTokenAbsoluteTTLSeconds bool   `json:"-"`
	RefreshTokenIdleTTLSeconds          *int64 `json:"refresh_token_idle_ttl_seconds,omitempty"`
	ClearRefreshTokenIdleTTLSeconds     bool   `json:"-"`
	// IntrospectionClientIDs are client_ids of confidential clients (e.g. this
	// API's backend) that may introspect its tokens.
	IntrospectionClientIDs []string `json:"introspection_client_ids,omitempty"`
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
func (s *ResourceServersService) Update(ctx context.Context, id string, params UpdateResourceServerParams, opts ...RequestOption) (*ResourceServer, error) {
	out := &ResourceServer{}
	return out, s.client.patch(ctx, "/v1/resource_servers/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes a resource server. DELETE /v1/resource_servers/:id.
func (s *ResourceServersService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/resource_servers/"+url.PathEscape(id), out, opts...)
}

func resourceServerTokenNulls(format, abs, idle bool) map[string]interface{} {
	extra := map[string]interface{}{}
	if format {
		extra["access_token_format"] = nil
	}
	if abs {
		extra["refresh_token_absolute_ttl_seconds"] = nil
	}
	if idle {
		extra["refresh_token_idle_ttl_seconds"] = nil
	}
	return extra
}

// MarshalJSON sends null for the Clear* flags.
func (p CreateResourceServerParams) MarshalJSON() ([]byte, error) {
	type plain CreateResourceServerParams
	return marshalWithExtra(plain(p), resourceServerTokenNulls(p.ClearAccessTokenFormat, p.ClearRefreshTokenAbsoluteTTLSeconds, p.ClearRefreshTokenIdleTTLSeconds))
}

// MarshalJSON sends null for the Clear* flags.
func (p UpdateResourceServerParams) MarshalJSON() ([]byte, error) {
	type plain UpdateResourceServerParams
	return marshalWithExtra(plain(p), resourceServerTokenNulls(p.ClearAccessTokenFormat, p.ClearRefreshTokenAbsoluteTTLSeconds, p.ClearRefreshTokenIdleTTLSeconds))
}
