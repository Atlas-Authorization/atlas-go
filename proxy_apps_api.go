package atlas

import (
	"context"
	"net/url"
)

// ProxyAppsService is the proxyApps resource.
type ProxyAppsService struct {
	client *Client
}

// List: List the identity-aware proxy apps — hostnames protected by the forward-auth endpoint,
// with their path rules.
// GET /v1/proxy_apps.
func (s *ProxyAppsService) List(ctx context.Context, params ListParams) (*ProxyAppsListResult, error) {
	out := &ProxyAppsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/proxy_apps", params.values(), nil, out)
}

// Create: Create a proxy app: a hostname, optional upstream URL, ordered path/method rules
// requiring a role, permission or entitlement, public paths, and header/token injection. The
// hostname is unique across the deployment.
// POST /v1/proxy_apps.
func (s *ProxyAppsService) Create(ctx context.Context, params ProxyAppsCreateParams, opts ...RequestOption) (*ProxyAppsListResultDataItem, error) {
	out := &ProxyAppsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/proxy_apps", nil, params, out, opts...)
}

// Get: Read one identity-aware proxy app.
// GET /v1/proxy_apps/{id}.
func (s *ProxyAppsService) Get(ctx context.Context, id string) (*ProxyAppsListResultDataItem, error) {
	out := &ProxyAppsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/proxy_apps/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update a proxy app. Omitted fields keep their value.
// PATCH /v1/proxy_apps/{id}.
func (s *ProxyAppsService) Update(ctx context.Context, id string, params ProxyAppsUpdateParams, opts ...RequestOption) (*ProxyAppsListResultDataItem, error) {
	out := &ProxyAppsListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/proxy_apps/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a proxy app. Its hostname stops resolving at the forward-auth endpoint.
// DELETE /v1/proxy_apps/{id}.
func (s *ProxyAppsService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/proxy_apps/"+url.PathEscape(id), nil, nil, nil, opts...)
}
