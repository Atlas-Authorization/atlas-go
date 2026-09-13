package atlas

import (
	"context"
	"net/url"
)

// RadiusClientsService is the /v1/radius_clients namespace — RADIUS NAS clients.
// The per-NAS shared secret is write-only; a view reports only HasSecret.
type RadiusClientsService struct{ client *Client }

// RadiusClient is a RADIUS NAS client.
type RadiusClient struct {
	Object                      string  `json:"object"`
	ID                          string  `json:"id"`
	Name                        string  `json:"name"`
	NASIdentifier               string  `json:"nas_identifier"`
	IPAddress                   *string `json:"ip_address"`
	HasSecret                   bool    `json:"has_secret"`
	RequireMessageAuthenticator bool    `json:"require_message_authenticator"`
	Enabled                     bool    `json:"enabled"`
	CreatedAt                   int64   `json:"created_at"`
	UpdatedAt                   int64   `json:"updated_at"`
}

// CreateRadiusClientParams is the body of POST /v1/radius_clients.
type CreateRadiusClientParams struct {
	Name                        string  `json:"name"`
	NASIdentifier               string  `json:"nas_identifier"`
	SharedSecret                string  `json:"shared_secret"`
	IPAddress                   *string `json:"ip_address,omitempty"`
	RequireMessageAuthenticator *bool   `json:"require_message_authenticator,omitempty"`
	Enabled                     *bool   `json:"enabled,omitempty"`
}

// UpdateRadiusClientParams is the body of PATCH /v1/radius_clients/:id.
type UpdateRadiusClientParams struct {
	Name                        string  `json:"name,omitempty"`
	NASIdentifier               string  `json:"nas_identifier,omitempty"`
	SharedSecret                string  `json:"shared_secret,omitempty"`
	IPAddress                   *string `json:"ip_address,omitempty"`
	RequireMessageAuthenticator *bool   `json:"require_message_authenticator,omitempty"`
	Enabled                     *bool   `json:"enabled,omitempty"`
}

// List returns the RADIUS clients. GET /v1/radius_clients.
func (s *RadiusClientsService) List(ctx context.Context) (*ListPage[RadiusClient], error) {
	out := &ListPage[RadiusClient]{}
	return out, s.client.get(ctx, "/v1/radius_clients", nil, out)
}

// Create creates a client. POST /v1/radius_clients.
func (s *RadiusClientsService) Create(ctx context.Context, params CreateRadiusClientParams, opts ...RequestOption) (*RadiusClient, error) {
	out := &RadiusClient{}
	return out, s.client.post(ctx, "/v1/radius_clients", params, out, opts...)
}

// Get returns one client. GET /v1/radius_clients/:id.
func (s *RadiusClientsService) Get(ctx context.Context, id string) (*RadiusClient, error) {
	out := &RadiusClient{}
	return out, s.client.get(ctx, "/v1/radius_clients/"+url.PathEscape(id), nil, out)
}

// Update patches a client. PATCH /v1/radius_clients/:id.
func (s *RadiusClientsService) Update(ctx context.Context, id string, params UpdateRadiusClientParams) (*RadiusClient, error) {
	out := &RadiusClient{}
	return out, s.client.patch(ctx, "/v1/radius_clients/"+url.PathEscape(id), params, out)
}

// Delete removes a client. DELETE /v1/radius_clients/:id.
func (s *RadiusClientsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/radius_clients/"+url.PathEscape(id), out)
}
