package atlas

import (
	"context"
	"net/url"
)

// OAuthClientsService is the /v1/oauth_clients namespace. Grants hangs off it.
type OAuthClientsService struct {
	client *Client

	Grants *OAuthClientGrantsService
}

// OAuthClient is a registered OAuth client (relying party).
type OAuthClient struct {
	Object                  string   `json:"object"`
	ID                      string   `json:"id"`
	ClientID                string   `json:"client_id"`
	Name                    string   `json:"name"`
	LogoURL                 *string  `json:"logo_url"`
	RedirectURIs            []string `json:"redirect_uris"`
	AllowedScopes           []string `json:"allowed_scopes"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	SecretPrefix            *string  `json:"secret_prefix"`
	IsPublic                bool     `json:"is_public"`
	FirstParty              bool     `json:"first_party"`
	CreatedAt               int64    `json:"created_at"`
	UpdatedAt               int64    `json:"updated_at"`
}

// OAuthClientWithSecret carries the client_secret, revealed once on create and
// rotate.
type OAuthClientWithSecret struct {
	OAuthClient
	ClientSecret string `json:"client_secret,omitempty"`
	Note         string `json:"note"`
}

// ClientGrant binds an OAuth client to a resource server with scopes.
type ClientGrant struct {
	Object           string   `json:"object"`
	ID               string   `json:"id"`
	ClientID         string   `json:"client_id"`
	ResourceServerID string   `json:"resource_server_id"`
	Scopes           []string `json:"scopes"`
	CreatedAt        int64    `json:"created_at"`
	UpdatedAt        int64    `json:"updated_at"`
}

// CreateOAuthClientParams is the body of POST /v1/oauth_clients.
type CreateOAuthClientParams struct {
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	AllowedScopes           []string `json:"allowed_scopes,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	LogoURL                 string   `json:"logo_url,omitempty"`
	FirstParty              *bool    `json:"first_party,omitempty"`
}

// UpdateOAuthClientParams is the body of PATCH /v1/oauth_clients/:id.
type UpdateOAuthClientParams struct {
	Name                    string   `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	AllowedScopes           []string `json:"allowed_scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	LogoURL                 string   `json:"logo_url,omitempty"`
	FirstParty              *bool    `json:"first_party,omitempty"`
}

// List returns all OAuth clients. GET /v1/oauth_clients.
func (s *OAuthClientsService) List(ctx context.Context) (*ListPage[OAuthClient], error) {
	out := &ListPage[OAuthClient]{}
	return out, s.client.get(ctx, "/v1/oauth_clients", nil, out)
}

// Get fetches an OAuth client. GET /v1/oauth_clients/:id.
func (s *OAuthClientsService) Get(ctx context.Context, id string) (*OAuthClient, error) {
	out := &OAuthClient{}
	return out, s.client.get(ctx, "/v1/oauth_clients/"+url.PathEscape(id), nil, out)
}

// Create registers an OAuth client; the response carries client_secret once.
// POST /v1/oauth_clients.
func (s *OAuthClientsService) Create(ctx context.Context, params CreateOAuthClientParams, opts ...RequestOption) (*OAuthClientWithSecret, error) {
	out := &OAuthClientWithSecret{}
	return out, s.client.post(ctx, "/v1/oauth_clients", params, out, opts...)
}

// Update patches an OAuth client. PATCH /v1/oauth_clients/:id.
func (s *OAuthClientsService) Update(ctx context.Context, id string, params UpdateOAuthClientParams) (*OAuthClient, error) {
	out := &OAuthClient{}
	return out, s.client.patch(ctx, "/v1/oauth_clients/"+url.PathEscape(id), params, out)
}

// RotateSecret rotates the client secret; the response carries it once.
// POST /v1/oauth_clients/:id/rotate_secret.
func (s *OAuthClientsService) RotateSecret(ctx context.Context, id string) (*OAuthClientWithSecret, error) {
	out := &OAuthClientWithSecret{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(id)+"/rotate_secret", nil, out)
}

// Delete removes an OAuth client. DELETE /v1/oauth_clients/:id.
func (s *OAuthClientsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/oauth_clients/"+url.PathEscape(id), out)
}

// OAuthClientGrantsService is /v1/oauth_clients/:id/grants.
type OAuthClientGrantsService struct{ client *Client }

// CreateClientGrantParams is the body of POST .../grants.
type CreateClientGrantParams struct {
	ResourceServerID string   `json:"resource_server_id"`
	Scopes           []string `json:"scopes,omitempty"`
}

// List lists a client's grants.
func (s *OAuthClientGrantsService) List(ctx context.Context, clientID string) (*ListPage[ClientGrant], error) {
	out := &ListPage[ClientGrant]{}
	return out, s.client.get(ctx, "/v1/oauth_clients/"+url.PathEscape(clientID)+"/grants", nil, out)
}

// Create creates a client grant.
func (s *OAuthClientGrantsService) Create(ctx context.Context, clientID string, params CreateClientGrantParams) (*ClientGrant, error) {
	out := &ClientGrant{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(clientID)+"/grants", params, out)
}

// Delete removes a client grant.
func (s *OAuthClientGrantsService) Delete(ctx context.Context, clientID, grantID string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/oauth_clients/"+url.PathEscape(clientID)+"/grants/"+url.PathEscape(grantID), out)
}
