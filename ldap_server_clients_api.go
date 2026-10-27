package atlas

import (
	"context"
	"net/url"
)

// LDAPServerClientsService is the ldapServerClients resource.
type LDAPServerClientsService struct {
	client *Client
}

// List: List the LDAP interface service accounts with their base DN, bind DN and allowed source
// networks. Secrets are never returned.
// GET /v1/ldap_server_clients.
func (s *LDAPServerClientsService) List(ctx context.Context, params ListParams) (*LDAPServerClientsListResult, error) {
	out := &LDAPServerClientsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/ldap_server_clients", params.values(), nil, out)
}

// Create: Create a service account for the LDAPS interface: base_dn (dc=/o=/ou= parts, unique
// across Atlas), bind_cn, allowed_cidrs (empty = nobody may connect), allow_user_bind and
// size_limit. The secret is returned once as secret.
// POST /v1/ldap_server_clients.
func (s *LDAPServerClientsService) Create(ctx context.Context, params LDAPServerClientsCreateParams, opts ...RequestOption) (*LDAPServerClientsListResultDataItem, error) {
	out := &LDAPServerClientsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/ldap_server_clients", nil, params, out, opts...)
}

// Get: Read one LDAP interface service account.
// GET /v1/ldap_server_clients/{id}.
func (s *LDAPServerClientsService) Get(ctx context.Context, id string) (*LDAPServerClientsListResultDataItem, error) {
	out := &LDAPServerClientsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/ldap_server_clients/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change the name, allowed networks, user-bind switch, size limit or status (active or
// disabled).
// PATCH /v1/ldap_server_clients/{id}.
func (s *LDAPServerClientsService) Update(ctx context.Context, id string, params LDAPServerClientsUpdateParams, opts ...RequestOption) (*LDAPServerClientsListResultDataItem, error) {
	out := &LDAPServerClientsListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/ldap_server_clients/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a service account; its connections can no longer bind.
// DELETE /v1/ldap_server_clients/{id}.
func (s *LDAPServerClientsService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/ldap_server_clients/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// RotateSecret: Issue a new service-account secret (returned once); the old one stops working
// immediately.
// POST /v1/ldap_server_clients/{id}/rotate_secret.
func (s *LDAPServerClientsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*LDAPServerClientsListResultDataItem, error) {
	out := &LDAPServerClientsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/ldap_server_clients/"+url.PathEscape(id)+"/rotate_secret", nil, nil, out, opts...)
}
