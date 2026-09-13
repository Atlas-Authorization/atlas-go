package atlas

import (
	"context"
	"net/url"
)

// SSOConnectionsService is the /v1/sso_connections namespace.
type SSOConnectionsService struct{ client *Client }

// ClaimRoleMapping maps an IdP claim value to a role. roleKey is camelCase on
// the wire, unlike the surrounding snake_case fields.
type ClaimRoleMapping struct {
	Claim   string `json:"claim"`
	Value   string `json:"value"`
	RoleKey string `json:"roleKey"`
}

// SsoConnection is an enterprise SSO connection (OIDC, SAML, or Discourse).
type SsoConnection struct {
	Object                 string             `json:"object"`
	ID                     string             `json:"id"`
	OrganizationID         *string            `json:"organization_id"`
	Type                   string             `json:"type"`
	Status                 string             `json:"status"`
	OIDCIssuer             *string            `json:"oidc_issuer"`
	OIDCClientID           *string            `json:"oidc_client_id"`
	HasSecret              bool               `json:"has_secret"`
	SAMLIDPEntityID        *string            `json:"saml_idp_entity_id"`
	SAMLIDPSSOURL          *string            `json:"saml_idp_sso_url"`
	SAMLSPEntityID         *string            `json:"saml_sp_entity_id"`
	HasSAMLCertificate     bool               `json:"has_saml_certificate"`
	SAMLAllowIDPInitiated  bool               `json:"saml_allow_idp_initiated"`
	SAMLSignAuthnRequests  bool               `json:"saml_sign_authn_requests"`
	SAMLWantResponseSigned bool               `json:"saml_want_response_signed"`
	HasDiscourseSecret     bool               `json:"has_discourse_secret"`
	DiscourseProviderURL   *string            `json:"discourse_provider_url"`
	AllowedDomains         []string           `json:"allowed_domains"`
	ClaimRoleMappings      []ClaimRoleMapping `json:"claim_role_mappings"`
	DefaultRoleID          *string            `json:"default_role_id"`
	CreatedAt              int64              `json:"created_at"`
	UpdatedAt              int64              `json:"updated_at"`
}

// SamlMetadata carries the SP EntityDescriptor XML inside a JSON envelope.
type SamlMetadata struct {
	Object      string `json:"object"`
	SPEntityID  string `json:"sp_entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataXML string `json:"metadata_xml"`
}

// CreateSsoConnectionParams is the body of POST /v1/sso_connections. Write-only
// secrets (oidc_client_secret, saml_idp_certificate, discourse_secret) are
// stored encrypted and never returned.
type CreateSsoConnectionParams struct {
	OrganizationID         *string            `json:"organization_id,omitempty"`
	Type                   string             `json:"type,omitempty"`
	Status                 string             `json:"status,omitempty"`
	OIDCIssuer             string             `json:"oidc_issuer,omitempty"`
	OIDCClientID           string             `json:"oidc_client_id,omitempty"`
	OIDCClientSecret       string             `json:"oidc_client_secret,omitempty"`
	SAMLIDPEntityID        string             `json:"saml_idp_entity_id,omitempty"`
	SAMLIDPSSOURL          string             `json:"saml_idp_sso_url,omitempty"`
	SAMLIDPCertificate     string             `json:"saml_idp_certificate,omitempty"`
	SAMLSPEntityID         string             `json:"saml_sp_entity_id,omitempty"`
	SAMLAllowIDPInitiated  *bool              `json:"saml_allow_idp_initiated,omitempty"`
	SAMLSignAuthnRequests  *bool              `json:"saml_sign_authn_requests,omitempty"`
	SAMLWantResponseSigned *bool              `json:"saml_want_response_signed,omitempty"`
	DiscourseSecret        string             `json:"discourse_secret,omitempty"`
	DiscourseProviderURL   string             `json:"discourse_provider_url,omitempty"`
	AllowedDomains         []string           `json:"allowed_domains,omitempty"`
	ClaimRoleMappings      []ClaimRoleMapping `json:"claim_role_mappings,omitempty"`
	DefaultRoleID          *string            `json:"default_role_id,omitempty"`
}

// UpdateSsoConnectionParams accepts everything create does except type, which is
// immutable.
type UpdateSsoConnectionParams = CreateSsoConnectionParams

// List returns all SSO connections. GET /v1/sso_connections.
func (s *SSOConnectionsService) List(ctx context.Context) (*ListPage[SsoConnection], error) {
	out := &ListPage[SsoConnection]{}
	return out, s.client.get(ctx, "/v1/sso_connections", nil, out)
}

// Get fetches an SSO connection. GET /v1/sso_connections/:id.
func (s *SSOConnectionsService) Get(ctx context.Context, id string) (*SsoConnection, error) {
	out := &SsoConnection{}
	return out, s.client.get(ctx, "/v1/sso_connections/"+url.PathEscape(id), nil, out)
}

// Create creates an SSO connection. POST /v1/sso_connections.
func (s *SSOConnectionsService) Create(ctx context.Context, params CreateSsoConnectionParams, opts ...RequestOption) (*SsoConnection, error) {
	out := &SsoConnection{}
	return out, s.client.post(ctx, "/v1/sso_connections", params, out, opts...)
}

// Update patches an SSO connection (type is ignored). PATCH /v1/sso_connections/:id.
func (s *SSOConnectionsService) Update(ctx context.Context, id string, params UpdateSsoConnectionParams) (*SsoConnection, error) {
	out := &SsoConnection{}
	return out, s.client.patch(ctx, "/v1/sso_connections/"+url.PathEscape(id), params, out)
}

// Delete removes an SSO connection. DELETE /v1/sso_connections/:id.
func (s *SSOConnectionsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/sso_connections/"+url.PathEscape(id), out)
}

// SAMLMetadata returns the SP SAML metadata for a connection.
// GET /v1/sso_connections/:id/saml_metadata.
func (s *SSOConnectionsService) SAMLMetadata(ctx context.Context, id string) (*SamlMetadata, error) {
	out := &SamlMetadata{}
	return out, s.client.get(ctx, "/v1/sso_connections/"+url.PathEscape(id)+"/saml_metadata", nil, out)
}
