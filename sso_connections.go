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
	Object                 string  `json:"object"`
	ID                     string  `json:"id"`
	OrganizationID         *string `json:"organization_id"`
	Type                   string  `json:"type"`
	Status                 string  `json:"status"`
	OIDCIssuer             *string `json:"oidc_issuer"`
	OIDCClientID           *string `json:"oidc_client_id"`
	HasSecret              bool    `json:"has_secret"`
	SAMLIDPEntityID        *string `json:"saml_idp_entity_id"`
	SAMLIDPSSOURL          *string `json:"saml_idp_sso_url"`
	SAMLSPEntityID         *string `json:"saml_sp_entity_id"`
	HasSAMLCertificate     bool    `json:"has_saml_certificate"`
	SAMLAllowIDPInitiated  bool    `json:"saml_allow_idp_initiated"`
	SAMLSignAuthnRequests  bool    `json:"saml_sign_authn_requests"`
	SAMLWantResponseSigned bool    `json:"saml_want_response_signed"`
	// SAMLSingleLogout is true when SAML Single Logout is on.
	SAMLSingleLogout bool `json:"saml_single_logout,omitempty"`
	// SAMLIDPSLOURL / SAMLIDPSLOResponseURL are the IdP SingleLogoutService
	// Location / ResponseLocation; SAMLIDPSLOBinding is "redirect" or "post".
	SAMLIDPSLOURL         *string `json:"saml_idp_slo_url,omitempty"`
	SAMLIDPSLOResponseURL *string `json:"saml_idp_slo_response_url,omitempty"`
	SAMLIDPSLOBinding     string  `json:"saml_idp_slo_binding,omitempty"`
	// SAMLIDPSLOSOAPURL is the IdP SOAP SingleLogoutService: the back channel
	// for sessions ended server-side.
	SAMLIDPSLOSOAPURL *string `json:"saml_idp_slo_soap_url,omitempty"`
	// SAMLRequireEncryptedAssertions refuses assertions not encrypted to the
	// connection's key.
	SAMLRequireEncryptedAssertions bool `json:"saml_require_encrypted_assertions,omitempty"`
	// HasSAMLEncryptionKey is true when an SP encryption key pair is set up;
	// HasPreviousSAMLEncryptionKey while a rotation is in progress.
	HasSAMLEncryptionKey         bool   `json:"has_saml_encryption_key,omitempty"`
	HasPreviousSAMLEncryptionKey bool   `json:"has_previous_saml_encryption_key,omitempty"`
	SAMLEncryptionRotatedAt      *int64 `json:"saml_encryption_rotated_at,omitempty"`
	// OIDC relying-party settings (see CustomOAuthProviders).
	ProfileMapping          map[string]interface{}     `json:"profile_mapping,omitempty"`
	TokenEndpointAuthMethod *string                    `json:"token_endpoint_auth_method,omitempty"`
	ClientAssertionAudience *string                    `json:"client_assertion_audience,omitempty"`
	Logout                  *UpstreamLogoutSettings    `json:"logout,omitempty"`
	IdpInitiatedLogin       *IdpInitiatedLoginSettings `json:"idp_initiated_login,omitempty"`
	// UpstreamURLs (OIDC connections) are the URLs to register at the IdP.
	UpstreamURLs         *UpstreamURLs      `json:"upstream_urls,omitempty"`
	HasDiscourseSecret   bool               `json:"has_discourse_secret"`
	DiscourseProviderURL *string            `json:"discourse_provider_url"`
	AllowedDomains       []string           `json:"allowed_domains"`
	ClaimRoleMappings    []ClaimRoleMapping `json:"claim_role_mappings"`
	DefaultRoleID        *string            `json:"default_role_id"`
	CreatedAt            int64              `json:"created_at"`
	UpdatedAt            int64              `json:"updated_at"`
}

// SamlMetadata carries the SP EntityDescriptor XML inside a JSON envelope.
type SamlMetadata struct {
	Object     string `json:"object"`
	SPEntityID string `json:"sp_entity_id"`
	ACSURL     string `json:"acs_url"`
	// SLOURL is the SP SingleLogoutService URL (both bindings) when Single
	// Logout is on.
	SLOURL      *string `json:"slo_url,omitempty"`
	MetadataXML string  `json:"metadata_xml"`
}

// SamlEncryptionKey is a SAML connection's SP encryption key pair —
// certificates only. Certificate is nil when encryption is off;
// PreviousCertificate is set during a rotation; RotatedAt is epoch ms.
type SamlEncryptionKey struct {
	Object                     string  `json:"object"`
	ConnectionID               string  `json:"connection_id"`
	Certificate                *string `json:"certificate"`
	PreviousCertificate        *string `json:"previous_certificate"`
	RotatedAt                  *int64  `json:"rotated_at"`
	RequireEncryptedAssertions bool    `json:"require_encrypted_assertions"`
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
	// SAML Single Logout. The URLs are https; SAMLIDPSLOBinding is "redirect"
	// or "post". SAMLIDPSLOSOAPURL is the back channel for sessions ended
	// server-side.
	SAMLSingleLogout      *bool  `json:"saml_single_logout,omitempty"`
	SAMLIDPSLOURL         string `json:"saml_idp_slo_url,omitempty"`
	SAMLIDPSLOResponseURL string `json:"saml_idp_slo_response_url,omitempty"`
	SAMLIDPSLOBinding     string `json:"saml_idp_slo_binding,omitempty"`
	SAMLIDPSLOSOAPURL     string `json:"saml_idp_slo_soap_url,omitempty"`
	// SAMLRequireEncryptedAssertions needs an encryption key first (see
	// CreateSAMLEncryptionKey).
	SAMLRequireEncryptedAssertions *bool `json:"saml_require_encrypted_assertions,omitempty"`
	// OIDC relying-party settings: declarative profile mapping (see
	// ProfileMapping), token-endpoint client authentication (private_key_jwt
	// needs no secret), RP-initiated / back-channel logout and third-party
	// initiated login.
	ProfileMapping          *ProfileMapping            `json:"profile_mapping,omitempty"`
	TokenEndpointAuthMethod string                     `json:"token_endpoint_auth_method,omitempty"`
	ClientAssertionAudience string                     `json:"client_assertion_audience,omitempty"`
	Logout                  *UpstreamLogoutSettings    `json:"logout,omitempty"`
	IdpInitiatedLogin       *IdpInitiatedLoginSettings `json:"idp_initiated_login,omitempty"`
	// Clear names settings to reset (sent as JSON null), e.g.
	// "saml_idp_slo_url", "saml_idp_slo_soap_url", "profile_mapping".
	Clear []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p CreateSsoConnectionParams) MarshalJSON() ([]byte, error) {
	type plain CreateSsoConnectionParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
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
func (s *SSOConnectionsService) Update(ctx context.Context, id string, params UpdateSsoConnectionParams, opts ...RequestOption) (*SsoConnection, error) {
	out := &SsoConnection{}
	return out, s.client.patch(ctx, "/v1/sso_connections/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes an SSO connection. DELETE /v1/sso_connections/:id.
func (s *SSOConnectionsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/sso_connections/"+url.PathEscape(id), out, opts...)
}

// SAMLMetadata returns the SP SAML metadata for a connection.
// GET /v1/sso_connections/:id/saml_metadata.
func (s *SSOConnectionsService) SAMLMetadata(ctx context.Context, id string) (*SamlMetadata, error) {
	out := &SamlMetadata{}
	return out, s.client.get(ctx, "/v1/sso_connections/"+url.PathEscape(id)+"/saml_metadata", nil, out)
}

func ssoPath(id string) string { return "/v1/sso_connections/" + url.PathEscape(id) }

// PreviewProfileMapping (OIDC) runs the connection's profile mapping — or the
// body's — against a pasted sample. POST /v1/sso_connections/:id/profile_mapping/preview.
func (s *SSOConnectionsService) PreviewProfileMapping(ctx context.Context, id string, params ProfileMappingPreviewParams, opts ...RequestOption) (*ProfileMappingPreview, error) {
	out := &ProfileMappingPreview{}
	return out, s.client.post(ctx, ssoPath(id)+"/profile_mapping/preview", params, out, opts...)
}

// SigningKeys (OIDC) are the connection's private_key_jwt signing keys.
func (s *SSOConnectionsService) SigningKeys(id string) *UpstreamSigningKeysService {
	return &UpstreamSigningKeysService{client: s.client, base: ssoPath(id)}
}

// GetSAMLEncryptionKey returns the SAML connection's SP encryption
// certificate(s). GET /v1/sso_connections/:id/saml_encryption_key.
func (s *SSOConnectionsService) GetSAMLEncryptionKey(ctx context.Context, id string) (*SamlEncryptionKey, error) {
	out := &SamlEncryptionKey{}
	return out, s.client.get(ctx, ssoPath(id)+"/saml_encryption_key", nil, out)
}

// CreateSAMLEncryptionKey generates the SP encryption key pair, or ROTATES it
// when one exists: the current pair becomes the previous one (still
// advertised and accepted until RetirePreviousSAMLEncryptionKey).
// POST /v1/sso_connections/:id/saml_encryption_key.
func (s *SSOConnectionsService) CreateSAMLEncryptionKey(ctx context.Context, id string, opts ...RequestOption) (*SamlEncryptionKey, error) {
	out := &SamlEncryptionKey{}
	return out, s.client.post(ctx, ssoPath(id)+"/saml_encryption_key", nil, out, opts...)
}

// RetirePreviousSAMLEncryptionKey finishes a rotation: the previous key is no
// longer accepted. DELETE /v1/sso_connections/:id/saml_encryption_key/previous.
func (s *SSOConnectionsService) RetirePreviousSAMLEncryptionKey(ctx context.Context, id string, opts ...RequestOption) (*SamlEncryptionKey, error) {
	out := &SamlEncryptionKey{}
	return out, s.client.del(ctx, ssoPath(id)+"/saml_encryption_key/previous", out, opts...)
}

// DeleteSAMLEncryptionKey turns assertion encryption off (refused while
// encrypted assertions are required). DELETE /v1/sso_connections/:id/saml_encryption_key.
func (s *SSOConnectionsService) DeleteSAMLEncryptionKey(ctx context.Context, id string, opts ...RequestOption) (*SamlEncryptionKey, error) {
	out := &SamlEncryptionKey{}
	return out, s.client.del(ctx, ssoPath(id)+"/saml_encryption_key", out, opts...)
}
