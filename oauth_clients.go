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
	// PreviousSecretExpiresAt is, after a rotation with overlap, when the
	// previous secret stops working (epoch ms); nil when only the current secret
	// is accepted.
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at,omitempty"`
	IsPublic                bool   `json:"is_public"`
	FirstParty              bool   `json:"first_party"`
	// SkipLogoutConfirmation is true when RP-initiated logout (/oauth2/logout)
	// with this client_id and an exactly registered post_logout_redirect_uri
	// ends the session and redirects straight back (with state) without the
	// confirmation page. First-party clients only.
	SkipLogoutConfirmation bool `json:"skip_logout_confirmation"`
	// Disabled refuses every OAuth flow for the client without deleting it.
	Disabled bool `json:"disabled"`
	// RequirePKCE forces PKCE for this confidential client too.
	RequirePKCE bool `json:"require_pkce"`
	// SubjectType is "public" (sub = user id) or "pairwise" (a per-sector sub).
	SubjectType string `json:"subject_type,omitempty"`
	// SectorIdentifierURI is the pairwise sector document, if registered.
	SectorIdentifierURI *string `json:"sector_identifier_uri,omitempty"`
	// ClientSecretExpiresAt is when the current secret stops authenticating
	// (epoch ms); nil means it never expires.
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`
	// AccessTokenFormat is "jwt" or "opaque" for this client; nil inherits from
	// the API / instance.
	AccessTokenFormat *string `json:"access_token_format,omitempty"`
	// TokenLifetimes are this client's lifetime overrides (seconds); a nil
	// field is inherited.
	TokenLifetimes *OAuthTokenLifetimes `json:"token_lifetimes,omitempty"`
	CreatedAt      int64                `json:"created_at"`
	UpdatedAt      int64                `json:"updated_at"`
	ProvisioningFields
}

// Access-token formats: signed JWTs, or opaque references validated by
// introspection.
const (
	AccessTokenFormatJWT    = "jwt"
	AccessTokenFormatOpaque = "opaque"
)

// OAuthTokenLifetimes are token lifetimes in seconds. A nil field inherits
// the API's, then the instance's, then Atlas's default. Bounds: access / id
// token 60–86400; refresh token 300–31536000 (idle ≤ absolute); authorization
// code 10–600; device code 60–1800.
type OAuthTokenLifetimes struct {
	AccessTokenTTLSeconds          *int64 `json:"access_token_ttl_seconds,omitempty"`
	IDTokenTTLSeconds              *int64 `json:"id_token_ttl_seconds,omitempty"`
	RefreshTokenAbsoluteTTLSeconds *int64 `json:"refresh_token_absolute_ttl_seconds,omitempty"`
	RefreshTokenIdleTTLSeconds     *int64 `json:"refresh_token_idle_ttl_seconds,omitempty"`
	AuthorizationCodeTTLSeconds    *int64 `json:"authorization_code_ttl_seconds,omitempty"`
	DeviceCodeTTLSeconds           *int64 `json:"device_code_ttl_seconds,omitempty"`
}

// OAuthClientWithSecret carries the client_secret, revealed once on create and
// rotate.
type OAuthClientWithSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	OAuthClient
	ClientSecret string `json:"client_secret,omitempty"`
	Note         string `json:"note"`
	// OverlapSeconds is, on a rotation, how long the previous secret keeps
	// working (echoed).
	OverlapSeconds int `json:"overlap_seconds,omitempty"`
}

// RotateOAuthClientSecretParams is the body of
// POST /v1/oauth_clients/:id/rotate_secret.
type RotateOAuthClientSecretParams struct {
	// OverlapSeconds is how long the previous secret keeps working. nil uses the
	// default, 86400 (24 hours); 0 revokes it now; at most 604800 (7 days).
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
	// SecretExpiresInSeconds gives the new secret a lifetime (reported as
	// client_secret_expires_at); nil issues one that does not expire.
	SecretExpiresInSeconds *int64 `json:"secret_expires_in_seconds,omitempty"`
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
	// RequirePKCE: new clients default to true (confidential ones included);
	// send false to opt out.
	RequirePKCE *bool `json:"require_pkce,omitempty"`
	// ProvisioningInput: metadata tags and an external_ref (idempotent create).
	ProvisioningInput
	// SkipLogoutConfirmation, when true, lets RP-initiated logout
	// (/oauth2/logout) with this client_id and an exactly registered
	// post_logout_redirect_uri end the session and redirect straight back with
	// state, without the confirmation page. First-party clients only: on a
	// third-party client the API answers 422 VALIDATION_FAILED (param
	// skip_logout_confirmation).
	SkipLogoutConfirmation *bool `json:"skip_logout_confirmation,omitempty"`
	// SecretExpiresInSeconds gives the issued secret a lifetime (reported as
	// client_secret_expires_at); nil issues one that does not expire.
	SecretExpiresInSeconds *int64 `json:"secret_expires_in_seconds,omitempty"`
	// SubjectType is "public" (default) or "pairwise" (a per-sector sub).
	SubjectType string `json:"subject_type,omitempty"`
	// SectorIdentifierURI is an https URL listing every redirect_uri; required
	// for a pairwise client whose redirect_uris span more than one host.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`
	// AccessTokenFormat is "jwt" or "opaque"; ClearAccessTokenFormat sends
	// null (inherit).
	AccessTokenFormat      string `json:"access_token_format,omitempty"`
	ClearAccessTokenFormat bool   `json:"-"`
	// TokenLifetimes replaces the client's overrides; ClearTokenLifetimes
	// sends null and clears them all.
	TokenLifetimes      *OAuthTokenLifetimes `json:"token_lifetimes,omitempty"`
	ClearTokenLifetimes bool                 `json:"-"`
}

// UpdateOAuthClientParams is the body of PATCH /v1/oauth_clients/:id.
type UpdateOAuthClientParams struct {
	Name                    string   `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	AllowedScopes           []string `json:"allowed_scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	LogoURL                 string   `json:"logo_url,omitempty"`
	FirstParty              *bool    `json:"first_party,omitempty"`
	// SkipLogoutConfirmation, when true, lets RP-initiated logout
	// (/oauth2/logout) with this client_id and an exactly registered
	// post_logout_redirect_uri end the session and redirect straight back with
	// state, without the confirmation page. First-party clients only: on a
	// third-party client the API answers 422 VALIDATION_FAILED (param
	// skip_logout_confirmation).
	SkipLogoutConfirmation *bool `json:"skip_logout_confirmation,omitempty"`
	// SecretExpiresInSeconds gives the issued secret a lifetime (reported as
	// client_secret_expires_at); nil issues one that does not expire.
	SecretExpiresInSeconds *int64 `json:"secret_expires_in_seconds,omitempty"`
	// SubjectType is "public" (default) or "pairwise" (a per-sector sub).
	SubjectType string `json:"subject_type,omitempty"`
	// SectorIdentifierURI is an https URL listing every redirect_uri; required
	// for a pairwise client whose redirect_uris span more than one host.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`
	// Disabled refuses (true) or re-allows (false) every OAuth flow.
	Disabled *bool `json:"disabled,omitempty"`
	// RequirePKCE forces PKCE for this confidential client too.
	RequirePKCE *bool `json:"require_pkce,omitempty"`
	// AccessTokenFormat is "jwt" or "opaque"; ClearAccessTokenFormat sends
	// null (inherit).
	AccessTokenFormat      string `json:"access_token_format,omitempty"`
	ClearAccessTokenFormat bool   `json:"-"`
	// TokenLifetimes replaces the client's overrides; ClearTokenLifetimes
	// sends null and clears them all.
	TokenLifetimes      *OAuthTokenLifetimes `json:"token_lifetimes,omitempty"`
	ClearTokenLifetimes bool                 `json:"-"`
}

func oauthClientTokenNulls(format, lifetimes bool) map[string]interface{} {
	extra := map[string]interface{}{}
	if format {
		extra["access_token_format"] = nil
	}
	if lifetimes {
		extra["token_lifetimes"] = nil
	}
	return extra
}

// MarshalJSON sends null for the Clear* flags.
func (p CreateOAuthClientParams) MarshalJSON() ([]byte, error) {
	type plain CreateOAuthClientParams
	return marshalWithExtra(plain(p), oauthClientTokenNulls(p.ClearAccessTokenFormat, p.ClearTokenLifetimes))
}

// MarshalJSON sends null for the Clear* flags.
func (p UpdateOAuthClientParams) MarshalJSON() ([]byte, error) {
	type plain UpdateOAuthClientParams
	return marshalWithExtra(plain(p), oauthClientTokenNulls(p.ClearAccessTokenFormat, p.ClearTokenLifetimes))
}

// List returns all OAuth clients. GET /v1/oauth_clients.
func (s *OAuthClientsService) List(ctx context.Context) (*ListPage[OAuthClient], error) {
	out := &ListPage[OAuthClient]{}
	return out, s.client.get(ctx, "/v1/oauth_clients", nil, out)
}

// ListWithMetadata lists the OAuth clients whose provisioning metadata matches
// every pair. GET /v1/oauth_clients?metadata[key]=value.
func (s *OAuthClientsService) ListWithMetadata(ctx context.Context, metadata map[string]interface{}) (*ListPage[OAuthClient], error) {
	out := &ListPage[OAuthClient]{}
	return out, s.client.get(ctx, "/v1/oauth_clients", MetadataQuery(metadata), out)
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
func (s *OAuthClientsService) Update(ctx context.Context, id string, params UpdateOAuthClientParams, opts ...RequestOption) (*OAuthClient, error) {
	out := &OAuthClient{}
	return out, s.client.patch(ctx, "/v1/oauth_clients/"+url.PathEscape(id), params, out, opts...)
}

// RotateSecret rotates the client secret; the response carries it once. The
// previous secret keeps working for the default overlap (24 hours); use
// RotateSecretWithParams to choose it. POST /v1/oauth_clients/:id/rotate_secret.
func (s *OAuthClientsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*OAuthClientWithSecret, error) {
	out := &OAuthClientWithSecret{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
}

// RotateSecretWithParams rotates the client secret with a chosen overlap: the
// previous secret keeps working for OverlapSeconds (0 revokes it now, e.g.
// after a leak). PreviousSecretExpiresAt in the response says when it stops.
// POST /v1/oauth_clients/:id/rotate_secret.
func (s *OAuthClientsService) RotateSecretWithParams(ctx context.Context, id string, params RotateOAuthClientSecretParams, opts ...RequestOption) (*OAuthClientWithSecret, error) {
	out := &OAuthClientWithSecret{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(id)+"/rotate_secret", params, out, opts...)
}

// Delete removes an OAuth client. DELETE /v1/oauth_clients/:id.
func (s *OAuthClientsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/oauth_clients/"+url.PathEscape(id), out, opts...)
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
func (s *OAuthClientGrantsService) Create(ctx context.Context, clientID string, params CreateClientGrantParams, opts ...RequestOption) (*ClientGrant, error) {
	out := &ClientGrant{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(clientID)+"/grants", params, out, opts...)
}

// Delete removes a client grant.
func (s *OAuthClientGrantsService) Delete(ctx context.Context, clientID, grantID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/oauth_clients/"+url.PathEscape(clientID)+"/grants/"+url.PathEscape(grantID), out, opts...)
}

// ImportOAuthClient is one client to import. Supply ClientSecret (hashed on
// arrival) or a pre-hashed ClientSecretHash, or neither for a public client.
type ImportOAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretHash        string   `json:"client_secret_hash,omitempty"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	AllowedScopes           []string `json:"allowed_scopes,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// Import bulk-imports OAuth clients for a migration (idempotent per client_id).
// POST /v1/oauth_clients/import.
func (s *OAuthClientsService) Import(ctx context.Context, clients []ImportOAuthClient, opts ...RequestOption) (*ListPage[OAuthClient], error) {
	out := &ListPage[OAuthClient]{}
	body := map[string]interface{}{"clients": clients}
	return out, s.client.post(ctx, "/v1/oauth_clients/import", body, out, opts...)
}
