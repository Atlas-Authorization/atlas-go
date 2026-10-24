package atlas

import (
	"context"
	"net/url"
)

// The instance's own credentials (scoped secret keys, the standard key list,
// whoami), partner links, and Sign in with Atlas grant revocation for the apps
// the instance manages.

// ResourceRef names what a credential is scoped to.
type ResourceRef struct {
	// Type is instance, account, application or webhook_endpoint.
	Type string `json:"type"`
	ID   string `json:"id"`
}

// StandardKey is the shape every credential listing uses.
type StandardKey struct {
	// Object is key or secret_key.
	Object string `json:"object"`
	ID     string `json:"id"`
	// Kind is secret_key, platform_key, account_key, webhook_secret,
	// partner_link or access_token.
	Kind string `json:"kind"`
	// Format is atlas (`atlas_<env>_<kind>_…`) or legacy (`sk_` / `psk_` /
	// `whsec_` / `dsk_`).
	Format string   `json:"format"`
	Prefix string   `json:"prefix"`
	Name   *string  `json:"name"`
	Owner  *string  `json:"owner"`
	Scopes []string `json:"scopes"`
	// Environment is live, test or nil.
	Environment   *string     `json:"environment"`
	Resource      ResourceRef `json:"resource"`
	ExpiresAt     *int64      `json:"expires_at"`
	ExpiresInDays *int        `json:"expires_in_days"`
	// Status is active, expiring, expired or revoked.
	Status          string   `json:"status"`
	IPAllowlist     []string `json:"ip_allowlist"`
	OriginAllowlist []string `json:"origin_allowlist"`
	// AllowedOrigins is the same list under the request field's name: the
	// browser origins the key is locked to (empty = no lock).
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	LastUsedAt     *int64   `json:"last_used_at"`
	LastUsedIP     *string  `json:"last_used_ip"`
	CreatedAt      int64    `json:"created_at"`
	RevokedAt      *int64   `json:"revoked_at"`
}

// SecretKey is a scoped instance secret key.
type SecretKey struct {
	StandardKey
	AllowedIPs  []string `json:"allowed_ips"`
	RotatedFrom *string  `json:"rotated_from"`
}

// SecretKeyWithSecret is a create or rotate response: the secret is present
// once (or sealed, with WithSecretRecipient).
type SecretKeyWithSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	SecretKey
	Secret       string `json:"secret,omitempty"`
	SealedSecret string `json:"sealed_secret,omitempty"`
	Note         string `json:"note"`
	// Replaces and PreviousKeyExpiresAt are set on a rotation.
	Replaces             string `json:"replaces,omitempty"`
	PreviousKeyExpiresAt *int64 `json:"previous_key_expires_at,omitempty"`
}

// SecretKeyRevoked is a revoked key.
type SecretKeyRevoked struct {
	SecretKey
	Revoked bool `json:"revoked"`
}

// CreateSecretKeyParams is the body of POST /v1/secret_keys.
type CreateSecretKeyParams struct {
	Name string `json:"name,omitempty"`
	// Scopes are instance scopes, or the presets read_only, privacy:execute
	// and privacy:grants:revoke.
	Scopes []string `json:"scopes"`
	// ExpiresAt is unix ms (at most one year away). ExpiresAtISO sends an
	// ISO 8601 string instead.
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	ExpiresAtISO string `json:"-"`
	// AllowedIPs are CIDRs the key may be used from.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// AllowedOrigins locks the key to browser origins (exact, or one-level
	// wildcard such as https://*.example.com). Enforced when a request carries
	// an Origin header; a call from another origin is refused with
	// ORIGIN_NOT_ALLOWED.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// Owner defaults to the creator (user:<id>, api_key:<id> or platform_key:<id>).
	Owner string `json:"owner,omitempty"`
	// KeyFormat is "atlas" (default) or "legacy" (for validators that check
	// for `sk_`).
	KeyFormat string `json:"key_format,omitempty"`
}

// MarshalJSON sends ExpiresAtISO as expires_at when ExpiresAt is unset.
func (p CreateSecretKeyParams) MarshalJSON() ([]byte, error) {
	type plain CreateSecretKeyParams
	var extra map[string]interface{}
	if p.ExpiresAt == nil && p.ExpiresAtISO != "" {
		extra = map[string]interface{}{"expires_at": p.ExpiresAtISO}
	}
	return marshalWithExtra(plain(p), extra)
}

// UpdateSecretKeyParams is the body of PATCH /v1/secret_keys/:id. Clear names
// nullable fields to send as null: name, owner, expires_at.
type UpdateSecretKeyParams struct {
	Name       string   `json:"name,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	ExpiresAt  *int64   `json:"expires_at,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// AllowedOrigins replaces the browser-origin lock.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Clear          []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdateSecretKeyParams) MarshalJSON() ([]byte, error) {
	type plain UpdateSecretKeyParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// RotateSecretKeyParams is the body of POST /v1/secret_keys/:id/rotate.
type RotateSecretKeyParams struct {
	// OverlapSeconds is how long the old key keeps working (default 72 h,
	// 0 = it stops now). nil sends the default.
	OverlapSeconds *int   `json:"overlap_seconds,omitempty"`
	KeyFormat      string `json:"key_format,omitempty"`
}

// SecretKeysService is /v1/secret_keys.
type SecretKeysService struct{ client *Client }

// Create mints a scoped secret key; the secret is in this response only.
// POST /v1/secret_keys.
func (s *SecretKeysService) Create(ctx context.Context, params CreateSecretKeyParams, opts ...RequestOption) (*SecretKeyWithSecret, error) {
	out := &SecretKeyWithSecret{}
	return out, s.client.post(ctx, "/v1/secret_keys", params, out, opts...)
}

// List returns the instance's secret keys. GET /v1/secret_keys.
func (s *SecretKeysService) List(ctx context.Context) (*ListPage[SecretKey], error) {
	out := &ListPage[SecretKey]{}
	return out, s.client.get(ctx, "/v1/secret_keys", nil, out)
}

// Get returns one secret key. GET /v1/secret_keys/:id.
func (s *SecretKeysService) Get(ctx context.Context, id string) (*SecretKey, error) {
	out := &SecretKey{}
	return out, s.client.get(ctx, "/v1/secret_keys/"+url.PathEscape(id), nil, out)
}

// Update changes a key's name, owner, expiry or IP allowlist.
// PATCH /v1/secret_keys/:id.
func (s *SecretKeysService) Update(ctx context.Context, id string, params UpdateSecretKeyParams, opts ...RequestOption) (*SecretKey, error) {
	out := &SecretKey{}
	return out, s.client.patch(ctx, "/v1/secret_keys/"+url.PathEscape(id), params, out, opts...)
}

// Rotate mints a new key with the same scopes; the old one keeps working for
// the overlap. POST /v1/secret_keys/:id/rotate.
func (s *SecretKeysService) Rotate(ctx context.Context, id string, params RotateSecretKeyParams, opts ...RequestOption) (*SecretKeyWithSecret, error) {
	out := &SecretKeyWithSecret{}
	return out, s.client.post(ctx, "/v1/secret_keys/"+url.PathEscape(id)+"/rotate", params, out, opts...)
}

// Revoke revokes a key at once. POST /v1/secret_keys/:id/revoke.
func (s *SecretKeysService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*SecretKeyRevoked, error) {
	out := &SecretKeyRevoked{}
	return out, s.client.post(ctx, "/v1/secret_keys/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}

// KeysService is /v1/keys.
type KeysService struct{ client *Client }

// List returns every credential on the instance, in the standard shape.
// GET /v1/keys.
func (s *KeysService) List(ctx context.Context) (*ListPage[StandardKey], error) {
	out := &ListPage[StandardKey]{}
	return out, s.client.get(ctx, "/v1/keys", nil, out)
}

// ---- whoami ------------------------------------------------------------------

// WhoamiKey describes the credential a request was signed with.
type WhoamiKey struct {
	ID *string `json:"id"`
	// Type is secret, publishable, platform, partner_link or access_token.
	Type            string   `json:"type"`
	Prefix          *string  `json:"prefix"`
	Environment     *string  `json:"environment"`
	Scopes          []string `json:"scopes"`
	EffectiveScopes []string `json:"effective_scopes"`
	Owner           *string  `json:"owner"`
	CreatedAt       *int64   `json:"created_at"`
	ExpiresAt       *int64   `json:"expires_at"`
	LastUsedAt      *int64   `json:"last_used_at"`
	LastUsedIP      *string  `json:"last_used_ip,omitempty"`
	ApplicationIDs  []string `json:"application_ids,omitempty"`
}

// WhoamiInstance is the instance the key belongs to.
type WhoamiInstance struct {
	ID           string  `json:"id"`
	Environment  *string `json:"environment"`
	Issuer       string  `json:"issuer,omitempty"`
	DiscoveryURL string  `json:"discovery_url,omitempty"`
	JWKSURI      string  `json:"jwks_uri,omitempty"`
}

// Whoami is GET /v1/whoami (and /v1/platform/whoami): what the credential in
// use is and what it may do.
type Whoami struct {
	Object   string          `json:"object"`
	Key      WhoamiKey       `json:"key"`
	Instance *WhoamiInstance `json:"instance"`
	Account  struct {
		ID *string `json:"id"`
	} `json:"account"`
	Platform *struct {
		ID string `json:"id"`
	} `json:"platform,omitempty"`
	Partner *struct {
		LinkID string  `json:"link_id"`
		ID     string  `json:"id"`
		Name   *string `json:"name"`
	} `json:"partner,omitempty"`
	Operator *struct {
		Sub      string   `json:"sub"`
		AuthTime *int64   `json:"auth_time"`
		ACR      *string  `json:"acr"`
		AMR      []string `json:"amr"`
	} `json:"operator,omitempty"`
}

// Whoami introspects the key this client uses. GET /v1/whoami.
func (c *Client) Whoami(ctx context.Context) (*Whoami, error) {
	out := &Whoami{}
	return out, c.get(ctx, "/v1/whoami", nil, out)
}

// ---- partner links -----------------------------------------------------------

// PartnerLink is a credential an integrated partner service holds on this
// instance.
type PartnerLink struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object   string `json:"object"`
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	// Partner is any lowercase id; cookiemunch, chatly, forumulate and
	// referalli are presets.
	Partner            string   `json:"partner"`
	Name               string   `json:"name"`
	Preset             bool     `json:"preset"`
	Resource           string   `json:"resource"`
	Scopes             []string `json:"scopes"`
	ClientSecretPrefix string   `json:"client_secret_prefix"`
	TokenEndpoint      string   `json:"token_endpoint"`
	// CertFingerprints are the client-certificate SHA-256 fingerprints
	// (base64url) every use must present (mTLS); empty = no lock.
	CertFingerprints []string `json:"cert_fingerprints"`
	AuthMethods      []string `json:"auth_methods"`
	// RequestID is the partner link request this link was approved from; nil
	// when it was created by hand.
	RequestID *string `json:"request_id"`
	// Status is active, expired or revoked.
	Status     string  `json:"status"`
	ExpiresAt  *int64  `json:"expires_at"`
	RevokedAt  *int64  `json:"revoked_at"`
	LastUsedAt *int64  `json:"last_used_at"`
	LastUsedIP *string `json:"last_used_ip"`
	Calls30d   int     `json:"calls_30d"`
	CreatedAt  int64   `json:"created_at"`
	// ClientSecret / SealedClientSecret are set once, on create and rotate.
	ClientSecret       string `json:"client_secret,omitempty"`
	SealedClientSecret string `json:"sealed_client_secret,omitempty"`
}

// PartnerLinkRevoked is a revoked partner link.
type PartnerLinkRevoked struct {
	PartnerLink
	Revoked bool `json:"revoked"`
}

// CreatePartnerLinkParams is the body of POST /v1/partner_links.
type CreatePartnerLinkParams struct {
	Partner string   `json:"partner"`
	Name    string   `json:"name,omitempty"`
	Scopes  []string `json:"scopes"`
	// ExpiresAt is unix ms.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	// CertFingerprints asks for a certificate-locked (mTLS) link.
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
}

// OutboundPartnerLink is a credential this instance holds for a partner's API
// (for example a data-rights orchestrator).
type OutboundPartnerLink struct {
	Object   string   `json:"object"`
	ID       string   `json:"id"`
	Partner  string   `json:"partner"`
	Name     string   `json:"name"`
	Preset   bool     `json:"preset"`
	Resource *string  `json:"resource"`
	Scopes   []string `json:"scopes"`
	BaseURL  string   `json:"base_url"`
	TokenURL string   `json:"token_url"`
	ClientID string   `json:"client_id"`
	// AuthMethod is client_credentials or bearer_secret.
	AuthMethod      string `json:"auth_method"`
	HasClientSecret bool   `json:"has_client_secret"`
	// Source is manual or oauth_install.
	Source string `json:"source"`
	// Status is active, revoked or failing.
	Status      string  `json:"status"`
	ExpiresAt   *int64  `json:"expires_at"`
	LastUsedAt  *int64  `json:"last_used_at"`
	LastError   *string `json:"last_error"`
	LastErrorAt *int64  `json:"last_error_at"`
	Calls30d    int     `json:"calls_30d"`
	CreatedAt   int64   `json:"created_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// SaveOutboundPartnerLinkParams is the body of
// PUT /v1/partner_links/outbound/:partner.
type SaveOutboundPartnerLinkParams struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"`
	Resource     string   `json:"resource,omitempty"`
	// BaseURL and TokenURL are required for a partner that is not a preset.
	BaseURL    string `json:"base_url,omitempty"`
	TokenURL   string `json:"token_url,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
	Name       string `json:"name,omitempty"`
	ExpiresAt  *int64 `json:"expires_at,omitempty"`
}

// OutboundPartnerLinkTest is the result of testing an outbound link.
type OutboundPartnerLinkTest struct {
	Object  string `json:"object"`
	Partner string `json:"partner"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// OutboundPartnerLinkDeleted acknowledges removing an outbound link.
type OutboundPartnerLinkDeleted struct {
	Object  string `json:"object"`
	Partner string `json:"partner"`
	Deleted bool   `json:"deleted"`
}

// PartnerLinksService is /v1/partner_links. Outbound and Requests hang off it.
type PartnerLinksService struct {
	client *Client

	Outbound *OutboundPartnerLinksService
	// Requests are the partner link requests: a partner asks, you approve or
	// deny, and Atlas delivers the credentials to the partner's callback.
	Requests *PartnerLinkRequestsService
}

// SetCertificates locks a link to client certificates (mTLS): the SHA-256
// fingerprints (base64url) every use must present. An empty list removes the
// lock. PATCH /v1/partner_links/:id.
func (s *PartnerLinksService) SetCertificates(ctx context.Context, id string, certFingerprints []string, opts ...RequestOption) (*PartnerLink, error) {
	if certFingerprints == nil {
		certFingerprints = []string{}
	}
	out := &PartnerLink{}
	return out, s.client.patch(ctx, "/v1/partner_links/"+url.PathEscape(id), map[string]interface{}{"cert_fingerprints": certFingerprints}, out, opts...)
}

// Create grants a partner a credential on this instance; the secret is
// shown once. POST /v1/partner_links.
func (s *PartnerLinksService) Create(ctx context.Context, params CreatePartnerLinkParams, opts ...RequestOption) (*PartnerLink, error) {
	out := &PartnerLink{}
	return out, s.client.post(ctx, "/v1/partner_links", params, out, opts...)
}

// List returns the partner links. GET /v1/partner_links.
func (s *PartnerLinksService) List(ctx context.Context) (*ListPage[PartnerLink], error) {
	out := &ListPage[PartnerLink]{}
	return out, s.client.get(ctx, "/v1/partner_links", nil, out)
}

// Get returns one partner link. GET /v1/partner_links/:id.
func (s *PartnerLinksService) Get(ctx context.Context, id string) (*PartnerLink, error) {
	out := &PartnerLink{}
	return out, s.client.get(ctx, "/v1/partner_links/"+url.PathEscape(id), nil, out)
}

// RotateSecret issues a new client secret. POST /v1/partner_links/:id/rotate_secret.
func (s *PartnerLinksService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*PartnerLink, error) {
	out := &PartnerLink{}
	return out, s.client.post(ctx, "/v1/partner_links/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
}

// Revoke revokes a partner link. DELETE /v1/partner_links/:id.
func (s *PartnerLinksService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*PartnerLinkRevoked, error) {
	out := &PartnerLinkRevoked{}
	return out, s.client.del(ctx, "/v1/partner_links/"+url.PathEscape(id), out, opts...)
}

// OutboundPartnerLinksService is /v1/partner_links/outbound.
type OutboundPartnerLinksService struct{ client *Client }

// List returns the outbound links. GET /v1/partner_links/outbound.
func (s *OutboundPartnerLinksService) List(ctx context.Context) (*ListPage[OutboundPartnerLink], error) {
	out := &ListPage[OutboundPartnerLink]{}
	return out, s.client.get(ctx, "/v1/partner_links/outbound", nil, out)
}

// Save creates or replaces the outbound link for a partner.
// PUT /v1/partner_links/outbound/:partner.
func (s *OutboundPartnerLinksService) Save(ctx context.Context, partner string, params SaveOutboundPartnerLinkParams, opts ...RequestOption) (*OutboundPartnerLink, error) {
	out := &OutboundPartnerLink{}
	return out, s.client.put(ctx, "/v1/partner_links/outbound/"+url.PathEscape(partner), params, out, opts...)
}

// Test calls the partner with the stored credential.
// POST /v1/partner_links/outbound/:partner/test.
func (s *OutboundPartnerLinksService) Test(ctx context.Context, partner string, opts ...RequestOption) (*OutboundPartnerLinkTest, error) {
	out := &OutboundPartnerLinkTest{}
	return out, s.client.post(ctx, "/v1/partner_links/outbound/"+url.PathEscape(partner)+"/test", nil, out, opts...)
}

// Remove deletes the outbound link. DELETE /v1/partner_links/outbound/:partner.
func (s *OutboundPartnerLinksService) Remove(ctx context.Context, partner string, opts ...RequestOption) (*OutboundPartnerLinkDeleted, error) {
	out := &OutboundPartnerLinkDeleted{}
	return out, s.client.del(ctx, "/v1/partner_links/outbound/"+url.PathEscape(partner), out, opts...)
}

// ---- Sign in with Atlas grants for the apps the instance manages -------------

// AtlasIDGrantsService is /v1/atlas_id_apps.
type AtlasIDGrantsService struct{ client *Client }

// ManagedAtlasIDApp is a Sign in with Atlas app this instance manages.
type ManagedAtlasIDApp struct {
	Object              string `json:"object"`
	ID                  string `json:"id"`
	ClientID            string `json:"client_id"`
	Name                string `json:"name"`
	ManagedByInstanceID string `json:"managed_by_instance_id"`
	// ManagedVia is instance_toggle or adopted.
	ManagedVia    string   `json:"managed_via,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	CreatedAt     int64    `json:"created_at,omitempty"`
	// ButtonRenderedOrigins are the page origins the button script ran on in the
	// last 7 days.
	ButtonRenderedOrigins []AtlasIDOriginSeen `json:"button_rendered_origins,omitempty"`
}

// Preflight is the setup check of an app this instance manages
// (diagnostics:read is enough). GET /v1/atlas_id_apps/:id/preflight.
func (s *AtlasIDGrantsService) Preflight(ctx context.Context, appID string) (*AtlasIDAppPreflight, error) {
	out := &AtlasIDAppPreflight{}
	return out, s.client.get(ctx, "/v1/atlas_id_apps/"+url.PathEscape(appID)+"/preflight", nil, out)
}

// AtlasIDGrantLookup says a verified email is a user of an app.
type AtlasIDGrantLookup struct {
	Object    string   `json:"object"`
	Sub       string   `json:"sub"`
	GrantID   string   `json:"grant_id"`
	Scopes    []string `json:"scopes"`
	GrantedAt int64    `json:"granted_at"`
}

// InstanceAtlasIDGrantRevocation is the result of revoking a grant.
type InstanceAtlasIDGrantRevocation struct {
	Object             string `json:"object"`
	ID                 string `json:"id"`
	Sub                string `json:"sub"`
	Revoked            bool   `json:"revoked"`
	TokensRevoked      int    `json:"tokens_revoked"`
	BackchannelLogouts int    `json:"backchannel_logouts"`
}

// ListApps returns the Sign in with Atlas apps this instance manages.
// GET /v1/atlas_id_apps.
func (s *AtlasIDGrantsService) ListApps(ctx context.Context) (*ListPage[ManagedAtlasIDApp], error) {
	out := &ListPage[ManagedAtlasIDApp]{}
	return out, s.client.get(ctx, "/v1/atlas_id_apps", nil, out)
}

// Lookup asks whether a verified email is a user of the app (an empty list
// when not). GET /v1/atlas_id_apps/:id/users?email=.
func (s *AtlasIDGrantsService) Lookup(ctx context.Context, appID, email string) (*ListPage[AtlasIDGrantLookup], error) {
	out := &ListPage[AtlasIDGrantLookup]{}
	return out, s.client.get(ctx, "/v1/atlas_id_apps/"+url.PathEscape(appID)+"/users", url.Values{"email": {email}}, out)
}

// Revoke revokes one user's grant. Needs privacy:grants:revoke or the
// per-app grant scope. DELETE /v1/atlas_id_apps/:id/grants/:grantId.
func (s *AtlasIDGrantsService) Revoke(ctx context.Context, appID, grantID string, opts ...RequestOption) (*InstanceAtlasIDGrantRevocation, error) {
	out := &InstanceAtlasIDGrantRevocation{}
	return out, s.client.del(ctx, "/v1/atlas_id_apps/"+url.PathEscape(appID)+"/grants/"+url.PathEscape(grantID), out, opts...)
}
