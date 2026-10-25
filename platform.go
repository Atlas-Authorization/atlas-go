package atlas

import (
	"context"
	"encoding/json"
	"net/url"
)

// PlatformService is the platform surface (/v1/platform/*), signed with a
// platform key ("psk_..."): provision and manage apps, register Sign in with
// Atlas apps, and store the account's design images. Build the client with
// NewPlatform(psk) or New(sk, WithPlatformKey(psk)).
type PlatformService struct {
	client *Client

	// Apps is /v1/platform/apps (+ accountless apps, claims and transfers).
	Apps *PlatformAppsService
	// AtlasIDApps is /v1/platform/atlas_id_apps — Sign in with Atlas apps.
	AtlasIDApps *AtlasIDAppsService
	// DesignAssets is /v1/platform/design/assets — images for Sign in with
	// Atlas app designs.
	DesignAssets *PlatformDesignAssetsService
	// AtlasIDPublisher is /v1/platform/atlas_id_publisher — the account's
	// publisher name and verified domain.
	AtlasIDPublisher *AtlasIDPublisherService
	// Keys is /v1/platform/keys — every credential on the account, and
	// minting / revoking them.
	Keys *PlatformKeysService
	// Audit is the account audit log (/v1/platform/audit_logs) and its streams.
	Audit *PlatformAuditService
	// Domains is /v1/platform/domains — domains the account verified by DNS;
	// they gate test sign-in mode and the test-account domain restriction.
	Domains *PlatformDomainsService
}

// --- Apps -------------------------------------------------------------------

// PlatformAppsService is /v1/platform/apps.
type PlatformAppsService struct{ client *Client }

// PlatformApp is an app (instance) the platform owns. It never carries a
// secret except on create, rotate and claim.
type PlatformApp struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	// Environment is production or development.
	Environment    string `json:"environment"`
	PublishableKey string `json:"publishable_key"`
	// FrontendAPIHost is the default per-app host, or the custom domain once it
	// is active.
	FrontendAPIHost *string `json:"frontend_api_host,omitempty"`
	// Issuer is the iss the app's session tokens carry. It changes when a custom
	// domain goes active, so read it rather than hard-coding it.
	Issuer string `json:"issuer,omitempty"`
	// DiscoveryURL is the OpenID discovery document whose issuer equals Issuer.
	DiscoveryURL string `json:"discovery_url,omitempty"`
	// JWKSURI is the JWKS holding the app's signing keys.
	JWKSURI        string   `json:"jwks_uri,omitempty"`
	AllowedOrigins []string `json:"allowed_origins"`
	// AllowedOriginIntegrations is the declared integration per allowed origin
	// ("redirect" or "embedded").
	AllowedOriginIntegrations map[string]string `json:"allowed_origin_integrations,omitempty"`
	Tags                      []string          `json:"tags"`
	// Archived hides the app from the default listing; it still serves auth.
	Archived   bool   `json:"archived"`
	ArchivedAt *int64 `json:"archived_at"`
	Disabled   bool   `json:"disabled"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	// Note is an explanatory message some responses add.
	Note string `json:"note,omitempty"`

	// ProvisioningFields: metadata, external_ref, idempotent_replay. A create
	// that sent an external_ref and matched an existing app answers 200 with
	// IdempotentReplay set and no secret.
	ProvisioningFields
}

// PlatformAppWithSecret is a PlatformApp plus its reveal-once secret key.
type PlatformAppWithSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	PlatformApp
	Secret string `json:"secret"`
}

// PlatformAppProvisioned is the result of provisioning an app: the app and its
// secret, plus the auto-created test-mode sibling when one was made.
type PlatformAppProvisioned struct {
	PlatformAppWithSecret
	SiblingInstance *PlatformAppWithSecret `json:"sibling_instance,omitempty"`
}

// CreatePlatformAppParams is the body of POST /v1/platform/apps.
type CreatePlatformAppParams struct {
	Name string `json:"name,omitempty"`
	// Environment is production or development.
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// CreateDevelopmentSibling controls the test-mode sibling instance (on by
	// default for a production app); set false to skip it.
	CreateDevelopmentSibling *bool    `json:"create_development_sibling,omitempty"`
	Tags                     []string `json:"tags,omitempty"`
	// AllowedOriginEntries, when set, is sent as allowed_origins instead of
	// AllowedOrigins: each entry also says how the origin signs in.
	AllowedOriginEntries []AllowedOriginEntry `json:"-"`
	// ProvisioningInput: metadata tags and an external_ref (idempotent create).
	ProvisioningInput
}

// MarshalJSON sends AllowedOriginEntries as allowed_origins when set.
func (p CreatePlatformAppParams) MarshalJSON() ([]byte, error) {
	type plain CreatePlatformAppParams
	return marshalWithExtra(plain(p), originEntriesExtra(p.AllowedOriginEntries))
}

// UpdatePlatformAppParams is the body of PATCH /v1/platform/apps/:id.
type UpdatePlatformAppParams struct {
	Name           string   `json:"name,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	// AllowedOriginEntries, when set, is sent as allowed_origins instead of
	// AllowedOrigins: each entry also says how the origin signs in.
	AllowedOriginEntries []AllowedOriginEntry `json:"-"`
	// Metadata replaces the provisioning tags.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MarshalJSON sends AllowedOriginEntries as allowed_origins when set.
func (p UpdatePlatformAppParams) MarshalJSON() ([]byte, error) {
	type plain UpdatePlatformAppParams
	return marshalWithExtra(plain(p), originEntriesExtra(p.AllowedOriginEntries))
}

// ListPlatformAppsParams filters GET /v1/platform/apps. Archived apps are
// hidden unless IncludeArchived or Archived is set.
type ListPlatformAppsParams struct {
	IncludeArchived bool
	// Archived lists only archived apps.
	Archived bool
	Tag      string
	// Metadata keeps only apps whose provisioning metadata matches every pair.
	Metadata map[string]interface{}
}

func (p ListPlatformAppsParams) values() url.Values {
	v := url.Values{}
	if p.IncludeArchived {
		v.Set("include_archived", "true")
	}
	if p.Archived {
		v.Set("archived", "true")
	}
	if p.Tag != "" {
		v.Set("tag", p.Tag)
	}
	for k, vals := range MetadataQuery(p.Metadata) {
		v[k] = vals
	}
	return v
}

// PlatformAppDisabled acknowledges DELETE /v1/platform/apps/:id (a soft,
// reversible disable).
type PlatformAppDisabled struct {
	Object   string `json:"object"`
	ID       string `json:"id"`
	Disabled bool   `json:"disabled"`
	Note     string `json:"note"`
}

// PlatformAppsBulkDeleteResult is the per-id outcome of a bulk delete.
type PlatformAppsBulkDeleteResult struct {
	Object string `json:"object"`
	// Mode is disable (ids) or hard_delete (a sandbox metadata selection).
	Mode    string `json:"mode,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
	Results []struct {
		ID         string `json:"id"`
		Type       string `json:"type,omitempty"`
		InstanceID string `json:"instance_id,omitempty"`
		Deleted    bool   `json:"deleted"`
		Reason     string `json:"reason,omitempty"`
	} `json:"results"`
	Changes []DryRunChange `json:"changes,omitempty"`
}

// PlatformAppSecretRotation is the result of rotating an app's secret with
// overlap: the new secret (revealed once) and when the prior keys expire.
type PlatformAppSecretRotation struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object               string `json:"object"`
	AppID                string `json:"app_id"`
	Secret               string `json:"secret"`
	OverlapSeconds       int    `json:"overlap_seconds"`
	PreviousKeysExpireAt *int64 `json:"previous_keys_expire_at"`
	Note                 string `json:"note"`
}

// PlatformSecretKey is metadata for one currently valid secret key — never the
// secret itself.
type PlatformSecretKey struct {
	Object    string  `json:"object"`
	ID        string  `json:"id"`
	Name      *string `json:"name,omitempty"`
	Prefix    string  `json:"prefix"`
	CreatedAt int64   `json:"created_at"`
	ExpiresAt *int64  `json:"expires_at"`
	ProvisioningFields
}

// PlatformInstanceSecret is the result of rotating one instance's secret.
type PlatformInstanceSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object     string `json:"object"`
	AppID      string `json:"app_id"`
	InstanceID string `json:"instance_id"`
	// Deprecated: never sent by the API; read InstanceID.
	ID string `json:"id,omitempty"`
	// Secret is the new secret key, revealed exactly once.
	Secret string `json:"secret"`
	// OverlapSeconds is the overlap applied.
	OverlapSeconds int `json:"overlap_seconds"`
	// PreviousKeysExpireAt is when the prior keys stop working (epoch ms); nil
	// on a hard cut.
	PreviousKeysExpireAt *int64 `json:"previous_keys_expire_at"`
	Note                 string `json:"note"`
}

// RotatePlatformSecretParams is the body of
// POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret.
type RotatePlatformSecretParams struct {
	// OverlapSeconds is how long the prior keys keep working. nil uses the
	// default, 259200 (72 hours); 0 revokes them now; at most 604800 (7 days).
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
}

// RotateAtlasIDAppSecretParams is the body of the Sign in with Atlas app
// rotate calls (client secret and webhook secret).
type RotateAtlasIDAppSecretParams struct {
	// OverlapSeconds is how long the previous secret keeps working, at most
	// 604800 (7 days). nil uses the default: 86400 (24 hours) for the client
	// secret, 0 (stops at once) for the webhook secret. 0 stops it now.
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
}

// CreatePlatformInstanceParams is the body of
// POST /v1/platform/apps/:id/instances.
type CreatePlatformInstanceParams struct {
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AllowedOriginEntries, when set, is sent as allowed_origins instead of
	// AllowedOrigins: each entry also says how the origin signs in.
	AllowedOriginEntries []AllowedOriginEntry `json:"-"`
	ProvisioningInput
}

// MarshalJSON sends AllowedOriginEntries as allowed_origins when set.
func (p CreatePlatformInstanceParams) MarshalJSON() ([]byte, error) {
	type plain CreatePlatformInstanceParams
	return marshalWithExtra(plain(p), originEntriesExtra(p.AllowedOriginEntries))
}

// CreateAccountlessAppParams is the body of POST /v1/platform/accountless_apps.
type CreateAccountlessAppParams struct {
	Name           string   `json:"name,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AllowedOriginEntries, when set, is sent as allowed_origins instead of
	// AllowedOrigins: each entry also says how the origin signs in.
	AllowedOriginEntries []AllowedOriginEntry `json:"-"`
}

// MarshalJSON sends AllowedOriginEntries as allowed_origins when set.
func (p CreateAccountlessAppParams) MarshalJSON() ([]byte, error) {
	type plain CreateAccountlessAppParams
	return marshalWithExtra(plain(p), originEntriesExtra(p.AllowedOriginEntries))
}

// AccountlessApp is an app owned by no platform, with its one-time claim token.
type AccountlessApp struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Environment    string `json:"environment"`
	PublishableKey string `json:"publishable_key"`
	ClaimToken     string `json:"claim_token"`
	ExpiresAt      int64  `json:"expires_at"`
	Note           string `json:"note"`
}

// PlatformAppTransfer is a one-time transfer token for an owned app.
type PlatformAppTransfer struct {
	Object        string `json:"object"`
	ID            string `json:"id"`
	TransferToken string `json:"transfer_token"`
	ExpiresAt     int64  `json:"expires_at"`
	Note          string `json:"note"`
}

// Create provisions a new app; its secret is revealed once. POST /v1/platform/apps.
func (s *PlatformAppsService) Create(ctx context.Context, params CreatePlatformAppParams, opts ...RequestOption) (*PlatformAppProvisioned, error) {
	out := &PlatformAppProvisioned{}
	return out, s.client.platPost(ctx, "/v1/platform/apps", params, out, opts...)
}

// List returns the platform's apps. GET /v1/platform/apps.
func (s *PlatformAppsService) List(ctx context.Context, params ListPlatformAppsParams) (*ListPage[PlatformApp], error) {
	out := &ListPage[PlatformApp]{}
	return out, s.client.platGet(ctx, "/v1/platform/apps", params.values(), out)
}

// Get fetches one owned app. GET /v1/platform/apps/:id.
func (s *PlatformAppsService) Get(ctx context.Context, id string) (*PlatformApp, error) {
	out := &PlatformApp{}
	return out, s.client.platGet(ctx, "/v1/platform/apps/"+url.PathEscape(id), nil, out)
}

// Update changes an owned app's name, allowed origins or tags.
// PATCH /v1/platform/apps/:id.
func (s *PlatformAppsService) Update(ctx context.Context, id string, params UpdatePlatformAppParams, opts ...RequestOption) (*PlatformApp, error) {
	out := &PlatformApp{}
	return out, s.client.platPatch(ctx, "/v1/platform/apps/"+url.PathEscape(id), params, out, opts...)
}

// Delete disables an owned app (soft and reversible).
// DELETE /v1/platform/apps/:id.
func (s *PlatformAppsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*PlatformAppDisabled, error) {
	out := &PlatformAppDisabled{}
	return out, s.client.platDel(ctx, "/v1/platform/apps/"+url.PathEscape(id), out, opts...)
}

// BulkDelete disables up to 100 owned apps. POST /v1/platform/apps/bulk_delete.
func (s *PlatformAppsService) BulkDelete(ctx context.Context, ids []string, opts ...RequestOption) (*PlatformAppsBulkDeleteResult, error) {
	out := &PlatformAppsBulkDeleteResult{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/bulk_delete", map[string][]string{"ids": ids}, out, opts...)
}

// Archive hides an owned app from the default listing (it keeps serving auth).
// POST /v1/platform/apps/:id/archive.
func (s *PlatformAppsService) Archive(ctx context.Context, id string, opts ...RequestOption) (*PlatformApp, error) {
	out := &PlatformApp{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/archive", nil, out, opts...)
}

// Unarchive returns an app to the default listing.
// POST /v1/platform/apps/:id/unarchive.
func (s *PlatformAppsService) Unarchive(ctx context.Context, id string, opts ...RequestOption) (*PlatformApp, error) {
	out := &PlatformApp{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/unarchive", nil, out, opts...)
}

// RotateSecret mints a new secret key while prior keys stay valid for
// overlapSeconds (nil = the server default of 72h; 0 = revoke them at once).
// POST /v1/platform/apps/:id/rotate_secret.
func (s *PlatformAppsService) RotateSecret(ctx context.Context, id string, overlapSeconds *int, opts ...RequestOption) (*PlatformAppSecretRotation, error) {
	out := &PlatformAppSecretRotation{}
	body := map[string]interface{}{}
	if overlapSeconds != nil {
		body["overlap_seconds"] = *overlapSeconds
	}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/rotate_secret", body, out, opts...)
}

// SecretKeys lists an app's currently valid secret keys (metadata only).
// GET /v1/platform/apps/:id/secret_keys.
func (s *PlatformAppsService) SecretKeys(ctx context.Context, id string) (*ListPage[PlatformSecretKey], error) {
	out := &ListPage[PlatformSecretKey]{}
	return out, s.client.platGet(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/secret_keys", nil, out)
}

// CreateInstance provisions another instance (e.g. development) under an app.
// POST /v1/platform/apps/:id/instances.
func (s *PlatformAppsService) CreateInstance(ctx context.Context, id string, params CreatePlatformInstanceParams, opts ...RequestOption) (*PlatformAppWithSecret, error) {
	out := &PlatformAppWithSecret{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/instances", params, out, opts...)
}

// ListInstances lists every instance under an app.
// GET /v1/platform/apps/:id/instances.
func (s *PlatformAppsService) ListInstances(ctx context.Context, id string) (*ListPage[PlatformApp], error) {
	out := &ListPage[PlatformApp]{}
	return out, s.client.platGet(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/instances", nil, out)
}

// RotateInstanceSecret mints a new secret key for one instance, revealed once;
// the prior keys stay valid for the default overlap (72 hours). Use
// RotateInstanceSecretWithParams to choose it (0 revokes them at once).
// POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret.
func (s *PlatformAppsService) RotateInstanceSecret(ctx context.Context, id, instanceID string, opts ...RequestOption) (*PlatformInstanceSecret, error) {
	out := &PlatformInstanceSecret{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/instances/"+url.PathEscape(instanceID)+"/rotate_secret", nil, out, opts...)
}

// RotateInstanceSecretWithParams is RotateInstanceSecret with a chosen overlap.
// PreviousKeysExpireAt in the response says when the prior keys stop.
// POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret.
func (s *PlatformAppsService) RotateInstanceSecretWithParams(ctx context.Context, id, instanceID string, params RotatePlatformSecretParams, opts ...RequestOption) (*PlatformInstanceSecret, error) {
	out := &PlatformInstanceSecret{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/instances/"+url.PathEscape(instanceID)+"/rotate_secret", params, out, opts...)
}

// CreateAccountless mints an app owned by no platform and returns its one-time
// claim token. POST /v1/platform/accountless_apps.
func (s *PlatformAppsService) CreateAccountless(ctx context.Context, params CreateAccountlessAppParams, opts ...RequestOption) (*AccountlessApp, error) {
	out := &AccountlessApp{}
	return out, s.client.platPost(ctx, "/v1/platform/accountless_apps", params, out, opts...)
}

// Claim claims an accountless app by its claim token and reveals its first
// secret key. POST /v1/platform/apps/claim.
func (s *PlatformAppsService) Claim(ctx context.Context, claimToken string, opts ...RequestOption) (*PlatformAppWithSecret, error) {
	out := &PlatformAppWithSecret{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/claim", map[string]string{"claim_token": claimToken}, out, opts...)
}

// Transfer starts a transfer of an owned app and returns its one-time token.
// POST /v1/platform/apps/:id/transfer.
func (s *PlatformAppsService) Transfer(ctx context.Context, id string, opts ...RequestOption) (*PlatformAppTransfer, error) {
	out := &PlatformAppTransfer{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/transfer", nil, out, opts...)
}

// AcceptTransfer moves an app to the calling platform by its transfer token.
// POST /v1/platform/apps/accept_transfer.
func (s *PlatformAppsService) AcceptTransfer(ctx context.Context, transferToken string, opts ...RequestOption) (*PlatformApp, error) {
	out := &PlatformApp{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/accept_transfer", map[string]string{"transfer_token": transferToken}, out, opts...)
}

// --- Sign in with Atlas apps ------------------------------------------------

// AtlasIDAppsService is /v1/platform/atlas_id_apps: OpenID Connect clients on
// https://atlasauth.net ("Sign in with Atlas") owned by the platform's account.
type AtlasIDAppsService struct {
	client *Client
	// ProvisionedAccounts is the app's test and review accounts. Needs the
	// platform:atlas_id_apps:provision scope, or the per-app
	// atlas_id_apps:<app id>:provision scope.
	ProvisionedAccounts *AtlasIDProvisionedAccountsService
}

// AtlasIDApp is a registered Sign in with Atlas app. It never carries the
// client secret except on create and rotate (ClientSecret).
type AtlasIDApp struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object      string              `json:"object"`
	ID          string              `json:"id"`
	ClientID    string              `json:"client_id"`
	Name        string              `json:"name"`
	LogoURL     *string             `json:"logo_url"`
	HomepageURL *string             `json:"homepage_url"`
	Branding    *AtlasIDAppBranding `json:"branding,omitempty"`
	// RedirectURIs are the exact-match sign-in callback URLs.
	RedirectURIs []string `json:"redirect_uris"`
	// PostLogoutRedirectURIs are where /oauth2/logout may send the user.
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI              *string  `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required"`
	FrontchannelLogoutURI             *string  `json:"frontchannel_logout_uri"`
	FrontchannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required"`
	AllowedScopes                     []string `json:"allowed_scopes"`
	// Type is confidential or public.
	Type                string  `json:"type"`
	SecretPrefix        *string `json:"secret_prefix"`
	ManagedByInstanceID *string `json:"managed_by_instance_id"`
	// ManagedVia is instance_toggle (an instance's Sign in with Atlas toggle app)
	// or adopted (handed to an instance with SetManagedBy); nil otherwise.
	ManagedVia *string `json:"managed_via,omitempty"`
	CreatedAt  int64   `json:"created_at"`
	UpdatedAt  int64   `json:"updated_at"`
	// UserCount is the number of people who approved the app (Get only).
	UserCount *int `json:"user_count,omitempty"`
	// ClientSecret is returned exactly once, on create and rotate, for
	// confidential apps.
	ClientSecret string `json:"client_secret,omitempty"`
	Note         string `json:"note,omitempty"`
	// WebhookURL is the per-app webhook URL, or nil.
	WebhookURL *string `json:"webhook_url,omitempty"`
	// WebhookEvents are the events the per-app webhook gets.
	WebhookEvents []string `json:"webhook_events,omitempty"`
	// WebhookActive is false once auto-disabled after repeated failures; nil
	// without a webhook.
	WebhookActive *bool `json:"webhook_active,omitempty"`
	// WebhookSecret is the per-app webhook signing secret, returned exactly
	// once (first set, or rotated).
	WebhookSecret string `json:"webhook_secret,omitempty"`
	// WebhookPreviousSecretExpiresAt is, while a webhook secret rotation
	// overlap is open, when the previous secret stops signing (epoch ms).
	WebhookPreviousSecretExpiresAt *int64 `json:"webhook_previous_secret_expires_at,omitempty"`
	// PreviousSecretExpiresAt is, after a client secret rotation with an
	// overlap, when the previous secret stops working (epoch ms).
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at,omitempty"`
	// SecretIssuedAt is when the current client secret was issued (epoch ms);
	// nil for a public app.
	SecretIssuedAt *int64 `json:"secret_issued_at,omitempty"`
	// OverlapSeconds is, on a rotation, the overlap applied.
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
	// TestMode is whether test sign-in mode is on: +atlas_test addresses on a
	// verified domain sign in to this app with the fixed code 424242.
	TestMode bool `json:"test_mode"`
	// ProvisionedVerifiedDomainsOnly restricts test and review accounts to
	// addresses on a domain you verified.
	ProvisionedVerifiedDomainsOnly bool `json:"provisioned_verified_domains_only"`

	ProvisioningFields

	// ButtonRenderedOrigins are the page origins the Sign in with Atlas button
	// script ran on in the last 7 days (Get only).
	ButtonRenderedOrigins []AtlasIDOriginSeen `json:"button_rendered_origins,omitempty"`
	// AuthorizeRequests7d counts how the last 7 days' sign-ins started.
	AuthorizeRequests7d *AtlasIDAuthorizeSources `json:"authorize_requests_7d,omitempty"`
	// FallbackOrigins are origins of sign-ins that came through the no-script
	// fallback link (?atlasid_fallback=1).
	FallbackOrigins []AtlasIDOriginSeen `json:"fallback_origins,omitempty"`
	// HomepageIncludesScript is whether the app's homepage references the
	// button script (nil = could not check).
	HomepageIncludesScript *bool `json:"homepage_includes_script,omitempty"`
}

// AtlasIDOriginSeen is a page origin the button (or the fallback link) was
// seen on.
type AtlasIDOriginSeen struct {
	Origin     string `json:"origin"`
	LastSeenAt int64  `json:"last_seen_at"`
	Requests   int    `json:"requests"`
}

// AtlasIDAuthorizeSources counts how sign-ins started: the rendered button,
// the script API, One Tap, the no-script fallback, or unmarked.
type AtlasIDAuthorizeSources struct {
	Button   int `json:"button"`
	JS       int `json:"js"`
	FedCM    int `json:"fedcm"`
	Fallback int `json:"fallback"`
	Unmarked int `json:"unmarked"`
}

// AtlasIDAppBranding is how the Sign in with Atlas page and consent screen look
// for an app.
type AtlasIDAppBranding struct {
	// Theme is auto, light or dark.
	Theme             string  `json:"theme"`
	AccentColor       *string `json:"accent_color"`
	BackgroundColor   *string `json:"background_color"`
	PrivacyPolicyURL  *string `json:"privacy_policy_url"`
	TermsOfServiceURL *string `json:"terms_of_service_url"`
	// Design is the stored design override (nil = none).
	Design *Design `json:"design"`
	// ResolvedDesign is what the page renders with.
	ResolvedDesign *ResolvedDesign `json:"resolved_design,omitempty"`
	Copy           AtlasIDAppCopy  `json:"copy"`
}

// AtlasIDAppCopy is the page text. Nil means the default.
type AtlasIDAppCopy struct {
	SignInTitle    *string `json:"sign_in_title,omitempty"`
	SignInSubtitle *string `json:"sign_in_subtitle,omitempty"`
	SignUpTitle    *string `json:"sign_up_title,omitempty"`
	SignUpSubtitle *string `json:"sign_up_subtitle,omitempty"`
	ConsentMessage *string `json:"consent_message,omitempty"`
	SupportURL     *string `json:"support_url,omitempty"`
	SupportLabel   *string `json:"support_label,omitempty"`
}

// AtlasIDAppList is the list of Sign in with Atlas apps plus the issuer and
// discovery URL relying parties use.
type AtlasIDAppList struct {
	Object       string       `json:"object"`
	Data         []AtlasIDApp `json:"data"`
	Issuer       string       `json:"issuer"`
	DiscoveryURL string       `json:"discovery_url"`
	Limit        int          `json:"limit"`
}

// AtlasIDAppBrandingParams sets an app's branding. On update each field merges
// with what is stored; put a key in Clear to send null and reset it (for
// example "accent_color", "design" or "copy").
type AtlasIDAppBrandingParams struct {
	// Theme is auto, light or dark.
	Theme             string `json:"theme,omitempty"`
	AccentColor       string `json:"accent_color,omitempty"`
	BackgroundColor   string `json:"background_color,omitempty"`
	PrivacyPolicyURL  string `json:"privacy_policy_url,omitempty"`
	TermsOfServiceURL string `json:"terms_of_service_url,omitempty"`
	// Design is merged like a design PATCH over what is stored (a nil value
	// inside removes a setting).
	Design DesignPatch `json:"design,omitempty"`
	// Copy is the page text; an empty string or nil uses the default. "{app}"
	// is replaced with the app name.
	Copy *AtlasIDAppCopyParams `json:"copy,omitempty"`
	// Clear lists branding keys to reset (sent as null).
	Clear []string `json:"-"`
}

// MarshalJSON adds the Clear keys as nulls.
func (p AtlasIDAppBrandingParams) MarshalJSON() ([]byte, error) {
	type plain AtlasIDAppBrandingParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// AtlasIDAppCopyParams sets page text. Put a key in Clear to reset it.
type AtlasIDAppCopyParams struct {
	SignInTitle    string   `json:"sign_in_title,omitempty"`
	SignInSubtitle string   `json:"sign_in_subtitle,omitempty"`
	SignUpTitle    string   `json:"sign_up_title,omitempty"`
	SignUpSubtitle string   `json:"sign_up_subtitle,omitempty"`
	ConsentMessage string   `json:"consent_message,omitempty"`
	SupportURL     string   `json:"support_url,omitempty"`
	SupportLabel   string   `json:"support_label,omitempty"`
	Clear          []string `json:"-"`
}

// MarshalJSON adds the Clear keys as nulls.
func (p AtlasIDAppCopyParams) MarshalJSON() ([]byte, error) {
	type plain AtlasIDAppCopyParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// CreateAtlasIDAppParams is the body of POST /v1/platform/atlas_id_apps.
type CreateAtlasIDAppParams struct {
	Name string `json:"name"`
	// RedirectURIs are exact-match https URLs (http://localhost allowed).
	RedirectURIs []string `json:"redirect_uris"`
	// PostLogoutRedirectURIs are where /oauth2/logout may send the user after
	// sign-out (https, or http on a loopback host).
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// BackchannelLogoutURI receives a signed logout_token (form field
	// `logout_token`) when the user signs out of Atlas. Verify it with
	// NewLogoutTokenVerifier.
	BackchannelLogoutURI             string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required,omitempty"`
	// FrontchannelLogoutURI is loaded in a hidden iframe on the Atlas sign-out
	// page, with iss (and sid when session-required).
	FrontchannelLogoutURI             string                    `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool                      `json:"frontchannel_logout_session_required,omitempty"`
	LogoURL                           string                    `json:"logo_url,omitempty"`
	HomepageURL                       string                    `json:"homepage_url,omitempty"`
	AllowedScopes                     []string                  `json:"allowed_scopes,omitempty"`
	Branding                          *AtlasIDAppBrandingParams `json:"branding,omitempty"`
	// Type is confidential (the default; a client_secret is returned once) or
	// public (PKCE, no secret).
	Type string `json:"type,omitempty"`
	ProvisioningInput
}

// UpdateAtlasIDAppParams is the body of PATCH /v1/platform/atlas_id_apps/:id.
// Unset fields are left alone. An empty (non-nil) PostLogoutRedirectURIs slice
// clears them; a pointer to "" clears a logout URI. Clear lists top-level keys
// to send as null (e.g. "logo_url", "branding").
type UpdateAtlasIDAppParams struct {
	Name                              string                    `json:"name,omitempty"`
	RedirectURIs                      []string                  `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs            []string                  `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI              *string                   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  *bool                     `json:"backchannel_logout_session_required,omitempty"`
	FrontchannelLogoutURI             *string                   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired *bool                     `json:"frontchannel_logout_session_required,omitempty"`
	AllowedScopes                     []string                  `json:"allowed_scopes,omitempty"`
	LogoURL                           *string                   `json:"logo_url,omitempty"`
	HomepageURL                       *string                   `json:"homepage_url,omitempty"`
	Branding                          *AtlasIDAppBrandingParams `json:"branding,omitempty"`
	// WebhookURL sets the per-app webhook (public https): user.updated,
	// user.deleted and grant.revoked for this app's users. The first set
	// returns WebhookSecret once. Put "webhook_url" in Clear to remove it.
	WebhookURL *string  `json:"webhook_url,omitempty"`
	Clear      []string `json:"-"`
	// TestMode turns test sign-in mode on or off for this app. Turning it on
	// needs a verified domain (422 DOMAIN_NOT_VERIFIED). While on, anyone who
	// knows the +atlas_test pattern can sign in as such an address on your
	// verified domain without reading mail: a risk you opt into.
	TestMode *bool `json:"test_mode,omitempty"`
	// ProvisionedVerifiedDomainsOnly requires test and review accounts to use
	// an address on a domain you verified.
	ProvisionedVerifiedDomainsOnly *bool `json:"provisioned_verified_domains_only,omitempty"`
	// Metadata replaces the provisioning tags.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MarshalJSON omits a nil PostLogoutRedirectURIs (an empty slice clears) and
// adds the Clear keys as nulls.
func (p UpdateAtlasIDAppParams) MarshalJSON() ([]byte, error) {
	type plain UpdateAtlasIDAppParams
	raw, err := marshalWithExtra(plain(p), nullKeys(p.Clear))
	if err != nil || p.PostLogoutRedirectURIs != nil {
		return raw, err
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if string(m["post_logout_redirect_uris"]) == "null" && !contains(p.Clear, "post_logout_redirect_uris") {
		delete(m, "post_logout_redirect_uris")
	}
	return json.Marshal(m)
}

func nullKeys(keys []string) map[string]interface{} {
	if len(keys) == 0 {
		return nil
	}
	m := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		m[k] = nil
	}
	return m
}

// AtlasIDAppDesignPreviewParams is the body of
// POST /v1/platform/atlas_id_apps/design/preview.
type AtlasIDAppDesignPreviewParams struct {
	Design Design `json:"design"`
}

// List returns the account's Sign in with Atlas apps with the issuer and
// discovery URL. GET /v1/platform/atlas_id_apps.
func (s *AtlasIDAppsService) List(ctx context.Context) (*AtlasIDAppList, error) {
	out := &AtlasIDAppList{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps", nil, out)
}

// Create registers a Sign in with Atlas app. A confidential app's ClientSecret
// is returned exactly once. POST /v1/platform/atlas_id_apps.
func (s *AtlasIDAppsService) Create(ctx context.Context, params CreateAtlasIDAppParams, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps", params, out, opts...)
}

// Get fetches one app, including UserCount. GET /v1/platform/atlas_id_apps/:id.
func (s *AtlasIDAppsService) Get(ctx context.Context, id string) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id), nil, out)
}

// Update changes an app; the type cannot change.
// PATCH /v1/platform/atlas_id_apps/:id.
func (s *AtlasIDAppsService) Update(ctx context.Context, id string, params UpdateAtlasIDAppParams, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPatch(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes an app; its client_id stops working at once.
// DELETE /v1/platform/atlas_id_apps/:id.
func (s *AtlasIDAppsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.platDel(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id), out, opts...)
}

// RotateSecret rotates a confidential app's client secret; the new one is in
// ClientSecret and the previous one keeps working for 24 hours.
// POST /v1/platform/atlas_id_apps/:id/rotate_secret.
func (s *AtlasIDAppsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
}

// RotateSecretWithParams rotates the client secret with a chosen overlap (0
// revokes the previous one now). POST /v1/platform/atlas_id_apps/:id/rotate_secret.
func (s *AtlasIDAppsService) RotateSecretWithParams(ctx context.Context, id string, params RotateAtlasIDAppSecretParams, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/rotate_secret", params, out, opts...)
}

// PreviewDesign compiles a Sign in with Atlas page design without saving it.
// POST /v1/platform/atlas_id_apps/design/preview.
func (s *AtlasIDAppsService) PreviewDesign(ctx context.Context, design Design, opts ...RequestOption) (*DesignPreview, error) {
	out := &DesignPreview{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/design/preview", AtlasIDAppDesignPreviewParams{Design: design}, out, opts...)
}

// --- Platform design images -------------------------------------------------

// PlatformDesignAssetsService is /v1/platform/design/assets: images owned by
// the platform's account, for Sign in with Atlas app designs.
type PlatformDesignAssetsService struct{ client *Client }

// Upload stores an image (PNG, JPEG, GIF or WebP). kind is "background" (the
// default when empty) or "logo"; an empty contentType is detected from the
// bytes. POST /v1/platform/design/assets.
func (s *PlatformDesignAssetsService) Upload(ctx context.Context, image []byte, contentType, kind string, opts ...RequestOption) (*DesignAsset, error) {
	return uploadDesignAsset(ctx, s.client, authPlatform, "/v1/platform/design/assets", image, contentType, kind, opts...)
}

// List returns the account's design images, newest first.
// GET /v1/platform/design/assets.
func (s *PlatformDesignAssetsService) List(ctx context.Context) (*DesignAssetList, error) {
	out := &DesignAssetList{}
	return out, s.client.platGet(ctx, "/v1/platform/design/assets", nil, out)
}

// Delete removes an image; refused with 409 while an app design uses it.
// DELETE /v1/platform/design/assets/:id.
func (s *PlatformDesignAssetsService) Delete(ctx context.Context, assetID string, opts ...RequestOption) (*DesignAssetDeleted, error) {
	out := &DesignAssetDeleted{}
	return out, s.client.platDel(ctx, "/v1/platform/design/assets/"+url.PathEscape(assetID), out, opts...)
}

// ---- provisioning additions --------------------------------------------------

// ListWithMetadata returns the account's Sign in with Atlas apps whose
// provisioning metadata matches every pair. GET /v1/platform/atlas_id_apps.
func (s *AtlasIDAppsService) ListWithMetadata(ctx context.Context, metadata map[string]interface{}) (*AtlasIDAppList, error) {
	out := &AtlasIDAppList{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps", MetadataQuery(metadata), out)
}

// SecretKeysWithMetadata lists an app's secret keys whose provisioning
// metadata matches every pair. GET /v1/platform/apps/:id/secret_keys.
func (s *PlatformAppsService) SecretKeysWithMetadata(ctx context.Context, id string, metadata map[string]interface{}) (*ListPage[PlatformSecretKey], error) {
	out := &ListPage[PlatformSecretKey]{}
	return out, s.client.platGet(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/secret_keys", MetadataQuery(metadata), out)
}

// CreatePlatformSecretKeyParams is the body of POST /v1/platform/apps/:id/secret_keys.
type CreatePlatformSecretKeyParams struct {
	Name string `json:"name,omitempty"`
	// InstanceID is any instance of the same app (default the app's own).
	InstanceID string `json:"instance_id,omitempty"`
	ProvisioningInput
}

// CreatedPlatformSecretKey is a minted secret key. Secret is present only on a
// fresh create (never on an idempotent replay).
type CreatedPlatformSecretKey struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	PlatformSecretKey
	AppID      string `json:"app_id"`
	InstanceID string `json:"instance_id"`
	Secret     string `json:"secret,omitempty"`
	Note       string `json:"note,omitempty"`
}

// CreateSecretKey mints an additional named, taggable secret key for an app
// (shown once; an external_ref makes it idempotent). Pass WithIdempotencyKey.
// POST /v1/platform/apps/:id/secret_keys.
func (s *PlatformAppsService) CreateSecretKey(ctx context.Context, id string, params CreatePlatformSecretKeyParams, opts ...RequestOption) (*CreatedPlatformSecretKey, error) {
	out := &CreatedPlatformSecretKey{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/secret_keys", params, out, opts...)
}

// CloneConfigParams is the body of POST /v1/platform/apps/:id/clone_config.
type CloneConfigParams struct {
	// ToEnvironment is development (default) or production.
	ToEnvironment    string `json:"to_environment,omitempty"`
	TargetInstanceID string `json:"target_instance_id,omitempty"`
	// Sections are auth_config, allowed_origins, roles, redirect_urls (default
	// auth_config, roles, redirect_urls).
	Sections       []string `json:"sections,omitempty"`
	IncludeOrigins bool     `json:"include_origins,omitempty"`
	DryRun         bool     `json:"dry_run,omitempty"`
}

// CloneConfigExcluded is a path that was not copied, and why (secret or
// instance_specific).
type CloneConfigExcluded struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// CloneConfigResult is the answer to a config clone.
type CloneConfigResult struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	// Object is clone_config_result, or dry_run.
	Object           string                `json:"object"`
	SourceInstanceID string                `json:"source_instance_id"`
	TargetInstanceID *string               `json:"target_instance_id"`
	ToEnvironment    string                `json:"to_environment"`
	CreatedTarget    bool                  `json:"created_target"`
	Sections         []string              `json:"sections"`
	Excluded         []CloneConfigExcluded `json:"excluded"`
	NeverCopied      []string              `json:"never_copied"`
	Changes          []DryRunChange        `json:"changes"`
	Target           *PlatformApp          `json:"target,omitempty"`
	// Secret is, when a new instance was created for the clone, its secret
	// key, shown once.
	Secret string `json:"secret,omitempty"`
	Note   string `json:"note,omitempty"`
}

// CloneConfig copies an app's configuration into its development (or another)
// instance, secrets excluded. Pass WithIdempotencyKey.
// POST /v1/platform/apps/:id/clone_config.
func (s *PlatformAppsService) CloneConfig(ctx context.Context, id string, params CloneConfigParams, opts ...RequestOption) (*CloneConfigResult, error) {
	out := &CloneConfigResult{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/clone_config", params, out, opts...)
}

// SandboxTeardown hard-deletes every sandbox-tagged app and resource of this
// platform. metadata must carry sandbox: true (nil = {"sandbox": true});
// dryRun lists what would go. POST /v1/platform/apps/bulk_delete.
func (s *PlatformAppsService) SandboxTeardown(ctx context.Context, metadata map[string]interface{}, dryRun bool, opts ...RequestOption) (*PlatformAppsBulkDeleteResult, error) {
	if metadata == nil {
		metadata = map[string]interface{}{"sandbox": true}
	}
	body := map[string]interface{}{"metadata": metadata}
	if dryRun {
		body["dry_run"] = true
	}
	out := &PlatformAppsBulkDeleteResult{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/bulk_delete", body, out, opts...)
}

// ---- platform credentials & account audit ------------------------------------

// PlatformKeysService is /v1/platform/keys.
type PlatformKeysService struct{ client *Client }

// ListPlatformKeysParams filters GET /v1/platform/keys.
type ListPlatformKeysParams struct {
	// Kind is secret_key, platform_key, account_key, webhook_secret,
	// partner_link or access_token.
	Kind string
	// Status is active, expiring, expired or revoked.
	Status     string
	InstanceID string
}

// CreatePlatformKeyParams is the body of POST /v1/platform/keys. Scopes are a
// subset of the caller's; per-app grant scopes
// atlas_id_apps:<app id>:grants:read|write are allowed.
type CreatePlatformKeyParams struct {
	Scopes         []string `json:"scopes"`
	Name           string   `json:"name,omitempty"`
	ApplicationIDs []string `json:"application_ids,omitempty"`
	ExpiresAt      *int64   `json:"expires_at,omitempty"`
	IPAllowlist    []string `json:"ip_allowlist,omitempty"`
	// AllowedOrigins locks the key to browser origins; a call from another
	// origin is refused with ORIGIN_NOT_ALLOWED.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	// KeyFormat is atlas (default) or legacy.
	KeyFormat string `json:"key_format,omitempty"`
}

// PlatformAPIKey is a platform key; Secret / SealedSecret are present once.
type PlatformAPIKey struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object       string   `json:"object"`
	ID           string   `json:"id"`
	Prefix       string   `json:"prefix,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Secret       string   `json:"secret,omitempty"`
	SealedSecret string   `json:"sealed_secret,omitempty"`
}

// UpdatePlatformKeyParams is the body of PATCH /v1/platform/keys/:id. Clear
// names nullable fields to send as null: name, owner, expires_at.
type UpdatePlatformKeyParams struct {
	Name      string `json:"name,omitempty"`
	Owner     string `json:"owner,omitempty"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	// AllowedOrigins replaces the browser-origin lock.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Clear          []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdatePlatformKeyParams) MarshalJSON() ([]byte, error) {
	type plain UpdatePlatformKeyParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// PlatformKeyRevoked acknowledges a revocation.
type PlatformKeyRevoked struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Revoked bool   `json:"revoked"`
}

// Whoami introspects the platform key / token this client uses.
// GET /v1/platform/whoami.
func (s *PlatformService) Whoami(ctx context.Context) (*Whoami, error) {
	out := &Whoami{}
	return out, s.client.platGet(ctx, "/v1/platform/whoami", nil, out)
}

// List returns every credential on the account, revoked ones included.
// GET /v1/platform/keys.
func (s *PlatformKeysService) List(ctx context.Context, params ListPlatformKeysParams) (*ListPage[StandardKey], error) {
	out := &ListPage[StandardKey]{}
	q := url.Values{}
	if params.Kind != "" {
		q.Set("kind", params.Kind)
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	if params.InstanceID != "" {
		q.Set("instance_id", params.InstanceID)
	}
	return out, s.client.platGet(ctx, "/v1/platform/keys", q, out)
}

// Create mints a platform key; the secret is in this response only.
// POST /v1/platform/keys.
func (s *PlatformKeysService) Create(ctx context.Context, params CreatePlatformKeyParams, opts ...RequestOption) (*PlatformAPIKey, error) {
	out := &PlatformAPIKey{}
	return out, s.client.platPost(ctx, "/v1/platform/keys", params, out, opts...)
}

// Update changes a key's name, owner or expiry. PATCH /v1/platform/keys/:id.
func (s *PlatformKeysService) Update(ctx context.Context, id string, params UpdatePlatformKeyParams, opts ...RequestOption) (*PlatformAPIKey, error) {
	out := &PlatformAPIKey{}
	return out, s.client.platPatch(ctx, "/v1/platform/keys/"+url.PathEscape(id), params, out, opts...)
}

// Revoke revokes a key at once. POST /v1/platform/keys/:id/revoke.
func (s *PlatformKeysService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*PlatformKeyRevoked, error) {
	out := &PlatformKeyRevoked{}
	return out, s.client.platPost(ctx, "/v1/platform/keys/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}

// AccountAuditRecord is one entry of the account audit log.
type AccountAuditRecord struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	AccountID string `json:"account_id"`
	Actor     struct {
		Type string  `json:"type"`
		ID   *string `json:"id"`
	} `json:"actor"`
	Action string `json:"action"`
	Target struct {
		Type *string `json:"type"`
		ID   *string `json:"id"`
	} `json:"target"`
	InstanceID *string                `json:"instance_id"`
	IP         *string                `json:"ip"`
	UserAgent  *string                `json:"user_agent"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  int64                  `json:"created_at"`
}

// AccountAuditStream forwards the account audit log to a URL.
type AccountAuditStream struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Object string `json:"object"`
	ID     string `json:"id"`
	URL    string `json:"url"`
	// Format is atlas or cloudevents.
	Format              string  `json:"format"`
	Active              bool    `json:"active"`
	HasSecret           bool    `json:"has_secret"`
	Cursor              *string `json:"cursor"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	FailingSince        *int64  `json:"failing_since"`
	NextAttemptAt       *int64  `json:"next_attempt_at"`
	LastDeliveredAt     *int64  `json:"last_delivered_at"`
	LastError           *string `json:"last_error"`
	CreatedAt           int64   `json:"created_at"`
	UpdatedAt           int64   `json:"updated_at"`
	// Secret / SealedSecret are present once, on create.
	Secret       string `json:"secret,omitempty"`
	SealedSecret string `json:"sealed_secret,omitempty"`
}

// CreateAccountAuditStreamParams is the body of POST /v1/platform/audit_streams.
type CreateAccountAuditStreamParams struct {
	URL string `json:"url"`
	// Format is atlas (default) or cloudevents.
	Format string `json:"format,omitempty"`
}

// UpdateAccountAuditStreamParams is the body of PATCH /v1/platform/audit_streams/:id.
type UpdateAccountAuditStreamParams struct {
	URL    string `json:"url,omitempty"`
	Format string `json:"format,omitempty"`
	Active *bool  `json:"active,omitempty"`
}

// AccountAuditStreamTest is the answer to a test send.
type AccountAuditStreamTest struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Status *int   `json:"status"`
	Error  string `json:"error,omitempty"`
}

// ListAccountAuditParams filters GET /v1/platform/audit_logs.
type ListAccountAuditParams struct {
	ListParams
	Action string
}

// PlatformAuditService is the account audit log and its streams.
type PlatformAuditService struct {
	client  *Client
	Streams *PlatformAuditStreamsService
}

// List returns one page of the account audit log. GET /v1/platform/audit_logs.
func (s *PlatformAuditService) List(ctx context.Context, params ListAccountAuditParams) (*CursorPage[AccountAuditRecord], error) {
	out := &CursorPage[AccountAuditRecord]{}
	q := params.ListParams.values()
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	return out, s.client.platGet(ctx, "/v1/platform/audit_logs", q, out)
}

// PlatformAuditStreamsService is /v1/platform/audit_streams.
type PlatformAuditStreamsService struct{ client *Client }

// List returns the streams. GET /v1/platform/audit_streams.
func (s *PlatformAuditStreamsService) List(ctx context.Context) (*ListPage[AccountAuditStream], error) {
	out := &ListPage[AccountAuditStream]{}
	return out, s.client.platGet(ctx, "/v1/platform/audit_streams", nil, out)
}

// Create adds a stream; its signing secret is in this response only.
// POST /v1/platform/audit_streams.
func (s *PlatformAuditStreamsService) Create(ctx context.Context, params CreateAccountAuditStreamParams, opts ...RequestOption) (*AccountAuditStream, error) {
	out := &AccountAuditStream{}
	return out, s.client.platPost(ctx, "/v1/platform/audit_streams", params, out, opts...)
}

// Update changes a stream. PATCH /v1/platform/audit_streams/:id.
func (s *PlatformAuditStreamsService) Update(ctx context.Context, id string, params UpdateAccountAuditStreamParams, opts ...RequestOption) (*AccountAuditStream, error) {
	out := &AccountAuditStream{}
	return out, s.client.platPatch(ctx, "/v1/platform/audit_streams/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes a stream. DELETE /v1/platform/audit_streams/:id.
func (s *PlatformAuditStreamsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.platDel(ctx, "/v1/platform/audit_streams/"+url.PathEscape(id), out, opts...)
}

// Test sends one synthetic event. POST /v1/platform/audit_streams/:id/test.
func (s *PlatformAuditStreamsService) Test(ctx context.Context, id string, opts ...RequestOption) (*AccountAuditStreamTest, error) {
	out := &AccountAuditStreamTest{}
	return out, s.client.platPost(ctx, "/v1/platform/audit_streams/"+url.PathEscape(id)+"/test", nil, out, opts...)
}
