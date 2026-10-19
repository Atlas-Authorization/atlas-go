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
	Environment    string   `json:"environment"`
	PublishableKey string   `json:"publishable_key"`
	AllowedOrigins []string `json:"allowed_origins"`
	Tags           []string `json:"tags"`
	// Archived hides the app from the default listing; it still serves auth.
	Archived   bool   `json:"archived"`
	ArchivedAt *int64 `json:"archived_at"`
	Disabled   bool   `json:"disabled"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	// Note is an explanatory message some responses add.
	Note string `json:"note,omitempty"`
}

// PlatformAppWithSecret is a PlatformApp plus its reveal-once secret key.
type PlatformAppWithSecret struct {
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
}

// UpdatePlatformAppParams is the body of PATCH /v1/platform/apps/:id.
type UpdatePlatformAppParams struct {
	Name           string   `json:"name,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// ListPlatformAppsParams filters GET /v1/platform/apps. Archived apps are
// hidden unless IncludeArchived or Archived is set.
type ListPlatformAppsParams struct {
	IncludeArchived bool
	// Archived lists only archived apps.
	Archived bool
	Tag      string
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
	Object  string `json:"object"`
	Results []struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
		Reason  string `json:"reason,omitempty"`
	} `json:"results"`
}

// PlatformAppSecretRotation is the result of rotating an app's secret with
// overlap: the new secret (revealed once) and when the prior keys expire.
type PlatformAppSecretRotation struct {
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
	Object    string `json:"object"`
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt *int64 `json:"expires_at"`
}

// PlatformInstanceSecret is the result of rotating one instance's secret.
type PlatformInstanceSecret struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Note   string `json:"note"`
}

// CreatePlatformInstanceParams is the body of
// POST /v1/platform/apps/:id/instances.
type CreatePlatformInstanceParams struct {
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
}

// CreateAccountlessAppParams is the body of POST /v1/platform/accountless_apps.
type CreateAccountlessAppParams struct {
	Name           string   `json:"name,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
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

// RotateInstanceSecret revokes one instance's keys and mints a new secret.
// POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret.
func (s *PlatformAppsService) RotateInstanceSecret(ctx context.Context, id, instanceID string, opts ...RequestOption) (*PlatformInstanceSecret, error) {
	out := &PlatformInstanceSecret{}
	return out, s.client.platPost(ctx, "/v1/platform/apps/"+url.PathEscape(id)+"/instances/"+url.PathEscape(instanceID)+"/rotate_secret", nil, out, opts...)
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
type AtlasIDAppsService struct{ client *Client }

// AtlasIDApp is a registered Sign in with Atlas app. It never carries the
// client secret except on create and rotate (ClientSecret).
type AtlasIDApp struct {
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
	CreatedAt           int64   `json:"created_at"`
	UpdatedAt           int64   `json:"updated_at"`
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
