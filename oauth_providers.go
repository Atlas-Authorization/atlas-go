package atlas

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// OAuthProvidersService is the /v1/oauth_providers namespace — the social
// sign-in provider catalog + this instance's configuration for each. Secrets are
// write-only; a read reports only HasSecret.
type OAuthProvidersService struct{ client *Client }

// OAuthProviderCredentialField is one credential input a provider needs.
type OAuthProviderCredentialField struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Secret    bool   `json:"secret,omitempty"`
	Multiline bool   `json:"multiline,omitempty"`
	Optional  bool   `json:"optional,omitempty"`
	Help      string `json:"help,omitempty"`
}

// OAuthProviderSetting is a provider-specific option beyond credentials.
type OAuthProviderSetting struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Options []string `json:"options,omitempty"`
	Help    string   `json:"help,omitempty"`
}

// OAuthProvider is a single social sign-in provider row: the catalog entry plus
// whatever is configured for this instance, and never the secret.
type OAuthProvider struct {
	Object           string                         `json:"object"`
	Provider         string                         `json:"provider"`
	DisplayName      string                         `json:"display_name"`
	Category         string                         `json:"category"`
	Tier             string                         `json:"tier"`
	SetupDocsURL     *string                        `json:"setup_docs_url"`
	DefaultScopes    []string                       `json:"default_scopes"`
	CredentialFields []OAuthProviderCredentialField `json:"credential_fields"`
	Settings         []OAuthProviderSetting         `json:"settings"`
	// APIScopes are extra scopes the provider offers for API access.
	APIScopes []string `json:"api_scopes,omitempty"`
	// SettingValues are the stored verifier settings of a credential-less
	// wallet provider (siwe, siws, siwf), e.g. domain, chain_ids, rpc_url.
	// Empty for every other provider.
	SettingValues map[string]string `json:"setting_values,omitempty"`
	Native        bool              `json:"native"`
	// Mode is the effective sign-in mode: native or redirect.
	Mode string `json:"mode,omitempty"`
	// JavaScriptOrigins are, for native providers, the origins to register on
	// the provider console.
	JavaScriptOrigins []string `json:"javascript_origins,omitempty"`
	RedirectURI       string   `json:"redirect_uri"`
	// AtlasCallback is Atlas's own callback URL; a CustomRedirectURI forwards
	// to it.
	AtlasCallback     string   `json:"atlas_callback,omitempty"`
	CustomRedirectURI *string  `json:"custom_redirect_uri,omitempty"`
	Configured        bool     `json:"configured"`
	ClientID          *string  `json:"client_id"`
	HasSecret         bool     `json:"has_secret"`
	Enabled           bool     `json:"enabled"`
	AllowSignIn       bool     `json:"allow_sign_in"`
	AllowSignUp       bool     `json:"allow_sign_up"`
	Scopes            []string `json:"scopes"`
	// IconURL is the instance's icon override for the button, or nil.
	IconURL   *string `json:"icon_url,omitempty"`
	UpdatedAt *int64  `json:"updated_at"`
}

// ListOAuthProvidersParams narrows GET /v1/oauth_providers.
type ListOAuthProvidersParams struct {
	// Providers keeps only these catalogue keys (exact match, e.g. "google").
	Providers []string
	// Configured, when set, keeps only providers whose credentials are (true)
	// or are not (false) stored.
	Configured *bool
}

func (p ListOAuthProvidersParams) values() url.Values {
	v := url.Values{}
	if len(p.Providers) > 0 {
		v.Set("provider", strings.Join(p.Providers, ","))
	}
	if p.Configured != nil {
		v.Set("configured", strconv.FormatBool(*p.Configured))
	}
	return v
}

// UpsertOAuthProviderParams sets a provider's credentials and/or re-brands its
// button. ClientSecret is write-only. Display fields (DisplayName, IconURL,
// Mode) need no credentials; credential-less providers (steam, siwe, siws,
// siwf) take only display fields and, for the wallets, Settings.
type UpsertOAuthProviderParams struct {
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Values       map[string]string `json:"values,omitempty"`
	// Settings are non-secret provider settings. For the wallet providers they
	// are the verifier settings — siwe: domain, chain_ids ("1,10"), rpc_url;
	// siws: domain, networks; siwf: domain, chain_ids, optimism_rpc_url,
	// id_registry_address. An empty string clears one.
	Settings map[string]string `json:"settings,omitempty"`
	// SettingsJSON is merged over Settings for values that are not strings: a
	// nil value is sent as JSON null (clears the setting) and slices such as
	// chain_ids []int{1, 10} are sent as arrays. See WalletSettings.
	SettingsJSON      map[string]interface{} `json:"-"`
	CustomRedirectURI string                 `json:"custom_redirect_uri,omitempty"`
	Native            *bool                  `json:"native,omitempty"`
	// Mode forces "native" or "redirect"; a pointer to "" clears the override.
	Mode *string `json:"mode,omitempty"`
	// DisplayName is the brand shown on the button; a pointer to "" clears it.
	DisplayName *string `json:"display_name,omitempty"`
	// IconURL is an http(s) or data:image icon URL; a pointer to "" clears it.
	IconURL *string `json:"icon_url,omitempty"`
}

// MarshalJSON merges SettingsJSON into settings.
func (p UpsertOAuthProviderParams) MarshalJSON() ([]byte, error) {
	type plain UpsertOAuthProviderParams
	if len(p.SettingsJSON) == 0 {
		return marshalWithExtra(plain(p), nil)
	}
	settings := map[string]interface{}{}
	for k, v := range p.Settings {
		settings[k] = v
	}
	for k, v := range p.SettingsJSON {
		settings[k] = v
	}
	return marshalWithExtra(plain(p), map[string]interface{}{"settings": settings})
}

// WalletSettings are the verifier settings of the wallet sign-in providers.
// Set only the fields the provider takes (siwe: Domain, ChainIDs, RPCURL;
// siws: Domain, Networks; siwf: Domain, ChainIDs, OptimismRPCURL,
// IDRegistryAddress) and pass Map() as UpsertOAuthProviderParams.SettingsJSON.
// Clear names setting keys to reset (sent as null).
type WalletSettings struct {
	Domain            string
	ChainIDs          []int
	RPCURL            string
	Networks          []string
	OptimismRPCURL    string
	IDRegistryAddress string
	Clear             []string
}

// Map renders the settings as the settings object the API expects.
func (w WalletSettings) Map() map[string]interface{} {
	m := map[string]interface{}{}
	if w.Domain != "" {
		m["domain"] = w.Domain
	}
	if len(w.ChainIDs) > 0 {
		m["chain_ids"] = w.ChainIDs
	}
	if w.RPCURL != "" {
		m["rpc_url"] = w.RPCURL
	}
	if len(w.Networks) > 0 {
		m["networks"] = strings.Join(w.Networks, ",")
	}
	if w.OptimismRPCURL != "" {
		m["optimism_rpc_url"] = w.OptimismRPCURL
	}
	if w.IDRegistryAddress != "" {
		m["id_registry_address"] = w.IDRegistryAddress
	}
	for _, k := range w.Clear {
		m[k] = nil
	}
	return m
}

// OAuthConnectionTest is the connectivity test's honest verdict.
type OAuthConnectionTest struct {
	Object     string   `json:"object"`
	Provider   string   `json:"provider"`
	OK         bool     `json:"ok"`
	Reason     string   `json:"reason"`
	Message    string   `json:"message"`
	Checked    []string `json:"checked"`
	NotChecked []string `json:"not_checked"`
}

// OAuthProviderUpsertResult acknowledges an upsert.
type OAuthProviderUpsertResult struct {
	Object     string `json:"object"`
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	// SettingValues are a wallet provider's verifier settings after the write.
	SettingValues map[string]string `json:"setting_values,omitempty"`
	UpdatedFields []string          `json:"updated_fields"`
	Warning       string            `json:"warning,omitempty"`
}

// OAuthProviderDeleteResult acknowledges a provider deletion.
type OAuthProviderDeleteResult struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Deleted  bool   `json:"deleted"`
	Note     string `json:"note"`
}

// OAuthProviderEnabledResult acknowledges an enable/disable toggle.
type OAuthProviderEnabledResult struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
}

// OAuthProviderScopeResult acknowledges a screen-scope change.
type OAuthProviderScopeResult struct {
	Object      string `json:"object"`
	Provider    string `json:"provider"`
	AllowSignIn bool   `json:"allow_sign_in"`
	AllowSignUp bool   `json:"allow_sign_up"`
}

// List returns the whole catalog, configured or not. GET /v1/oauth_providers.
func (s *OAuthProvidersService) List(ctx context.Context) (*ListPage[OAuthProvider], error) {
	out := &ListPage[OAuthProvider]{}
	return out, s.client.get(ctx, "/v1/oauth_providers", nil, out)
}

// ListFiltered returns the catalog narrowed by provider key and/or configured
// state. GET /v1/oauth_providers?provider=&configured=.
func (s *OAuthProvidersService) ListFiltered(ctx context.Context, params ListOAuthProvidersParams) (*ListPage[OAuthProvider], error) {
	out := &ListPage[OAuthProvider]{}
	return out, s.client.get(ctx, "/v1/oauth_providers", params.values(), out)
}

// Get returns one provider. GET /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Get(ctx context.Context, provider string) (*OAuthProvider, error) {
	out := &OAuthProvider{}
	return out, s.client.get(ctx, "/v1/oauth_providers/"+url.PathEscape(provider), nil, out)
}

// Upsert sets (or replaces) this instance's credentials for a provider.
// PUT /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Upsert(ctx context.Context, provider string, params UpsertOAuthProviderParams, opts ...RequestOption) (*OAuthProviderUpsertResult, error) {
	out := &OAuthProviderUpsertResult{}
	return out, s.client.put(ctx, "/v1/oauth_providers/"+url.PathEscape(provider), params, out, opts...)
}

// Delete clears a provider's credentials. DELETE /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Delete(ctx context.Context, provider string, opts ...RequestOption) (*OAuthProviderDeleteResult, error) {
	out := &OAuthProviderDeleteResult{}
	return out, s.client.del(ctx, "/v1/oauth_providers/"+url.PathEscape(provider), out, opts...)
}

// SetEnabled turns a configured provider on or off.
// POST /v1/oauth_providers/:provider/enabled.
func (s *OAuthProvidersService) SetEnabled(ctx context.Context, provider string, enabled bool, opts ...RequestOption) (*OAuthProviderEnabledResult, error) {
	out := &OAuthProviderEnabledResult{}
	body := map[string]bool{"enabled": enabled}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/enabled", body, out, opts...)
}

// SetScope sets which screens a provider serves. At least one must be true.
// POST /v1/oauth_providers/:provider/scope.
func (s *OAuthProvidersService) SetScope(ctx context.Context, provider string, allowSignIn, allowSignUp bool, opts ...RequestOption) (*OAuthProviderScopeResult, error) {
	out := &OAuthProviderScopeResult{}
	body := map[string]bool{"allow_sign_in": allowSignIn, "allow_sign_up": allowSignUp}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/scope", body, out, opts...)
}

// Test verifies stored credentials against the provider's token endpoint.
// POST /v1/oauth_providers/:provider/test.
func (s *OAuthProvidersService) Test(ctx context.Context, provider string, opts ...RequestOption) (*OAuthConnectionTest, error) {
	out := &OAuthConnectionTest{}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/test", nil, out, opts...)
}
