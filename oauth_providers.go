package atlas

import (
	"context"
	"net/url"
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
	Native           bool                           `json:"native"`
	RedirectURI      string                         `json:"redirect_uri"`
	Configured       bool                           `json:"configured"`
	ClientID         *string                        `json:"client_id"`
	HasSecret        bool                           `json:"has_secret"`
	Enabled          bool                           `json:"enabled"`
	AllowSignIn      bool                           `json:"allow_sign_in"`
	AllowSignUp      bool                           `json:"allow_sign_up"`
	Scopes           []string                       `json:"scopes"`
	UpdatedAt        *int64                         `json:"updated_at"`
}

// UpsertOAuthProviderParams are credentials for the redirect code-exchange flow.
// ClientSecret is write-only.
type UpsertOAuthProviderParams struct {
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Values       map[string]string `json:"values,omitempty"`
	Settings     map[string]string `json:"settings,omitempty"`
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

// Get returns one provider. GET /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Get(ctx context.Context, provider string) (*OAuthProvider, error) {
	out := &OAuthProvider{}
	return out, s.client.get(ctx, "/v1/oauth_providers/"+url.PathEscape(provider), nil, out)
}

// Upsert sets (or replaces) this instance's credentials for a provider.
// PUT /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Upsert(ctx context.Context, provider string, params UpsertOAuthProviderParams, opts ...RequestOption) (*OAuthProviderUpsertResult, error) {
	out := &OAuthProviderUpsertResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_providers/"+url.PathEscape(provider), nil, params, out, opts...)
}

// Delete clears a provider's credentials. DELETE /v1/oauth_providers/:provider.
func (s *OAuthProvidersService) Delete(ctx context.Context, provider string) (*OAuthProviderDeleteResult, error) {
	out := &OAuthProviderDeleteResult{}
	return out, s.client.del(ctx, "/v1/oauth_providers/"+url.PathEscape(provider), out)
}

// SetEnabled turns a configured provider on or off.
// POST /v1/oauth_providers/:provider/enabled.
func (s *OAuthProvidersService) SetEnabled(ctx context.Context, provider string, enabled bool) (*OAuthProviderEnabledResult, error) {
	out := &OAuthProviderEnabledResult{}
	body := map[string]bool{"enabled": enabled}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/enabled", body, out)
}

// SetScope sets which screens a provider serves. At least one must be true.
// POST /v1/oauth_providers/:provider/scope.
func (s *OAuthProvidersService) SetScope(ctx context.Context, provider string, allowSignIn, allowSignUp bool) (*OAuthProviderScopeResult, error) {
	out := &OAuthProviderScopeResult{}
	body := map[string]bool{"allow_sign_in": allowSignIn, "allow_sign_up": allowSignUp}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/scope", body, out)
}

// Test verifies stored credentials against the provider's token endpoint.
// POST /v1/oauth_providers/:provider/test.
func (s *OAuthProvidersService) Test(ctx context.Context, provider string) (*OAuthConnectionTest, error) {
	out := &OAuthConnectionTest{}
	return out, s.client.post(ctx, "/v1/oauth_providers/"+url.PathEscape(provider)+"/test", nil, out)
}
