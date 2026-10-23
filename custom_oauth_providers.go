package atlas

import (
	"context"
	"net/url"
)

// CustomOAuthProvidersService is the /v1/custom_oauth_providers namespace —
// your own upstream OAuth 2.0 / OpenID Connect login providers, with Atlas as
// the relying party. Configure the endpoints (or just an OIDC issuer), the
// token-endpoint client authentication (including private_key_jwt with an
// Atlas-held key), a declarative profile mapping, upstream logout and
// third-party initiated login. The provider then signs users in like any
// built-in one, under its provider_key.
type CustomOAuthProvidersService struct{ client *Client }

// Token-endpoint client authentication methods.
const (
	TokenEndpointAuthClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  = "client_secret_post"
	TokenEndpointAuthClientSecretJWT   = "client_secret_jwt"
	TokenEndpointAuthPrivateKeyJWT     = "private_key_jwt"
	TokenEndpointAuthNone              = "none"
)

// ProfileMappingExpr is a mapping expression: a claim path string
// ("email", "emails[0].value", "$id_token.sub"), a "{{template}}" string, or a
// rule object {from, template, value, transforms}. Use a string or a
// ProfileMappingRule.
type ProfileMappingExpr = interface{}

// ProfileMappingRule is the object form of a mapping expression. From is a
// path or a list of paths tried in order (the first non-empty wins); Value is
// a constant; Transforms are names ("lowercase", "trim", "first", …) or
// one-key objects ({"split": ","}, {"default": "x"}, …).
type ProfileMappingRule struct {
	From       interface{}   `json:"from,omitempty"`
	Template   string        `json:"template,omitempty"`
	Value      interface{}   `json:"value,omitempty"`
	Transforms []interface{} `json:"transforms,omitempty"`
}

// ProfileMapping maps an upstream profile onto an Atlas user. Fields keys are
// id, email, email_verified, first_name, last_name, full_name, username,
// image_url, phone_number and external_id. UpdateOnSignIn re-applies names,
// image and metadata on every sign-in (default: only at account creation).
type ProfileMapping struct {
	Fields          map[string]ProfileMappingExpr `json:"fields,omitempty"`
	PublicMetadata  map[string]ProfileMappingExpr `json:"public_metadata,omitempty"`
	PrivateMetadata map[string]ProfileMappingExpr `json:"private_metadata,omitempty"`
	UpdateOnSignIn  *bool                         `json:"update_on_sign_in,omitempty"`
}

// UpstreamLogoutSettings: RPInitiated hands back the provider's end-session
// URL on Atlas sign-out; Backchannel accepts OIDC Back-Channel Logout tokens;
// Frontchannel accepts OIDC Front-Channel Logout (FrontchannelSessionRequired,
// default true, requires iss + sid).
type UpstreamLogoutSettings struct {
	RPInitiated                 *bool   `json:"rp_initiated,omitempty"`
	PostLogoutRedirectURL       *string `json:"post_logout_redirect_url,omitempty"`
	Backchannel                 *bool   `json:"backchannel,omitempty"`
	Frontchannel                *bool   `json:"frontchannel,omitempty"`
	FrontchannelSessionRequired *bool   `json:"frontchannel_session_required,omitempty"`
	EndSessionEndpoint          *string `json:"end_session_endpoint,omitempty"`
}

// IdpInitiatedLoginSettings: third-party initiated login (OIDC Core §4).
// AllowedTargets are exact URLs or bare origins a login may land on.
type IdpInitiatedLoginSettings struct {
	Enabled        *bool    `json:"enabled,omitempty"`
	AllowedTargets []string `json:"allowed_targets,omitempty"`
	DefaultTarget  *string  `json:"default_target,omitempty"`
}

// UpstreamURLs are the URLs to register at the upstream provider.
type UpstreamURLs struct {
	ClientJWKSURI         string `json:"client_jwks_uri"`
	BackchannelLogoutURI  string `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	InitiateLoginURI      string `json:"initiate_login_uri"`
}

// UpstreamSigningKey is a private_key_jwt signing key Atlas holds for an
// upstream provider. Alg is RS256, PS256 or ES256; Status is active, retiring
// or retired.
type UpstreamSigningKey struct {
	Object    string                 `json:"object"`
	Kid       string                 `json:"kid"`
	Alg       string                 `json:"alg"`
	Status    string                 `json:"status"`
	PublicJWK map[string]interface{} `json:"public_jwk"`
	CreatedAt int64                  `json:"created_at"`
	RetiredAt *int64                 `json:"retired_at"`
}

// CustomOAuthProvider is a custom upstream provider. The client secret is
// never returned (HasSecret).
type CustomOAuthProvider struct {
	UpstreamURLs
	Object                  string                     `json:"object"`
	ID                      string                     `json:"id"`
	ProviderKey             string                     `json:"provider_key"`
	DisplayName             string                     `json:"display_name"`
	IconURL                 *string                    `json:"icon_url"`
	Protocol                string                     `json:"protocol"`
	Issuer                  *string                    `json:"issuer"`
	DiscoveryURL            *string                    `json:"discovery_url"`
	AuthorizationEndpoint   *string                    `json:"authorization_endpoint"`
	TokenEndpoint           *string                    `json:"token_endpoint"`
	UserinfoEndpoint        *string                    `json:"userinfo_endpoint"`
	JWKSURI                 *string                    `json:"jwks_uri"`
	EndSessionEndpoint      *string                    `json:"end_session_endpoint"`
	Scopes                  []string                   `json:"scopes"`
	ScopeSeparator          string                     `json:"scope_separator"`
	PKCE                    bool                       `json:"pkce"`
	AuthorizationParams     map[string]string          `json:"authorization_params"`
	TokenParams             map[string]string          `json:"token_params"`
	UserinfoAuth            string                     `json:"userinfo_auth"`
	TokenEndpointAuthMethod string                     `json:"token_endpoint_auth_method"`
	ClientAssertionAudience *string                    `json:"client_assertion_audience"`
	ProfileSource           string                     `json:"profile_source"`
	ProfileMapping          *ProfileMapping            `json:"profile_mapping"`
	Logout                  *UpstreamLogoutSettings    `json:"logout"`
	IdpInitiatedLogin       *IdpInitiatedLoginSettings `json:"idp_initiated_login"`
	ClientID                *string                    `json:"client_id"`
	HasSecret               bool                       `json:"has_secret"`
	Enabled                 bool                       `json:"enabled"`
	AllowSignIn             bool                       `json:"allow_sign_in"`
	AllowSignUp             bool                       `json:"allow_sign_up"`
	// RedirectURI is registered at the provider as the callback.
	RedirectURI string               `json:"redirect_uri"`
	SigningKeys []UpstreamSigningKey `json:"signing_keys"`
	CreatedAt   int64                `json:"created_at"`
	UpdatedAt   int64                `json:"updated_at"`
}

// CustomOAuthProviderParams is the body of create (POST, ProviderKey and
// DisplayName required) and update (PATCH). Protocol is "oidc" or "oauth2";
// ScopeSeparator " ", "," or "+"; UserinfoAuth "header" or "query";
// ProfileSource "merged", "userinfo" or "id_token". ClientSecret is
// write-only. Clear names settings to reset (sent as JSON null), e.g.
// "icon_url", "profile_mapping", "authorization_params".
type CustomOAuthProviderParams struct {
	ProviderKey             string                     `json:"provider_key,omitempty"`
	DisplayName             string                     `json:"display_name,omitempty"`
	IconURL                 string                     `json:"icon_url,omitempty"`
	Protocol                string                     `json:"protocol,omitempty"`
	Issuer                  string                     `json:"issuer,omitempty"`
	DiscoveryURL            string                     `json:"discovery_url,omitempty"`
	AuthorizationEndpoint   string                     `json:"authorization_endpoint,omitempty"`
	TokenEndpoint           string                     `json:"token_endpoint,omitempty"`
	UserinfoEndpoint        string                     `json:"userinfo_endpoint,omitempty"`
	JWKSURI                 string                     `json:"jwks_uri,omitempty"`
	EndSessionEndpoint      string                     `json:"end_session_endpoint,omitempty"`
	Scopes                  []string                   `json:"scopes,omitempty"`
	ScopeSeparator          string                     `json:"scope_separator,omitempty"`
	PKCE                    *bool                      `json:"pkce,omitempty"`
	AuthorizationParams     map[string]string          `json:"authorization_params,omitempty"`
	TokenParams             map[string]string          `json:"token_params,omitempty"`
	UserinfoAuth            string                     `json:"userinfo_auth,omitempty"`
	TokenEndpointAuthMethod string                     `json:"token_endpoint_auth_method,omitempty"`
	ClientAssertionAudience string                     `json:"client_assertion_audience,omitempty"`
	ProfileSource           string                     `json:"profile_source,omitempty"`
	ProfileMapping          *ProfileMapping            `json:"profile_mapping,omitempty"`
	Logout                  *UpstreamLogoutSettings    `json:"logout,omitempty"`
	IdpInitiatedLogin       *IdpInitiatedLoginSettings `json:"idp_initiated_login,omitempty"`
	ClientID                string                     `json:"client_id,omitempty"`
	ClientSecret            string                     `json:"client_secret,omitempty"`
	Enabled                 *bool                      `json:"enabled,omitempty"`
	AllowSignIn             *bool                      `json:"allow_sign_in,omitempty"`
	AllowSignUp             *bool                      `json:"allow_sign_up,omitempty"`
	Clear                   []string                   `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p CustomOAuthProviderParams) MarshalJSON() ([]byte, error) {
	type plain CustomOAuthProviderParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
}

// ProfileMappingPreviewParams is a sample to run a mapping against. IDToken
// is a sample id_token (decoded, not verified).
type ProfileMappingPreviewParams struct {
	ProfileMapping *ProfileMapping        `json:"profile_mapping,omitempty"`
	Userinfo       map[string]interface{} `json:"userinfo,omitempty"`
	IDTokenClaims  map[string]interface{} `json:"id_token_claims,omitempty"`
	IDToken        string                 `json:"id_token,omitempty"`
}

// ProfileMappingPreview is the mapped profile with a per-target trace and
// warnings.
type ProfileMappingPreview struct {
	Object  string `json:"object"`
	Profile struct {
		ID              *string                `json:"id"`
		Email           *string                `json:"email"`
		EmailVerified   bool                   `json:"email_verified"`
		FirstName       *string                `json:"first_name"`
		LastName        *string                `json:"last_name"`
		Username        *string                `json:"username"`
		ImageURL        *string                `json:"image_url"`
		PhoneNumber     *string                `json:"phone_number"`
		ExternalID      *string                `json:"external_id"`
		PublicMetadata  map[string]interface{} `json:"public_metadata"`
		PrivateMetadata map[string]interface{} `json:"private_metadata"`
	} `json:"profile"`
	Trace    map[string]ProfileMappingTrace `json:"trace"`
	Warnings []string                       `json:"warnings"`
}

// ProfileMappingTrace says where a mapped value came from.
type ProfileMappingTrace struct {
	Value  interface{} `json:"value"`
	Source *string     `json:"source"`
}

// OIDCDiscoveryResult is a fetched and validated OpenID configuration.
type OIDCDiscoveryResult struct {
	Object                            string   `json:"object"`
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  *string  `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                *string  `json:"end_session_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValues []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported"`
}

// DeletedCustomOAuthProvider acknowledges a delete.
type DeletedCustomOAuthProvider struct {
	Object      string `json:"object"`
	ID          string `json:"id"`
	ProviderKey string `json:"provider_key"`
	Deleted     bool   `json:"deleted"`
}

func customProviderPath(id string) string {
	return "/v1/custom_oauth_providers/" + url.PathEscape(id)
}

// List returns the custom providers. GET /v1/custom_oauth_providers.
func (s *CustomOAuthProvidersService) List(ctx context.Context) (*ListPage[CustomOAuthProvider], error) {
	out := &ListPage[CustomOAuthProvider]{}
	return out, s.client.get(ctx, "/v1/custom_oauth_providers", nil, out)
}

// Get returns one. GET /v1/custom_oauth_providers/:id.
func (s *CustomOAuthProvidersService) Get(ctx context.Context, id string) (*CustomOAuthProvider, error) {
	out := &CustomOAuthProvider{}
	return out, s.client.get(ctx, customProviderPath(id), nil, out)
}

// Create registers a provider (ProviderKey and DisplayName are required).
// POST /v1/custom_oauth_providers.
func (s *CustomOAuthProvidersService) Create(ctx context.Context, params CustomOAuthProviderParams, opts ...RequestOption) (*CustomOAuthProvider, error) {
	out := &CustomOAuthProvider{}
	return out, s.client.post(ctx, "/v1/custom_oauth_providers", params, out, opts...)
}

// Update patches a provider. PATCH /v1/custom_oauth_providers/:id.
func (s *CustomOAuthProvidersService) Update(ctx context.Context, id string, params CustomOAuthProviderParams, opts ...RequestOption) (*CustomOAuthProvider, error) {
	out := &CustomOAuthProvider{}
	return out, s.client.patch(ctx, customProviderPath(id), params, out, opts...)
}

// Delete removes a provider. DELETE /v1/custom_oauth_providers/:id.
func (s *CustomOAuthProvidersService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedCustomOAuthProvider, error) {
	out := &DeletedCustomOAuthProvider{}
	return out, s.client.del(ctx, customProviderPath(id), out, opts...)
}

// Discover fetches and validates an issuer's OpenID configuration (for
// autofill). discoveryURL may be empty. POST /v1/custom_oauth_providers/discover.
func (s *CustomOAuthProvidersService) Discover(ctx context.Context, issuer, discoveryURL string, opts ...RequestOption) (*OIDCDiscoveryResult, error) {
	body := map[string]string{"issuer": issuer}
	if discoveryURL != "" {
		body["discovery_url"] = discoveryURL
	}
	out := &OIDCDiscoveryResult{}
	return out, s.client.post(ctx, "/v1/custom_oauth_providers/discover", body, out, opts...)
}

// PreviewProfileMapping runs a mapping against a pasted sample. With a
// non-empty id the provider's stored mapping is used unless params carries
// one. POST /v1/custom_oauth_providers[/:id]/profile_mapping/preview.
func (s *CustomOAuthProvidersService) PreviewProfileMapping(ctx context.Context, id string, params ProfileMappingPreviewParams, opts ...RequestOption) (*ProfileMappingPreview, error) {
	path := "/v1/custom_oauth_providers/profile_mapping/preview"
	if id != "" {
		path = customProviderPath(id) + "/profile_mapping/preview"
	}
	out := &ProfileMappingPreview{}
	return out, s.client.post(ctx, path, params, out, opts...)
}

// SigningKeys are the provider's private_key_jwt signing keys.
func (s *CustomOAuthProvidersService) SigningKeys(id string) *UpstreamSigningKeysService {
	return &UpstreamSigningKeysService{client: s.client, base: customProviderPath(id)}
}

// UpstreamSigningKeysService manages the private_key_jwt keys of one custom
// provider or OIDC SSO connection. The public halves are published at the
// provider's client_jwks_uri.
type UpstreamSigningKeysService struct {
	client *Client
	base   string
}

// List returns the keys. GET …/signing_keys.
func (s *UpstreamSigningKeysService) List(ctx context.Context) (*ListPage[UpstreamSigningKey], error) {
	out := &ListPage[UpstreamSigningKey]{}
	return out, s.client.get(ctx, s.base+"/signing_keys", nil, out)
}

// Rotate generates a new active key (alg RS256, PS256 or ES256; empty for the
// default); the previous one turns retiring and stays published.
// POST …/signing_keys.
func (s *UpstreamSigningKeysService) Rotate(ctx context.Context, alg string, opts ...RequestOption) (*UpstreamSigningKey, error) {
	body := map[string]string{}
	if alg != "" {
		body["alg"] = alg
	}
	out := &UpstreamSigningKey{}
	return out, s.client.post(ctx, s.base+"/signing_keys", body, out, opts...)
}

// Retire retires a non-active key (it leaves the JWKS).
// POST …/signing_keys/:kid/retire.
func (s *UpstreamSigningKeysService) Retire(ctx context.Context, kid string, opts ...RequestOption) (*UpstreamSigningKey, error) {
	out := &UpstreamSigningKey{}
	return out, s.client.post(ctx, s.base+"/signing_keys/"+url.PathEscape(kid)+"/retire", nil, out, opts...)
}
