package atlas

import "context"

// InstanceService is the /v1/instance namespace — §9.3 instance configuration.
// The signing private key is never returned. JWT templates live under their own
// JWTTemplates resource.
type InstanceService struct {
	client       *Client
	Integrations *InstanceIntegrationsService
}

// Instance is the tenant's environment configuration.
type Instance struct {
	Object          string `json:"object"`
	ID              string `json:"id"`
	Environment     string `json:"environment"`
	PublishableKey  string `json:"publishable_key"`
	FrontendAPIHost string `json:"frontend_api_host"`
	// Issuer is the iss the instance's session tokens carry. It changes when a
	// custom domain goes active, so read it (and the two URLs below) rather than
	// hard-coding it.
	Issuer string `json:"issuer,omitempty"`
	// DiscoveryURL is the OpenID discovery document whose issuer equals Issuer.
	DiscoveryURL string `json:"discovery_url,omitempty"`
	// JWKSURI is the JWKS holding the instance's signing keys.
	JWKSURI        string   `json:"jwks_uri,omitempty"`
	AllowedOrigins []string `json:"allowed_origins"`
	// AllowedOriginIntegrations is the declared integration per allowed origin
	// ("redirect" or "embedded"). An origin not listed is inferred.
	AllowedOriginIntegrations map[string]string `json:"allowed_origin_integrations,omitempty"`
	AuthConfig                Metadata          `json:"auth_config"`
	CreatedAt                 int64             `json:"created_at"`
}

// UpdateInstanceParams is the body of PATCH /v1/instance.
type UpdateInstanceParams struct {
	AllowedOrigins []string               `json:"allowed_origins,omitempty"`
	AuthConfig     map[string]interface{} `json:"auth_config,omitempty"`
	// AllowedOriginEntries, when set, is sent as allowed_origins instead of
	// AllowedOrigins: each entry also says how the origin signs in.
	AllowedOriginEntries []AllowedOriginEntry `json:"-"`
}

// MarshalJSON sends AllowedOriginEntries as allowed_origins when set.
func (p UpdateInstanceParams) MarshalJSON() ([]byte, error) {
	type plain UpdateInstanceParams
	return marshalWithExtra(plain(p), originEntriesExtra(p.AllowedOriginEntries))
}

// InstanceUpdateResult echoes only the mutable fields.
type InstanceUpdateResult struct {
	Object                    string            `json:"object"`
	ID                        string            `json:"id"`
	AllowedOrigins            []string          `json:"allowed_origins"`
	AllowedOriginIntegrations map[string]string `json:"allowed_origin_integrations,omitempty"`
	AuthConfig                Metadata          `json:"auth_config"`
	// Warnings is what the write did not do as sent: origin_still_referenced (a
	// removed origin URLs still point at) and, on a lenient write, unknown_field
	// (an auth_config key that was ignored and not stored).
	Warnings []InstanceUpdateWarning `json:"warnings,omitempty"`
}

// InstanceUpdateWarning is one entry of InstanceUpdateResult.Warnings.
type InstanceUpdateWarning struct {
	// Code is origin_still_referenced or unknown_field.
	Code    string `json:"code"`
	Message string `json:"message"`
	// Field is, for unknown_field, the full path (auth_config.strategies.x).
	Field string `json:"field,omitempty"`
	// Hint names the endpoint for a setting that has its own (branding: PATCH /v1/branding).
	Hint       string `json:"hint,omitempty"`
	DidYouMean string `json:"did_you_mean,omitempty"`
	// Origin is, for origin_still_referenced, the removed origin.
	Origin string `json:"origin,omitempty"`
}

// Get reads the instance config. GET /v1/instance.
func (s *InstanceService) Get(ctx context.Context) (*Instance, error) {
	out := &Instance{}
	return out, s.client.get(ctx, "/v1/instance", nil, out)
}

// Update patches the mutable instance config. PATCH /v1/instance.
func (s *InstanceService) Update(ctx context.Context, params UpdateInstanceParams, opts ...RequestOption) (*InstanceUpdateResult, error) {
	out := &InstanceUpdateResult{}
	return out, s.client.patch(ctx, "/v1/instance", params, out, opts...)
}

// SignInWithAtlasSettings is "Sign in with Atlas" on the instance.
type SignInWithAtlasSettings struct {
	Object string `json:"object"`
	// Enabled is whether the embedded and hosted sign-in show "Continue with Atlas".
	Enabled bool `json:"enabled"`
	// ConnectionID is the SSO connection the button starts; nil when off.
	ConnectionID *string `json:"connection_id"`
	// ManagedVia is instance_toggle (Atlas created the connection and its Atlas
	// ID app) or linked (an existing connection of yours); nil when off.
	ManagedVia       *string `json:"managed_via"`
	ConnectionStatus *string `json:"connection_status"`
	// Available is whether this deployment can offer Sign in with Atlas at all.
	Available bool `json:"available"`
	// Issuer is the Atlas issuer the connection must point at.
	Issuer *string `json:"issuer"`
	// Candidates are the active OIDC connections to that issuer that could be linked.
	Candidates []SignInWithAtlasCandidate `json:"candidates"`
}

// SignInWithAtlasCandidate is a connection that could back Sign in with Atlas.
type SignInWithAtlasCandidate struct {
	ID                    string  `json:"id"`
	ClientID              *string `json:"client_id"`
	ManagedByThisInstance bool    `json:"managed_by_this_instance"`
}

// UpdateSignInWithAtlasParams is the body of PATCH /v1/instance/sign_in_with_atlas.
// Enabled true links ConnectionID (an active OIDC connection to the Atlas
// issuer), or picks or creates one when it is empty.
type UpdateSignInWithAtlasParams struct {
	Enabled      bool   `json:"enabled"`
	ConnectionID string `json:"connection_id,omitempty"`
}

// GetSignInWithAtlas reads the Sign in with Atlas setting.
// GET /v1/instance/sign_in_with_atlas.
func (s *InstanceService) GetSignInWithAtlas(ctx context.Context) (*SignInWithAtlasSettings, error) {
	out := &SignInWithAtlasSettings{}
	return out, s.client.get(ctx, "/v1/instance/sign_in_with_atlas", nil, out)
}

// UpdateSignInWithAtlas turns Sign in with Atlas on or off.
// PATCH /v1/instance/sign_in_with_atlas.
func (s *InstanceService) UpdateSignInWithAtlas(ctx context.Context, params UpdateSignInWithAtlasParams, opts ...RequestOption) (*SignInWithAtlasSettings, error) {
	out := &SignInWithAtlasSettings{}
	return out, s.client.patch(ctx, "/v1/instance/sign_in_with_atlas", params, out, opts...)
}

// HostedPagesSettings is where the hosted pages send the browser. A set URL
// makes that hosted page answer 302 there; nil serves the hosted page.
type HostedPagesSettings struct {
	Object    string  `json:"object"`
	SignInURL *string `json:"sign_in_url"`
	SignUpURL *string `json:"sign_up_url"`
	UserURL   *string `json:"user_url"`
	// Hosted are the hosted pages these settings apply to.
	Hosted struct {
		SignIn string `json:"sign_in"`
		SignUp string `json:"sign_up"`
		User   string `json:"user"`
	} `json:"hosted"`
}

// UpdateHostedPagesParams is the body of PATCH /v1/instance/hosted_pages. Each
// URL is https on one of the instance's allowed origins. Clear lists the keys
// to send as null (sign_in_url, sign_up_url, user_url), which clears them.
type UpdateHostedPagesParams struct {
	SignInURL string   `json:"sign_in_url,omitempty"`
	SignUpURL string   `json:"sign_up_url,omitempty"`
	UserURL   string   `json:"user_url,omitempty"`
	Clear     []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdateHostedPagesParams) MarshalJSON() ([]byte, error) {
	type plain UpdateHostedPagesParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// GetHostedPages reads the hosted page redirects. GET /v1/instance/hosted_pages.
func (s *InstanceService) GetHostedPages(ctx context.Context) (*HostedPagesSettings, error) {
	out := &HostedPagesSettings{}
	return out, s.client.get(ctx, "/v1/instance/hosted_pages", nil, out)
}

// UpdateHostedPages sets or clears the hosted page redirects.
// PATCH /v1/instance/hosted_pages.
func (s *InstanceService) UpdateHostedPages(ctx context.Context, params UpdateHostedPagesParams, opts ...RequestOption) (*HostedPagesSettings, error) {
	out := &HostedPagesSettings{}
	return out, s.client.patch(ctx, "/v1/instance/hosted_pages", params, out, opts...)
}
