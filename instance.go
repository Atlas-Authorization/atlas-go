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
