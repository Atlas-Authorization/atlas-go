package atlas

import "context"

// InstanceService is the /v1/instance namespace — §9.3 instance configuration.
// The signing private key is never returned. JWT templates live under their own
// JWTTemplates resource.
type InstanceService struct{ client *Client }

// Instance is the tenant's environment configuration.
type Instance struct {
	Object          string   `json:"object"`
	ID              string   `json:"id"`
	Environment     string   `json:"environment"`
	PublishableKey  string   `json:"publishable_key"`
	FrontendAPIHost string   `json:"frontend_api_host"`
	AllowedOrigins  []string `json:"allowed_origins"`
	AuthConfig      Metadata `json:"auth_config"`
	CreatedAt       int64    `json:"created_at"`
}

// UpdateInstanceParams is the body of PATCH /v1/instance.
type UpdateInstanceParams struct {
	AllowedOrigins []string               `json:"allowed_origins,omitempty"`
	AuthConfig     map[string]interface{} `json:"auth_config,omitempty"`
}

// InstanceUpdateResult echoes only the mutable fields.
type InstanceUpdateResult struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	AllowedOrigins []string `json:"allowed_origins"`
	AuthConfig     Metadata `json:"auth_config"`
}

// Get reads the instance config. GET /v1/instance.
func (s *InstanceService) Get(ctx context.Context) (*Instance, error) {
	out := &Instance{}
	return out, s.client.get(ctx, "/v1/instance", nil, out)
}

// Update patches the mutable instance config. PATCH /v1/instance.
func (s *InstanceService) Update(ctx context.Context, params UpdateInstanceParams) (*InstanceUpdateResult, error) {
	out := &InstanceUpdateResult{}
	return out, s.client.patch(ctx, "/v1/instance", params, out)
}
