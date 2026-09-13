package atlas

import "context"

// ManagedWAFService is the /v1/managed_waf namespace — the self-service control
// plane for Atlas's managed AWS WAF captcha gate. Secrets are write-only.
type ManagedWAFService struct{ client *Client }

// ManagedWAFCredential is credential config with secrets reduced to has_* markers.
type ManagedWAFCredential struct {
	Mode               string  `json:"mode"`
	AccessKeyID        *string `json:"access_key_id"`
	HasSecretAccessKey bool    `json:"has_secret_access_key"`
	RoleARN            *string `json:"role_arn"`
	HasExternalID      bool    `json:"has_external_id"`
}

// ManagedWAF is the §5 Managed AWS WAF config + provisioning state.
type ManagedWAF struct {
	Object                   string                `json:"object"`
	Configured               bool                  `json:"configured"`
	Enabled                  bool                  `json:"enabled"`
	Status                   string                `json:"status"`
	Scope                    string                `json:"scope,omitempty"`
	Region                   string                `json:"region,omitempty"`
	WebACLName               string                `json:"web_acl_name,omitempty"`
	EdgeResourceARN          *string               `json:"edge_resource_arn,omitempty"`
	CloudfrontDistributionID *string               `json:"cloudfront_distribution_id,omitempty"`
	TokenDomains             []string              `json:"token_domains,omitempty"`
	GatedPaths               []string              `json:"gated_paths,omitempty"`
	ImmunitySeconds          int                   `json:"immunity_seconds,omitempty"`
	Credential               *ManagedWAFCredential `json:"credential,omitempty"`
	WebACLID                 *string               `json:"web_acl_id,omitempty"`
	WebACLARN                *string               `json:"web_acl_arn,omitempty"`
	LastError                *string               `json:"last_error,omitempty"`
	LastProvisionedAt        *int64                `json:"last_provisioned_at,omitempty"`
	UpdatedAt                int64                 `json:"updated_at,omitempty"`
}

// ManagedWAFStatus is just the provisioning state.
type ManagedWAFStatus struct {
	Object            string  `json:"object"`
	Enabled           bool    `json:"enabled"`
	Status            string  `json:"status"`
	WebACLID          *string `json:"web_acl_id"`
	WebACLARN         *string `json:"web_acl_arn"`
	LastError         *string `json:"last_error"`
	LastProvisionedAt *int64  `json:"last_provisioned_at"`
}

// ManagedWAFOutcome is the fail-safe result of a provision/deprovision.
type ManagedWAFOutcome struct {
	ManagedWAF
	OK    bool    `json:"ok"`
	Error *string `json:"error"`
}

// ManagedWAFCredentialInput carries the write-only credential fields.
type ManagedWAFCredentialInput struct {
	Mode            string  `json:"mode,omitempty"`
	AccessKeyID     *string `json:"access_key_id,omitempty"`
	SecretAccessKey *string `json:"secret_access_key,omitempty"`
	RoleARN         *string `json:"role_arn,omitempty"`
	ExternalID      *string `json:"external_id,omitempty"`
}

// UpdateManagedWAFParams is the body of PUT /v1/managed_waf.
type UpdateManagedWAFParams struct {
	Enabled                  *bool                      `json:"enabled,omitempty"`
	Scope                    string                     `json:"scope,omitempty"`
	Region                   string                     `json:"region,omitempty"`
	WebACLName               string                     `json:"web_acl_name,omitempty"`
	EdgeResourceARN          *string                    `json:"edge_resource_arn,omitempty"`
	CloudfrontDistributionID *string                    `json:"cloudfront_distribution_id,omitempty"`
	TokenDomains             []string                   `json:"token_domains,omitempty"`
	GatedPaths               []string                   `json:"gated_paths,omitempty"`
	ImmunitySeconds          *int                       `json:"immunity_seconds,omitempty"`
	Credential               *ManagedWAFCredentialInput `json:"credential,omitempty"`
}

// Get reads config + provisioning state, secrets reduced to has_* markers.
// GET /v1/managed_waf.
func (s *ManagedWAFService) Get(ctx context.Context) (*ManagedWAF, error) {
	out := &ManagedWAF{}
	return out, s.client.get(ctx, "/v1/managed_waf", nil, out)
}

// Status reads just the provisioning state. GET /v1/managed_waf/status.
func (s *ManagedWAFService) Status(ctx context.Context) (*ManagedWAFStatus, error) {
	out := &ManagedWAFStatus{}
	return out, s.client.get(ctx, "/v1/managed_waf/status", nil, out)
}

// Update sets config and write-only credentials. PUT /v1/managed_waf.
func (s *ManagedWAFService) Update(ctx context.Context, params UpdateManagedWAFParams) (*ManagedWAF, error) {
	out := &ManagedWAF{}
	return out, s.client.put(ctx, "/v1/managed_waf", params, out)
}

// Provision applies now (idempotent create/update + associate the WebACL).
// POST /v1/managed_waf/provision.
func (s *ManagedWAFService) Provision(ctx context.Context) (*ManagedWAFOutcome, error) {
	out := &ManagedWAFOutcome{}
	return out, s.client.post(ctx, "/v1/managed_waf/provision", nil, out)
}

// Deprovision disassociates and deletes the WebACL.
// POST /v1/managed_waf/deprovision.
func (s *ManagedWAFService) Deprovision(ctx context.Context) (*ManagedWAFOutcome, error) {
	out := &ManagedWAFOutcome{}
	return out, s.client.post(ctx, "/v1/managed_waf/deprovision", nil, out)
}
