package atlas

import (
	"context"
	"net/url"
)

// InstanceSecurityService is the /v1/instance/security namespace — the agent
// mirror of the dashboard security screen: per-flow kill switches, the customer
// IP allowlist, and the write-only provider secrets. No secret is readable back.
type InstanceSecurityService struct{ client *Client }

// InstanceKillSwitches are the per-instance flow kill switches.
type InstanceKillSwitches struct {
	DisableSignUps    *bool    `json:"disableSignUps,omitempty"`
	DisableSignIns    *bool    `json:"disableSignIns,omitempty"`
	ForceChallenge    *bool    `json:"forceChallenge,omitempty"`
	DisabledProviders []string `json:"disabledProviders,omitempty"`
}

// InstanceSecurity is the security config.
type InstanceSecurity struct {
	Object       string               `json:"object"`
	KillSwitches InstanceKillSwitches `json:"kill_switches"`
	IPAllowlist  []string             `json:"ip_allowlist"`
}

// UpdateInstanceSecurityParams is the body of PATCH /v1/instance/security.
type UpdateInstanceSecurityParams struct {
	KillSwitches *InstanceKillSwitches `json:"kill_switches,omitempty"`
	IPAllowlist  []string              `json:"ip_allowlist,omitempty"`
	// ConfirmLockout is required to set an allowlist that omits the caller's own
	// IP — which would lock this management API out irreversibly.
	ConfirmLockout *bool `json:"confirm_lockout,omitempty"`
}

// InstanceSecurityResult adds a plain-language warning on a confirmed lockout.
type InstanceSecurityResult struct {
	InstanceSecurity
	Warning string `json:"warning,omitempty"`
}

// CaptchaSecretResult acknowledges a captcha secret set/delete.
type CaptchaSecretResult struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Set      bool   `json:"set,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// KerberosSecretResult acknowledges a Kerberos secret set/delete.
type KerberosSecretResult struct {
	Object  string `json:"object"`
	Set     bool   `json:"set,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// LDAPBindPasswordResult acknowledges an LDAP bind-password set/delete.
type LDAPBindPasswordResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	Set          bool   `json:"set,omitempty"`
	Deleted      bool   `json:"deleted,omitempty"`
}

// Get reads the security config. GET /v1/instance/security.
func (s *InstanceSecurityService) Get(ctx context.Context) (*InstanceSecurity, error) {
	out := &InstanceSecurity{}
	return out, s.client.get(ctx, "/v1/instance/security", nil, out)
}

// Update patches the security config. PATCH /v1/instance/security.
func (s *InstanceSecurityService) Update(ctx context.Context, params UpdateInstanceSecurityParams) (*InstanceSecurityResult, error) {
	out := &InstanceSecurityResult{}
	return out, s.client.patch(ctx, "/v1/instance/security", params, out)
}

// SetCaptchaSecret stores the captcha provider secret.
// PUT /v1/instance/captcha_secret.
func (s *InstanceSecurityService) SetCaptchaSecret(ctx context.Context, secret string) (*CaptchaSecretResult, error) {
	out := &CaptchaSecretResult{}
	body := map[string]string{"secret": secret}
	return out, s.client.put(ctx, "/v1/instance/captcha_secret", body, out)
}

// DeleteCaptchaSecret removes the captcha secret. DELETE /v1/instance/captcha_secret.
func (s *InstanceSecurityService) DeleteCaptchaSecret(ctx context.Context) (*CaptchaSecretResult, error) {
	out := &CaptchaSecretResult{}
	return out, s.client.del(ctx, "/v1/instance/captcha_secret", out)
}

// SetKerberosSecret stores the Kerberos/IWA trusted-proxy secret.
// PUT /v1/instance/kerberos_secret.
func (s *InstanceSecurityService) SetKerberosSecret(ctx context.Context, secret string) (*KerberosSecretResult, error) {
	out := &KerberosSecretResult{}
	body := map[string]string{"secret": secret}
	return out, s.client.put(ctx, "/v1/instance/kerberos_secret", body, out)
}

// DeleteKerberosSecret removes the Kerberos secret.
// DELETE /v1/instance/kerberos_secret.
func (s *InstanceSecurityService) DeleteKerberosSecret(ctx context.Context) (*KerberosSecretResult, error) {
	out := &KerberosSecretResult{}
	return out, s.client.del(ctx, "/v1/instance/kerberos_secret", out)
}

// SetLDAPBindPassword stores an LDAP connection's bind password.
// PUT /v1/instance/ldap_connections/:connectionId/bind_password.
func (s *InstanceSecurityService) SetLDAPBindPassword(ctx context.Context, connectionID, bindPassword string) (*LDAPBindPasswordResult, error) {
	out := &LDAPBindPasswordResult{}
	body := map[string]string{"bind_password": bindPassword}
	return out, s.client.put(ctx, "/v1/instance/ldap_connections/"+url.PathEscape(connectionID)+"/bind_password", body, out)
}

// DeleteLDAPBindPassword removes an LDAP connection's bind password.
// DELETE /v1/instance/ldap_connections/:connectionId/bind_password.
func (s *InstanceSecurityService) DeleteLDAPBindPassword(ctx context.Context, connectionID string) (*LDAPBindPasswordResult, error) {
	out := &LDAPBindPasswordResult{}
	return out, s.client.del(ctx, "/v1/instance/ldap_connections/"+url.PathEscape(connectionID)+"/bind_password", out)
}
