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
	// FlowsTurnedOff lists the captcha flows a forced delete switched off.
	FlowsTurnedOff []string `json:"flows_turned_off,omitempty"`
}

// SetCaptchaSecretParams are the options of SetCaptchaSecretWithParams.
type SetCaptchaSecretParams struct {
	Secret string `json:"secret"`
	// Provider names the captcha provider the secret belongs to (defaults to the
	// configured one). Captcha is bring-your-own-keys: store the secret before
	// turning captcha on.
	Provider string `json:"provider,omitempty"`
}

// DeleteCaptchaSecretParams are the options of DeleteCaptchaSecretWithParams.
type DeleteCaptchaSecretParams struct {
	// Provider names the captcha provider whose secret to remove (defaults to the
	// configured one).
	Provider string
	// Force removes a secret a captcha flow uses (otherwise 409 CAPTCHA_IN_USE)
	// and turns those flows off.
	Force bool
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
func (s *InstanceSecurityService) Update(ctx context.Context, params UpdateInstanceSecurityParams, opts ...RequestOption) (*InstanceSecurityResult, error) {
	out := &InstanceSecurityResult{}
	return out, s.client.patch(ctx, "/v1/instance/security", params, out, opts...)
}

// SetCaptchaSecret stores the captcha provider secret.
// PUT /v1/instance/captcha_secret.
func (s *InstanceSecurityService) SetCaptchaSecret(ctx context.Context, secret string, opts ...RequestOption) (*CaptchaSecretResult, error) {
	out := &CaptchaSecretResult{}
	body := map[string]string{"secret": secret}
	return out, s.client.put(ctx, "/v1/instance/captcha_secret", body, out, opts...)
}

// SetCaptchaSecretWithParams stores the captcha secret for a named provider,
// so it can be stored before captcha is turned on.
// PUT /v1/instance/captcha_secret.
func (s *InstanceSecurityService) SetCaptchaSecretWithParams(ctx context.Context, params SetCaptchaSecretParams, opts ...RequestOption) (*CaptchaSecretResult, error) {
	out := &CaptchaSecretResult{}
	return out, s.client.put(ctx, "/v1/instance/captcha_secret", params, out, opts...)
}

// DeleteCaptchaSecret removes the captcha secret. DELETE /v1/instance/captcha_secret.
//
// Refused with 409 CAPTCHA_IN_USE (ErrCodeCaptchaInUse) while a captcha flow
// uses the secret; use DeleteCaptchaSecretWithParams with Force to remove it
// anyway.
func (s *InstanceSecurityService) DeleteCaptchaSecret(ctx context.Context, opts ...RequestOption) (*CaptchaSecretResult, error) {
	return s.DeleteCaptchaSecretWithParams(ctx, DeleteCaptchaSecretParams{}, opts...)
}

// DeleteCaptchaSecretWithParams is DeleteCaptchaSecret with options (?provider=,
// ?force=true). DELETE /v1/instance/captcha_secret.
func (s *InstanceSecurityService) DeleteCaptchaSecretWithParams(ctx context.Context, params DeleteCaptchaSecretParams, opts ...RequestOption) (*CaptchaSecretResult, error) {
	q := url.Values{}
	if params.Provider != "" {
		q.Set("provider", params.Provider)
	}
	if params.Force {
		q.Set("force", "true")
	}
	out := &CaptchaSecretResult{}
	return out, s.client.delQ(ctx, "/v1/instance/captcha_secret", q, out, opts...)
}

// SetKerberosSecret stores the Kerberos/IWA trusted-proxy secret.
// PUT /v1/instance/kerberos_secret.
func (s *InstanceSecurityService) SetKerberosSecret(ctx context.Context, secret string, opts ...RequestOption) (*KerberosSecretResult, error) {
	out := &KerberosSecretResult{}
	body := map[string]string{"secret": secret}
	return out, s.client.put(ctx, "/v1/instance/kerberos_secret", body, out, opts...)
}

// DeleteKerberosSecret removes the Kerberos secret.
// DELETE /v1/instance/kerberos_secret.
func (s *InstanceSecurityService) DeleteKerberosSecret(ctx context.Context, opts ...RequestOption) (*KerberosSecretResult, error) {
	out := &KerberosSecretResult{}
	return out, s.client.del(ctx, "/v1/instance/kerberos_secret", out, opts...)
}

// SetLDAPBindPassword stores an LDAP connection's bind password.
// PUT /v1/instance/ldap_connections/:connectionId/bind_password.
func (s *InstanceSecurityService) SetLDAPBindPassword(ctx context.Context, connectionID, bindPassword string, opts ...RequestOption) (*LDAPBindPasswordResult, error) {
	out := &LDAPBindPasswordResult{}
	body := map[string]string{"bind_password": bindPassword}
	return out, s.client.put(ctx, "/v1/instance/ldap_connections/"+url.PathEscape(connectionID)+"/bind_password", body, out, opts...)
}

// DeleteLDAPBindPassword removes an LDAP connection's bind password.
// DELETE /v1/instance/ldap_connections/:connectionId/bind_password.
func (s *InstanceSecurityService) DeleteLDAPBindPassword(ctx context.Context, connectionID string, opts ...RequestOption) (*LDAPBindPasswordResult, error) {
	out := &LDAPBindPasswordResult{}
	return out, s.client.del(ctx, "/v1/instance/ldap_connections/"+url.PathEscape(connectionID)+"/bind_password", out, opts...)
}
