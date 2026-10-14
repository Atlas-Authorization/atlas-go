package atlas

import (
	"context"
	"encoding/json"
	"net/url"
)

// OrgPolicy is an organization's security policy, typed. Keys this SDK does not
// model yet are kept in Extra.
type OrgPolicy struct {
	// RequireMFA requires an MFA-verified session to hold the org active.
	RequireMFA *bool `json:"requireMfa,omitempty"`
	// SSORequired forces enterprise SSO for identifiers in the org's verified
	// domains.
	SSORequired *bool `json:"ssoRequired,omitempty"`
	// SessionIdleOverrideMS overrides the session idle window while the org is
	// active, in milliseconds.
	SessionIdleOverrideMS *int64 `json:"sessionIdleOverrideMs,omitempty"`
	// AllowedSignInMethods restricts which sign-in methods a member may use
	// (e.g. "password", "passkey", "oauth", "oauth:google", "saml",
	// "magic_link"). Empty means every method.
	AllowedSignInMethods []string `json:"allowedSignInMethods,omitempty"`
	// IPAllowlist is a CIDR allow-list gating member sign-in. Empty means
	// unrestricted.
	IPAllowlist []string `json:"ipAllowlist,omitempty"`
	// MaxSessionAgeSeconds caps the absolute session lifetime for members
	// (300 … 7776000).
	MaxSessionAgeSeconds *int64 `json:"maxSessionAgeSeconds,omitempty"`
	// EndUserPool configures the org's end-user (reader) pool.
	EndUserPool *OrgEndUserPoolPolicy `json:"endUserPool,omitempty"`

	// Extra holds policy keys not modelled above.
	Extra map[string]interface{} `json:"-"`
}

// OrgEndUserPoolPolicy is the org's end-user (reader) pool configuration.
type OrgEndUserPoolPolicy struct {
	Enabled bool `json:"enabled"`
	// RequireApproval seats a new reader as pending until an org admin approves.
	RequireApproval *bool `json:"requireApproval,omitempty"`
	// AllowHostedSignup lets readers self-serve through the hosted sign-up.
	AllowHostedSignup *bool `json:"allowHostedSignup,omitempty"`
}

var orgPolicyKnownKeys = []string{
	"requireMfa", "ssoRequired", "sessionIdleOverrideMs", "allowedSignInMethods",
	"ipAllowlist", "maxSessionAgeSeconds", "endUserPool",
}

// UnmarshalJSON decodes the typed keys and keeps the rest in Extra.
func (p *OrgPolicy) UnmarshalJSON(data []byte) error {
	type plain OrgPolicy
	var v plain
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	extra, err := unknownKeys(data, orgPolicyKnownKeys...)
	if err != nil {
		return err
	}
	*p = OrgPolicy(v)
	p.Extra = extra
	return nil
}

// MarshalJSON encodes the typed keys plus Extra.
func (p OrgPolicy) MarshalJSON() ([]byte, error) {
	type plain OrgPolicy
	return marshalWithExtra(plain(p), p.Extra)
}

// OrgPolicyPatch is a partial policy update: set fields are merged into the
// stored policy, unset fields are left alone. Clear lists keys to remove
// (sent as null), e.g. []string{"ipAllowlist"}. Extra sends keys this SDK does
// not model yet.
type OrgPolicyPatch struct {
	RequireMFA            *bool                 `json:"requireMfa,omitempty"`
	SSORequired           *bool                 `json:"ssoRequired,omitempty"`
	SessionIdleOverrideMS *int64                `json:"sessionIdleOverrideMs,omitempty"`
	AllowedSignInMethods  []string              `json:"allowedSignInMethods,omitempty"`
	IPAllowlist           []string              `json:"ipAllowlist,omitempty"`
	MaxSessionAgeSeconds  *int64                `json:"maxSessionAgeSeconds,omitempty"`
	EndUserPool           *OrgEndUserPoolPolicy `json:"endUserPool,omitempty"`

	Clear []string               `json:"-"`
	Extra map[string]interface{} `json:"-"`
}

// MarshalJSON encodes the set fields, the Clear keys as null, and Extra.
func (p OrgPolicyPatch) MarshalJSON() ([]byte, error) {
	type plain OrgPolicyPatch
	extra := nullKeys(p.Clear)
	if extra == nil && len(p.Extra) > 0 {
		extra = map[string]interface{}{}
	}
	for k, v := range p.Extra {
		extra[k] = v
	}
	return marshalWithExtra(plain(p), extra)
}

// OrgPolicyResult is the policy after an update.
type OrgPolicyResult struct {
	Object         string    `json:"object"`
	OrganizationID string    `json:"organization_id"`
	Policy         OrgPolicy `json:"policy"`
}

// SetPolicy patches an organization's security policy with typed fields.
// PATCH /v1/organizations/:id/policy.
func (s *OrganizationsService) SetPolicy(ctx context.Context, id string, patch OrgPolicyPatch, opts ...RequestOption) (*OrgPolicyResult, error) {
	out := &OrgPolicyResult{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id)+"/policy", patch, out, opts...)
}
