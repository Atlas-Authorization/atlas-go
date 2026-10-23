package atlas

import "context"

// RateLimitPolicyService is the /v1/rate_limit_policy namespace — the two budgets
// layered over the built-in request limiter.
type RateLimitPolicyService struct{ client *Client }

// RateLimitBound is the min/max a single knob is clamped to on write.
type RateLimitBound struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// RateLimitPolicy is the per-instance rate-limit policy (§9.1).
type RateLimitPolicy struct {
	Object            string `json:"object"`
	FAPICreatePerMin  int    `json:"fapi_create_per_min"`
	BAPIPerMin        int    `json:"bapi_per_min"`
	FAPIVerifyPerMin  int    `json:"fapi_verify_per_min,omitempty"`
	LDAPPerIPPerMin   int    `json:"ldap_per_ip_per_min,omitempty"`
	LDAPPerUserPerMin int    `json:"ldap_per_user_per_min,omitempty"`
	Bounds            struct {
		FAPICreatePerMin  RateLimitBound `json:"fapi_create_per_min"`
		FAPIVerifyPerMin  RateLimitBound `json:"fapi_verify_per_min"`
		BAPIPerMin        RateLimitBound `json:"bapi_per_min"`
		LDAPPerIPPerMin   RateLimitBound `json:"ldap_per_ip_per_min"`
		LDAPPerUserPerMin RateLimitBound `json:"ldap_per_user_per_min"`
		RuleWindowSeconds RateLimitBound `json:"rule_window_seconds"`
		RuleMax           RateLimitBound `json:"rule_max"`
	} `json:"bounds"`
	// Rules are the per-endpoint rules (one per group) over the built-in
	// limiter.
	Rules []RateLimitRule `json:"rules"`
	// Groups is the catalog of groups a rule may name, with what each covers
	// and its built-in or recommended budget.
	Groups []map[string]interface{} `json:"groups,omitempty"`
}

// Rate-limit rule keys: what one budget counts per.
const (
	RateLimitKeyIP       = "ip"
	RateLimitKeyUser     = "user"
	RateLimitKeyInstance = "instance"
)

// RateLimitRule is one per-endpoint rule: at most Max requests per
// WindowSeconds for the named Group, counted per Key ("ip", "user" or
// "instance"). A rule on a group that owns a built-in budget replaces it;
// any other rule adds a budget on top.
type RateLimitRule struct {
	Group         string `json:"group"`
	WindowSeconds int    `json:"window_seconds"`
	Max           int    `json:"max"`
	Key           string `json:"key"`
}

// UpdateRateLimitPolicyParams is the body of PATCH /v1/rate_limit_policy.
// Rules, when non-nil, is the FULL rule list (it replaces the stored one; an
// empty non-nil slice clears it).
type UpdateRateLimitPolicyParams struct {
	FAPICreatePerMin  *int            `json:"fapi_create_per_min,omitempty"`
	FAPIVerifyPerMin  *int            `json:"fapi_verify_per_min,omitempty"`
	BAPIPerMin        *int            `json:"bapi_per_min,omitempty"`
	LDAPPerIPPerMin   *int            `json:"ldap_per_ip_per_min,omitempty"`
	LDAPPerUserPerMin *int            `json:"ldap_per_user_per_min,omitempty"`
	Rules             []RateLimitRule `json:"-"`
}

// MarshalJSON sends rules whenever Rules is non-nil (so an empty slice clears).
func (p UpdateRateLimitPolicyParams) MarshalJSON() ([]byte, error) {
	type plain UpdateRateLimitPolicyParams
	var extra map[string]interface{}
	if p.Rules != nil {
		extra = map[string]interface{}{"rules": p.Rules}
	}
	return marshalWithExtra(plain(p), extra)
}

// Get reads the current policy and its bounds. GET /v1/rate_limit_policy.
func (s *RateLimitPolicyService) Get(ctx context.Context) (*RateLimitPolicy, error) {
	out := &RateLimitPolicy{}
	return out, s.client.get(ctx, "/v1/rate_limit_policy", nil, out)
}

// Update adjusts either budget; omitted knobs are unchanged.
// PATCH /v1/rate_limit_policy.
func (s *RateLimitPolicyService) Update(ctx context.Context, params UpdateRateLimitPolicyParams, opts ...RequestOption) (*RateLimitPolicy, error) {
	out := &RateLimitPolicy{}
	return out, s.client.patch(ctx, "/v1/rate_limit_policy", params, out, opts...)
}
