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
	Object           string `json:"object"`
	FAPICreatePerMin int    `json:"fapi_create_per_min"`
	BAPIPerMin       int    `json:"bapi_per_min"`
	Bounds           struct {
		FAPICreatePerMin RateLimitBound `json:"fapi_create_per_min"`
		BAPIPerMin       RateLimitBound `json:"bapi_per_min"`
	} `json:"bounds"`
}

// UpdateRateLimitPolicyParams is the body of PATCH /v1/rate_limit_policy.
type UpdateRateLimitPolicyParams struct {
	FAPICreatePerMin *int `json:"fapi_create_per_min,omitempty"`
	BAPIPerMin       *int `json:"bapi_per_min,omitempty"`
}

// Get reads the current policy and its bounds. GET /v1/rate_limit_policy.
func (s *RateLimitPolicyService) Get(ctx context.Context) (*RateLimitPolicy, error) {
	out := &RateLimitPolicy{}
	return out, s.client.get(ctx, "/v1/rate_limit_policy", nil, out)
}

// Update adjusts either budget; omitted knobs are unchanged.
// PATCH /v1/rate_limit_policy.
func (s *RateLimitPolicyService) Update(ctx context.Context, params UpdateRateLimitPolicyParams) (*RateLimitPolicy, error) {
	out := &RateLimitPolicy{}
	return out, s.client.patch(ctx, "/v1/rate_limit_policy", params, out)
}
