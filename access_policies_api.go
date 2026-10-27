package atlas

import (
	"context"
	"net/url"
)

// AccessPoliciesService is the accessPolicies resource.
type AccessPoliciesService struct {
	client *Client
}

// List: List conditional-access policies, in evaluation order.
// GET /v1/access_policies.
func (s *AccessPoliciesService) List(ctx context.Context, params ListParams) (*CursorPage[AccessPoliciesListItem], error) {
	out := &CursorPage[AccessPoliciesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/access_policies", params.values(), nil, out)
}

// Create: Create a conditional-access policy. `conditions` (applications, userIds, groups, orgs,
// roles, networkZones {include, exclude}, countries, riskLevels, deviceTrust, authMethods,
// timeWindow) are ANDed; an empty condition matches anything. `grants` are allow, block,
// require_mfa, require_acr, require_policy_acceptance or require_action. `stages` limits it to
// sign_in, authorize and/or token (default all). A matching block wins; step-up grants are
// unioned.
// POST /v1/access_policies.
func (s *AccessPoliciesService) Create(ctx context.Context, params AccessPoliciesCreateParams, opts ...RequestOption) (*AccessPoliciesListItem, error) {
	out := &AccessPoliciesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/access_policies", nil, params, out, opts...)
}

// Simulate: What-if: describe a request (stage, ip, application, orgs, roles, country, risk level,
// device trust, auth methods, whether MFA was verified) and see the decision, the policies that
// matched and the unmet step-up requirements. Pass `policy_id` to test one policy even if it is
// disabled.
// POST /v1/access_policies/simulate.
func (s *AccessPoliciesService) Simulate(ctx context.Context, params AccessPoliciesSimulateParams, opts ...RequestOption) (*AccessPoliciesSimulateResult, error) {
	out := &AccessPoliciesSimulateResult{}
	return out, s.client.do(ctx, "POST", "/v1/access_policies/simulate", nil, params, out, opts...)
}

// Get: Read one access policy.
// GET /v1/access_policies/{id}.
func (s *AccessPoliciesService) Get(ctx context.Context, id string) (*AccessPoliciesListItem, error) {
	out := &AccessPoliciesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/access_policies/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update an access policy. Sent fields replace the stored value.
// PATCH /v1/access_policies/{id}.
func (s *AccessPoliciesService) Update(ctx context.Context, id string, params AccessPoliciesCreateParams, opts ...RequestOption) (*AccessPoliciesListItem, error) {
	out := &AccessPoliciesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/access_policies/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete an access policy.
// DELETE /v1/access_policies/{id}.
func (s *AccessPoliciesService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/access_policies/"+url.PathEscape(id), nil, nil, nil, opts...)
}
