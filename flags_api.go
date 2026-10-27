package atlas

import (
	"context"
	"net/url"
)

// FlagsService is the flags resource.
type FlagsService struct {
	client *Client
}

// AssignOrganizationEntitlements: Assign an organization's entitlements (a plan, a feature list
// and/or limits, optionally expiring) without a billing subscription. Replaces whatever was
// assigned or overridden before; an empty body clears it and the organization falls back to its
// billing plan. Reaches the `pla`, `fea` and `ent` session claims on the next token.
// PUT /v1/organizations/{id}/entitlements.
func (s *FlagsService) AssignOrganizationEntitlements(ctx context.Context, id string, params FlagsAssignOrganizationEntitlementsParams, opts ...RequestOption) (*FlagsAssignOrganizationEntitlementsResult, error) {
	out := &FlagsAssignOrganizationEntitlementsResult{}
	return out, s.client.do(ctx, "PUT", "/v1/organizations/"+url.PathEscape(id)+"/entitlements", nil, params, out, opts...)
}

// Create: Create a feature flag: a typed value (`boolean`, `string`, `int` or `json`) with a
// `default_value`, an `off_value` (served while `enabled` is false; defaults to false for a
// boolean, else the default) and ordered targeting `rules` by org, user, plan and percentage. 409
// when the key exists.
// POST /v1/feature_flags.
func (s *FlagsService) Create(ctx context.Context, params FlagsCreateParams, opts ...RequestOption) (*FlagsCreateResult, error) {
	out := &FlagsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/feature_flags", nil, params, out, opts...)
}

// List: List feature flags ordered by key. `starting_after` is the key of the last flag of the
// previous page.
// GET /v1/feature_flags.
func (s *FlagsService) List(ctx context.Context, params ListParams) (*CursorPage[FlagsCreateResult], error) {
	out := &CursorPage[FlagsCreateResult]{}
	return out, s.client.do(ctx, "GET", "/v1/feature_flags", params.values(), nil, out)
}

// Retrieve: Read one feature flag.
// GET /v1/feature_flags/{key}.
func (s *FlagsService) Retrieve(ctx context.Context, key string) (*FlagsCreateResult, error) {
	out := &FlagsCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/feature_flags/"+url.PathEscape(key), nil, nil, out)
}

// Update: Change a flag's description, kill switch, default or off value, or replace its rules.
// The type and key are fixed.
// PATCH /v1/feature_flags/{key}.
func (s *FlagsService) Update(ctx context.Context, key string, params FlagsUpdateParams, opts ...RequestOption) (*FlagsCreateResult, error) {
	out := &FlagsCreateResult{}
	return out, s.client.do(ctx, "PATCH", "/v1/feature_flags/"+url.PathEscape(key), nil, params, out, opts...)
}

// Delete: Delete a feature flag.
// DELETE /v1/feature_flags/{key}.
func (s *FlagsService) Delete(ctx context.Context, key string, opts ...RequestOption) (*FlagsDeleteResult, error) {
	out := &FlagsDeleteResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/feature_flags/"+url.PathEscape(key), nil, nil, out, opts...)
}

// Evaluate: Evaluate every flag (or the listed `keys`) for a subject (`user_id`, `org_id`,
// `plan`). When `plan` is omitted it is the organization's (else the user's) resolved plan. Each
// result carries the `value` and a `reason` (`off`, `default` or `rule:<index>`).
// POST /v1/feature_flags/evaluate.
func (s *FlagsService) Evaluate(ctx context.Context, params FlagsEvaluateParams, opts ...RequestOption) (*FlagsEvaluateResult, error) {
	out := &FlagsEvaluateResult{}
	return out, s.client.do(ctx, "POST", "/v1/feature_flags/evaluate", nil, params, out, opts...)
}

// AssignUserEntitlements: Assign a user's entitlements the same way as for an organization.
// PUT /v1/users/{id}/entitlements.
func (s *FlagsService) AssignUserEntitlements(ctx context.Context, id string, params FlagsAssignOrganizationEntitlementsParams, opts ...RequestOption) (*FlagsAssignOrganizationEntitlementsResult, error) {
	out := &FlagsAssignOrganizationEntitlementsResult{}
	return out, s.client.do(ctx, "PUT", "/v1/users/"+url.PathEscape(id)+"/entitlements", nil, params, out, opts...)
}
