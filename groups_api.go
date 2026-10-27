package atlas

import (
	"context"
	"net/url"
)

// GroupsService is the groups resource.
type GroupsService struct {
	client *Client
	Rules  *GroupsRulesService
}

// List: Every instance group with its member count, by slug.
// GET /v1/groups.
func (s *GroupsService) List(ctx context.Context, params ListParams) (*CursorPage[GroupsListItem], error) {
	out := &CursorPage[GroupsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/groups", params.values(), nil, out)
}

// Create: Create an instance group. Emits group.created. → 201.
// POST /v1/groups.
func (s *GroupsService) Create(ctx context.Context, params GroupsCreateParams, opts ...RequestOption) (*GroupsListItem, error) {
	out := &GroupsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/groups", nil, params, out, opts...)
}

// Get: One group, by id or slug.
// GET /v1/groups/{id}.
func (s *GroupsService) Get(ctx context.Context, id string) (*GroupsListItem, error) {
	out := &GroupsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/groups/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a group. Emits group.updated.
// PATCH /v1/groups/{id}.
func (s *GroupsService) Update(ctx context.Context, id string, params GroupsUpdateParams, opts ...RequestOption) (*GroupsListItem, error) {
	out := &GroupsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/groups/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a group: its memberships go, its children move to the top level. Emits
// group.deleted.
// DELETE /v1/groups/{id}.
func (s *GroupsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/groups/"+url.PathEscape(id), nil, nil, out, opts...)
}

// ListMembers: The members of one group (direct members only), with how each joined (manual,
// dynamic, sso, rule). Cursor paged by user id.
// GET /v1/groups/{id}/members.
func (s *GroupsService) ListMembers(ctx context.Context, id string, params ListParams) (*CursorPage[GroupsListMembersItem], error) {
	out := &CursorPage[GroupsListMembersItem]{}
	return out, s.client.do(ctx, "GET", "/v1/groups/"+url.PathEscape(id)+"/members", params.values(), nil, out)
}

// AddMembers: Add up to 500 users by hand. A member who joined by filter, SSO or rule becomes
// manual, so a re-apply leaves them. Emits group.member_added per new member.
// POST /v1/groups/{id}/members.
func (s *GroupsService) AddMembers(ctx context.Context, id string, params GroupsAddMembersParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/groups/"+url.PathEscape(id)+"/members", nil, params, nil, opts...)
}

// RemoveMembers: Remove up to 500 users from a group. Emits group.member_removed.
// POST /v1/groups/{id}/members/remove.
func (s *GroupsService) RemoveMembers(ctx context.Context, id string, params GroupsAddMembersParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/groups/"+url.PathEscape(id)+"/members/remove", nil, params, nil, opts...)
}

// Reapply: Re-evaluate a dynamic group now: users matching dynamic_filter are added, those who no
// longer match are removed; manual members are never touched (400 when the group has no
// dynamic_filter, or the filter matches over 50,000 users).
// POST /v1/groups/{id}/reapply.
func (s *GroupsService) Reapply(ctx context.Context, id string, opts ...RequestOption) (*GroupsReapplyResult, error) {
	out := &GroupsReapplyResult{}
	return out, s.client.do(ctx, "POST", "/v1/groups/"+url.PathEscape(id)+"/reapply", nil, nil, out, opts...)
}

// ForUser: A user's direct groups and how they joined each.
// GET /v1/users/{id}/groups.
func (s *GroupsService) ForUser(ctx context.Context, id string, params ListParams) (*CursorPage[GroupsListItem], error) {
	out := &CursorPage[GroupsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/groups", params.values(), nil, out)
}

// GroupsRulesService is the groups rules group of GroupsService.
type GroupsRulesService struct {
	client *Client
}

// List: Group rules, lowest priority number first.
// GET /v1/group_rules.
func (s *GroupsRulesService) List(ctx context.Context, params ListParams) (*CursorPage[GroupsRulesListItem], error) {
	out := &CursorPage[GroupsRulesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/group_rules", params.values(), nil, out)
}

// Create: Create a rule: when a user matches condition, run the actions (add to a group, grant an
// app role, set a trait). → 201.
// POST /v1/group_rules.
func (s *GroupsRulesService) Create(ctx context.Context, params GroupsRulesCreateParams, opts ...RequestOption) (*GroupsRulesListItem, error) {
	out := &GroupsRulesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/group_rules", nil, params, out, opts...)
}

// ApplyAll: Run every enabled rule in priority order. One result per rule.
// POST /v1/group_rules/apply.
func (s *GroupsRulesService) ApplyAll(ctx context.Context, opts ...RequestOption) (*CursorPage[GroupsRulesApplyAllItem], error) {
	out := &CursorPage[GroupsRulesApplyAllItem]{}
	return out, s.client.do(ctx, "POST", "/v1/group_rules/apply", nil, nil, out, opts...)
}

// Get: One group rule, with its condition and actions.
// GET /v1/group_rules/{id}.
func (s *GroupsRulesService) Get(ctx context.Context, id string) (*GroupsRulesListItem, error) {
	out := &GroupsRulesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/group_rules/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a group rule, its condition or actions.
// PATCH /v1/group_rules/{id}.
func (s *GroupsRulesService) Update(ctx context.Context, id string, params GroupsRulesUpdateParams, opts ...RequestOption) (*GroupsRulesListItem, error) {
	out := &GroupsRulesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/group_rules/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a rule. Memberships it created stay until removed.
// DELETE /v1/group_rules/{id}.
func (s *GroupsRulesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/group_rules/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Apply: Run one rule against every matching user now. Returns the match count and what changed.
// POST /v1/group_rules/{id}/apply.
func (s *GroupsRulesService) Apply(ctx context.Context, id string, opts ...RequestOption) (*GroupsRulesApplyAllItem, error) {
	out := &GroupsRulesApplyAllItem{}
	return out, s.client.do(ctx, "POST", "/v1/group_rules/"+url.PathEscape(id)+"/apply", nil, nil, out, opts...)
}
