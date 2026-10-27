package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// OrgRoleGrantsService is the orgRoleGrants resource.
type OrgRoleGrantsService struct {
	client *Client
}

// OrgRoleGrantsListQuery holds the query parameters of OrgRoleGrantsService.List.
type OrgRoleGrantsListQuery struct {
	// Only grants made by this organization.
	GrantorOrgID string
	// Only grants made to this organization.
	GranteeOrgID string
	// active: leave out revoked grants.
	Status string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q OrgRoleGrantsListQuery) values() url.Values {
	v := url.Values{}
	if q.GrantorOrgID != "" {
		v.Set("grantor_org_id", q.GrantorOrgID)
	}
	if q.GranteeOrgID != "" {
		v.Set("grantee_org_id", q.GranteeOrgID)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List cross-organization role grants, filtered by grantor_org_id, grantee_org_id or
// status=active.
// GET /v1/org_role_grants.
func (s *OrgRoleGrantsService) List(ctx context.Context, query OrgRoleGrantsListQuery) (*CursorPage[OrgRoleGrantsListItem], error) {
	out := &CursorPage[OrgRoleGrantsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/org_role_grants", query.values(), nil, out)
}

// Create: Let a grantee organization hand out a bounded set of the grantor organization’s roles
// (role_keys) to its own members. One active grant per pair.
// POST /v1/org_role_grants.
func (s *OrgRoleGrantsService) Create(ctx context.Context, params OrgRoleGrantsCreateParams, opts ...RequestOption) (*OrgRoleGrantsListItem, error) {
	out := &OrgRoleGrantsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/org_role_grants", nil, params, out, opts...)
}

// Get: Fetch one cross-organization role grant.
// GET /v1/org_role_grants/{id}.
func (s *OrgRoleGrantsService) Get(ctx context.Context, id string) (*OrgRoleGrantsListItem, error) {
	out := &OrgRoleGrantsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/org_role_grants/"+url.PathEscape(id), nil, nil, out)
}

// Update: Replace the granted role_keys. Delegations of roles no longer granted are removed.
// PATCH /v1/org_role_grants/{id}.
func (s *OrgRoleGrantsService) Update(ctx context.Context, id string, params OrgRoleGrantsUpdateParams, opts ...RequestOption) (*OrgRoleGrantsListItem, error) {
	out := &OrgRoleGrantsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/org_role_grants/"+url.PathEscape(id), nil, params, out, opts...)
}

// Revoke: Revoke a grant. Every delegation under it stops taking effect immediately.
// DELETE /v1/org_role_grants/{id}.
func (s *OrgRoleGrantsService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*OrgRoleGrantsListItem, error) {
	out := &OrgRoleGrantsListItem{}
	return out, s.client.do(ctx, "DELETE", "/v1/org_role_grants/"+url.PathEscape(id), nil, nil, out, opts...)
}

// ListDelegations: List the members holding roles under a grant.
// GET /v1/org_role_grants/{id}/delegations.
func (s *OrgRoleGrantsService) ListDelegations(ctx context.Context, id string, params ListParams) (*CursorPage[OrgRoleGrantsListDelegationsItem], error) {
	out := &CursorPage[OrgRoleGrantsListDelegationsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/org_role_grants/"+url.PathEscape(id)+"/delegations", params.values(), nil, out)
}

// Delegate: Delegate one granted role_key to a member (user_id) of the grantee organization.
// POST /v1/org_role_grants/{id}/delegations.
func (s *OrgRoleGrantsService) Delegate(ctx context.Context, id string, params OrgRoleGrantsDelegateParams, opts ...RequestOption) (*OrgRoleGrantsListDelegationsItem, error) {
	out := &OrgRoleGrantsListDelegationsItem{}
	return out, s.client.do(ctx, "POST", "/v1/org_role_grants/"+url.PathEscape(id)+"/delegations", nil, params, out, opts...)
}

// Undelegate: Remove a delegation of a granted role.
// DELETE /v1/org_role_grants/{id}/delegations/{delegationId}.
func (s *OrgRoleGrantsService) Undelegate(ctx context.Context, id string, delegationID string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/org_role_grants/"+url.PathEscape(id)+"/delegations/"+url.PathEscape(delegationID), nil, nil, nil, opts...)
}

// OrgRoleGrantsEffectiveQuery holds the query parameters of OrgRoleGrantsService.Effective.
type OrgRoleGrantsEffectiveQuery struct {
	// The user whose delegated roles to list. Required.
	UserID string
	// Only roles held in this grantor organization.
	OrganizationID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q OrgRoleGrantsEffectiveQuery) values() url.Values {
	v := url.Values{}
	v.Set("user_id", q.UserID)
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Effective: The roles and permissions a user (user_id) holds in a grantor organization
// (organization_id, optional) through active delegations.
// GET /v1/org_role_grants/effective.
func (s *OrgRoleGrantsService) Effective(ctx context.Context, query OrgRoleGrantsEffectiveQuery) (*CursorPage[OrgRoleGrantsEffectiveItem], error) {
	out := &CursorPage[OrgRoleGrantsEffectiveItem]{}
	return out, s.client.do(ctx, "GET", "/v1/org_role_grants/effective", query.values(), nil, out)
}
