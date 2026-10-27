package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ManagedGrantsService is the managedGrants resource.
type ManagedGrantsService struct {
	client *Client
}

// ManagedGrantsListQuery holds the query parameters of ManagedGrantsService.List.
type ManagedGrantsListQuery struct {
	// Only this user's grants.
	UserID string
	// Only grants held by this OAuth client (its public client_id).
	ClientID string
	// Only grants in this state.
	Status string
	// Page size. Defaults to 50; values above 200 are capped at 200.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q ManagedGrantsListQuery) values() url.Values {
	v := url.Values{}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.ClientID != "" {
		v.Set("client_id", q.ClientID)
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

// List: List OpenID Grant Management grants: what each OAuth client holds for each user under a
// `grant_id`, newest first. Filter by `user_id`, `client_id` (the public client id) and `status`.
// GET /v1/grant_management/grants.
func (s *ManagedGrantsService) List(ctx context.Context, query ManagedGrantsListQuery) (*ManagedGrantsListResult, error) {
	out := &ManagedGrantsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/grant_management/grants", query.values(), nil, out)
}

// Get: Read one grant: its scopes, resource, authorization_details, status and revision.
// GET /v1/grant_management/grants/{id}.
func (s *ManagedGrantsService) Get(ctx context.Context, id string) (*ManagedGrantsListResultDataItem, error) {
	out := &ManagedGrantsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/grant_management/grants/"+url.PathEscape(id), nil, nil, out)
}

// Narrow: Narrow a grant: send the `scopes` and/or `authorization_details` it should keep.
// Anything it does not already hold is a 400 (only the user widens a grant, by authorizing again
// with `grant_management_action=merge`). Refresh tokens under the grant are clamped to the
// narrower scope; a revoked grant is a 404.
// PATCH /v1/grant_management/grants/{id}.
func (s *ManagedGrantsService) Narrow(ctx context.Context, id string, params ManagedGrantsNarrowParams, opts ...RequestOption) (*ManagedGrantsListResultDataItem, error) {
	out := &ManagedGrantsListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/grant_management/grants/"+url.PathEscape(id), nil, params, out, opts...)
}

// Revoke: Revoke a grant and everything issued under it: refresh tokens stop refreshing and access
// tokens that carry the `grant_id` stop validating at once. `tokens_ended` counts the refresh
// grants that ended with it. Revoking an already-revoked grant answers 200 with `tokens_ended: 0`.
// DELETE /v1/grant_management/grants/{id}.
func (s *ManagedGrantsService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*ManagedGrantsRevokeResult, error) {
	out := &ManagedGrantsRevokeResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/grant_management/grants/"+url.PathEscape(id), nil, nil, out, opts...)
}
