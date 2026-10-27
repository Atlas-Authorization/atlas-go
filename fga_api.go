package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ListUsers: List the users that have a relation on an object, filtered to one user type (or to
// `type#relation` usersets via `user_filters[0].relation`). Exact for wildcards (`type:*` plus
// `excluded_users` under `but not`), nested groups and contextual tuples; tuple conditions are
// evaluated against `context`. Pages with `page_size` / `continuation_token`; `consistency` /
// `consistency_token` behave as on check.
// POST /v1/fga/stores/{id}/list-users.
func (s *FGAService) ListUsers(ctx context.Context, id string, params FGAListUsersParams, opts ...RequestOption) (*FGAListUsersResult, error) {
	out := &FGAListUsersResult{}
	return out, s.client.do(ctx, "POST", "/v1/fga/stores/"+url.PathEscape(id)+"/list-users", nil, params, out, opts...)
}

// FGAReadChangesQuery holds the query parameters of FGAService.ReadChanges.
type FGAReadChangesQuery struct {
	// Only changes to tuples on objects of this type. A continuation token is pinned to the type it
	// was issued for.
	Type string
	// Changes per page.
	PageSize int64
	// The `continuation_token` of the previous page.
	ContinuationToken string
	// RFC 3339 timestamp: only changes recorded at or after it.
	StartTime string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q FGAReadChangesQuery) values() url.Values {
	v := url.Values{}
	if q.Type != "" {
		v.Set("type", q.Type)
	}
	if q.PageSize != 0 {
		v.Set("page_size", strconv.FormatInt(q.PageSize, 10))
	}
	if q.ContinuationToken != "" {
		v.Set("continuation_token", q.ContinuationToken)
	}
	if q.StartTime != "" {
		v.Set("start_time", q.StartTime)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// ReadChanges: Read the store’s tuple changelog: every tuple write and delete in commit order,
// resumable with `continuation_token` (returned even on the last page — pass it later to receive
// only newer changes). Filter by object `type` and `start_time`.
// GET /v1/fga/stores/{id}/changes.
func (s *FGAService) ReadChanges(ctx context.Context, id string, query FGAReadChangesQuery) (*FGAReadChangesResult, error) {
	out := &FGAReadChangesResult{}
	return out, s.client.do(ctx, "GET", "/v1/fga/stores/"+url.PathEscape(id)+"/changes", query.values(), nil, out)
}
