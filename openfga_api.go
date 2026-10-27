package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ListUsers: List the users that have a relation on an object (OpenFGA-wire ListUsers): concrete
// users, usersets (`user_filters[0].relation`), and the `type:*` wildcard with `excluded_users`.
// Honours contextual tuples and tuple conditions; pages with `page_size` / `continuation_token`.
// POST /v1/openfga/stores/{store}/list-users.
func (s *OpenFGAService) ListUsers(ctx context.Context, store string, params OpenFGAListUsersParams, opts ...RequestOption) (*OpenFGAListUsersResult, error) {
	out := &OpenFGAListUsersResult{}
	return out, s.client.do(ctx, "POST", "/v1/openfga/stores/"+url.PathEscape(store)+"/list-users", nil, params, out, opts...)
}

// OpenFGAReadChangesQuery holds the query parameters of OpenFGAService.ReadChanges.
type OpenFGAReadChangesQuery struct {
	// Only changes to tuples on objects of this type. A continuation token is pinned to the type it
	// was issued for.
	Type string
	// Changes per page.
	PageSize int64
	// The `continuation_token` of the previous page.
	ContinuationToken string
	// RFC 3339 timestamp: only changes recorded at or after it.
	StartTime string
}

func (q OpenFGAReadChangesQuery) values() url.Values {
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
	return v
}

// ReadChanges: Read the tuple changelog (OpenFGA-wire ReadChanges): every tuple write and delete
// in order, resumable with `continuation_token` (the token is returned even on the last page —
// pass it later to receive only newer changes).
// GET /v1/openfga/stores/{store}/changes.
func (s *OpenFGAService) ReadChanges(ctx context.Context, store string, query OpenFGAReadChangesQuery) (*OpenFGAReadChangesResult, error) {
	out := &OpenFGAReadChangesResult{}
	return out, s.client.do(ctx, "GET", "/v1/openfga/stores/"+url.PathEscape(store)+"/changes", query.values(), nil, out)
}
