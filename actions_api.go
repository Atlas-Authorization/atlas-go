package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ActionsCallsQuery holds the query parameters of ActionsService.Calls.
type ActionsCallsQuery struct {
	// Page size, 1 to 200 (default 50).
	Limit int64
	// Only calls with this status; `failed` is every call that was not ok or denied.
	Status string
	// true: only dry-run tests; false: only real calls.
	Test *bool
	// Cursor: the `next_cursor` of the previous page.
	StartingAfter string
}

func (q ActionsCallsQuery) values() url.Values {
	v := url.Values{}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Test != nil {
		v.Set("test", strconv.FormatBool(*q.Test))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Calls: The call log of an `http` Action (an Action that calls your own endpoint), newest first,
// with 24 hour stats: calls, denied, failed, timeouts and p95 latency. Real calls and dry-run
// tests are both logged (`test`). 409 for a `node` Action.
// GET /v1/actions/{id}/calls.
func (s *ActionsService) Calls(ctx context.Context, id string, query ActionsCallsQuery) (*ActionsCallsResult, error) {
	out := &ActionsCallsResult{}
	return out, s.client.do(ctx, "GET", "/v1/actions/"+url.PathEscape(id)+"/calls", query.values(), nil, out)
}
