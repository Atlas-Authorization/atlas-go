package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// LeastPrivilegeService is the leastPrivilege resource.
type LeastPrivilegeService struct {
	client *Client
}

// LeastPrivilegeReportQuery holds the query parameters of LeastPrivilegeService.Report.
type LeastPrivilegeReportQuery struct {
	// Look-back window in days. Defaults to 30.
	Days int64
	// Only this kind of credential.
	SubjectType string
	// Only this credential.
	SubjectID string
	// Only credentials with at least one unused permission.
	OnlyUnused *bool
	// At most this many credentials (default 200, at most 500).
	Limit int64
	// json (default) or a CSV export with one row per used or unused permission.
	Format string
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q LeastPrivilegeReportQuery) values() url.Values {
	v := url.Values{}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.SubjectType != "" {
		v.Set("subject_type", q.SubjectType)
	}
	if q.SubjectID != "" {
		v.Set("subject_id", q.SubjectID)
	}
	if q.OnlyUnused != nil {
		v.Set("only_unused", strconv.FormatBool(*q.OnlyUnused))
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Report: The least-privilege report: for every active secret key, OAuth client, MCP gateway and
// agent, what it is allowed to do against what it used over the window, the permissions never
// used, and the narrower grant that would still cover its use. Credentials with something unused
// come first. `format=csv` exports one row per permission.
// GET /v1/least_privilege/report.
func (s *LeastPrivilegeService) Report(ctx context.Context, query LeastPrivilegeReportQuery) (*LeastPrivilegeReportResult, error) {
	out := &LeastPrivilegeReportResult{}
	return out, s.client.do(ctx, "GET", "/v1/least_privilege/report", query.values(), nil, out)
}

// LeastPrivilegeGetQuery holds the query parameters of LeastPrivilegeService.Get.
type LeastPrivilegeGetQuery struct {
	// Look-back window in days. Defaults to 30.
	Days int64
}

func (q LeastPrivilegeGetQuery) values() url.Values {
	v := url.Values{}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	return v
}

// Get: The least-privilege report of one credential (`type` is api_key, oauth_client, mcp_gateway
// or agent). 404 for a credential the report does not cover, such as a revoked key.
// GET /v1/least_privilege/report/{type}/{id}.
func (s *LeastPrivilegeService) Get(ctx context.Context, typeName string, id string, query LeastPrivilegeGetQuery) (*LeastPrivilegeReportResultDataItem, error) {
	out := &LeastPrivilegeReportResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/least_privilege/report/"+url.PathEscape(typeName)+"/"+url.PathEscape(id), query.values(), nil, out)
}

// Apply: Apply a credential's suggestion: narrow a secret key's scopes, an OAuth client's allowed
// scopes, an MCP gateway's tool policy, or revoke an agent's unused tool grants. Preview it first
// with `?dry_run=true`, then send the same body for real. `digest` (from the report) must match
// the current suggestion, else 409, so what you previewed is what is applied; the write is
// conditional on the credential being unchanged. A suggestion only ever removes permissions. Over
// a window the data does not fully cover (`confidence: low`) it needs `acknowledge_short_window:
// true`. Audited as `least_privilege.applied`.
// POST /v1/least_privilege/apply.
func (s *LeastPrivilegeService) Apply(ctx context.Context, params LeastPrivilegeApplyParams, opts ...RequestOption) (*LeastPrivilegeApplyResult, error) {
	out := &LeastPrivilegeApplyResult{}
	return out, s.client.do(ctx, "POST", "/v1/least_privilege/apply", nil, params, out, opts...)
}
