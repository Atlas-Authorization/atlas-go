package atlas

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// AnalyticsFunnelQuery holds the query parameters of AnalyticsService.Funnel.
type AnalyticsFunnelQuery struct {
	// Default sign_in.
	Kind string
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsFunnelQuery) values() url.Values {
	v := url.Values{}
	if q.Kind != "" {
		v.Set("kind", q.Kind)
	}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Funnel: Where sign-in or sign-up attempts end, per method: started, completed, abandoned, and
// the step each unfinished attempt stopped at, with the completion rate. Each attempt is counted
// once, at its final state.
// GET /v1/analytics/funnel.
func (s *AnalyticsService) Funnel(ctx context.Context, query AnalyticsFunnelQuery) (*AnalyticsFunnelResult, error) {
	out := &AnalyticsFunnelResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/funnel", query.values(), nil, out)
}

// AnalyticsJourneyFunnelQuery holds the query parameters of AnalyticsService.JourneyFunnel.
type AnalyticsJourneyFunnelQuery struct {
	// The journey (GET /v1/flows).
	JourneyID string
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsJourneyFunnelQuery) values() url.Values {
	v := url.Values{}
	v.Set("journey_id", q.JourneyID)
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// JourneyFunnel: What happened at each step of a sign-in journey: how often it held a sign-in (a
// required action or form), was completed, ran at the sign-in (an Action, claim or redirect) or
// refused it, with the completion rate of its holds. Steps follow the active version; a sub-flow's
// steps are prefixed with the sub-flow step id. No organization slice.
// GET /v1/analytics/journey_funnel.
func (s *AnalyticsService) JourneyFunnel(ctx context.Context, query AnalyticsJourneyFunnelQuery) (*AnalyticsJourneyFunnelResult, error) {
	out := &AnalyticsJourneyFunnelResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/journey_funnel", query.values(), nil, out)
}

// AnalyticsFailuresQuery holds the query parameters of AnalyticsService.Failures.
type AnalyticsFailuresQuery struct {
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsFailuresQuery) values() url.Values {
	v := url.Values{}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Failures: Failed first- and second-factor attempts by reason and method, most frequent first. No
// organization slice (a failed attempt belongs to no organization).
// GET /v1/analytics/failures.
func (s *AnalyticsService) Failures(ctx context.Context, query AnalyticsFailuresQuery) (*AnalyticsFailuresResult, error) {
	out := &AnalyticsFailuresResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/failures", query.values(), nil, out)
}

// AnalyticsBreakdownQuery holds the query parameters of AnalyticsService.Breakdown.
type AnalyticsBreakdownQuery struct {
	// Default method.
	Dimension string
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsBreakdownQuery) values() url.Values {
	v := url.Values{}
	if q.Dimension != "" {
		v.Set("dimension", q.Dimension)
	}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Breakdown: Sign-ins split by one dimension: method, device type, browser, operating system or
// country (country needs a GeoIP database on the deployment; otherwise it reports `unknown`).
// GET /v1/analytics/breakdown.
func (s *AnalyticsService) Breakdown(ctx context.Context, query AnalyticsBreakdownQuery) (*AnalyticsBreakdownResult, error) {
	out := &AnalyticsBreakdownResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/breakdown", query.values(), nil, out)
}

// AnalyticsActiveUsersQuery holds the query parameters of AnalyticsService.ActiveUsers.
type AnalyticsActiveUsersQuery struct {
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsActiveUsersQuery) values() url.Values {
	v := url.Values{}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// ActiveUsers: Distinct active users and sign-ins per bucket, each bucket split into new users
// (signed up in that bucket) and returning users, plus trailing 1/7/30-day active-user counts
// (dau, wau, mau) ending at `to`.
// GET /v1/analytics/active_users.
func (s *AnalyticsService) ActiveUsers(ctx context.Context, query AnalyticsActiveUsersQuery) (*AnalyticsActiveUsersResult, error) {
	out := &AnalyticsActiveUsersResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/active_users", query.values(), nil, out)
}

// AnalyticsPasskeyAdoptionQuery holds the query parameters of AnalyticsService.PasskeyAdoption.
type AnalyticsPasskeyAdoptionQuery struct {
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsPasskeyAdoptionQuery) values() url.Values {
	v := url.Values{}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// PasskeyAdoption: How many users hold a passkey (adoption rate), and the passkey share of
// sign-ins per bucket.
// GET /v1/analytics/passkey_adoption.
func (s *AnalyticsService) PasskeyAdoption(ctx context.Context, query AnalyticsPasskeyAdoptionQuery) (*AnalyticsPasskeyAdoptionResult, error) {
	out := &AnalyticsPasskeyAdoptionResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/passkey_adoption", query.values(), nil, out)
}

// AnalyticsAPIUsageQuery holds the query parameters of AnalyticsService.APIUsage.
type AnalyticsAPIUsageQuery struct {
	// Only this kind of subject.
	SubjectType string
	// Only this key or organization.
	SubjectID string
	// The current window, 10 to 1440 (default 60).
	WindowMinutes int64
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsAPIUsageQuery) values() url.Values {
	v := url.Values{}
	if q.SubjectType != "" {
		v.Set("subject_type", q.SubjectType)
	}
	if q.SubjectID != "" {
		v.Set("subject_id", q.SubjectID)
	}
	if q.WindowMinutes != 0 {
		v.Set("window_minutes", strconv.FormatInt(q.WindowMinutes, 10))
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// APIUsage: API usage per subject against its own baseline: secret keys calling the Backend API,
// end-user API keys verified through /v1/api_keys/verify, and organizations (Backend API calls on
// the organization plus verifications of its keys). For each: requests and the failure rate in the
// window, the average hourly rate over the 7 days before, and the ratio between them, highest
// ratio first (at most 100). Counts are written in batches and can lag by up to a minute.
// GET /v1/analytics/api_usage.
func (s *AnalyticsService) APIUsage(ctx context.Context, query AnalyticsAPIUsageQuery) (*AnalyticsAPIUsageResult, error) {
	out := &AnalyticsAPIUsageResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/api_usage", query.values(), nil, out)
}

// AnalyticsReportsService is the analytics reports group of AnalyticsService.
type AnalyticsReportsService struct {
	client *Client
}

// AnalyticsReportsInactiveUsersQuery holds the query parameters of AnalyticsReportsService.InactiveUsers.
type AnalyticsReportsInactiveUsersQuery struct {
	// Days without a sign-in. Default 90.
	InactiveDays int64
	// Page size (default 100, at most 1000).
	Limit int64
	// Cursor: the last user_id of the previous page.
	StartingAfter string
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
}

func (q AnalyticsReportsInactiveUsersQuery) values() url.Values {
	v := url.Values{}
	if q.InactiveDays != 0 {
		v.Set("inactive_days", strconv.FormatInt(q.InactiveDays, 10))
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	return v
}

// InactiveUsers: Compliance report: users who have not signed in for `inactive_days` (default 90),
// oldest id first, cursor-paginated (an export returns up to 50,000 rows).
// GET /v1/analytics/reports/inactive_users.
func (s *AnalyticsReportsService) InactiveUsers(ctx context.Context, query AnalyticsReportsInactiveUsersQuery) (*AnalyticsReportsInactiveUsersResult, error) {
	out := &AnalyticsReportsInactiveUsersResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/reports/inactive_users", query.values(), nil, out)
}

// AnalyticsReportsMFACoverageQuery holds the query parameters of AnalyticsReportsService.MFACoverage.
type AnalyticsReportsMFACoverageQuery struct {
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsReportsMFACoverageQuery) values() url.Values {
	v := url.Values{}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// MFACoverage: Compliance report: how many users are protected by a second factor, a passkey,
// either, or neither.
// GET /v1/analytics/reports/mfa_coverage.
func (s *AnalyticsReportsService) MFACoverage(ctx context.Context, query AnalyticsReportsMFACoverageQuery) (*AnalyticsReportsMFACoverageResult, error) {
	out := &AnalyticsReportsMFACoverageResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/reports/mfa_coverage", query.values(), nil, out)
}

// AnalyticsReportsAccessByAppQuery holds the query parameters of AnalyticsReportsService.AccessByApp.
type AnalyticsReportsAccessByAppQuery struct {
	// Window start: Unix epoch milliseconds or an ISO 8601 time.
	From interface{}
	// Window end (exclusive). Defaults to now.
	To interface{}
	// Window length in days ending at `to`, used when `from` is absent. Default 30, at most 180.
	Days int64
	// Bucket size for time series.
	Granularity string
	// Only members of this organization (a per-organization slice). Not available for failures or the
	// journey funnel.or the journey funnel.
	OrganizationID string
	// Response format. csv and parquet return the `data` rows as a file (parquet: one uncompressed row
	// group, every column required).
	Format string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AnalyticsReportsAccessByAppQuery) values() url.Values {
	v := url.Values{}
	if q.From != nil {
		v.Set("from", fmt.Sprint(q.From))
	}
	if q.To != nil {
		v.Set("to", fmt.Sprint(q.To))
	}
	if q.Days != 0 {
		v.Set("days", strconv.FormatInt(q.Days, 10))
	}
	if q.Granularity != "" {
		v.Set("granularity", q.Granularity)
	}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// AccessByApp: Compliance report: for each application (OAuth client), how many users have access,
// how many grants are active and how many users signed in during the window.
// GET /v1/analytics/reports/access_by_app.
func (s *AnalyticsReportsService) AccessByApp(ctx context.Context, query AnalyticsReportsAccessByAppQuery) (*AnalyticsReportsAccessByAppResult, error) {
	out := &AnalyticsReportsAccessByAppResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/reports/access_by_app", query.values(), nil, out)
}

// AnalyticsAlertRulesService is the analytics alertRules group of AnalyticsService.
type AnalyticsAlertRulesService struct {
	client *Client
}

// List: List analytics alert rules with their state and last measured value. The metric catalog is
// included.
// GET /v1/analytics/alert_rules.
func (s *AnalyticsAlertRulesService) List(ctx context.Context, params ListParams) (*AnalyticsAlertRulesListResult, error) {
	out := &AnalyticsAlertRulesListResult{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/alert_rules", params.values(), nil, out)
}

// Create: Create an alert rule: tell me when a sign-in health metric, or a key or organization's
// API usage against its baseline, crosses a threshold over a trailing window. It must have
// email_contacts, a webhook_url or ssf. A webhook signing secret is returned once.
// POST /v1/analytics/alert_rules.
func (s *AnalyticsAlertRulesService) Create(ctx context.Context, params AnalyticsAlertRulesCreateParams, opts ...RequestOption) (*AnalyticsAlertRulesListResultDataItem, error) {
	out := &AnalyticsAlertRulesListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/analytics/alert_rules", nil, params, out, opts...)
}

// Get: One analytics alert rule.
// GET /v1/analytics/alert_rules/{id}.
func (s *AnalyticsAlertRulesService) Get(ctx context.Context, id string) (*AnalyticsAlertRulesListResultDataItem, error) {
	out := &AnalyticsAlertRulesListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/analytics/alert_rules/"+url.PathEscape(id), nil, nil, out)
}

// Update: Edit an alert rule. Editing re-arms it.
// PATCH /v1/analytics/alert_rules/{id}.
func (s *AnalyticsAlertRulesService) Update(ctx context.Context, id string, params AnalyticsAlertRulesUpdateParams, opts ...RequestOption) (*AnalyticsAlertRulesListResultDataItem, error) {
	out := &AnalyticsAlertRulesListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/analytics/alert_rules/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete an alert rule.
// DELETE /v1/analytics/alert_rules/{id}.
func (s *AnalyticsAlertRulesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/analytics/alert_rules/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Test: Measure the rule now. With `notify: true` it also sends the rule's email and webhook,
// whether or not the rule is breaching, to prove the delivery path.
// POST /v1/analytics/alert_rules/{id}/test.
func (s *AnalyticsAlertRulesService) Test(ctx context.Context, id string, params AnalyticsAlertRulesTestParams, opts ...RequestOption) (*AnalyticsAlertRulesTestResult, error) {
	out := &AnalyticsAlertRulesTestResult{}
	return out, s.client.do(ctx, "POST", "/v1/analytics/alert_rules/"+url.PathEscape(id)+"/test", nil, params, out, opts...)
}
