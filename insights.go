package atlas

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ── Custom audit events (/v1/audit_events) ──────────────────────────────────

// AuditEventsService is the /v1/audit_events namespace — your application's
// OWN audit events (as opposed to Client.AuditLogs, Atlas's record of its own
// actions). Org-scoped events are streamed to that organization's SIEM.
type AuditEventsService struct{ client *Client }

// AuditEventActor names who did something.
type AuditEventActor struct {
	Type string  `json:"type,omitempty"`
	ID   *string `json:"id,omitempty"`
}

// AuditEventTarget names what an action was done to.
type AuditEventTarget struct {
	Type *string `json:"type,omitempty"`
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// AuditEvent is one stored custom audit event. OccurredAt and CreatedAt are
// epoch milliseconds.
type AuditEvent struct {
	Object         string           `json:"object"`
	ID             string           `json:"id"`
	OrganizationID *string          `json:"organization_id"`
	Actor          AuditEventActor  `json:"actor"`
	Action         string           `json:"action"`
	Target         AuditEventTarget `json:"target"`
	OccurredAt     int64            `json:"occurred_at"`
	Metadata       Metadata         `json:"metadata"`
	CreatedAt      int64            `json:"created_at"`
}

// AuditEventInputActor is the actor of an event you write.
type AuditEventInputActor struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// AuditEventInputTarget is the optional target of an event you write.
type AuditEventInputTarget struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CreateAuditEventParams is one event to write. OccurredAt is epoch ms and
// defaults to now; OrganizationID scopes the event to an org.
type CreateAuditEventParams struct {
	Actor          AuditEventInputActor   `json:"actor"`
	Action         string                 `json:"action"`
	Target         *AuditEventInputTarget `json:"target,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	OccurredAt     int64                  `json:"occurred_at,omitempty"`
	Metadata       Metadata               `json:"metadata,omitempty"`
}

// AuditEventFilter filters the list and export endpoints. ActorID, Action,
// TargetType and TargetID accept a comma-separated list. AnyOf ORs the filters
// instead of ANDing them. MetadataKey and MetadataValue go together.
type AuditEventFilter struct {
	OrganizationID string
	ActorID        string
	Action         string
	TargetType     string
	TargetID       string
	From           time.Time
	To             time.Time
	AnyOf          bool
	MetadataKey    string
	MetadataValue  string
	StartingAfter  string
}

func (f AuditEventFilter) apply(v url.Values) {
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("organization_id", f.OrganizationID)
	set("actor_id", f.ActorID)
	set("action", f.Action)
	set("target_type", f.TargetType)
	set("target_id", f.TargetID)
	if !f.From.IsZero() {
		v.Set("from", strconv.FormatInt(f.From.UnixMilli(), 10))
	}
	if !f.To.IsZero() {
		v.Set("to", strconv.FormatInt(f.To.UnixMilli(), 10))
	}
	if f.AnyOf {
		v.Set("any_of", "true")
	}
	set("metadata_key", f.MetadataKey)
	set("metadata_value", f.MetadataValue)
	set("starting_after", f.StartingAfter)
}

// ListAuditEventsParams filters and pages GET /v1/audit_events.
type ListAuditEventsParams struct {
	AuditEventFilter
	Limit int
}

// AuditEventsDeleted is the result of a test-mode bulk delete.
type AuditEventsDeleted struct {
	Object  string `json:"object"`
	Deleted int    `json:"deleted"`
}

// Create writes one event. POST /v1/audit_events.
func (s *AuditEventsService) Create(ctx context.Context, params CreateAuditEventParams, opts ...RequestOption) (*AuditEvent, error) {
	out := &AuditEvent{}
	return out, s.client.post(ctx, "/v1/audit_events", params, out, opts...)
}

// CreateBatch writes up to 100 events atomically. POST /v1/audit_events/batch.
func (s *AuditEventsService) CreateBatch(ctx context.Context, events []CreateAuditEventParams, opts ...RequestOption) (*ListPage[AuditEvent], error) {
	out := &ListPage[AuditEvent]{}
	body := map[string]interface{}{"events": events}
	return out, s.client.post(ctx, "/v1/audit_events/batch", body, out, opts...)
}

// List queries events, cursor-paginated. GET /v1/audit_events.
func (s *AuditEventsService) List(ctx context.Context, params ListAuditEventsParams) (*CursorPage[AuditEvent], error) {
	q := url.Values{}
	params.apply(q)
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	out := &CursorPage[AuditEvent]{}
	return out, s.client.get(ctx, "/v1/audit_events", q, out)
}

// Export returns every matching event in one streamed body: format "jsonl"
// (default; a truncated export ends with a {"truncated":true,…} line) or "csv".
// GET /v1/audit_events/export.
func (s *AuditEventsService) Export(ctx context.Context, format string, filter AuditEventFilter) ([]byte, error) {
	q := url.Values{}
	filter.apply(q)
	if format != "" {
		q.Set("format", format)
	}
	return s.client.doBytes(ctx, http.MethodGet, "/v1/audit_events/export", q)
}

// DeleteAll bulk-deletes custom audit events, optionally narrowed to one
// organization and/or action. Development (test-mode) instances only; a
// production instance answers 403. DELETE /v1/audit_events.
func (s *AuditEventsService) DeleteAll(ctx context.Context, organizationID, action string, opts ...RequestOption) (*AuditEventsDeleted, error) {
	q := url.Values{}
	if organizationID != "" {
		q.Set("organization_id", organizationID)
	}
	if action != "" {
		q.Set("action", action)
	}
	out := &AuditEventsDeleted{}
	return out, s.client.delQ(ctx, "/v1/audit_events", q, out, opts...)
}

// ── Diagnostics (/v1/diagnostics/*, /v1/config_changelog) ───────────────────

// DiagnosticsService answers "why doesn't this work": login readiness for an
// origin, a request inspector, and the config change history.
type DiagnosticsService struct{ client *Client }

// LoginReadinessCheck is one hop of the login-readiness probe (cors,
// session_cookie, email_provisioning, token_signing).
type LoginReadinessCheck struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
	// Applies is false when the check does not matter for the assumed
	// integration (it then never makes Ready false); nil from older servers.
	Applies  *bool       `json:"applies,omitempty"`
	Observed interface{} `json:"observed"`
	Detail   string      `json:"detail"`
}

// LoginReadinessIntegration is the integration the checks assumed for the
// origin, and why.
type LoginReadinessIntegration struct {
	// Assumed is "redirect" (hosted-redirect OIDC: the cors and session_cookie
	// checks do not apply) or "embedded".
	Assumed string `json:"assumed"`
	// Source is declared, embedded_traffic, redirect_clients or default.
	Source string `json:"source"`
	// Reason is a plain sentence saying why.
	Reason string `json:"reason"`
}

// LoginReadiness is the GET /v1/diagnostics/login_readiness report.
type LoginReadiness struct {
	Object     string  `json:"object"`
	Origin     string  `json:"origin"`
	Live       bool    `json:"live"`
	DataRegion *string `json:"data_region"`
	Ready      bool    `json:"ready"`
	// Integration is the integration the checks assumed (nil from older servers).
	Integration *LoginReadinessIntegration `json:"integration,omitempty"`
	Checks      []LoginReadinessCheck      `json:"checks"`
}

// RequestInspectionFinding is one check of the request inspector; Blocks says
// whether it alone would reject the request.
type RequestInspectionFinding struct {
	Check    string      `json:"check"`
	Blocks   bool        `json:"blocks"`
	Observed interface{} `json:"observed"`
	Detail   string      `json:"detail"`
}

// RequestInspection is the GET /v1/diagnostics/request_inspector report.
type RequestInspection struct {
	Object          string                     `json:"object"`
	Origin          string                     `json:"origin"`
	Method          string                     `json:"method"`
	Path            string                     `json:"path"`
	WouldBeRejected bool                       `json:"would_be_rejected"`
	Findings        []RequestInspectionFinding `json:"findings"`
}

// RequestInspectorParams describes the browser request to explain. Method
// defaults to POST and Path to /v1/client/sign_ins; Token optionally adds a JWT
// verification check.
type RequestInspectorParams struct {
	Origin string
	Method string
	Path   string
	Token  string
}

// ConfigChange is one config-change history entry. Changes carries a
// per-section before/after diff when the change recorded one; otherwise Fields
// names the changed fields.
type ConfigChange struct {
	ID     string          `json:"id"`
	At     int64           `json:"at"`
	Actor  AuditEventActor `json:"actor"`
	Action string          `json:"action"`
	IP     *string         `json:"ip"`
	// Target is the object that changed, e.g. {Type: oauth_client, ID: ...}.
	Target *ConfigChangeTarget `json:"target,omitempty"`
	// Changes always has one entry per changed field. On an older entry that
	// recorded only field names, ValuesRecorded is false and Before / After
	// are nil.
	Changes []ConfigChangeDiff `json:"changes,omitempty"`
	// Fields is deprecated: read Changes[].Section.
	Fields []string `json:"fields,omitempty"`
	// NoOp is true when the write changed nothing.
	NoOp bool `json:"no_op,omitempty"`
	// Recorded is what the source recorded: diff (before/after values), fields
	// (names only) or none.
	Recorded string `json:"recorded,omitempty"`
}

// ConfigChangeTarget names the object a config change touched.
type ConfigChangeTarget struct {
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

// ConfigChangeDiff is the before/after of one config section.
type ConfigChangeDiff struct {
	Section        string      `json:"section"`
	Before         interface{} `json:"before"`
	After          interface{} `json:"after"`
	ValuesRecorded bool        `json:"values_recorded"`
}

// ConfigChangelogParams filters GET /v1/config_changelog.
type ConfigChangelogParams struct {
	ListParams
	Action string
	Since  time.Time
	// IncludeNoOp false leaves out writes that changed nothing; nil keeps the
	// server default.
	IncludeNoOp *bool
}

// LoginReadiness probes end-to-end login readiness for origin; live upgrades
// the signing hop to a real JWKS round-trip.
// GET /v1/diagnostics/login_readiness.
func (s *DiagnosticsService) LoginReadiness(ctx context.Context, origin string, live bool) (*LoginReadiness, error) {
	q := url.Values{"origin": {origin}}
	if live {
		q.Set("live", "true")
	}
	out := &LoginReadiness{}
	return out, s.client.get(ctx, "/v1/diagnostics/login_readiness", q, out)
}

// RequestInspector explains why a browser request would be rejected.
// GET /v1/diagnostics/request_inspector.
func (s *DiagnosticsService) RequestInspector(ctx context.Context, params RequestInspectorParams) (*RequestInspection, error) {
	q := url.Values{"origin": {params.Origin}}
	if params.Method != "" {
		q.Set("method", params.Method)
	}
	if params.Path != "" {
		q.Set("path", params.Path)
	}
	if params.Token != "" {
		q.Set("token", params.Token)
	}
	out := &RequestInspection{}
	return out, s.client.get(ctx, "/v1/diagnostics/request_inspector", q, out)
}

// ConfigChangelog lists config changes, newest first. GET /v1/config_changelog.
func (s *DiagnosticsService) ConfigChangelog(ctx context.Context, params ConfigChangelogParams) (*CursorPage[ConfigChange], error) {
	q := params.ListParams.values()
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	if !params.Since.IsZero() {
		q.Set("since", params.Since.UTC().Format(time.RFC3339))
	}
	if params.IncludeNoOp != nil {
		q.Set("include_no_op", strconv.FormatBool(*params.IncludeNoOp))
	}
	out := &CursorPage[ConfigChange]{}
	return out, s.client.get(ctx, "/v1/config_changelog", q, out)
}

// ── Analytics (/v1/events, /v1/usage) ───────────────────────────────────────

// AnalyticsService reads the product activity feed and usage analytics.
type AnalyticsService struct{ client *Client }

// ActivityEvent is one entry in the activity feed.
type ActivityEvent struct {
	Object    string                 `json:"object"`
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt int64                  `json:"created_at"`
}

// ActivityEventPage is a page of the activity feed plus the event types this
// instance has actually emitted.
type ActivityEventPage struct {
	Object         string          `json:"object"`
	Data           []ActivityEvent `json:"data"`
	HasMore        bool            `json:"has_more"`
	NextCursor     *string         `json:"next_cursor"`
	AvailableTypes []string        `json:"available_types"`
	// Retention is how long events are kept.
	Retention interface{} `json:"retention,omitempty"`
}

// ListActivityEventsParams filters GET /v1/events.
type ListActivityEventsParams struct {
	ListParams
	Type string
	From time.Time
	To   time.Time
	// Since and Until bound the feed by time (they win over From / To).
	Since time.Time
	Until time.Time
	// Order is asc or desc.
	Order string
}

// UsagePoint is one day of a usage series (Day is YYYY-MM-DD).
type UsagePoint struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// UsageTrend compares a window against the previous one.
type UsageTrend struct {
	Current       float64  `json:"current"`
	Previous      float64  `json:"previous"`
	ChangePercent *float64 `json:"changePercent"`
	Direction     string   `json:"direction"`
}

// UsageMetricSeries is one metric's daily series. Total is nil for a
// non-additive metric (active users).
type UsageMetricSeries struct {
	Metric      string       `json:"metric"`
	Label       string       `json:"label"`
	Description string       `json:"description"`
	Additive    bool         `json:"additive"`
	Points      []UsagePoint `json:"points"`
	Peak        int64        `json:"peak"`
	Total       *int64       `json:"total"`
	Trend       *UsageTrend  `json:"trend"`
}

// UsageWindow is a day range.
type UsageWindow struct {
	From string `json:"from"`
	To   string `json:"to"`
	Days int    `json:"days,omitempty"`
}

// UsageReport is the GET /v1/usage report.
type UsageReport struct {
	Object             string              `json:"object"`
	Window             UsageWindow         `json:"window"`
	PreviousWindow     UsageWindow         `json:"previous_window"`
	Metrics            []UsageMetricSeries `json:"metrics"`
	MonthlyActiveUsers struct {
		Value      *int64      `json:"value"`
		WindowDays int         `json:"window_days"`
		Trend      *UsageTrend `json:"trend"`
	} `json:"monthly_active_users"`
}

// Events reads the activity feed. GET /v1/events.
func (s *AnalyticsService) Events(ctx context.Context, params ListActivityEventsParams) (*ActivityEventPage, error) {
	q := params.ListParams.values()
	if params.Type != "" {
		q.Set("type", params.Type)
	}
	if !params.From.IsZero() {
		q.Set("from", params.From.UTC().Format(time.RFC3339))
	}
	if !params.To.IsZero() {
		q.Set("to", params.To.UTC().Format(time.RFC3339))
	}
	if !params.Since.IsZero() {
		q.Set("since", params.Since.UTC().Format(time.RFC3339))
	}
	if !params.Until.IsZero() {
		q.Set("until", params.Until.UTC().Format(time.RFC3339))
	}
	if params.Order != "" {
		q.Set("order", params.Order)
	}
	out := &ActivityEventPage{}
	return out, s.client.get(ctx, "/v1/events", q, out)
}

// Usage reads usage analytics over the last days days (0 = server default).
// GET /v1/usage.
func (s *AnalyticsService) Usage(ctx context.Context, days int) (*UsageReport, error) {
	var q url.Values
	if days > 0 {
		q = url.Values{"days": {strconv.Itoa(days)}}
	}
	out := &UsageReport{}
	return out, s.client.get(ctx, "/v1/usage", q, out)
}
