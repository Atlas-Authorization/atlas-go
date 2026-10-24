package atlas

import (
	"context"
	"net/url"
)

// Notices, security advisories, sub-processors, audit export and the standard
// entitlements document.

// ---- notices & advisories ----------------------------------------------------

// InstanceNotice is a behaviour change that does (or does not) affect this
// instance.
type InstanceNotice struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Date   string `json:"date"`
	// Type is behavior_change, deprecation or new.
	Type string `json:"type"`
	// Tags are breaking, behaviour or security.
	Tags        []string `json:"tags"`
	Title       string   `json:"title"`
	Summary     string   `json:"summary"`
	Affects     []string `json:"affects"`
	DocsURL     string   `json:"docs_url"`
	ChangelogID string   `json:"changelog_id"`
	Applies     bool     `json:"applies"`
	// Detail is one sentence about this instance.
	Detail         *string `json:"detail"`
	Count          *int    `json:"count"`
	FirstSeenAt    *int64  `json:"first_seen_at"`
	EmailedAt      *int64  `json:"emailed_at"`
	AcknowledgedAt *int64  `json:"acknowledged_at"`
}

// InstanceNoticeList is the notice list with its counts.
type InstanceNoticeList struct {
	Object         string           `json:"object"`
	Data           []InstanceNotice `json:"data"`
	HasMore        bool             `json:"has_more"`
	Unacknowledged int              `json:"unacknowledged"`
	ChangelogURL   string           `json:"changelog_url"`
}

// NoticesService is /v1/instance/notices.
type NoticesService struct{ client *Client }

// List returns the behaviour changes that affect this instance; all=true also
// lists the ones that do not apply. GET /v1/instance/notices.
func (s *NoticesService) List(ctx context.Context, all bool) (*InstanceNoticeList, error) {
	out := &InstanceNoticeList{}
	var q url.Values
	if all {
		q = url.Values{"all": {"true"}}
	}
	return out, s.client.get(ctx, "/v1/instance/notices", q, out)
}

// Acknowledge marks a notice as read. POST /v1/instance/notices/:id/acknowledge.
func (s *NoticesService) Acknowledge(ctx context.Context, id string, opts ...RequestOption) (*InstanceNotice, error) {
	out := &InstanceNotice{}
	return out, s.client.post(ctx, "/v1/instance/notices/"+url.PathEscape(id)+"/acknowledge", nil, out, opts...)
}

// SecurityAdvisory is an advisory, with whether it applies to this instance
// (absent on the public catalog).
type SecurityAdvisory struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Published string `json:"published"`
	// Severity is low, medium, high or critical.
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Affects  []string `json:"affects"`
	FixedOn  string   `json:"fixed_on"`
	Action   string   `json:"action"`
	DocsURL  string   `json:"docs_url"`
	// Applies and the fields below are absent on the public catalog.
	Applies        *bool   `json:"applies,omitempty"`
	Detail         *string `json:"detail,omitempty"`
	Count          *int    `json:"count,omitempty"`
	FirstSeenAt    *int64  `json:"first_seen_at,omitempty"`
	EmailedAt      *int64  `json:"emailed_at,omitempty"`
	AcknowledgedAt *int64  `json:"acknowledged_at,omitempty"`
}

// SecurityAdvisoryList is the advisory list with the count that applies.
type SecurityAdvisoryList struct {
	Object   string             `json:"object"`
	Data     []SecurityAdvisory `json:"data"`
	HasMore  bool               `json:"has_more"`
	Applying int                `json:"applying"`
}

// SecurityAdvisoriesService is /v1/security_advisories.
type SecurityAdvisoriesService struct{ client *Client }

// List returns every advisory with whether it applies to this instance.
// GET /v1/security_advisories.
func (s *SecurityAdvisoriesService) List(ctx context.Context) (*SecurityAdvisoryList, error) {
	out := &SecurityAdvisoryList{}
	return out, s.client.get(ctx, "/v1/security_advisories", nil, out)
}

// Acknowledge marks an advisory as handled.
// POST /v1/security_advisories/:id/acknowledge.
func (s *SecurityAdvisoriesService) Acknowledge(ctx context.Context, id string, opts ...RequestOption) (*SecurityAdvisory, error) {
	out := &SecurityAdvisory{}
	return out, s.client.post(ctx, "/v1/security_advisories/"+url.PathEscape(id)+"/acknowledge", nil, out, opts...)
}

// Catalog returns the public catalog (no instance data).
// GET /v1/public/security_advisories.
func (s *SecurityAdvisoriesService) Catalog(ctx context.Context) (*ListPage[SecurityAdvisory], error) {
	out := &ListPage[SecurityAdvisory]{}
	return out, s.client.get(ctx, "/v1/public/security_advisories", nil, out)
}

// ---- sub-processors ----------------------------------------------------------

// SubProcessor is a party that processes the instance's end-user data.
type SubProcessor struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	// Role is atlas_sub_processor or engaged_by_you.
	Role string `json:"role"`
	// Source is atlas, integration, referral_platform, consent_manager,
	// email_provider, sms_provider, log_stream, audit_export or
	// webhook_endpoint.
	Source    string   `json:"source"`
	Purpose   string   `json:"purpose"`
	Data      []string `json:"data"`
	Location  *string  `json:"location"`
	EnabledBy *string  `json:"enabled_by"`
	URL       *string  `json:"url"`
}

// SubProcessorList says who processes this instance's end-user data, and in
// which role.
type SubProcessorList struct {
	Object     string            `json:"object"`
	InstanceID string            `json:"instance_id"`
	Roles      map[string]string `json:"roles"`
	DataRegion *string           `json:"data_region"`
	Processor  struct {
		Name string `json:"name"`
		Role string `json:"role"`
		URL  string `json:"url"`
	} `json:"processor"`
	AtlasSubProcessors []SubProcessor `json:"atlas_sub_processors"`
	EngagedByYou       []SubProcessor `json:"engaged_by_you"`
	DPAURL             string         `json:"dpa_url"`
}

// SubProcessorsService is /v1/instance/sub_processors.
type SubProcessorsService struct{ client *Client }

// Get returns the sub-processor view. GET /v1/instance/sub_processors.
func (s *SubProcessorsService) Get(ctx context.Context) (*SubProcessorList, error) {
	out := &SubProcessorList{}
	return out, s.client.get(ctx, "/v1/instance/sub_processors", nil, out)
}

// ---- audit export ------------------------------------------------------------

// AuditExportCursor is how far an export has read.
type AuditExportCursor struct {
	ID        *string `json:"id"`
	CreatedAt *int64  `json:"created_at"`
}

// AuditExport forwards the audit log to a webhook or an S3-compatible bucket.
type AuditExport struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	// Type is webhook or s3.
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	// Status is active or failing.
	Status       string   `json:"status"`
	ActionFilter []string `json:"action_filter"`
	// Destination holds the non-secret fields plus has_* markers.
	Destination         map[string]interface{} `json:"destination"`
	Cursor              AuditExportCursor      `json:"cursor"`
	ConsecutiveFailures int                    `json:"consecutive_failures"`
	LastError           *string                `json:"last_error"`
	LastDeliveredAt     *int64                 `json:"last_delivered_at"`
	ExportedCount       int64                  `json:"exported_count"`
	MandatoryActions    []string               `json:"mandatory_actions"`
	// Secret is a webhook export's signing secret, on create and rotate only.
	Secret    string `json:"secret,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// AuditExportList is the export list plus the always-exported actions.
type AuditExportList struct {
	Object           string        `json:"object"`
	Data             []AuditExport `json:"data"`
	HasMore          bool          `json:"has_more"`
	MandatoryActions []string      `json:"mandatory_actions"`
}

// CreateAuditExportParams is the body of POST /v1/audit_exports. Destination
// is {url} for a webhook, or {endpoint, bucket, region?, prefix?,
// access_key_id, secret_access_key} for s3.
type CreateAuditExportParams struct {
	Name string `json:"name"`
	// Type is webhook or s3.
	Type        string                 `json:"type"`
	Destination map[string]interface{} `json:"destination"`
	// ActionFilter lists action names or prefixes; key and data-rights events
	// are always exported. Empty = everything.
	ActionFilter []string `json:"action_filter,omitempty"`
	Enabled      *bool    `json:"enabled,omitempty"`
	// BackfillHours also exports the last N hours (0-720).
	BackfillHours int `json:"backfill_hours,omitempty"`
}

// UpdateAuditExportParams is the body of PATCH /v1/audit_exports/:id.
// Destination is merged; a secret left out is kept. ClearActionFilter sends
// action_filter as null (everything).
type UpdateAuditExportParams struct {
	Name              string                 `json:"name,omitempty"`
	Destination       map[string]interface{} `json:"destination,omitempty"`
	ActionFilter      []string               `json:"action_filter,omitempty"`
	ClearActionFilter bool                   `json:"-"`
	Enabled           *bool                  `json:"enabled,omitempty"`
}

// MarshalJSON sends ClearActionFilter as a null action_filter.
func (p UpdateAuditExportParams) MarshalJSON() ([]byte, error) {
	type plain UpdateAuditExportParams
	var extra map[string]interface{}
	if p.ClearActionFilter {
		extra = map[string]interface{}{"action_filter": nil}
	}
	return marshalWithExtra(plain(p), extra)
}

// AuditCloudEventActor is who acted, in an exported audit event.
type AuditCloudEventActor struct {
	Type      string  `json:"type"`
	ID        *string `json:"id"`
	KeyName   *string `json:"key_name"`
	KeyPrefix *string `json:"key_prefix"`
}

// AuditCloudEventData is the data of an exported audit event.
type AuditCloudEventData struct {
	Actor    AuditCloudEventActor `json:"actor"`
	Action   string               `json:"action"`
	Resource *struct {
		Type *string `json:"type"`
		ID   *string `json:"id"`
	} `json:"resource"`
	Org *struct {
		ID string `json:"id"`
	} `json:"org"`
	Trace    *string                `json:"trace"`
	IP       *string                `json:"ip"`
	Metadata map[string]interface{} `json:"metadata"`
}

// AuditCloudEvent is an audit entry as an export sends it (CloudEvents 1.0,
// structured JSON; Type is net.atlasauth.audit.<action>).
type AuditCloudEvent struct {
	SpecVersion     string              `json:"specversion"`
	ID              string              `json:"id"`
	Source          string              `json:"source"`
	Type            string              `json:"type"`
	Subject         string              `json:"subject,omitempty"`
	Time            string              `json:"time"`
	DataContentType string              `json:"datacontenttype"`
	AtlasInstance   string              `json:"atlasinstance"`
	Data            AuditCloudEventData `json:"data"`
}

// AuditExportTestResult is the answer to a test send.
type AuditExportTestResult struct {
	Object   string          `json:"object"`
	ID       string          `json:"id"`
	OK       bool            `json:"ok"`
	Status   *int            `json:"status"`
	Error    *string         `json:"error"`
	Location *string         `json:"location"`
	Event    AuditCloudEvent `json:"event"`
}

// AuditExportsService is /v1/audit_exports.
type AuditExportsService struct{ client *Client }

// List returns the exports. GET /v1/audit_exports.
func (s *AuditExportsService) List(ctx context.Context) (*AuditExportList, error) {
	out := &AuditExportList{}
	return out, s.client.get(ctx, "/v1/audit_exports", nil, out)
}

// Get returns one export. GET /v1/audit_exports/:id.
func (s *AuditExportsService) Get(ctx context.Context, id string) (*AuditExport, error) {
	out := &AuditExport{}
	return out, s.client.get(ctx, "/v1/audit_exports/"+url.PathEscape(id), nil, out)
}

// Create adds an export; a webhook export's signing secret is in this
// response only. Pass WithIdempotencyKey. POST /v1/audit_exports.
func (s *AuditExportsService) Create(ctx context.Context, params CreateAuditExportParams, opts ...RequestOption) (*AuditExport, error) {
	out := &AuditExport{}
	return out, s.client.post(ctx, "/v1/audit_exports", params, out, opts...)
}

// Update changes an export. PATCH /v1/audit_exports/:id.
func (s *AuditExportsService) Update(ctx context.Context, id string, params UpdateAuditExportParams, opts ...RequestOption) (*AuditExport, error) {
	out := &AuditExport{}
	return out, s.client.patch(ctx, "/v1/audit_exports/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes an export. DELETE /v1/audit_exports/:id.
func (s *AuditExportsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/audit_exports/"+url.PathEscape(id), out, opts...)
}

// Test sends one synthetic audit_export.test event now.
// POST /v1/audit_exports/:id/test.
func (s *AuditExportsService) Test(ctx context.Context, id string, opts ...RequestOption) (*AuditExportTestResult, error) {
	out := &AuditExportTestResult{}
	return out, s.client.post(ctx, "/v1/audit_exports/"+url.PathEscape(id)+"/test", nil, out, opts...)
}

// RotateSecret rotates a webhook export's signing secret.
// POST /v1/audit_exports/:id/rotate_secret.
func (s *AuditExportsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*AuditExport, error) {
	out := &AuditExport{}
	return out, s.client.post(ctx, "/v1/audit_exports/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
}

// ---- entitlements ------------------------------------------------------------

// EntitlementsService is /v1/entitlements.
type EntitlementsService struct{ client *Client }

// EntitlementItem is one entitlement of a subject.
type EntitlementItem struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	Limit   *int64 `json:"limit,omitempty"`
	Used    *int64 `json:"used,omitempty"`
	// Source is plan, override or internal.
	Source string `json:"source"`
}

// Entitlements is the standard entitlements document (JSON Schema
// https://atlasauth.net/schemas/entitlements-v1.json): one shape any product
// can serve.
type Entitlements struct {
	Object  string `json:"object"`
	Schema  string `json:"$schema,omitempty"`
	Subject struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"subject"`
	Plan *string `json:"plan"`
	// PlanSource is plan (a subscription), override (a sales-led grant),
	// internal (an owner account, never revenue) or none.
	PlanSource   string            `json:"planSource"`
	Entitlements []EntitlementItem `json:"entitlements"`
}

// Get returns the entitlements of a user or organization. subjectType is
// "user" or "org". GET /v1/entitlements.
func (s *EntitlementsService) Get(ctx context.Context, subjectType, subjectID string) (*Entitlements, error) {
	out := &Entitlements{}
	q := url.Values{"subject_type": {subjectType}, "subject_id": {subjectID}}
	return out, s.client.get(ctx, "/v1/entitlements", q, out)
}
