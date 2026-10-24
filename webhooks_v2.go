package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Webhook destinations, health, replay, signature v2 and event-name aliases.

// Webhook destination types.
const (
	WebhookDestinationHTTPS           = "https"
	WebhookDestinationAWSEventBridge  = "aws_eventbridge"
	WebhookDestinationGCPPubSub       = "gcp_pubsub"
	WebhookDestinationCloudflareQueue = "cloudflare_queue"
)

// WebhookDestinationTypeInfo describes a destination type the API offers.
type WebhookDestinationTypeInfo struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Config      []string `json:"config"`
	Credentials []string `json:"credentials"`
}

// WebhookDestination is where an endpoint's deliveries go. Type is one of the
// WebhookDestination* constants; set the fields that type needs. Credentials
// are never returned (CredentialsSet says whether they are stored).
type WebhookDestination struct {
	Type string `json:"type"`
	// aws_eventbridge
	Region       string `json:"region,omitempty"`
	EventBusName string `json:"event_bus_name,omitempty"`
	Source       string `json:"source,omitempty"`
	// gcp_pubsub
	ProjectID string `json:"project_id,omitempty"`
	TopicID   string `json:"topic_id,omitempty"`
	// cloudflare_queue
	AccountID string `json:"account_id,omitempty"`
	QueueID   string `json:"queue_id,omitempty"`
	// CredentialsSet is returned by the API: whether credentials are stored.
	CredentialsSet *bool `json:"credentials_set,omitempty"`
}

// WebhookDestinationCredentials are your own credentials for an event
// destination (stored encrypted, write-only): access_key_id +
// secret_access_key (+ session_token) for AWS, service_account_json for GCP,
// api_token for Cloudflare.
type WebhookDestinationCredentials map[string]interface{}

// WebhookEndpointSettings are the create/update fields for the newer endpoint
// features. Embedded in CreateWebhookEndpointParams and
// UpdateWebhookEndpointParams.
type WebhookEndpointSettings struct {
	// EventNaming is canonical or legacy.
	EventNaming string `json:"event_naming,omitempty"`
	External    *bool  `json:"external,omitempty"`
	// SignatureVersions: v1, v2 (the HMAC also covers the URL).
	SignatureVersions []string `json:"signature_versions,omitempty"`
	// AlertContacts: up to 20 addresses; empty leaves the default (the
	// account's owners).
	AlertContacts []string `json:"alert_contacts,omitempty"`
	Description   string   `json:"description,omitempty"`
	// Destination is an event destination instead of an HTTPS url.
	Destination            *WebhookDestination           `json:"destination,omitempty"`
	DestinationCredentials WebhookDestinationCredentials `json:"destination_credentials,omitempty"`
}

// WebhookLastFailure is the last failed attempt.
type WebhookLastFailure struct {
	At         int64   `json:"at"`
	HTTPStatus *int    `json:"status"`
	Error      *string `json:"error"`
}

// WebhookAttempts24h counts the last 24 hours of attempts.
type WebhookAttempts24h struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// WebhookAlertsSent says which failure emails went out.
type WebhookAlertsSent struct {
	FirstSentAt    *int64 `json:"first_sent_at"`
	SecondSentAt   *int64 `json:"second_sent_at"`
	DisabledSentAt *int64 `json:"disabled_sent_at"`
}

// WebhookAutoDisableRule is when a failing endpoint is switched off.
type WebhookAutoDisableRule struct {
	AfterFailingMS                  int64  `json:"after_failing_ms"`
	AfterConsecutiveFailures        int    `json:"after_consecutive_failures"`
	ConsecutiveFailuresMinFailingMS int64  `json:"consecutive_failures_min_failing_ms"`
	Description                     string `json:"description"`
}

// WebhookRetention is how long events, delivery logs and replays are kept.
type WebhookRetention struct {
	EventsDays       int `json:"events_days"`
	DeliveryLogDays  int `json:"delivery_log_days"`
	ReplayWindowDays int `json:"replay_window_days"`
}

// WebhookReplayHint is the replay call that re-sends what a re-enabled
// endpoint missed.
type WebhookReplayHint struct {
	Since  int64  `json:"since"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Note   string `json:"note"`
}

// UpsertWebhookEndpointParams is the body of PUT /v1/webhook_endpoints/by_url:
// find-or-create by url.
type UpsertWebhookEndpointParams struct {
	URL           string   `json:"url"`
	EnabledEvents []string `json:"enabled_events,omitempty"`
	Active        *bool    `json:"active,omitempty"`
	WebhookEndpointSettings
	ProvisioningInput
}

// WebhookEndpointUpserted is the result of an upsert: the endpoint (Created
// says whether this call created it) and, then, its secret once.
type WebhookEndpointUpserted struct {
	WebhookEndpoint
	Secret string `json:"secret,omitempty"`
}

// WebhookTestResult is the inline result of TestNow.
type WebhookTestResult struct {
	Object              string  `json:"object"`
	DeliveryID          string  `json:"delivery_id"`
	EventID             string  `json:"event_id"`
	Status              string  `json:"status"`
	HTTPStatus          *int    `json:"http_status"`
	LatencyMS           *int64  `json:"latency_ms"`
	ResponseSnippet     *string `json:"response_snippet"`
	Error               *string `json:"error"`
	SignatureHeaderSent *string `json:"signature_header_sent"`
	WillRetry           bool    `json:"will_retry"`
}

// WebhookWindow bounds a bulk redelivery or replay. Since and Until are epoch
// ms (at most 90 days ago).
type WebhookWindow struct {
	Since int64 `json:"since,omitempty"`
	Until int64 `json:"until,omitempty"`
}

// SinceFailingSince is the Since keyword for a replay or redelivery: from the
// start of the endpoint's last failure streak. The server resolves it from the
// live failing_since, else disabled_at, else last_failing_since (kept after the
// endpoint recovers or is re-enabled), and answers 400 when the endpoint never
// failed.
const SinceFailingSince = "failing_since"

// RedeliverWebhookWindowParams is the body of POST
// /v1/webhook_endpoints/:id/redeliver.
type RedeliverWebhookWindowParams struct {
	WebhookWindow
	// Status is failed (default) or success: redeliver every event whose
	// latest attempt in the window has it.
	Status string `json:"status,omitempty"`
	// SinceKeyword sends since as a keyword instead of epoch ms (when Since is
	// unset): SinceFailingSince.
	SinceKeyword string `json:"-"`
}

// MarshalJSON sends SinceKeyword as since when Since is unset.
func (p RedeliverWebhookWindowParams) MarshalJSON() ([]byte, error) {
	type plain RedeliverWebhookWindowParams
	return marshalWithExtra(plain(p), sinceKeywordExtra(p.Since, p.SinceKeyword))
}

// ReplayWebhookParams is the body of POST /v1/webhook_endpoints/:id/replay.
type ReplayWebhookParams struct {
	WebhookWindow
	// EventType limits the replay (comma-separated event names).
	EventType string `json:"event_type,omitempty"`
	// SinceKeyword sends since as a keyword instead of epoch ms (when Since is
	// unset): SinceFailingSince replays everything since the endpoint started
	// failing.
	SinceKeyword string `json:"-"`
}

// MarshalJSON sends SinceKeyword as since when Since is unset.
func (p ReplayWebhookParams) MarshalJSON() ([]byte, error) {
	type plain ReplayWebhookParams
	return marshalWithExtra(plain(p), sinceKeywordExtra(p.Since, p.SinceKeyword))
}

func sinceKeywordExtra(since int64, keyword string) map[string]interface{} {
	if since == 0 && keyword != "" {
		return map[string]interface{}{"since": keyword}
	}
	return nil
}

// WebhookBulkResult is the answer to a bulk redelivery or replay.
type WebhookBulkResult struct {
	// Object is webhook_redelivery or webhook_replay.
	Object           string `json:"object"`
	EndpointID       string `json:"endpoint_id"`
	Queued           int    `json:"queued"`
	EventsConsidered int    `json:"events_considered,omitempty"`
	HasMore          bool   `json:"has_more"`
	// NextSince, when HasMore, is the Since that continues the call.
	NextSince *int64           `json:"next_since"`
	Retention WebhookRetention `json:"retention"`
}

// ListWebhookDeliveriesParams filters an endpoint's delivery log.
type ListWebhookDeliveriesParams struct {
	// Limit is 1-1000 (0 = the server default of 50).
	Limit         int
	StartingAfter string
	// Status is pending, success or failed.
	Status string
	// EventType is comma-separated event names.
	EventType string
	// Since and Until are epoch ms.
	Since int64
	Until int64
}

func (p ListWebhookDeliveriesParams) values() url.Values {
	v := url.Values{}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.StartingAfter != "" {
		v.Set("starting_after", p.StartingAfter)
	}
	if p.Status != "" {
		v.Set("status", p.Status)
	}
	if p.EventType != "" {
		v.Set("event_type", p.EventType)
	}
	if p.Since > 0 {
		v.Set("since", strconv.FormatInt(p.Since, 10))
	}
	if p.Until > 0 {
		v.Set("until", strconv.FormatInt(p.Until, 10))
	}
	return v
}

// ListWebhookEndpointsParams tunes the detailed endpoint list.
type ListWebhookEndpointsParams struct {
	// IncludeDeprecated adds the deprecated event spellings to the catalogue.
	IncludeDeprecated bool
	// Metadata filters on provisioning tags (metadata[key]=value).
	Metadata map[string]interface{}
}

// ListWithParams is ListDetailed with the include_deprecated and metadata[…]
// filters. GET /v1/webhook_endpoints.
func (s *WebhookEndpointsService) ListWithParams(ctx context.Context, params ListWebhookEndpointsParams) (*WebhookEndpointList, error) {
	out := &WebhookEndpointList{}
	q := MetadataQuery(params.Metadata)
	if params.IncludeDeprecated {
		q.Set("include_deprecated", "true")
	}
	return out, s.client.get(ctx, "/v1/webhook_endpoints", q, out)
}

// Get returns one endpoint with its health. GET /v1/webhook_endpoints/:id.
func (s *WebhookEndpointsService) Get(ctx context.Context, id string) (*WebhookEndpoint, error) {
	out := &WebhookEndpoint{}
	return out, s.client.get(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id), nil, out)
}

// UpsertByURL finds the endpoint with this url and updates it, or creates it
// (then Secret is set, once). Safe to run on every deploy. Pass
// WithIdempotencyKey. PUT /v1/webhook_endpoints/by_url.
func (s *WebhookEndpointsService) UpsertByURL(ctx context.Context, params UpsertWebhookEndpointParams, opts ...RequestOption) (*WebhookEndpointUpserted, error) {
	out := &WebhookEndpointUpserted{}
	return out, s.client.put(ctx, "/v1/webhook_endpoints/by_url", params, out, opts...)
}

// TestNow sends webhook.test now and returns the result: status, HTTP status,
// latency, response snippet, error and the signature header sent. wait is at
// most 10 s ("10s", "5000ms"); empty = "10s".
// POST /v1/webhook_endpoints/:id/test?wait=.
func (s *WebhookEndpointsService) TestNow(ctx context.Context, id, wait string, opts ...RequestOption) (*WebhookTestResult, error) {
	if wait == "" {
		wait = "10s"
	}
	out := &WebhookTestResult{}
	return out, s.client.postQ(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/test", url.Values{"wait": {wait}}, nil, out, opts...)
}

// RedeliverWindow redelivers every event whose latest attempt in the window
// has the given status (default failed). Pass WithIdempotencyKey.
// POST /v1/webhook_endpoints/:id/redeliver.
func (s *WebhookEndpointsService) RedeliverWindow(ctx context.Context, id string, params RedeliverWebhookWindowParams, opts ...RequestOption) (*WebhookBulkResult, error) {
	out := &WebhookBulkResult{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/redeliver", params, out, opts...)
}

// Replay re-sends everything since Since that the endpoint subscribes to and
// has not received. Pass WithIdempotencyKey.
// POST /v1/webhook_endpoints/:id/replay.
func (s *WebhookEndpointsService) Replay(ctx context.Context, id string, params ReplayWebhookParams, opts ...RequestOption) (*WebhookBulkResult, error) {
	out := &WebhookBulkResult{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/replay", params, out, opts...)
}

// DeliveriesWithParams returns an endpoint's delivery log with the status,
// event_type, since/until and starting_after filters (limit up to 1000).
// GET /v1/webhook_endpoints/:id/deliveries.
func (s *WebhookEndpointsService) DeliveriesWithParams(ctx context.Context, id string, params ListWebhookDeliveriesParams) (*CursorPage[WebhookDelivery], error) {
	out := &CursorPage[WebhookDelivery]{}
	return out, s.client.get(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/deliveries", params.values(), out)
}

// ---- delivery health & egress ------------------------------------------------

// Delivery target kinds.
const (
	DeliveryTargetWebhookEndpoint     = "webhook_endpoint"
	DeliveryTargetReferralConnection  = "referral_connection"
	DeliveryTargetBackchannelReceiver = "backchannel_receiver"
	DeliveryTargetIntegration         = "integration"
)

// DeliveryService is /v1/delivery_health and /v1/meta/egress_ips.
type DeliveryService struct{ client *Client }

// EgressIPs are the addresses deliveries leave from.
type EgressIPs struct {
	Object string `json:"object"`
	// Static is false when this deployment does not send from fixed addresses.
	Static    bool     `json:"static"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	AppliesTo []string `json:"applies_to"`
	Note      string   `json:"note"`
}

// DeliveryHealth is the delivery health of one outbound target.
type DeliveryHealth struct {
	Object   string  `json:"object"`
	Kind     string  `json:"kind"`
	TargetID string  `json:"target_id"`
	URL      *string `json:"url"`
	Label    *string `json:"label"`
	// State is healthy, failing or disabled.
	State               string              `json:"state"`
	FailingSince        *int64              `json:"failing_since"`
	DisabledAt          *int64              `json:"disabled_at"`
	LastSuccessAt       *int64              `json:"last_success_at"`
	LastFailure         *WebhookLastFailure `json:"last_failure"`
	ConsecutiveFailures int                 `json:"consecutive_failures"`
	SuccessRate24h      *float64            `json:"success_rate_24h"`
	Attempts24h         WebhookAttempts24h  `json:"attempts_24h"`
	AlertContacts       []string            `json:"alert_contacts"`
	Alerts              WebhookAlertsSent   `json:"alerts"`
}

// DeliveryHealthList is the delivery health list.
type DeliveryHealthList struct {
	Data           []DeliveryHealth `json:"data"`
	HasMore        bool             `json:"has_more"`
	UnhealthyCount int              `json:"unhealthy_count"`
}

// DeliveryHealthParams filters GET /v1/delivery_health.
type DeliveryHealthParams struct {
	// Kind is one of the DeliveryTarget* constants.
	Kind string
	// State is unhealthy or all.
	State string
}

// EgressIPs returns the addresses deliveries leave from (public).
// GET /v1/meta/egress_ips.
func (s *DeliveryService) EgressIPs(ctx context.Context) (*EgressIPs, error) {
	out := &EgressIPs{}
	return out, s.client.get(ctx, "/v1/meta/egress_ips", nil, out)
}

// Health returns the delivery health of every outbound target (webhooks, the
// referral connection, back-channel receivers, integrations).
// GET /v1/delivery_health.
func (s *DeliveryService) Health(ctx context.Context, params DeliveryHealthParams) (*DeliveryHealthList, error) {
	out := &DeliveryHealthList{}
	q := url.Values{}
	if params.Kind != "" {
		q.Set("kind", params.Kind)
	}
	if params.State != "" {
		q.Set("state", params.State)
	}
	return out, s.client.get(ctx, "/v1/delivery_health", q, out)
}

// SetAlertContacts sets who is emailed when a target fails; nil = the
// account's owners.
// PUT /v1/delivery_health/:kind/:targetId/alert_contacts.
func (s *DeliveryService) SetAlertContacts(ctx context.Context, kind, targetID string, alertContacts []string, opts ...RequestOption) (*DeliveryHealth, error) {
	out := &DeliveryHealth{}
	body := map[string]interface{}{"alert_contacts": alertContacts}
	return out, s.client.put(ctx, "/v1/delivery_health/"+url.PathEscape(kind)+"/"+url.PathEscape(targetID)+"/alert_contacts", body, out, opts...)
}

// ---- signature v2 ------------------------------------------------------------

// VerifyWebhookURL verifies a delivery that may carry a v2 signature: an
// endpoint with signature_versions including v2 signs HMAC-SHA256 over
// "<id>.<timestamp>.<url>.<body>", where url is the exact URL Atlas POSTed to
// (your endpoint's url), so a captured delivery cannot be replayed to another
// URL. A delivery verifies when any v1 entry (over id.timestamp.body) or any
// v2 entry matches; entries of unknown versions are ignored. With requireV2,
// only a v2 entry is accepted.
//
//	hook, err := atlas.VerifyWebhookURL(body, r.Header, secret, "https://app.example.com/hooks/atlas", true, nil)
func VerifyWebhookURL(body []byte, header http.Header, secret, endpointURL string, requireV2 bool, opts *WebhookVerifyOptions) (*VerifiedWebhook, error) {
	id := header.Get(WebhookHeaderID)
	tsRaw := header.Get(WebhookHeaderTimestamp)
	sig := header.Get(WebhookHeaderSignature)
	if id == "" || tsRaw == "" || sig == "" {
		return nil, ErrWebhookMissingHeaders
	}
	var v1 []string
	if !requireV2 {
		v1 = webhookSignaturesOf(sig, "v1")
	}
	v2 := webhookSignaturesOf(sig, "v2")
	if len(v1) == 0 && len(v2) == 0 {
		return nil, ErrWebhookMalformedSignature
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tsRaw), 10, 64)
	if err != nil {
		return nil, ErrWebhookStaleTimestamp
	}
	now := time.Now()
	tolerance := WebhookReplayTolerance
	if opts != nil {
		if !opts.Now.IsZero() {
			now = opts.Now
		}
		if opts.Tolerance > 0 {
			tolerance = opts.Tolerance
		}
	}
	diff := now.UnixMilli() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance.Milliseconds() {
		return nil, ErrWebhookStaleTimestamp
	}

	tsStr := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + tsStr + "."))
	mac.Write(body)
	expected1 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	mac2 := hmac.New(sha256.New, []byte(secret))
	mac2.Write([]byte(id + "." + tsStr + "." + endpointURL + "."))
	mac2.Write(body)
	expected2 := base64.StdEncoding.EncodeToString(mac2.Sum(nil))

	matched := false
	for _, c := range v1 {
		if hmac.Equal([]byte(expected1), []byte(c)) {
			matched = true
		}
	}
	for _, c := range v2 {
		if hmac.Equal([]byte(expected2), []byte(c)) {
			matched = true
		}
	}
	if !matched {
		return nil, ErrWebhookSignatureMismatch
	}
	out := &VerifiedWebhook{DeliveryID: id, Timestamp: ts}
	var event WebhookEvent
	if jsonUnmarshal(body, &event) == nil {
		out.Event = &event
	}
	return out, nil
}

// webhookSignaturesOf returns the entries of one version in an
// atlas-signature header ("v1,<base64> v2,<base64>").
func webhookSignaturesOf(header, version string) []string {
	var out []string
	for _, entry := range strings.Fields(header) {
		v, value, ok := strings.Cut(entry, ",")
		if ok && v == version && value != "" {
			out = append(out, value)
		}
	}
	return out
}

// ---- event names -------------------------------------------------------------

// WebhookEventAlias describes a deprecated event spelling.
type WebhookEventAlias struct {
	// Canonical is the event to subscribe to instead.
	Canonical string
	// Kind is "rename" (sent whenever the canonical event is) or "companion"
	// (only for some occurrences).
	Kind string
}

// WebhookEventAliases maps every deprecated event spelling to its canonical
// event. An endpoint that lists one by name still receives it (with the same
// atlas-id as the canonical event) until the sunset date.
var WebhookEventAliases = map[string]WebhookEventAlias{
	"session.ended":                   {"session.revoked", "companion"},
	"session.removed":                 {"session.revoked", "companion"},
	"organizationMembership.created":  {"organization_membership.created", "rename"},
	"organizationMembership.updated":  {"organization_membership.updated", "rename"},
	"organizationMembership.deleted":  {"organization_membership.deleted", "rename"},
	"organization.membership.deleted": {"organization_membership.deleted", "rename"},
	"organizationInvitation.created":  {"organization_invitation.created", "rename"},
	"organizationInvitation.accepted": {"organization_invitation.accepted", "rename"},
	"organizationInvitation.revoked":  {"organization_invitation.revoked", "rename"},
	"organizationInvitation.declined": {"organization_invitation.declined", "rename"},
	"organizationInvitation.resent":   {"organization_invitation.resent", "rename"},
	"teamMembership.created":          {"team_membership.created", "rename"},
	"teamMembership.deleted":          {"team_membership.deleted", "rename"},
	"appRole.created":                 {"app_role.created", "rename"},
	"appRole.updated":                 {"app_role.updated", "rename"},
	"appRole.deleted":                 {"app_role.deleted", "rename"},
	"organizationDomain.created":      {"organization_domain.created", "rename"},
	"organizationDomain.updated":      {"organization_domain.updated", "rename"},
	"organizationDomain.deleted":      {"organization_domain.deleted", "rename"},
	"organization.settings.updated":   {"organization_settings.updated", "rename"},
	"waitlistEntry.created":           {"waitlist_entry.created", "rename"},
	"waitlistEntry.updated":           {"waitlist_entry.updated", "rename"},
	"billing.subscription.created":    {"billing_subscription.created", "rename"},
	"billing.subscription.updated":    {"billing_subscription.updated", "rename"},
	"billing.subscription.canceled":   {"billing_subscription.canceled", "rename"},
	"billing.invoice.payment_failed":  {"billing_invoice.payment_failed", "rename"},
	"billing.trial.started":           {"billing_trial.started", "rename"},
	"billing.trial.will_end":          {"billing_trial.will_end", "rename"},
	"billing.trial.ended":             {"billing_trial.ended", "rename"},
	"entitlement.override.created":    {"entitlement_override.created", "rename"},
	"entitlement.override.deleted":    {"entitlement_override.deleted", "rename"},
	"entitlement.override.expired":    {"entitlement_override.expired", "rename"},
	"scimToken.created":               {"scim_token.created", "rename"},
	"scimToken.revoked":               {"scim_token.revoked", "rename"},
	"ssoConnection.created":           {"sso_connection.created", "rename"},
	"ssoConnection.updated":           {"sso_connection.updated", "rename"},
	"ssoConnection.deleted":           {"sso_connection.deleted", "rename"},
	"user.data_export.requested":      {"user.data_export_requested", "rename"},
	"user.deletion_cancelled":         {"user.deletion_canceled", "companion"},
}

// IsDeprecatedWebhookEvent reports whether name is a deprecated spelling.
func IsDeprecatedWebhookEvent(name string) bool {
	_, ok := WebhookEventAliases[name]
	return ok
}

// CanonicalWebhookEvent returns the canonical name for any spelling (an
// unknown name is returned unchanged).
func CanonicalWebhookEvent(name string) string {
	if a, ok := WebhookEventAliases[name]; ok {
		return a.Canonical
	}
	return name
}

// WebhookEventSpellings returns every name an event is known by: the
// canonical one, then its deprecated aliases (sorted).
func WebhookEventSpellings(name string) []string {
	canonical := CanonicalWebhookEvent(name)
	var aliases []string
	for alias, a := range WebhookEventAliases {
		if a.Canonical == canonical {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	return append([]string{canonical}, aliases...)
}

// Webhook events added with endpoint health, secret keys and the test event.
const (
	// WebhookEventWebhookEndpointFailing / Disabled / Recovered: an endpoint's
	// health changed (also sent as email to the alert contacts).
	WebhookEventWebhookEndpointFailing   = "webhook_endpoint.failing"
	WebhookEventWebhookEndpointDisabled  = "webhook_endpoint.disabled"
	WebhookEventWebhookEndpointRecovered = "webhook_endpoint.recovered"
	// WebhookEventDeliveryTargetFailing / Disabled / Recovered: the same for
	// any outbound target (referral connection, back-channel receiver,
	// integration).
	WebhookEventDeliveryTargetFailing   = "delivery_target.failing"
	WebhookEventDeliveryTargetDisabled  = "delivery_target.disabled"
	WebhookEventDeliveryTargetRecovered = "delivery_target.recovered"
	// WebhookEventWebhookTest is the synthetic test event.
	WebhookEventWebhookTest = "webhook.test"
	// WebhookEventSecretKeyExpiring / Revoked: a secret key is about to expire
	// (data carries days_left and threshold_days) or was revoked (audience
	// security).
	WebhookEventSecretKeyExpiring = "secret_key.expiring"
	WebhookEventSecretKeyRevoked  = "secret_key.revoked"

	// ScopeWebhooksReveal lets a key reveal webhook signing secrets.
	ScopeWebhooksReveal = "webhooks:reveal"
)
