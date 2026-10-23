package atlas

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Atlas policy source protocol v1 - the system that SERVES an Atlas
// instance's policy documents (a CMS, a docs platform, your own service).
//
//	Atlas -> you:  GET {endpoint_url}/policies            (full feed)
//	               GET {endpoint_url}/policies?key=<key>  (one policy, after your event)
//	  signed with the source's signing secret: atlas-id, atlas-timestamp (epoch
//	  ms) and atlas-signature "v1,<base64 HMAC-SHA256>" over
//	  "{atlas-id}.{atlas-timestamp}.GET\n{path+query}". Check it with
//	  VerifyPolicyFeedRequest, then answer a PolicyFeed.
//	You -> Atlas:  POST {webhook_url} (from PolicySource.Get), a
//	  PolicySourceEvent signed with the same secret by SignPolicySourceEvent.
//	  Atlas then re-fetches that policy; it never stores content from the event.
//
// Matches verifyPolicyFeedRequest / signPolicySourceEvent in @atlasauth/backend.

// PolicySourceProtocolVersion is the protocol version Atlas sends in the
// atlas-policies-version header.
const PolicySourceProtocolVersion = "2026-10-24"

// PolicySourceVersionHeader is the header carrying PolicySourceProtocolVersion.
const PolicySourceVersionHeader = "Atlas-Policies-Version"

// PolicySource is the instance's external policy source. The signing secret
// is never returned, only SigningSecretSet.
type PolicySource struct {
	Object           string  `json:"object"`
	Enabled          bool    `json:"enabled"`
	EndpointURL      *string `json:"endpoint_url"`
	SigningSecretSet bool    `json:"signing_secret_set"`
	// Sync is "webhook" or "poll".
	Sync                string `json:"sync"`
	PollIntervalMinutes int    `json:"poll_interval_minutes"`
	// WebhookURL is where your source sends policy.published / policy.retired events.
	WebhookURL      *string `json:"webhook_url"`
	ProtocolVersion string  `json:"protocol_version"`
	LastSyncedAt    *int64  `json:"last_synced_at"`
	LastSyncOK      *bool   `json:"last_sync_ok"`
	LastSyncError   *string `json:"last_sync_error"`
	NextPollAt      *int64  `json:"next_poll_at"`
}

// UpdatePolicySourceParams is the body of PUT /v1/instance/policy_source: only
// the fields set change; Clear names fields to send as null (endpoint_url,
// signing_secret). Enabling needs EndpointURL and SigningSecret.
type UpdatePolicySourceParams struct {
	Enabled *bool `json:"enabled,omitempty"`
	// EndpointURL is the base URL; Atlas calls GET {EndpointURL}/policies.
	EndpointURL string `json:"endpoint_url,omitempty"`
	// SigningSecret is write-only (a whsec_ secret works).
	SigningSecret string `json:"signing_secret,omitempty"`
	// Sync is "webhook" or "poll".
	Sync string `json:"sync,omitempty"`
	// PollIntervalMinutes (poll mode): 5-1440.
	PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty"`
	Clear               []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdatePolicySourceParams) MarshalJSON() ([]byte, error) {
	type plain UpdatePolicySourceParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
}

// PolicySourceDelivery is one entry of the delivery log.
type PolicySourceDelivery struct {
	Object     string                 `json:"object"`
	ID         string                 `json:"id"`
	Direction  string                 `json:"direction"` // outbound or inbound
	Kind       string                 `json:"kind"`      // fetch, test, poll or webhook
	Status     string                 `json:"status"`    // ok, failed or rejected
	HTTPStatus *int                   `json:"http_status"`
	Error      *string                `json:"error"`
	EventType  *string                `json:"event_type"`
	Policy     *string                `json:"policy"`
	Version    *string                `json:"version"`
	URL        *string                `json:"url"`
	Changes    map[string]interface{} `json:"changes"`
	LatencyMS  *int                   `json:"latency_ms"`
	CreatedAt  int64                  `json:"created_at"`
}

// PolicySourceFeedSummary is one policy as the feed lists it.
type PolicySourceFeedSummary struct {
	Key      string   `json:"key"`
	Title    string   `json:"title"`
	Versions []string `json:"versions"`
}

// PolicySourceTestResult is the answer to a test: a signed fetch, validated, not stored.
type PolicySourceTestResult struct {
	Object     string                    `json:"object"`
	OK         bool                      `json:"ok"`
	HTTPStatus *int                      `json:"http_status"`
	LatencyMS  *int                      `json:"latency_ms"`
	Error      *string                   `json:"error"`
	Warnings   []string                  `json:"warnings"`
	Policies   []PolicySourceFeedSummary `json:"policies"`
	Delivery   *PolicySourceDelivery     `json:"delivery,omitempty"`
}

// PolicySourceChanges is what a sync did, by policy key (or key@version).
type PolicySourceChanges struct {
	Created   []string `json:"created"`
	Updated   []string `json:"updated"`
	Published []string `json:"published"`
	Unchanged []string `json:"unchanged"`
	Rejected  []string `json:"rejected"`
	Retired   []string `json:"retired"`
}

// PolicySourceSyncResult is the answer to a sync.
type PolicySourceSyncResult struct {
	Object   string                `json:"object"`
	OK       bool                  `json:"ok"`
	Error    *string               `json:"error"`
	Warnings []string              `json:"warnings"`
	Changes  *PolicySourceChanges  `json:"changes"`
	Delivery *PolicySourceDelivery `json:"delivery,omitempty"`
}

// ListPolicySourceDeliveriesParams filters the delivery log.
type ListPolicySourceDeliveriesParams struct {
	Limit         int
	StartingAfter string
	Kind          string
	Status        string
}

func (p ListPolicySourceDeliveriesParams) values() url.Values {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.StartingAfter != "" {
		q.Set("starting_after", p.StartingAfter)
	}
	if p.Kind != "" {
		q.Set("kind", p.Kind)
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	return q
}

// PolicySourceService is /v1/instance/policy_source.
type PolicySourceService struct{ client *Client }

// Get reads the source: endpoint, sync mode, the webhook URL to give the
// source and the last sync outcome. GET /v1/instance/policy_source.
func (s *PolicySourceService) Get(ctx context.Context) (*PolicySource, error) {
	out := &PolicySource{}
	return out, s.client.get(ctx, "/v1/instance/policy_source", nil, out)
}

// Update configures the source. PUT /v1/instance/policy_source.
func (s *PolicySourceService) Update(ctx context.Context, params UpdatePolicySourceParams, opts ...RequestOption) (*PolicySource, error) {
	out := &PolicySource{}
	return out, s.client.put(ctx, "/v1/instance/policy_source", params, out, opts...)
}

// Delete disconnects the source (its policies and history stay; they stop
// syncing). DELETE /v1/instance/policy_source.
func (s *PolicySourceService) Delete(ctx context.Context, opts ...RequestOption) (*PolicySource, error) {
	out := &PolicySource{}
	return out, s.client.del(ctx, "/v1/instance/policy_source", out, opts...)
}

// Test does a signed fetch of the feed, validated but not stored.
// POST /v1/instance/policy_source/test.
func (s *PolicySourceService) Test(ctx context.Context) (*PolicySourceTestResult, error) {
	out := &PolicySourceTestResult{}
	return out, s.client.post(ctx, "/v1/instance/policy_source/test", nil, out)
}

// Sync fetches the feed now and stores it. A published version whose content
// changed at the source is refused: publish a new version there.
// POST /v1/instance/policy_source/sync.
func (s *PolicySourceService) Sync(ctx context.Context) (*PolicySourceSyncResult, error) {
	out := &PolicySourceSyncResult{}
	return out, s.client.post(ctx, "/v1/instance/policy_source/sync", nil, out)
}

// ListDeliveries returns the delivery log (every fetch, test, poll and
// inbound event), newest first. GET /v1/instance/policy_source/deliveries.
func (s *PolicySourceService) ListDeliveries(ctx context.Context, params ListPolicySourceDeliveriesParams) (*CursorPage[PolicySourceDelivery], error) {
	out := &CursorPage[PolicySourceDelivery]{}
	return out, s.client.get(ctx, "/v1/instance/policy_source/deliveries", params.values(), out)
}

// --- The protocol, for the system that serves the feed ------------------------

// PolicyFeedVersion is one version in the feed. Send one of ContentHTML /
// ContentMarkdown, or ContentURL for Atlas to snapshot (at most 512 KB).
type PolicyFeedVersion struct {
	Version string `json:"version"`
	// PublishedAt and EffectiveAt are epoch ms (int64) or ISO 8601 strings;
	// EffectiveAt is when Atlas starts asking users (default PublishedAt).
	PublishedAt      interface{} `json:"published_at,omitempty"`
	EffectiveAt      interface{} `json:"effective_at,omitempty"`
	ContentHTML      string      `json:"content_html,omitempty"`
	ContentMarkdown  string      `json:"content_markdown,omitempty"`
	ContentURL       string      `json:"content_url,omitempty"`
	SummaryOfChanges string      `json:"summary_of_changes,omitempty"`
	Locale           string      `json:"locale,omitempty"`
}

// PolicyFeedPolicy is one policy in the feed.
type PolicyFeedPolicy struct {
	// Key is a slug: lowercase letters, digits, _ and -.
	Key       string              `json:"key"`
	Title     string              `json:"title"`
	Display   string              `json:"display,omitempty"`
	Required  *bool               `json:"required,omitempty"`
	AppliesTo string              `json:"applies_to,omitempty"`
	Versions  []PolicyFeedVersion `json:"versions"`
}

// PolicyFeed is the answer to GET {endpoint_url}/policies.
type PolicyFeed struct {
	Object   string             `json:"object"`
	Policies []PolicyFeedPolicy `json:"policies"`
}

// NewPolicyFeed wraps policies in a feed.
func NewPolicyFeed(policies ...PolicyFeedPolicy) PolicyFeed {
	if policies == nil {
		policies = []PolicyFeedPolicy{}
	}
	return PolicyFeed{Object: "policy_list", Policies: policies}
}

// Policy source event types.
const (
	PolicySourceEventPublished = "policy.published"
	PolicySourceEventRetired   = "policy.retired"
)

// PolicySourceEvent is an event you send to Atlas's webhook_url.
type PolicySourceEvent struct {
	// Type is PolicySourceEventPublished or PolicySourceEventRetired.
	Type string `json:"type"`
	Key  string `json:"key"`
	// Version is required for policy.published: the label to re-fetch.
	Version string `json:"version,omitempty"`
	// OccurredAt is ISO 8601; default now.
	OccurredAt string `json:"-"`
}

// Errors returned by VerifyPolicyFeedRequest.
var (
	ErrPolicyFeedWrongMethod       = errors.New("atlas policy feed: not a GET")
	ErrPolicyFeedMissingHeaders    = errors.New("atlas policy feed: missing one of the atlas-id/atlas-timestamp/atlas-signature headers")
	ErrPolicyFeedMalformedSig      = errors.New("atlas policy feed: malformed signature header")
	ErrPolicyFeedStaleTimestamp    = errors.New("atlas policy feed: stale or invalid timestamp")
	ErrPolicyFeedSignatureMismatch = errors.New("atlas policy feed: signature mismatch")
)

// PolicyFeedRequest is a feed request whose signature and timestamp checked out.
type PolicyFeedRequest struct {
	// DeliveryID is the signed atlas-id header.
	DeliveryID string
	// Timestamp is the signed atlas-timestamp header (epoch ms).
	Timestamp int64
	// Key is the key query parameter when Atlas asks for one policy, else "".
	Key string
	// ProtocolVersion is the atlas-policies-version header, when sent (not signed).
	ProtocolVersion string
}

// PolicyFeedVerifyOptions tunes VerifyPolicyFeedRequest. The zero value uses the defaults.
type PolicyFeedVerifyOptions struct {
	// Now overrides the current time (tests).
	Now time.Time
	// Tolerance overrides WebhookReplayTolerance (5 minutes).
	Tolerance time.Duration
}

func policyMAC(secret, id, ts, payload string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + ts + "." + payload))
	return mac.Sum(nil)
}

// VerifyPolicyFeedRequest verifies Atlas's signed GET of your feed. Pass the
// request's method, its path AND query exactly as received (r.URL.RequestURI())
// and its headers. The atlas-signature header may carry several
// "v1,<base64>" values; one match is enough. A timestamp more than five
// minutes from now is refused.
//
//	func feed(w http.ResponseWriter, r *http.Request) {
//		req, err := atlas.VerifyPolicyFeedRequest(r.Method, r.URL.RequestURI(), r.Header, secret, nil)
//		if err != nil { w.WriteHeader(401); return }
//		json.NewEncoder(w).Encode(buildFeed(req.Key)) // one policy when req.Key is set
//	}
func VerifyPolicyFeedRequest(method, pathAndQuery string, header http.Header, secret string, opts *PolicyFeedVerifyOptions) (*PolicyFeedRequest, error) {
	if method != "" && strings.ToUpper(method) != http.MethodGet {
		return nil, ErrPolicyFeedWrongMethod
	}
	id := header.Get("Atlas-Id")
	tsRaw := header.Get("Atlas-Timestamp")
	sig := header.Get("Atlas-Signature")
	if id == "" || tsRaw == "" || sig == "" {
		return nil, ErrPolicyFeedMissingHeaders
	}
	var provided [][]byte
	for _, entry := range strings.Fields(sig) {
		if !strings.HasPrefix(entry, "v1,") {
			continue
		}
		raw := entry[3:]
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
			if err != nil {
				b = nil
			}
		}
		provided = append(provided, b)
	}
	if len(provided) == 0 {
		return nil, ErrPolicyFeedMalformedSig
	}
	ts, err := strconv.ParseFloat(strings.TrimSpace(tsRaw), 64)
	if err != nil || math.IsNaN(ts) || math.IsInf(ts, 0) {
		return nil, ErrPolicyFeedStaleTimestamp
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
	if math.Abs(float64(now.UnixMilli())-ts) > float64(tolerance.Milliseconds()) {
		return nil, ErrPolicyFeedStaleTimestamp
	}
	expected := policyMAC(secret, id, tsRaw, "GET\n"+pathAndQuery)
	matched := false
	for _, candidate := range provided { // no early exit
		if hmac.Equal(expected, candidate) {
			matched = true
		}
	}
	if !matched {
		return nil, ErrPolicyFeedSignatureMismatch
	}
	out := &PolicyFeedRequest{DeliveryID: id, Timestamp: int64(ts), ProtocolVersion: header.Get(PolicySourceVersionHeader)}
	if q := strings.IndexByte(pathAndQuery, '?'); q != -1 {
		if vals, _ := url.ParseQuery(pathAndQuery[q+1:]); vals != nil {
			out.Key = vals.Get("key")
		}
	}
	return out, nil
}

// PolicyFeedHandler serves a feed from build, which gets the key Atlas asked
// for ("" for the whole feed). A request that fails verification is a 401.
func PolicyFeedHandler(secret string, build func(ctx context.Context, key string) (PolicyFeed, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := VerifyPolicyFeedRequest(r.Method, r.URL.RequestURI(), r.Header, secret, nil)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		feed, err := build(r.Context(), req.Key)
		if err != nil {
			http.Error(w, "feed unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(feed)
	})
}

// SignedPolicySourceEvent is a signed event: send Body byte-for-byte with Header.
type SignedPolicySourceEvent struct {
	Body   []byte
	Header http.Header
}

// Request builds the POST to webhookURL (the webhook_url from PolicySource.Get).
func (e *SignedPolicySourceEvent) Request(ctx context.Context, webhookURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(e.Body))
	if err != nil {
		return nil, err
	}
	req.Header = e.Header.Clone()
	return req, nil
}

// PolicySourceEventOptions tunes SignPolicySourceEvent.
type PolicySourceEventOptions struct {
	// ID is the atlas-id (default evt_<random>); keep it the same on retries.
	ID string
	// Now overrides the clock (tests).
	Now time.Time
}

// SignPolicySourceEvent signs a policy.published / policy.retired event for
// POST {webhook_url}: atlas-id, atlas-timestamp (ms) and atlas-signature
// "v1,<base64 HMAC-SHA256 of {id}.{ts}.{body}>". Atlas also accepts Standard
// Webhooks signatures if you prefer a library for that.
//
//	e, _ := atlas.SignPolicySourceEvent(atlas.PolicySourceEvent{Type: atlas.PolicySourceEventPublished, Key: "tos", Version: "2026-10-24"}, secret, nil)
//	req, _ := e.Request(ctx, webhookURL)
//	resp, err := http.DefaultClient.Do(req)
func SignPolicySourceEvent(event PolicySourceEvent, secret string, opts *PolicySourceEventOptions) (*SignedPolicySourceEvent, error) {
	var o PolicySourceEventOptions
	if opts != nil {
		o = *opts
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	if o.ID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		o.ID = "evt_" + hex.EncodeToString(b)
	}
	if event.Type != PolicySourceEventPublished && event.Type != PolicySourceEventRetired {
		return nil, errors.New("atlas policy source: event type must be policy.published or policy.retired")
	}
	if event.Type == PolicySourceEventPublished && event.Version == "" {
		return nil, errors.New("atlas policy source: policy.published needs a version")
	}
	occurred := event.OccurredAt
	if occurred == "" {
		occurred = now.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	payload := struct {
		OccurredAt string `json:"occurred_at"`
		Type       string `json:"type"`
		Key        string `json:"key"`
		Version    string `json:"version,omitempty"`
	}{occurred, event.Type, event.Key, event.Version}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	body := bytes.TrimRight(buf.Bytes(), "\n")
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	h := http.Header{}
	h.Set("Atlas-Id", o.ID)
	h.Set("Atlas-Timestamp", ts)
	h.Set("Atlas-Signature", "v1,"+base64.StdEncoding.EncodeToString(policyMAC(secret, o.ID, ts, string(body))))
	h.Set("Content-Type", "application/json")
	return &SignedPolicySourceEvent{Body: body, Header: h}, nil
}
