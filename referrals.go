package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ReferralsService is the /v1/instance/referrals namespace: the instance's
// connection to a referral platform, the connection test and the call log.
//
// With referrals on, every interactive sign-up is reported to the platform
// before user.created is sent and before the session is issued; the answer
// lands on the user (Referral, ReferralCode, ReferralLink). A slow or failing
// platform never fails a sign-up: the call is retried, and
// user.referral_attributed is sent when it resolves. SigningSecret and APIKey
// are write-only: reads return SigningSecretSet / APIKeySet.
type ReferralsService struct{ client *Client }

// ReferralProviderCapabilities says what a provider can do. An operation it
// lacks is recorded as skipped.
type ReferralProviderCapabilities struct {
	Signup     bool `json:"signup"`
	Erase      bool `json:"erase"`
	Export     bool `json:"export"`
	Partner    bool `json:"partner"`
	AutoEnroll bool `json:"auto_enroll"`
	Signal     bool `json:"signal"`
}

// ReferralProvider is a referral provider Atlas supports.
type ReferralProvider struct {
	// ID is "webhook" (the Atlas referral protocol) or a vendor adapter id.
	ID           string                       `json:"id"`
	Name         string                       `json:"name"`
	Capabilities ReferralProviderCapabilities `json:"capabilities"`
	// Needs lists what must be set before Enabled can be true: endpoint_url,
	// signing_secret, api_key, connection_id.
	Needs                []string `json:"needs"`
	DefaultContextCookie *string  `json:"default_context_cookie"`
	DocsURL              *string  `json:"docs_url"`
}

// ReferralSecuritySettings is fraud and bot protection for referred sign-ups.
type ReferralSecuritySettings struct {
	// ChallengeReferredSignups is "always" (default: a sign-up carrying a
	// referral code must pass the bot challenge) or "inherit".
	ChallengeReferredSignups string `json:"challenge_referred_signups"`
	// OnHighRisk is "flag" (default), "strip" or "hold".
	OnHighRisk string `json:"on_high_risk"`
	// HoldUntilEmailVerified holds every referred sign-up until the email is proven.
	HoldUntilEmailVerified bool `json:"hold_until_email_verified"`
	// MaxReferredSignupsPerIPHour is referred sign-ups per code from one IP
	// network or device per hour before a velocity signal (1-1000, default 5).
	MaxReferredSignupsPerIPHour int `json:"max_referred_signups_per_ip_hour"`
}

// UpdateReferralSecurityParams is a partial update of the security settings:
// only the fields set change.
type UpdateReferralSecurityParams struct {
	ChallengeReferredSignups    *string `json:"challenge_referred_signups,omitempty"`
	OnHighRisk                  *string `json:"on_high_risk,omitempty"`
	HoldUntilEmailVerified      *bool   `json:"hold_until_email_verified,omitempty"`
	MaxReferredSignupsPerIPHour *int    `json:"max_referred_signups_per_ip_hour,omitempty"`
}

// ReferralLastTest is the last connection test.
type ReferralLastTest struct {
	OK bool `json:"ok"`
	// At is epoch ms.
	At         int64   `json:"at"`
	HTTPStatus *int    `json:"http_status"`
	Error      *string `json:"error"`
}

// ReferralConnectionStatus is the connection's health.
type ReferralConnectionStatus struct {
	LastTest *ReferralLastTest `json:"last_test"`
	// FailedCalls7d counts calls that failed permanently in the last 7 days.
	FailedCalls7d int `json:"failed_calls_7d"`
	// RetryingCalls counts calls waiting for a retry.
	RetryingCalls int    `json:"retrying_calls"`
	LastSuccessAt *int64 `json:"last_success_at"`
}

// ReferralSettings is GET /v1/instance/referrals. Secrets are never returned.
type ReferralSettings struct {
	Object   string `json:"object"`
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	// EndpointURL is the base URL of the platform connection (Atlas referral protocol).
	EndpointURL      *string `json:"endpoint_url"`
	ProgramID        *string `json:"program_id"`
	ConnectionID     *string `json:"connection_id"`
	SigningSecretSet bool    `json:"signing_secret_set"`
	APIKeySet        bool    `json:"api_key_set"`
	// URLParams are the query parameters that carry a referral code, in priority order.
	URLParams               []string `json:"url_params"`
	ContextCookie           *string  `json:"context_cookie"`
	ConsentCategory         string   `json:"consent_category"`
	ConsentFallbackCategory *string  `json:"consent_fallback_category"`
	AutoEnrollUsers         bool     `json:"auto_enroll_users"`
	// LinkTemplate (e.g. https://app.example.com/join?ref={code}) builds referral_link.
	LinkTemplate *string                  `json:"link_template"`
	TimeoutMS    int                      `json:"timeout_ms"`
	Security     ReferralSecuritySettings `json:"security"`
	// Missing lists what the chosen provider still needs before referrals can be enabled.
	Missing    []string                  `json:"missing"`
	Connection *ReferralConnectionStatus `json:"connection"`
	Providers  []ReferralProvider        `json:"providers"`
	UpdatedAt  *int64                    `json:"updated_at"`
}

// UpdateReferralSettingsParams is the body of PATCH /v1/instance/referrals:
// only the fields set change. Clear names nullable fields to clear (sent as
// null): endpoint_url, program_id, connection_id, signing_secret, api_key,
// context_cookie, consent_fallback_category, link_template. Enabling without
// what the provider needs is 422 REFERRALS_NOT_CONFIGURED.
type UpdateReferralSettingsParams struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Provider string `json:"provider,omitempty"`
	// EndpointURL must be https (http only for localhost on a development instance).
	EndpointURL  string `json:"endpoint_url,omitempty"`
	ProgramID    string `json:"program_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	// SigningSecret is write-only, 16-512 characters.
	SigningSecret string `json:"signing_secret,omitempty"`
	// APIKey is the write-only vendor API key.
	APIKey                  string                        `json:"api_key,omitempty"`
	URLParams               []string                      `json:"url_params,omitempty"`
	ContextCookie           string                        `json:"context_cookie,omitempty"`
	ConsentCategory         string                        `json:"consent_category,omitempty"`
	ConsentFallbackCategory string                        `json:"consent_fallback_category,omitempty"`
	AutoEnrollUsers         *bool                         `json:"auto_enroll_users,omitempty"`
	LinkTemplate            string                        `json:"link_template,omitempty"`
	TimeoutMS               int                           `json:"timeout_ms,omitempty"`
	Security                *UpdateReferralSecurityParams `json:"security,omitempty"`
	Clear                   []string                      `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdateReferralSettingsParams) MarshalJSON() ([]byte, error) {
	type plain UpdateReferralSettingsParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
}

// ReferralTestError says why a connection test failed.
type ReferralTestError struct {
	// Code is e.g. signature_rejected (the platform answered 401/403), timeout,
	// network_error, url_blocked, http_500.
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ReferralConnectionTest is POST /v1/instance/referrals/test.
type ReferralConnectionTest struct {
	OK         bool               `json:"ok"`
	HTTPStatus *int               `json:"http_status"`
	LatencyMS  *int               `json:"latency_ms"`
	Error      *ReferralTestError `json:"error,omitempty"`
}

// ReferralRisk is the risk verdict sent with a sign-up (camelCase, as on the
// referral protocol).
type ReferralRisk struct {
	// Level is low, medium or high.
	Level string `json:"level"`
	// Score is 0-100.
	Score int `json:"score"`
	// Signals are e.g. self_referral, ip_velocity, device_velocity,
	// disposable_email, datacenter_ip, tor_ip, captcha_not_passed,
	// email_unverified, restricted_identifier.
	Signals []string `json:"signals"`
	// Captcha is passed, not_required or not_configured.
	Captcha       string `json:"captcha"`
	EmailVerified bool   `json:"emailVerified"`
}

// ReferralCall is one call in the referral call log.
type ReferralCall struct {
	Object string `json:"object"`
	// ID is also the signed atlas-id header of every attempt.
	ID string `json:"id"`
	// Kind is signup, erase, export, partner, signal or test.
	Kind string `json:"kind"`
	// Status is pending, succeeded, retrying, failed, held or skipped.
	Status string `json:"status"`
	// Outcome (sign-ups) is referred, not_referred or stripped.
	Outcome     *string `json:"outcome"`
	CustomerRef string  `json:"customer_ref"`
	UserID      *string `json:"user_id"`
	HTTPStatus  *int    `json:"http_status"`
	LastError   *string `json:"last_error"`
	Attempts    int     `json:"attempts"`
	// NextAttemptAt is epoch ms of the next retry, while pending or retrying.
	NextAttemptAt *int64        `json:"next_attempt_at"`
	Risk          *ReferralRisk `json:"risk"`
	// Payload is what was sent (never secrets).
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt int64                  `json:"created_at"`
	UpdatedAt int64                  `json:"updated_at"`
}

// ListReferralCallsParams filters the call log. Zero values are omitted.
type ListReferralCallsParams struct {
	// Limit is 1-200 (default 50), newest first.
	Limit  int
	Status string
	Kind   string
	UserID string
}

func (p ListReferralCallsParams) values() url.Values {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Kind != "" {
		q.Set("kind", p.Kind)
	}
	if p.UserID != "" {
		q.Set("user_id", p.UserID)
	}
	return q
}

// Get reads the referral settings, connection status and supported providers.
// GET /v1/instance/referrals.
func (s *ReferralsService) Get(ctx context.Context) (*ReferralSettings, error) {
	out := &ReferralSettings{}
	return out, s.client.get(ctx, "/v1/instance/referrals", nil, out)
}

// Update patches the referral settings. PATCH /v1/instance/referrals.
func (s *ReferralsService) Update(ctx context.Context, params UpdateReferralSettingsParams, opts ...RequestOption) (*ReferralSettings, error) {
	out := &ReferralSettings{}
	return out, s.client.patch(ctx, "/v1/instance/referrals", params, out, opts...)
}

// Test sends a signed probe to the platform: OK on 2xx or 404; Error.Code
// signature_rejected on 401/403. POST /v1/instance/referrals/test.
func (s *ReferralsService) Test(ctx context.Context) (*ReferralConnectionTest, error) {
	out := &ReferralConnectionTest{}
	return out, s.client.post(ctx, "/v1/instance/referrals/test", nil, out)
}

// ListCalls returns the call log, newest first. GET /v1/instance/referrals/calls.
func (s *ReferralsService) ListCalls(ctx context.Context, params ListReferralCallsParams) (*ListPage[ReferralCall], error) {
	out := &ListPage[ReferralCall]{}
	return out, s.client.get(ctx, "/v1/instance/referrals/calls", params.values(), out)
}

// RetryCall retries a failed, retrying or skipped call now (not a connection
// test). POST /v1/instance/referrals/calls/:id/retry.
func (s *ReferralsService) RetryCall(ctx context.Context, id string, opts ...RequestOption) (*ReferralCall, error) {
	out := &ReferralCall{}
	return out, s.client.post(ctx, "/v1/instance/referrals/calls/"+url.PathEscape(id)+"/retry", nil, out, opts...)
}

// ---------------------------------------------------------------------------
// The Atlas referral protocol, for a referral platform receiving Atlas's calls
// ---------------------------------------------------------------------------

// The Atlas referral protocol (v1). An Atlas instance with referral
// attribution on (provider "webhook") calls the platform's base URL. Every
// call is a signed POST whose JSON body says which operation it is (op) and
// which customer it is about:
//
//	POST {base}/signups   {op: signup, customerRef, ...}                    → 200 ReferralSignupResponse
//	POST {base}/erase     {op: erase, customerRef}                          → 2xx (404 = already gone)
//	POST {base}/export    {op: export, customerRef, test}                   → 200 JSON (any shape) | 404
//	POST {base}/partners  {op: partner, customerRef, code, emailHash}       → 2xx | 409 taken | 404/405/501 unsupported
//	POST {base}/signals   {op: signal, customerRef, type, occurredAt, data} → 2xx | 404/405/501 unsupported
//
// The connection test is POST {base}/export with {op: export, customerRef:
// atlas_connection_test, test: true} (answer 2xx or 404). Every call is signed
// exactly like an Atlas webhook (atlas-id, atlas-timestamp, atlas-signature
// over "<id>.<timestamp>.<raw body>"), with Idempotency-Key and
// User-Agent: Atlas-Referrals/1. atlas-id is the call id, the same on every
// retry.
//
// The signature covers the body, not the URL. Pass the path the call arrived
// on (or the operation you expect): a signed body whose op does not match it
// is refused, so a captured call cannot be replayed against another endpoint.

const (
	// ReferralConnectionTestRef is the customerRef of the connection test.
	ReferralConnectionTestRef = "atlas_connection_test"
	// ReferralProtocolUserAgent is the User-Agent Atlas sends on every referral call.
	ReferralProtocolUserAgent = "Atlas-Referrals/1"
)

// Referral protocol operations (the op of every call, ReferralRequest.Op).
const (
	ReferralOpSignup  = "signup"
	ReferralOpErase   = "erase"
	ReferralOpExport  = "export"
	ReferralOpPartner = "partner"
	ReferralOpSignal  = "signal"
)

// ReferralOpEndpoints maps each operation to the endpoint (last path segment)
// it is sent to.
var ReferralOpEndpoints = map[string]string{
	ReferralOpSignup:  "signups",
	ReferralOpErase:   "erase",
	ReferralOpExport:  "export",
	ReferralOpPartner: "partners",
	ReferralOpSignal:  "signals",
}

// Errors returned by VerifyReferralRequest besides the VerifyWebhook ones.
var (
	// ErrReferralMalformedBody: the signed body is not a JSON object.
	ErrReferralMalformedBody = errors.New("atlas referral: body is not a JSON object")
	// ErrReferralMissingOp: the signed body has no op.
	ErrReferralMissingOp = errors.New("atlas referral: body has no op")
	// ErrReferralUnknownOp: the signed op is not a protocol operation.
	ErrReferralUnknownOp = errors.New("atlas referral: unknown op")
	// ErrReferralUnknownEndpoint: the path's last segment is not a protocol endpoint.
	ErrReferralUnknownEndpoint = errors.New("atlas referral: path is not a referral protocol endpoint")
	// ErrReferralOpMismatch: the signed op is not the operation of the endpoint
	// the call arrived on, or not the expected operation (a replay against
	// another endpoint).
	ErrReferralOpMismatch = errors.New("atlas referral: op does not match the endpoint")
)

// Lifecycle signal types (ReferralSignalPayload.Type).
const (
	ReferralSignalEmailVerified  = "email_verified"
	ReferralSignalUserBanned     = "user_banned"
	ReferralSignalUserUnbanned   = "user_unbanned"
	ReferralSignalUserLocked     = "user_locked"
	ReferralSignalRiskElevated   = "risk_elevated"
	ReferralSignalFraudConfirmed = "fraud_confirmed"
)

// ReferralContext is the referral captured at sign-up. Never trusted.
type ReferralContext struct {
	Code    *string `json:"code"`
	ClickID *string `json:"clickId"`
	AnonID  *string `json:"anonId"`
	// CapturedAt is ISO 8601.
	CapturedAt string `json:"capturedAt"`
	// Consent is "granted" (cookie read under consent) or "not_required" (URL code only).
	Consent string `json:"consent"`
}

// ReferralRejection is set when Atlas stripped the referral (risk policy).
type ReferralRejection struct {
	Reason string `json:"reason"`
}

// ReferralSignupPayload is the body of POST {base}/signups. Idempotent on CustomerRef.
type ReferralSignupPayload struct {
	Op string `json:"op"`
	// CustomerRef is the app's id for the user: its external_id when set, else the Atlas user id.
	CustomerRef string `json:"customerRef"`
	// EmailHash is the sha256 hex of the lower-cased, trimmed primary email; nil without one.
	EmailHash *string `json:"emailHash"`
	IP        *string `json:"ip"`
	UA        *string `json:"ua"`
	// SignedUpAt is ISO 8601: the original sign-up time, the same on every retry.
	SignedUpAt string  `json:"signedUpAt"`
	ProgramID  *string `json:"programId"`
	// AutoEnroll asks the platform to make the user a referrer (answer with Partner).
	AutoEnroll bool               `json:"autoEnroll"`
	Referral   *ReferralContext   `json:"referral"`
	Risk       *ReferralRisk      `json:"risk,omitempty"`
	Rejected   *ReferralRejection `json:"rejected,omitempty"`
}

// ReferralSignupMatch is the matched referral in a ReferralSignupResponse.
type ReferralSignupMatch struct {
	PartnerID *string `json:"partnerId"`
	// ReferrerExternalRef is the referrer's customerRef; Atlas maps it to a local user.
	ReferrerExternalRef *string `json:"referrerExternalRef"`
	MatchedVia          *string `json:"matchedVia"`
	Status              *string `json:"status"`
}

// ReferralPartner is the user's own partner record when AutoEnroll was true.
type ReferralPartner struct {
	ID   *string `json:"id"`
	Code *string `json:"code"`
	// Link may be omitted: Atlas builds it from its link template.
	Link *string `json:"link,omitempty"`
}

// ReferralSignupResponse is the answer to POST {base}/signups.
type ReferralSignupResponse struct {
	Referral *ReferralSignupMatch `json:"referral"`
	Partner  *ReferralPartner     `json:"partner,omitempty"`
}

// ReferralErasePayload is the body of POST {base}/erase.
type ReferralErasePayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
}

// ReferralExportPayload is the body of POST {base}/export: answer what you
// hold about the customer as any JSON, or 404.
type ReferralExportPayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
	// Test is true for the connection test (customerRef atlas_connection_test).
	Test bool `json:"test"`
}

// ReferralPartnerPayload is the body of POST {base}/partners.
type ReferralPartnerPayload struct {
	Op          string  `json:"op"`
	CustomerRef string  `json:"customerRef"`
	Code        string  `json:"code"`
	EmailHash   *string `json:"emailHash"`
}

// ReferralSignalPayload is the body of POST {base}/signals.
type ReferralSignalPayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
	// Type is one of the ReferralSignal* constants (new types may appear).
	Type string `json:"type"`
	// OccurredAt is ISO 8601.
	OccurredAt string                 `json:"occurredAt"`
	Data       map[string]interface{} `json:"data"`
}

// ReferralRequest is a verified call from Atlas. Exactly one payload field is
// set, matching Op.
type ReferralRequest struct {
	// Op is one of the ReferralOp* constants.
	Op string
	// CustomerRef is the signed customerRef.
	CustomerRef string
	// Test is true for the connection test (an export with test: true): answer 2xx or 404.
	Test    bool
	Signup  *ReferralSignupPayload
	Erase   *ReferralErasePayload
	Export  *ReferralExportPayload
	Partner *ReferralPartnerPayload
	Signal  *ReferralSignalPayload
	// Raw is the verified body.
	Raw []byte
	// DeliveryID is the signed atlas-id (the call id), the same on every retry.
	DeliveryID string
	// Timestamp is the signed atlas-timestamp (epoch ms).
	Timestamp int64
	// IdempotencyKey is the Idempotency-Key header (not signed).
	IdempotencyKey string
}

// ReferralVerifyOptions tunes VerifyReferralRequest. The zero value checks
// only the signature and the op.
type ReferralVerifyOptions struct {
	WebhookVerifyOptions
	// Path is the path (or URL) the call arrived on, e.g. r.URL.Path. Its last
	// segment (signups, erase, export, partners, signals) must match the signed op.
	Path string
	// ExpectedOp is the operation this handler serves; the signed op must equal it.
	ExpectedOp string
}

// ReferralOpForPath returns the operation of a path's (or URL's) last segment,
// or "" when it is not a protocol endpoint.
func ReferralOpForPath(path string) string {
	if u, err := url.Parse(path); err == nil {
		path = u.Path
	}
	segments := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(segments) == 0 {
		return ""
	}
	last := segments[len(segments)-1]
	for op, endpoint := range ReferralOpEndpoints {
		if endpoint == last {
			return op
		}
	}
	return ""
}

// VerifyReferralRequest verifies a call from Atlas to a referral platform and
// tells which operation it is. Pass the RAW body, the headers, the signing
// secret configured on the Atlas instance and, in opts, the Path the call
// arrived on (or the ExpectedOp): a signed op that does not match is
// ErrReferralOpMismatch. It also returns the VerifyWebhook errors and
// ErrReferralMalformedBody, ErrReferralMissingOp, ErrReferralUnknownOp and
// ErrReferralUnknownEndpoint.
//
//	body, _ := io.ReadAll(r.Body)
//	req, err := atlas.VerifyReferralRequest(body, r.Header, secret, &atlas.ReferralVerifyOptions{Path: r.URL.Path})
//	if err != nil { w.WriteHeader(401); return }
//	switch req.Op {
//	case atlas.ReferralOpSignup:
//		_ = json.NewEncoder(w).Encode(attribute(req.Signup)) // a ReferralSignupResponse
//	case atlas.ReferralOpExport:
//		if req.Test { w.WriteHeader(404); return }
//	}
func VerifyReferralRequest(body []byte, header http.Header, secret string, opts *ReferralVerifyOptions) (*ReferralRequest, error) {
	var hookOpts *WebhookVerifyOptions
	if opts != nil {
		hookOpts = &opts.WebhookVerifyOptions
	}
	hook, err := VerifyWebhook(body, header, secret, hookOpts)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil || envelope == nil {
		return nil, ErrReferralMalformedBody
	}
	rawOp, ok := envelope["op"]
	if !ok || string(rawOp) == "null" || string(rawOp) == `""` {
		return nil, ErrReferralMissingOp
	}
	var op string
	if json.Unmarshal(rawOp, &op) != nil {
		return nil, ErrReferralUnknownOp
	}
	if _, known := ReferralOpEndpoints[op]; !known {
		return nil, ErrReferralUnknownOp
	}
	if opts != nil && opts.Path != "" {
		endpointOp := ReferralOpForPath(opts.Path)
		if endpointOp == "" {
			return nil, ErrReferralUnknownEndpoint
		}
		if endpointOp != op {
			return nil, ErrReferralOpMismatch
		}
	}
	if opts != nil && opts.ExpectedOp != "" && opts.ExpectedOp != op {
		return nil, ErrReferralOpMismatch
	}
	out := &ReferralRequest{
		Op:             op,
		Raw:            body,
		DeliveryID:     hook.DeliveryID,
		Timestamp:      hook.Timestamp,
		IdempotencyKey: header.Get("Idempotency-Key"),
	}
	decode := func(v interface{}) error {
		if err := json.Unmarshal(body, v); err != nil {
			return ErrReferralMalformedBody
		}
		return nil
	}
	switch op {
	case ReferralOpSignup:
		p := &ReferralSignupPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Signup, out.CustomerRef = p, p.CustomerRef
	case ReferralOpErase:
		p := &ReferralErasePayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Erase, out.CustomerRef = p, p.CustomerRef
	case ReferralOpExport:
		p := &ReferralExportPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Export, out.CustomerRef, out.Test = p, p.CustomerRef, p.Test
	case ReferralOpPartner:
		p := &ReferralPartnerPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Partner, out.CustomerRef = p, p.CustomerRef
	case ReferralOpSignal:
		p := &ReferralSignalPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Signal, out.CustomerRef = p, p.CustomerRef
	}
	return out, nil
}
