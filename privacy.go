package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// The data-rights executor protocol (v2): the routes a DSAR orchestrator
// calls to find a person and carry out a request against their identity data
// (needs a key with the privacy:execute scope; privacy:grants:revoke lets the
// erasure also revoke the Sign in with Atlas grant), and the instance's own
// orchestrator connection, where Atlas opens a case when an account deletion
// is scheduled.

// Canonical privacy request types.
const (
	PrivacyTypeAccess        = "access"
	PrivacyTypeDeletion      = "deletion"
	PrivacyTypeClosure       = "closure"
	PrivacyTypeRestriction   = "restriction"
	PrivacyTypeRectification = "rectification"
)

// Privacy request statuses.
const (
	PrivacyStatusPending                = "pending"
	PrivacyStatusScheduled              = "scheduled"
	PrivacyStatusProcessing             = "processing"
	PrivacyStatusCompleted              = "completed"
	PrivacyStatusCompletedWithRetention = "completed_with_retention"
	PrivacyStatusRejected               = "rejected"
	PrivacyStatusNoMatch                = "no_match"
	PrivacyStatusCancelled              = "cancelled"
)

// Webhook events and scopes of the data-rights executor.
const (
	// WebhookEventPrivacyRequestUpdated / Completed: a privacy request moved
	// forward / finished. data is the same PrivacyRequest the GET returns.
	WebhookEventPrivacyRequestUpdated   = "privacy_request.updated"
	WebhookEventPrivacyRequestCompleted = "privacy_request.completed"
	// WebhookEventUserDeletionScheduled / Canceled: an account deletion was
	// scheduled / cancelled inside its grace window (also sent to Sign in with
	// Atlas app webhooks).
	WebhookEventUserDeletionScheduled = "user.deletion_scheduled"
	WebhookEventUserDeletionCanceled  = "user.deletion_canceled"

	// ScopePrivacyExecute lets a key call /v1/privacy/*.
	ScopePrivacyExecute = "privacy:execute"
	// ScopePrivacyGrantsRevoke lets an erasure revoke the Sign in with Atlas
	// grant for the app this instance manages.
	ScopePrivacyGrantsRevoke = "privacy:grants:revoke"
)

// PrivacySubject identifies a person for a lookup. atlas.sub alone wins, then
// atlas.ext, then the emails.
type PrivacySubject struct {
	Iss       string `json:"iss,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Ext       string `json:"ext,omitempty"`
	Principal string `json:"principal,omitempty"`
}

// PrivacyLookupParams is the body of POST /v1/privacy/lookup.
type PrivacyLookupParams struct {
	Emails []string        `json:"emails,omitempty"`
	Atlas  *PrivacySubject `json:"atlas,omitempty"`
}

// PrivacyLookupResult is the answer to a lookup.
type PrivacyLookupResult struct {
	Object string `json:"object"`
	// Status is found or no_match.
	Status    string  `json:"status"`
	SubjectID *string `json:"subjectId"`
	// MatchedBy is atlas.sub, atlas.ext, email or email_unverified.
	MatchedBy *string `json:"matchedBy"`
	Detail    *string `json:"detail"`
	Principal string  `json:"principal,omitempty"`
}

// PrivacyRetention is a category of data kept after an erasure, with its basis.
type PrivacyRetention struct {
	Category string `json:"category"`
	Basis    string `json:"basis"`
	Until    string `json:"until"`
}

// PrivacyStep is one step of carrying out a request.
type PrivacyStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	At     int64  `json:"at,omitempty"`
}

// PrivacyRequest is a data-rights request.
type PrivacyRequest struct {
	Object        string             `json:"object"`
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	CanonicalType string             `json:"canonicalType"`
	RequestedType string             `json:"requestedType"`
	Status        string             `json:"status"`
	SubjectID     string             `json:"subjectId"`
	CaseID        *string            `json:"caseId"`
	ExecuteAfter  *string            `json:"executeAfter"`
	ETA           *string            `json:"eta"`
	Detail        *string            `json:"detail"`
	Retention     []PrivacyRetention `json:"retention"`
	Steps         []PrivacyStep      `json:"steps"`
	Trace         *string            `json:"trace"`
	CreatedAt     string             `json:"createdAt"`
	UpdatedAt     string             `json:"updatedAt"`
	CompletedAt   *string            `json:"completedAt"`
	// Result is set on a finished request (GET).
	Result interface{} `json:"result,omitempty"`
}

// CreatePrivacyRequestParams is the body of POST /v1/privacy/requests. Type is
// access, deletion, closure, restriction or rectification (export, erasure
// and erase are accepted aliases).
type CreatePrivacyRequestParams struct {
	SubjectID string `json:"subjectId"`
	Type      string `json:"type"`
	CaseID    string `json:"caseId"`
	// ExecuteAfter (ISO 8601): nothing is erased before it. ExecuteAfterMS
	// sends epoch milliseconds instead.
	ExecuteAfter   string `json:"executeAfter,omitempty"`
	ExecuteAfterMS int64  `json:"-"`
	Reason         string `json:"reason,omitempty"`
}

// MarshalJSON sends ExecuteAfterMS as executeAfter when ExecuteAfter is empty.
func (p CreatePrivacyRequestParams) MarshalJSON() ([]byte, error) {
	type plain CreatePrivacyRequestParams
	var extra map[string]interface{}
	if p.ExecuteAfter == "" && p.ExecuteAfterMS > 0 {
		extra = map[string]interface{}{"executeAfter": p.ExecuteAfterMS}
	}
	return marshalWithExtra(plain(p), extra)
}

// PrivacyOrchestrator is the instance's data-rights orchestrator connection.
// The credentials are never returned; a signing secret appears once, on the
// write that mints it.
type PrivacyOrchestrator struct {
	Object           string  `json:"object"`
	Configured       bool    `json:"configured"`
	Enabled          bool    `json:"enabled"`
	Provider         *string `json:"provider"`
	Name             *string `json:"name"`
	CaseURL          *string `json:"case_url"`
	CancelURL        *string `json:"cancel_url"`
	AuthHeader       string  `json:"auth_header"`
	AuthScheme       string  `json:"auth_scheme"`
	APIKeySet        bool    `json:"api_key_set"`
	SigningSecretSet bool    `json:"signing_secret_set"`
	UsePartnerLink   bool    `json:"use_partner_link"`
	// PartnerLinkID is the partner link the orchestrator's owner granted this
	// platform (sent as X-Partner-Link).
	PartnerLinkID *string `json:"partner_link_id"`
	// SiteID is the orchestrator-side site a case is for.
	SiteID *string `json:"site_id"`
	// CancelDeletionOnSignIn cancels a self-scheduled deletion when the person
	// signs back in during the grace period.
	CancelDeletionOnSignIn bool                     `json:"cancel_deletion_on_sign_in"`
	OpenClosureCases       bool                     `json:"open_closure_cases"`
	CompletionWebhook      map[string]interface{}   `json:"completion_webhook"`
	LastCaseAt             *int64                   `json:"last_case_at"`
	LastError              *string                  `json:"last_error"`
	LastErrorAt            *int64                   `json:"last_error_at"`
	Presets                []map[string]interface{} `json:"presets"`
	// SigningSecret / CompletionWebhookSecret (whsec_…) are returned once.
	SigningSecret           string `json:"signing_secret,omitempty"`
	CompletionWebhookSecret string `json:"completion_webhook_secret,omitempty"`
	// Deleted is set on the answer to Delete.
	Deleted bool `json:"deleted,omitempty"`
}

// SetPrivacyOrchestratorParams is the body of PUT /v1/instance/privacy_orchestrator.
// Clear names nullable fields to send as null: case_url, cancel_url, api_key,
// completion_webhook_url, partner_link_id, site_id.
type SetPrivacyOrchestratorParams struct {
	// Provider is a preset id (cookiemunch, custom) or your own lower-case id.
	Provider string `json:"provider,omitempty"`
	Name     string `json:"name,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
	CaseURL  string `json:"case_url,omitempty"`
	// CancelURL must contain {id}.
	CancelURL  string `json:"cancel_url,omitempty"`
	AuthHeader string `json:"auth_header,omitempty"`
	// AuthScheme is bearer or raw.
	AuthScheme string `json:"auth_scheme,omitempty"`
	// APIKey is write-only.
	APIKey string `json:"api_key,omitempty"`
	// UsePartnerLink calls through the partner link the orchestrator granted
	// Atlas (partner id = provider).
	UsePartnerLink *bool `json:"use_partner_link,omitempty"`
	// PartnerLinkID implies UsePartnerLink.
	PartnerLinkID string `json:"partner_link_id,omitempty"`
	// SiteID is the orchestrator-side site a case is for.
	SiteID string `json:"site_id,omitempty"`
	// CancelDeletionOnSignIn cancels a self-scheduled deletion when the person
	// signs back in during the grace period.
	CancelDeletionOnSignIn *bool `json:"cancel_deletion_on_sign_in,omitempty"`
	OpenClosureCases       *bool `json:"open_closure_cases,omitempty"`
	// SignRequests mints (true) a secret and signs every case call; true again
	// rotates it, false stops signing.
	SignRequests         *bool    `json:"sign_requests,omitempty"`
	CompletionWebhookURL string   `json:"completion_webhook_url,omitempty"`
	Clear                []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p SetPrivacyOrchestratorParams) MarshalJSON() ([]byte, error) {
	type plain SetPrivacyOrchestratorParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// PrivacyService is the executor protocol (/v1/privacy). Orchestrator hangs
// off it.
type PrivacyService struct {
	client *Client

	Orchestrator *PrivacyOrchestratorService
}

// Discover returns what this executor speaks (public). GET /v1/privacy.
func (s *PrivacyService) Discover(ctx context.Context) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	err := s.client.get(ctx, "/v1/privacy", nil, &out)
	return out, err
}

// Preset returns a ready-made orchestrator connection profile such as
// cookiemunch (public). GET /v1/privacy/presets/:id.
func (s *PrivacyService) Preset(ctx context.Context, id string) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	err := s.client.get(ctx, "/v1/privacy/presets/"+url.PathEscape(id), nil, &out)
	return out, err
}

// Lookup finds a person. POST /v1/privacy/lookup.
func (s *PrivacyService) Lookup(ctx context.Context, params PrivacyLookupParams, opts ...RequestOption) (*PrivacyLookupResult, error) {
	out := &PrivacyLookupResult{}
	return out, s.client.post(ctx, "/v1/privacy/lookup", params, out, opts...)
}

// CreateRequest opens a request, or returns the existing one for the same
// case. Pass WithIdempotencyKey. POST /v1/privacy/requests.
func (s *PrivacyService) CreateRequest(ctx context.Context, params CreatePrivacyRequestParams, opts ...RequestOption) (*PrivacyRequest, error) {
	out := &PrivacyRequest{}
	return out, s.client.post(ctx, "/v1/privacy/requests", params, out, opts...)
}

// GetRequest returns one request. GET /v1/privacy/requests/:id.
func (s *PrivacyService) GetRequest(ctx context.Context, id string) (*PrivacyRequest, error) {
	out := &PrivacyRequest{}
	return out, s.client.get(ctx, "/v1/privacy/requests/"+url.PathEscape(id), nil, out)
}

// CancelRequest cancels a request before it runs: nothing is erased, the
// account stays. POST /v1/privacy/requests/:id/cancel.
func (s *PrivacyService) CancelRequest(ctx context.Context, id string, opts ...RequestOption) (*PrivacyRequest, error) {
	out := &PrivacyRequest{}
	return out, s.client.post(ctx, "/v1/privacy/requests/"+url.PathEscape(id)+"/cancel", nil, out, opts...)
}

// PrivacyOrchestratorService is /v1/instance/privacy_orchestrator.
type PrivacyOrchestratorService struct{ client *Client }

// Get returns the orchestrator connection. GET /v1/instance/privacy_orchestrator.
func (s *PrivacyOrchestratorService) Get(ctx context.Context) (*PrivacyOrchestrator, error) {
	out := &PrivacyOrchestrator{}
	return out, s.client.get(ctx, "/v1/instance/privacy_orchestrator", nil, out)
}

// Set connects or updates the orchestrator; new secrets come back once.
// PUT /v1/instance/privacy_orchestrator.
func (s *PrivacyOrchestratorService) Set(ctx context.Context, params SetPrivacyOrchestratorParams, opts ...RequestOption) (*PrivacyOrchestrator, error) {
	out := &PrivacyOrchestrator{}
	return out, s.client.put(ctx, "/v1/instance/privacy_orchestrator", params, out, opts...)
}

// Delete removes the connection. DELETE /v1/instance/privacy_orchestrator.
func (s *PrivacyOrchestratorService) Delete(ctx context.Context, opts ...RequestOption) (*PrivacyOrchestrator, error) {
	out := &PrivacyOrchestrator{}
	return out, s.client.del(ctx, "/v1/instance/privacy_orchestrator", out, opts...)
}

// PrivacyCall is a verified call from Atlas to your orchestrator or executor
// receiver: the signed case request (when Atlas opens a case for a scheduled
// deletion), its cancellation, or a privacy_request.* event.
type PrivacyCall struct {
	// DeliveryID is the signed Atlas-Id header (also the Idempotency-Key Atlas
	// sends); deduplicate retries on it.
	DeliveryID string
	// Timestamp is the signed Atlas-Timestamp (epoch ms).
	Timestamp int64
	// Traceparent is the W3C traceparent Atlas sent, or "".
	Traceparent string
	// Body is the raw JSON body.
	Body json.RawMessage
	// Event is set when the body is a webhook envelope (privacy_request.*).
	Event *WebhookEvent
}

// VerifyPrivacyCall verifies a call Atlas makes to a data-rights receiver. With
// sign_requests on, case calls carry Atlas-Id, Atlas-Timestamp and
// Atlas-Signature exactly like a webhook (HMAC-SHA256 over id.timestamp.body
// with the signing secret); the completion endpoint's privacy_request.*
// events are ordinary signed webhooks. Verify the RAW body.
func VerifyPrivacyCall(body []byte, header http.Header, secret string, opts *WebhookVerifyOptions) (*PrivacyCall, error) {
	v, err := VerifyWebhook(body, header, secret, opts)
	if err != nil {
		return nil, err
	}
	out := &PrivacyCall{
		DeliveryID:  v.DeliveryID,
		Timestamp:   v.Timestamp,
		Traceparent: TraceparentFromHeader(header),
		Body:        json.RawMessage(body),
	}
	if v.Event != nil && v.Event.Type != "" {
		out.Event = v.Event
	}
	return out, nil
}

// PrivacyRequestFromEvent decodes the data of a privacy_request.updated /
// privacy_request.completed event.
func PrivacyRequestFromEvent(ev *WebhookEvent) (*PrivacyRequest, error) {
	out := &PrivacyRequest{}
	if err := json.Unmarshal(ev.Data, out); err != nil {
		return nil, err
	}
	return out, nil
}
