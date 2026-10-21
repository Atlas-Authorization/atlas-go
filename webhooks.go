package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// WebhooksService is the /v1/webhook_endpoints namespace. Endpoints hangs off it.
type WebhooksService struct {
	client *Client

	Endpoints *WebhookEndpointsService
}

// WebhookEndpoint is a registered webhook endpoint.
type WebhookEndpoint struct {
	Object        string   `json:"object"`
	ID            string   `json:"id"`
	URL           string   `json:"url"`
	EnabledEvents []string `json:"enabled_events"`
	Active        bool     `json:"active"`
	// FailingSince is the start of the current failure streak (epoch ms), or
	// nil when the last delivery succeeded.
	FailingSince *int64 `json:"failing_since"`
	DisabledAt   *int64 `json:"disabled_at"`
	// PreviousSecretExpiresAt is, while a secret rotation overlap is open,
	// when the previous secret stops signing deliveries (epoch ms); until then
	// every delivery carries two signatures. nil otherwise.
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at,omitempty"`
	CreatedAt               int64  `json:"created_at"`
}

// WebhookEndpointWithSecret reveals the signing secret (whsec_...) once, on
// create.
type WebhookEndpointWithSecret struct {
	WebhookEndpoint
	Secret string `json:"secret"`
}

// WebhookDelivery is one delivery attempt in an endpoint's log.
type WebhookDelivery struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	EventID string `json:"event_id"`
	// EventType is the event type, or nil once the event has passed retention.
	EventType     *string `json:"event_type,omitempty"`
	AttemptNumber int     `json:"attempt_number"`
	MaxAttempts   int     `json:"max_attempts,omitempty"`
	// Payload is the event payload that was sent (nil once past retention).
	Payload    interface{} `json:"payload,omitempty"`
	Status     string      `json:"status"`
	HTTPStatus *int        `json:"http_status"`
	// Error is why the attempt failed: webhook_redirect_not_followed (see
	// Location), webhook_http_error, webhook_timeout, webhook_network_error or
	// webhook_url_blocked. Nil on success or while pending.
	Error *string `json:"error,omitempty"`
	// Location is the absolute Location of a 3xx answer. Not followed.
	Location        *string `json:"location,omitempty"`
	ResponseSnippet *string `json:"response_snippet"`
	NextRetryAt     *int64  `json:"next_retry_at"`
	DeliveredAt     *int64  `json:"delivered_at"`
	CreatedAt       int64   `json:"created_at"`
}

// CreateWebhookEndpointParams is the body of POST /v1/webhook_endpoints. Each
// enabled event is "*" or a known event name.
type CreateWebhookEndpointParams struct {
	URL           string   `json:"url"`
	EnabledEvents []string `json:"enabled_events,omitempty"`
}

// Deliveries returns an endpoint's delivery log.
// GET /v1/webhook_endpoints/:id/deliveries.
func (s *WebhooksService) Deliveries(ctx context.Context, id string) (*ListPage[WebhookDelivery], error) {
	out := &ListPage[WebhookDelivery]{}
	return out, s.client.get(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/deliveries", nil, out)
}

// WebhookEndpointsService is /v1/webhook_endpoints.
type WebhookEndpointsService struct{ client *Client }

// List returns all webhook endpoints. GET /v1/webhook_endpoints.
func (s *WebhookEndpointsService) List(ctx context.Context) (*ListPage[WebhookEndpoint], error) {
	out := &ListPage[WebhookEndpoint]{}
	return out, s.client.get(ctx, "/v1/webhook_endpoints", nil, out)
}

// Create registers a webhook endpoint; the response reveals the secret once.
// POST /v1/webhook_endpoints.
func (s *WebhookEndpointsService) Create(ctx context.Context, params CreateWebhookEndpointParams, opts ...RequestOption) (*WebhookEndpointWithSecret, error) {
	out := &WebhookEndpointWithSecret{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints", params, out, opts...)
}

// Delete removes a webhook endpoint. DELETE /v1/webhook_endpoints/:id.
func (s *WebhookEndpointsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id), out, opts...)
}

// WebhookEndpointList is the endpoint list plus the subscribable event types
// and the retry schedule.
type WebhookEndpointList struct {
	Object  string            `json:"object"`
	Data    []WebhookEndpoint `json:"data"`
	HasMore bool              `json:"has_more"`
	// AvailableEvents is every event type an endpoint can subscribe to.
	AvailableEvents []string `json:"available_events"`
	// EventCatalog describes the same events, in the same order.
	EventCatalog []WebhookEventCatalogEntry `json:"event_catalog,omitempty"`
	// EventAudiences is every value RelevantFor can hold.
	EventAudiences []string `json:"event_audiences,omitempty"`
	// RetryScheduleMS is the delay before each retry, in milliseconds.
	RetryScheduleMS []int64 `json:"retry_schedule_ms"`
	// MaxAttempts is the delivery attempts per event before it is marked failed.
	MaxAttempts int `json:"max_attempts"`
}

// WebhookEventCatalogEntry describes one subscribable event.
type WebhookEventCatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// RelevantFor is who should act on it (rp_sessions, rp_accounts, dsar, …).
	RelevantFor []string `json:"relevant_for"`
	// DeprecatedAliasOf is set on a superseded spelling: subscribe to this
	// event instead.
	DeprecatedAliasOf string `json:"deprecated_alias_of,omitempty"`
}

// UpdateWebhookEndpointParams is the body of PATCH /v1/webhook_endpoints/:id.
// Unset fields are left alone; the signing secret is preserved.
type UpdateWebhookEndpointParams struct {
	URL           string   `json:"url,omitempty"`
	EnabledEvents []string `json:"enabled_events,omitempty"`
	Active        *bool    `json:"active,omitempty"`
}

// WebhookSecret is an endpoint's signing secret (whsec_...).
type WebhookSecret struct {
	Object string `json:"object"`
	Secret string `json:"secret"`
	// Warning is set on rotation: what happens to the old secret.
	Warning string `json:"warning,omitempty"`
	// OverlapSeconds is, on a rotation, the overlap applied.
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
	// PreviousSecretExpiresAt is, on a rotation, when the previous secret
	// stops signing deliveries (epoch ms), or nil when it already has.
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at,omitempty"`
}

// RotateWebhookSecretParams is the body of
// POST /v1/webhook_endpoints/:id/rotate_secret.
type RotateWebhookSecretParams struct {
	// OverlapSeconds is how long the previous secret keeps signing deliveries
	// (as a second atlas-signature entry). nil or 0: it stops at once (the
	// default); at most 604800 (7 days). Set it only once every receiver
	// verifies with a verifier that accepts several signatures (0.7.0+).
	OverlapSeconds *int `json:"overlap_seconds,omitempty"`
}

// WebhookDispatch acknowledges a test send or a redelivery.
type WebhookDispatch struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	EventID string `json:"event_id"`
	Status  string `json:"status"`
	Note    string `json:"note"`
}

// ListDetailed returns the endpoints with their health, the subscribable event
// types and the retry schedule. GET /v1/webhook_endpoints.
func (s *WebhookEndpointsService) ListDetailed(ctx context.Context) (*WebhookEndpointList, error) {
	out := &WebhookEndpointList{}
	return out, s.client.get(ctx, "/v1/webhook_endpoints", nil, out)
}

// Update changes an endpoint's url, enabled_events or active flag in place.
// PATCH /v1/webhook_endpoints/:id.
func (s *WebhookEndpointsService) Update(ctx context.Context, id string, params UpdateWebhookEndpointParams, opts ...RequestOption) (*WebhookEndpoint, error) {
	out := &WebhookEndpoint{}
	return out, s.client.patch(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id), params, out, opts...)
}

// Deliveries returns an endpoint's delivery log, newest first. limit is 1–100
// (0 = the server default of 50). GET /v1/webhook_endpoints/:id/deliveries.
func (s *WebhookEndpointsService) Deliveries(ctx context.Context, id string, limit int) (*ListPage[WebhookDelivery], error) {
	out := &ListPage[WebhookDelivery]{}
	var q url.Values
	if limit > 0 {
		q = url.Values{"limit": {strconv.Itoa(limit)}}
	}
	return out, s.client.get(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/deliveries", q, out)
}

// RevealSecret shows the endpoint's current signing secret again without
// changing it. POST /v1/webhook_endpoints/:id/reveal_secret.
func (s *WebhookEndpointsService) RevealSecret(ctx context.Context, id string, opts ...RequestOption) (*WebhookSecret, error) {
	out := &WebhookSecret{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/reveal_secret", nil, out, opts...)
}

// RotateSecret replaces the signing secret; the new one is revealed once.
// POST /v1/webhook_endpoints/:id/rotate_secret.
func (s *WebhookEndpointsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*WebhookSecret, error) {
	return s.RotateSecretWithParams(ctx, id, RotateWebhookSecretParams{}, opts...)
}

// RotateSecretWithParams rotates the signing secret with a chosen overlap:
// for OverlapSeconds every delivery is signed with both secrets, so a verifier
// holding either passes. POST /v1/webhook_endpoints/:id/rotate_secret.
func (s *WebhookEndpointsService) RotateSecretWithParams(ctx context.Context, id string, params RotateWebhookSecretParams, opts ...RequestOption) (*WebhookSecret, error) {
	out := &WebhookSecret{}
	if params.OverlapSeconds == nil {
		// No body, as before: the server default (no overlap).
		return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
	}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/rotate_secret", params, out, opts...)
}

// Test sends a synthetic webhook.test event to this endpoint only.
// POST /v1/webhook_endpoints/:id/test.
func (s *WebhookEndpointsService) Test(ctx context.Context, id string, opts ...RequestOption) (*WebhookDispatch, error) {
	out := &WebhookDispatch{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/test", nil, out, opts...)
}

// Redeliver sends a past event again as a fresh attempt (409 once the event is
// past its 90-day retention).
// POST /v1/webhook_endpoints/:id/deliveries/:deliveryId/redeliver.
func (s *WebhookEndpointsService) Redeliver(ctx context.Context, id, deliveryID string, opts ...RequestOption) (*WebhookDispatch, error) {
	out := &WebhookDispatch{}
	return out, s.client.post(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id)+"/deliveries/"+url.PathEscape(deliveryID)+"/redeliver", nil, out, opts...)
}
