package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// AppEventsService is application webhooks: send YOUR app's own events
// (call.completed, invoice.paid) to endpoints your customers (organizations)
// register. Atlas signs them (Standard Webhooks: verify with
// VerifyStandardWebhook), retries, tracks health, auto-disables a dead
// endpoint and keeps the delivery log with redeliver and replay.
//
//	c.AppEvents.Types.Create(ctx, atlas.CreateAppEventTypeParams{Type: "call.completed"})
//	c.AppEvents.Publish(ctx, atlas.PublishAppEventParams{OrganizationID: "org_1", Type: "call.completed", Data: data, IdempotencyKey: "c1"})
type AppEventsService struct {
	client *Client

	// Types is your event catalog (/v1/app_event_types).
	Types *AppEventTypesService
	// Endpoints is one organization's endpoints for your events
	// (/v1/organizations/:id/app_webhook_endpoints).
	Endpoints *AppWebhookEndpointsService
}

// AppEventType is one event type of your catalog.
type AppEventType struct {
	Object string `json:"object"`
	// ID is aet_...
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Description *string `json:"description"`
	// Schema is the JSON Schema every published Data must match; nil = any object.
	Schema map[string]interface{} `json:"schema"`
	// Deprecated types are still publishable but hidden from the endpoint picker.
	Deprecated bool  `json:"deprecated"`
	CreatedAt  int64 `json:"created_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// CreateAppEventTypeParams is the body of POST /v1/app_event_types.
type CreateAppEventTypeParams struct {
	// Type is a lowercase dotted name, e.g. call.completed.
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	Deprecated  bool                   `json:"deprecated,omitempty"`
}

// UpdateAppEventTypeParams is the body of PATCH /v1/app_event_types/:id.
type UpdateAppEventTypeParams struct {
	Description *string                `json:"description,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	Deprecated  *bool                  `json:"deprecated,omitempty"`
}

// DeletedAppEventType acknowledges an event type delete.
type DeletedAppEventType struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Deleted bool   `json:"deleted"`
}

// PublishAppEventParams is the body of POST /v1/app_events.
type PublishAppEventParams struct {
	// OrganizationID is the organization (your customer) whose endpoints
	// receive the event.
	OrganizationID string                 `json:"organization_id"`
	Type           string                 `json:"type"`
	Data           map[string]interface{} `json:"data"`
	// IdempotencyKey: a repeat with the same key returns the first event and
	// queues nothing (kept 90 days). WithIdempotencyKey sends the same as a
	// header.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// AppEvent is a published application event.
type AppEvent struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	OrganizationID string                 `json:"organization_id"`
	Data           map[string]interface{} `json:"data"`
	IdempotencyKey *string                `json:"idempotency_key"`
	CreatedAt      int64                  `json:"created_at"`
}

// PublishedAppEvent is the answer to Publish.
type PublishedAppEvent struct {
	AppEvent
	// IdempotentReplay is true for an earlier publish with the same key:
	// nothing new was queued.
	IdempotentReplay bool `json:"idempotent_replay"`
	// DeliveriesQueued and EndpointIDs are set on the first publish only.
	DeliveriesQueued *int     `json:"deliveries_queued,omitempty"`
	EndpointIDs      []string `json:"endpoint_ids,omitempty"`
}

// ListAppEventsParams filters GET /v1/app_events. OrganizationID is required.
type ListAppEventsParams struct {
	OrganizationID string
	Type           string
	Limit          int
	StartingAfter  string
}

// Publish sends one event to one organization's subscribed endpoints (201
// new, 200 replay). POST /v1/app_events.
func (s *AppEventsService) Publish(ctx context.Context, params PublishAppEventParams, opts ...RequestOption) (*PublishedAppEvent, error) {
	out := &PublishedAppEvent{}
	return out, s.client.post(ctx, "/v1/app_events", params, out, opts...)
}

// List returns one organization's published events, newest first.
// GET /v1/app_events.
func (s *AppEventsService) List(ctx context.Context, params ListAppEventsParams) (*ListPage[AppEvent], error) {
	q := url.Values{"organization_id": {params.OrganizationID}}
	if params.Type != "" {
		q.Set("type", params.Type)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.StartingAfter != "" {
		q.Set("starting_after", params.StartingAfter)
	}
	out := &ListPage[AppEvent]{}
	return out, s.client.get(ctx, "/v1/app_events", q, out)
}

// Get returns one published event. GET /v1/app_events/:id.
func (s *AppEventsService) Get(ctx context.Context, id string) (*AppEvent, error) {
	out := &AppEvent{}
	return out, s.client.get(ctx, "/v1/app_events/"+url.PathEscape(id), nil, out)
}

// AppEventTypesService is /v1/app_event_types. idOrType is the aet_ id or the
// type name.
type AppEventTypesService struct{ client *Client }

// List returns the catalog. GET /v1/app_event_types.
func (s *AppEventTypesService) List(ctx context.Context) (*ListPage[AppEventType], error) {
	out := &ListPage[AppEventType]{}
	return out, s.client.get(ctx, "/v1/app_event_types", nil, out)
}

// Create adds an event type. POST /v1/app_event_types.
func (s *AppEventTypesService) Create(ctx context.Context, params CreateAppEventTypeParams, opts ...RequestOption) (*AppEventType, error) {
	out := &AppEventType{}
	return out, s.client.post(ctx, "/v1/app_event_types", params, out, opts...)
}

// Get returns one event type. GET /v1/app_event_types/:id_or_type.
func (s *AppEventTypesService) Get(ctx context.Context, idOrType string) (*AppEventType, error) {
	out := &AppEventType{}
	return out, s.client.get(ctx, "/v1/app_event_types/"+url.PathEscape(idOrType), nil, out)
}

// Update changes an event type. PATCH /v1/app_event_types/:id_or_type.
func (s *AppEventTypesService) Update(ctx context.Context, idOrType string, params UpdateAppEventTypeParams, opts ...RequestOption) (*AppEventType, error) {
	out := &AppEventType{}
	return out, s.client.patch(ctx, "/v1/app_event_types/"+url.PathEscape(idOrType), params, out, opts...)
}

// Delete removes an event type. DELETE /v1/app_event_types/:id_or_type.
func (s *AppEventTypesService) Delete(ctx context.Context, idOrType string, opts ...RequestOption) (*DeletedAppEventType, error) {
	out := &DeletedAppEventType{}
	return out, s.client.del(ctx, "/v1/app_event_types/"+url.PathEscape(idOrType), out, opts...)
}

// AppWebhookEndpointsService is /v1/organizations/:id/app_webhook_endpoints.
// The endpoints are webhook endpoint objects as for instance webhooks, signed
// with Standard Webhooks. The FAPI equivalent needs org:webhooks:manage.
type AppWebhookEndpointsService struct{ client *Client }

// AppWebhookEndpointParams is the body of an app webhook endpoint create or
// update. EnabledEvents are types from your catalog, or ["*"] (the default).
type AppWebhookEndpointParams struct {
	URL           string   `json:"url,omitempty"`
	EnabledEvents []string `json:"enabled_events,omitempty"`
	Description   *string  `json:"description,omitempty"`
	Active        *bool    `json:"active,omitempty"`
}

func appEndpointsPath(orgID string) string {
	return "/v1/organizations/" + url.PathEscape(orgID) + "/app_webhook_endpoints"
}

func appEndpointPath(orgID, endpointID string) string {
	return appEndpointsPath(orgID) + "/" + url.PathEscape(endpointID)
}

// List returns the organization's endpoints.
// GET /v1/organizations/:id/app_webhook_endpoints.
func (s *AppWebhookEndpointsService) List(ctx context.Context, orgID string) (*ListPage[WebhookEndpoint], error) {
	out := &ListPage[WebhookEndpoint]{}
	return out, s.client.get(ctx, appEndpointsPath(orgID), nil, out)
}

// Create registers an endpoint; the whsec_ secret is in this response only
// (or RevealSecret). POST /v1/organizations/:id/app_webhook_endpoints.
func (s *AppWebhookEndpointsService) Create(ctx context.Context, orgID string, params AppWebhookEndpointParams, opts ...RequestOption) (*WebhookEndpointWithSecret, error) {
	out := &WebhookEndpointWithSecret{}
	return out, s.client.post(ctx, appEndpointsPath(orgID), params, out, opts...)
}

// Get returns one endpoint.
// GET /v1/organizations/:id/app_webhook_endpoints/:endpoint_id.
func (s *AppWebhookEndpointsService) Get(ctx context.Context, orgID, endpointID string) (*WebhookEndpoint, error) {
	out := &WebhookEndpoint{}
	return out, s.client.get(ctx, appEndpointPath(orgID, endpointID), nil, out)
}

// Update changes an endpoint.
// PATCH /v1/organizations/:id/app_webhook_endpoints/:endpoint_id.
func (s *AppWebhookEndpointsService) Update(ctx context.Context, orgID, endpointID string, params AppWebhookEndpointParams, opts ...RequestOption) (*WebhookEndpoint, error) {
	out := &WebhookEndpoint{}
	return out, s.client.patch(ctx, appEndpointPath(orgID, endpointID), params, out, opts...)
}

// Delete removes an endpoint.
// DELETE /v1/organizations/:id/app_webhook_endpoints/:endpoint_id.
func (s *AppWebhookEndpointsService) Delete(ctx context.Context, orgID, endpointID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, appEndpointPath(orgID, endpointID), out, opts...)
}

// RotateSecret replaces the signing secret; the previous one keeps signing
// for 24 hours. POST .../app_webhook_endpoints/:endpoint_id/rotate_secret.
func (s *AppWebhookEndpointsService) RotateSecret(ctx context.Context, orgID, endpointID string, opts ...RequestOption) (*WebhookSecret, error) {
	out := &WebhookSecret{}
	return out, s.client.post(ctx, appEndpointPath(orgID, endpointID)+"/rotate_secret", nil, out, opts...)
}

// RevealSecret shows the current signing secret.
// POST .../app_webhook_endpoints/:endpoint_id/reveal_secret.
func (s *AppWebhookEndpointsService) RevealSecret(ctx context.Context, orgID, endpointID string, opts ...RequestOption) (*WebhookSecret, error) {
	out := &WebhookSecret{}
	return out, s.client.post(ctx, appEndpointPath(orgID, endpointID)+"/reveal_secret", nil, out, opts...)
}

// Test queues a test event (wait empty), or with wait ("10s", at most 10 s)
// attempts it now and returns the result in the WebhookTestResult fields.
// POST .../app_webhook_endpoints/:endpoint_id/test?wait=.
func (s *AppWebhookEndpointsService) Test(ctx context.Context, orgID, endpointID, wait string, opts ...RequestOption) (*AppWebhookTest, error) {
	var q url.Values
	if wait != "" {
		q = url.Values{"wait": {wait}}
	}
	out := &AppWebhookTest{}
	return out, s.client.postQ(ctx, appEndpointPath(orgID, endpointID)+"/test", q, nil, out, opts...)
}

// AppWebhookTest is a test send: queued (WebhookDispatch fields) or attempted
// with wait (WebhookTestResult fields).
type AppWebhookTest struct {
	WebhookTestResult
	ID   string `json:"id,omitempty"`
	Note string `json:"note,omitempty"`
}

// Deliveries returns the delivery log.
// GET .../app_webhook_endpoints/:endpoint_id/deliveries.
func (s *AppWebhookEndpointsService) Deliveries(ctx context.Context, orgID, endpointID string, params ListWebhookDeliveriesParams) (*CursorPage[WebhookDelivery], error) {
	out := &CursorPage[WebhookDelivery]{}
	return out, s.client.get(ctx, appEndpointPath(orgID, endpointID)+"/deliveries", params.values(), out)
}

// Redeliver sends one past delivery again as a fresh attempt.
// POST .../app_webhook_endpoints/:endpoint_id/deliveries/:delivery_id/redeliver.
func (s *AppWebhookEndpointsService) Redeliver(ctx context.Context, orgID, endpointID, deliveryID string, opts ...RequestOption) (*WebhookDispatch, error) {
	out := &WebhookDispatch{}
	return out, s.client.post(ctx, appEndpointPath(orgID, endpointID)+"/deliveries/"+url.PathEscape(deliveryID)+"/redeliver", nil, out, opts...)
}

// Replay re-sends what the endpoint missed (Since or SinceFailingSince).
// POST .../app_webhook_endpoints/:endpoint_id/replay.
func (s *AppWebhookEndpointsService) Replay(ctx context.Context, orgID, endpointID string, params ReplayWebhookParams, opts ...RequestOption) (*WebhookBulkResult, error) {
	out := &WebhookBulkResult{}
	return out, s.client.post(ctx, appEndpointPath(orgID, endpointID)+"/replay", params, out, opts...)
}

// AppEventTypes returns the event types the organization's endpoints can
// subscribe to (the picker list). GET /v1/organizations/:id/app_event_types.
func (s *AppWebhookEndpointsService) AppEventTypes(ctx context.Context, orgID string) (*ListPage[AppEventType], error) {
	out := &ListPage[AppEventType]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/app_event_types", nil, out)
}
