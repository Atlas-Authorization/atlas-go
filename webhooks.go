package atlas

import (
	"context"
	"net/url"
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
	DisabledAt    *int64   `json:"disabled_at"`
	CreatedAt     int64    `json:"created_at"`
}

// WebhookEndpointWithSecret reveals the signing secret (whsec_...) once, on
// create.
type WebhookEndpointWithSecret struct {
	WebhookEndpoint
	Secret string `json:"secret"`
}

// WebhookDelivery is one delivery attempt in an endpoint's log.
type WebhookDelivery struct {
	Object          string  `json:"object"`
	ID              string  `json:"id"`
	EventID         string  `json:"event_id"`
	AttemptNumber   int     `json:"attempt_number"`
	Status          string  `json:"status"`
	HTTPStatus      *int    `json:"http_status"`
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
func (s *WebhookEndpointsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/webhook_endpoints/"+url.PathEscape(id), out)
}
