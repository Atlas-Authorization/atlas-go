package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ListConnectedApps: List the apps (OAuth clients) that hold an active grant in this
// organization's context, one entry per grant.
// GET /v1/organizations/{id}/connected_apps.
func (s *OrganizationsService) ListConnectedApps(ctx context.Context, id string, params ListParams) (*CursorPage[OrganizationsListConnectedAppsItem], error) {
	out := &CursorPage[OrganizationsListConnectedAppsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/organizations/"+url.PathEscape(id)+"/connected_apps", params.values(), nil, out)
}

// RevokeConnectedApp: Revoke one connected app grant of the organization: its tokens and any
// session minted from it stop working. Emits grant.revoked; audited as
// organization.connected_app_revoked.
// DELETE /v1/organizations/{id}/connected_apps/{grantId}.
func (s *OrganizationsService) RevokeConnectedApp(ctx context.Context, id string, grantID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/organizations/"+url.PathEscape(id)+"/connected_apps/"+url.PathEscape(grantID), nil, nil, out, opts...)
}

// OrganizationsGetConnectionSecretQuery holds the query parameters of OrganizationsService.GetConnectionSecret.
type OrganizationsGetConnectionSecretQuery struct {
	// current (default), previous, or a version number.
	Version string
}

func (q OrganizationsGetConnectionSecretQuery) values() url.Values {
	v := url.Values{}
	if q.Version != "" {
		v.Set("version", q.Version)
	}
	return v
}

// GetConnectionSecret: The same read, scoped to an organization: 404 unless the connection is
// owned by that organization. Needs connections:secret_read; audited.
// GET /v1/organizations/{id}/connections/{connectionId}/secret.
func (s *OrganizationsService) GetConnectionSecret(ctx context.Context, id string, connectionID string, query OrganizationsGetConnectionSecretQuery) (*OrganizationsGetConnectionSecretResult, error) {
	out := &OrganizationsGetConnectionSecretResult{}
	return out, s.client.do(ctx, "GET", "/v1/organizations/"+url.PathEscape(id)+"/connections/"+url.PathEscape(connectionID)+"/secret", query.values(), nil, out)
}

// OrganizationsWebhookEndpointsService is the organizations webhookEndpoints group of OrganizationsService.
type OrganizationsWebhookEndpointsService struct {
	client *Client
}

// List: List the organization's own webhook endpoints. Backend API. Never returns a secret.
// GET /v1/organizations/{id}/webhook_endpoints.
func (s *OrganizationsWebhookEndpointsService) List(ctx context.Context, id string, params ListParams) (*CursorPage[OrganizationsWebhookEndpointsListItem], error) {
	out := &CursorPage[OrganizationsWebhookEndpointsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints", params.values(), nil, out)
}

// Create: Register a webhook endpoint for one organization. It receives only that organization's
// events (membership, invitation, role, domain and organization events). The signing secret is
// returned in this response only. Backend API. At most 20 per organization.
// POST /v1/organizations/{id}/webhook_endpoints.
func (s *OrganizationsWebhookEndpointsService) Create(ctx context.Context, id string, params OrganizationsWebhookEndpointsCreateParams, opts ...RequestOption) (interface{}, error) {
	var out interface{}
	return out, s.client.do(ctx, "POST", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints", nil, params, &out, opts...)
}

// Get: Retrieve one of the organization's webhook endpoints, with its delivery health.
// GET /v1/organizations/{id}/webhook_endpoints/{endpointId}.
func (s *OrganizationsWebhookEndpointsService) Get(ctx context.Context, id string, endpointID string) (*OrganizationsWebhookEndpointsListItem, error) {
	out := &OrganizationsWebhookEndpointsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID), nil, nil, out)
}

// Update: Update the url, subscribed events, description or active flag of one of the
// organization's endpoints. Never re-reveals the secret.
// PATCH /v1/organizations/{id}/webhook_endpoints/{endpointId}.
func (s *OrganizationsWebhookEndpointsService) Update(ctx context.Context, id string, endpointID string, params OrganizationsWebhookEndpointsCreateParams, opts ...RequestOption) (*OrganizationsWebhookEndpointsListItem, error) {
	out := &OrganizationsWebhookEndpointsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID), nil, params, out, opts...)
}

// Delete: Delete one of the organization's webhook endpoints and its delivery log. An id from
// another organization is a 404.
// DELETE /v1/organizations/{id}/webhook_endpoints/{endpointId}.
func (s *OrganizationsWebhookEndpointsService) Delete(ctx context.Context, id string, endpointID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID), nil, nil, out, opts...)
}

// RotateSecret: Rotate the signing secret. The previous secret keeps signing alongside the new one
// for 24 hours so the receiver can switch over without dropping events.
// POST /v1/organizations/{id}/webhook_endpoints/{endpointId}/rotate_secret.
func (s *OrganizationsWebhookEndpointsService) RotateSecret(ctx context.Context, id string, endpointID string, opts ...RequestOption) (*OrganizationsWebhookEndpointsRotateSecretResult, error) {
	out := &OrganizationsWebhookEndpointsRotateSecretResult{}
	return out, s.client.do(ctx, "POST", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID)+"/rotate_secret", nil, nil, out, opts...)
}

// OrganizationsWebhookEndpointsDeliveriesQuery holds the query parameters of OrganizationsWebhookEndpointsService.Deliveries.
type OrganizationsWebhookEndpointsDeliveriesQuery struct {
	// Page size. Defaults to 50; values above 1000 are capped at 1000.
	Limit int64
	// Cursor: return only items after this id. Pass the `next_cursor` (or the last item id) of the
	// previous page.
	StartingAfter string
	// Only deliveries in this state.
	Status string
	// Only deliveries of these event types (comma-separated; any spelling matches every spelling of
	// the event).
	EventType string
	// Only deliveries created at or after this time: Unix epoch milliseconds or an ISO 8601 time.
	Since string
	// Only deliveries created before this time: Unix epoch milliseconds or an ISO 8601 time.
	Until string
	// Only deliveries that carried this trace: a 32-hex W3C trace-id (the second field of a
	// traceparent).
	Trace string
}

func (q OrganizationsWebhookEndpointsDeliveriesQuery) values() url.Values {
	v := url.Values{}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.EventType != "" {
		v.Set("event_type", q.EventType)
	}
	if q.Since != "" {
		v.Set("since", q.Since)
	}
	if q.Until != "" {
		v.Set("until", q.Until)
	}
	if q.Trace != "" {
		v.Set("trace", q.Trace)
	}
	return v
}

// Deliveries: The endpoint's delivery log: payload, response and retry state for each attempt,
// filterable by status, event type and time.
// GET /v1/organizations/{id}/webhook_endpoints/{endpointId}/deliveries.
func (s *OrganizationsWebhookEndpointsService) Deliveries(ctx context.Context, id string, endpointID string, query OrganizationsWebhookEndpointsDeliveriesQuery) (*CursorPage[OrganizationsWebhookEndpointsDeliveriesItem], error) {
	out := &CursorPage[OrganizationsWebhookEndpointsDeliveriesItem]{}
	return out, s.client.do(ctx, "GET", "/v1/organizations/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID)+"/deliveries", query.values(), nil, out)
}
