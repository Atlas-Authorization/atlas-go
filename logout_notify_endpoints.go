package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// LogoutNotifyEndpointsService is /v1/logout_notify_endpoints: downstream
// services that receive the same signed logout_token as your OIDC apps
// whenever an Atlas session ends, plus a subject-wide one (sub, no sid) on
// ban, deletion or deprovisioning.
type LogoutNotifyEndpointsService struct{ client *Client }

// LogoutNotifyEndpoint is one logout fan-out endpoint.
type LogoutNotifyEndpoint struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	URL    string `json:"url"`
	// OAuthClientID is the client_id the endpoint follows; nil = instance-wide.
	OAuthClientID *string `json:"oauth_client_id"`
	// Audience is the aud its logout_tokens carry.
	Audience    string  `json:"audience"`
	Description *string `json:"description"`
	CreatedAt   int64   `json:"created_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// CreateLogoutNotifyEndpointParams is the body of POST /v1/logout_notify_endpoints.
type CreateLogoutNotifyEndpointParams struct {
	// URL is a public https endpoint.
	URL string `json:"url"`
	// OAuthClientID follows one client instead of the whole instance.
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	// Audience defaults to the client_id when following a client, else the
	// instance id.
	Audience    string `json:"audience,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateLogoutNotifyEndpointParams is the body of PATCH
// /v1/logout_notify_endpoints/:id. Unset fields are left alone.
type UpdateLogoutNotifyEndpointParams struct {
	URL         string `json:"url,omitempty"`
	Audience    string `json:"audience,omitempty"`
	Description string `json:"description,omitempty"`
}

// LogoutNotifyDelivery is one logout_token sent to a fan-out endpoint.
type LogoutNotifyDelivery struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Sub    string `json:"sub"`
	// Sid is nil for a subject-wide logout (ban / deletion).
	Sid *string `json:"sid"`
	// Status is pending, success or failed.
	Status          string  `json:"status"`
	AttemptNumber   int     `json:"attempt_number"`
	HTTPStatus      *int    `json:"http_status"`
	ResponseSnippet *string `json:"response_snippet"`
	NextRetryAt     *int64  `json:"next_retry_at"`
	DeliveredAt     *int64  `json:"delivered_at"`
	CreatedAt       int64   `json:"created_at"`
}

// List returns the logout fan-out endpoints. GET /v1/logout_notify_endpoints.
func (s *LogoutNotifyEndpointsService) List(ctx context.Context) (*ListPage[LogoutNotifyEndpoint], error) {
	out := &ListPage[LogoutNotifyEndpoint]{}
	return out, s.client.get(ctx, "/v1/logout_notify_endpoints", nil, out)
}

// Create registers a logout fan-out endpoint. POST /v1/logout_notify_endpoints.
func (s *LogoutNotifyEndpointsService) Create(ctx context.Context, params CreateLogoutNotifyEndpointParams, opts ...RequestOption) (*LogoutNotifyEndpoint, error) {
	out := &LogoutNotifyEndpoint{}
	return out, s.client.post(ctx, "/v1/logout_notify_endpoints", params, out, opts...)
}

// Get fetches one endpoint. GET /v1/logout_notify_endpoints/:id.
func (s *LogoutNotifyEndpointsService) Get(ctx context.Context, id string) (*LogoutNotifyEndpoint, error) {
	out := &LogoutNotifyEndpoint{}
	return out, s.client.get(ctx, "/v1/logout_notify_endpoints/"+url.PathEscape(id), nil, out)
}

// Update changes an endpoint's url, audience or description.
// PATCH /v1/logout_notify_endpoints/:id.
func (s *LogoutNotifyEndpointsService) Update(ctx context.Context, id string, params UpdateLogoutNotifyEndpointParams, opts ...RequestOption) (*LogoutNotifyEndpoint, error) {
	out := &LogoutNotifyEndpoint{}
	return out, s.client.patch(ctx, "/v1/logout_notify_endpoints/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes an endpoint and its queued deliveries.
// DELETE /v1/logout_notify_endpoints/:id.
func (s *LogoutNotifyEndpointsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/logout_notify_endpoints/"+url.PathEscape(id), out, opts...)
}

// Deliveries returns an endpoint's delivery log, newest first (limit 1-100;
// 0 for the default). GET /v1/logout_notify_endpoints/:id/deliveries.
func (s *LogoutNotifyEndpointsService) Deliveries(ctx context.Context, id string, limit int) (*ListPage[LogoutNotifyDelivery], error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	out := &ListPage[LogoutNotifyDelivery]{}
	return out, s.client.get(ctx, "/v1/logout_notify_endpoints/"+url.PathEscape(id)+"/deliveries", q, out)
}
