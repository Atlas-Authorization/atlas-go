package atlas

import (
	"context"
	"net/url"
)

// SSFService is the ssf resource.
type SSFService struct {
	client    *Client
	Streams   *SSFStreamsService
	Receivers *SSFReceiversService
}

// SSFStreamsService is the ssf streams group of SSFService.
type SSFStreamsService struct {
	client *Client
}

// List: List the Shared Signals streams this instance transmits on (push and poll), with their
// delivery method, requested events and status.
// GET /v1/ssf/streams.
func (s *SSFStreamsService) List(ctx context.Context, params ListParams) (*CursorPage[OrgLDAPConnectionsGetSyncResult], error) {
	out := &CursorPage[OrgLDAPConnectionsGetSyncResult]{}
	return out, s.client.do(ctx, "GET", "/v1/ssf/streams", params.values(), nil, out)
}

// Create: Create a stream. `delivery_method` is `push` (we POST each signed SET to `endpoint_url`,
// with the optional `authorization_header`) or `poll` (the receiver pulls from the returned
// `poll_endpoint` with the one-time `poll_token`). `events_requested` limits the events sent
// (empty = all supported). SETs are signed with the instance signing key.
// POST /v1/ssf/streams.
func (s *SSFStreamsService) Create(ctx context.Context, params SSFStreamsCreateParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/ssf/streams", nil, params, nil, opts...)
}

// Get: Read a stream, including how many events are waiting to be delivered or acknowledged.
// GET /v1/ssf/streams/{id}.
func (s *SSFStreamsService) Get(ctx context.Context, id string) (*OrgLDAPConnectionsGetSyncResult, error) {
	out := &OrgLDAPConnectionsGetSyncResult{}
	return out, s.client.do(ctx, "GET", "/v1/ssf/streams/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a stream: its events, endpoint, authorization header, description, or status
// (`enabled`, `paused`, `disabled`). A paused stream stops receiving new events.
// PATCH /v1/ssf/streams/{id}.
func (s *SSFStreamsService) Update(ctx context.Context, id string, params SSFStreamsUpdateParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PATCH", "/v1/ssf/streams/"+url.PathEscape(id), nil, params, nil, opts...)
}

// Delete: Delete a stream and its queued events.
// DELETE /v1/ssf/streams/{id}.
func (s *SSFStreamsService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/ssf/streams/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// Verify: Queue an SSF verification event carrying `state`, so a receiver can confirm the stream
// works end to end.
// POST /v1/ssf/streams/{id}/verify.
func (s *SSFStreamsService) Verify(ctx context.Context, id string, params SSFStreamsVerifyParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/ssf/streams/"+url.PathEscape(id)+"/verify", nil, params, nil, opts...)
}

// GetStatus: The stream's delivery status: enabled, paused or disabled (SSF stream status).
// GET /v1/ssf/streams/{id}/status.
func (s *SSFStreamsService) GetStatus(ctx context.Context, id string) (*OrgLDAPConnectionsGetSyncResult, error) {
	out := &OrgLDAPConnectionsGetSyncResult{}
	return out, s.client.do(ctx, "GET", "/v1/ssf/streams/"+url.PathEscape(id)+"/status", nil, nil, out)
}

// UpdateStatus: Set the stream's delivery status to enabled, paused or disabled. A paused stream
// collects nothing.
// POST /v1/ssf/streams/{id}/status.
func (s *SSFStreamsService) UpdateStatus(ctx context.Context, id string, params SSFStreamsUpdateStatusParams, opts ...RequestOption) (*OrgLDAPConnectionsGetSyncResult, error) {
	out := &OrgLDAPConnectionsGetSyncResult{}
	return out, s.client.do(ctx, "POST", "/v1/ssf/streams/"+url.PathEscape(id)+"/status", nil, params, out, opts...)
}

// Events: The stream's recent events with delivery status, attempts and the last error (the
// dashboard activity view).
// GET /v1/ssf/streams/{id}/events.
func (s *SSFStreamsService) Events(ctx context.Context, id string, params ListParams) (*CursorPage[OrgLDAPConnectionsGetSyncResult], error) {
	out := &CursorPage[OrgLDAPConnectionsGetSyncResult]{}
	return out, s.client.do(ctx, "GET", "/v1/ssf/streams/"+url.PathEscape(id)+"/events", params.values(), nil, out)
}

// SSFReceiversService is the ssf receivers group of SSFService.
type SSFReceiversService struct {
	client *Client
}

// List: List inbound Shared Signals receivers: transmitters whose signed events act on this
// instance's users.
// GET /v1/ssf/receivers.
func (s *SSFReceiversService) List(ctx context.Context, params ListParams) (*CursorPage[OrgLDAPConnectionsGetSyncResult], error) {
	out := &CursorPage[OrgLDAPConnectionsGetSyncResult]{}
	return out, s.client.do(ctx, "GET", "/v1/ssf/receivers", params.values(), nil, out)
}

// Create: Register a transmitter. Its SETs are POSTed (`application/secevent+jwt`) to the returned
// `receive_endpoint` and verified against `jwks_uri`, `issuer` and the optional `audience`.
// `actions` maps an event type URI to `revoke_sessions`, `refresh_claims` (invalidate minted
// tokens so the next refresh carries fresh claims, sessions stay), `ban` or `ignore`; unmapped
// events are ignored. The default maps session-revoked, credential-change, credential-compromise
// and device-compliance-change (only when the new status is not-compliant) to `revoke_sessions`,
// token-claims-change to `refresh_claims` and account-disabled to `ban`.
// POST /v1/ssf/receivers.
func (s *SSFReceiversService) Create(ctx context.Context, params SSFReceiversCreateParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/ssf/receivers", nil, params, nil, opts...)
}

// Update: Change a receiver: name, JWKS URI, audience, action mapping, or enabled.
// PATCH /v1/ssf/receivers/{id}.
func (s *SSFReceiversService) Update(ctx context.Context, id string, params SSFReceiversUpdateParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PATCH", "/v1/ssf/receivers/"+url.PathEscape(id), nil, params, nil, opts...)
}

// Delete: Delete an inbound SSF receiver; its endpoint stops accepting events.
// DELETE /v1/ssf/receivers/{id}.
func (s *SSFReceiversService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/ssf/receivers/"+url.PathEscape(id), nil, nil, nil, opts...)
}
