package atlas

import (
	"context"
	"net/url"
)

// RelayAgentsService is the relayAgents resource.
type RelayAgentsService struct {
	client *Client
}

// List: List the on-prem relay agents with their allowed destinations and whether each is online.
// Secrets are never returned.
// GET /v1/relay_agents.
func (s *RelayAgentsService) List(ctx context.Context, params ListParams) (*RelayAgentsListResult, error) {
	out := &RelayAgentsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/relay_agents", params.values(), nil, out)
}

// Create: Register an outbound-only relay agent. The response carries the agent token once; it
// cannot be read back. An agent can reach only the destinations in allowed_destinations (host,
// host:port, *.domain).
// POST /v1/relay_agents.
func (s *RelayAgentsService) Create(ctx context.Context, params RelayAgentsCreateParams, opts ...RequestOption) (*RelayAgentsListResultDataItem, error) {
	out := &RelayAgentsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/relay_agents", nil, params, out, opts...)
}

// Get: Read one relay agent, including when it last polled.
// GET /v1/relay_agents/{id}.
func (s *RelayAgentsService) Get(ctx context.Context, id string) (*RelayAgentsListResultDataItem, error) {
	out := &RelayAgentsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/relay_agents/"+url.PathEscape(id), nil, nil, out)
}

// Update: Rename an agent, change its allowed destinations or pinned client-certificate
// thumbprints, or revoke it (status: revoked).
// PATCH /v1/relay_agents/{id}.
func (s *RelayAgentsService) Update(ctx context.Context, id string, params RelayAgentsUpdateParams, opts ...RequestOption) (*RelayAgentsListResultDataItem, error) {
	out := &RelayAgentsListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/relay_agents/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a relay agent and its queued jobs.
// DELETE /v1/relay_agents/{id}.
func (s *RelayAgentsService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/relay_agents/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// RotateSecret: Issue a new agent token (returned once). The old token stops working immediately.
// POST /v1/relay_agents/{id}/rotate_secret.
func (s *RelayAgentsService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*RelayAgentsListResultDataItem, error) {
	out := &RelayAgentsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/relay_agents/"+url.PathEscape(id)+"/rotate_secret", nil, nil, out, opts...)
}
