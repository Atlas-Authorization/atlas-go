package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// AgentsService is the agents resource.
type AgentsService struct {
	client *Client
}

// Claim: Backend-assisted claim: bind an agent to a user you already know and promote it to
// trusted. Audited as agent.claimed.
// POST /v1/agents/{id}/claim.
func (s *AgentsService) Claim(ctx context.Context, id string, params AgentsClaimParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/agents/"+url.PathEscape(id)+"/claim", nil, params, nil, opts...)
}

// AgentsListQuery holds the query parameters of AgentsService.List.
type AgentsListQuery struct {
	// Restrict to agents owned by this user.
	OwnerUserID string
	// Trust tier to filter by.
	Tier string
	// Page size. Defaults to 50; values above 200 are capped at 200.
	Limit int64
	// Cursor: the id of the last agent of the previous page.
	StartingAfter string
}

func (q AgentsListQuery) values() url.Values {
	v := url.Values{}
	if q.OwnerUserID != "" {
		v.Set("owner_user_id", q.OwnerUserID)
	}
	if q.Tier != "" {
		v.Set("tier", q.Tier)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: The agent registry: every registered agent with its tier, owner and status. Filter by
// owner_user_id or tier; page with limit and starting_after.
// GET /v1/agents.
func (s *AgentsService) List(ctx context.Context, query AgentsListQuery) (*AgentsListResult, error) {
	out := &AgentsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/agents", query.values(), nil, out)
}

// Get: One agent with its currently valid access grants.
// GET /v1/agents/{id}.
func (s *AgentsService) Get(ctx context.Context, id string) (*AgentsGetResult, error) {
	out := &AgentsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/agents/"+url.PathEscape(id), nil, nil, out)
}

// SetOwner: Set the owning user of an agent, or null to remove the owner (which also drops the
// agent back to untrusted).
// PUT /v1/agents/{id}/owner.
func (s *AgentsService) SetOwner(ctx context.Context, id string, params AgentsSetOwnerParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PUT", "/v1/agents/"+url.PathEscape(id)+"/owner", nil, params, nil, opts...)
}

// RevokeAccess: Revoke every grant and cancel every pending request of an agent. With disable:
// true the agent itself is revoked and can no longer get tokens. Emits agent.access_revoked.
// POST /v1/agents/{id}/revoke_access.
func (s *AgentsService) RevokeAccess(ctx context.Context, id string, params AgentsRevokeAccessParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/agents/"+url.PathEscape(id)+"/revoke_access", nil, params, nil, opts...)
}
