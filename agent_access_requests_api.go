package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// AgentAccessRequestsService is the agentAccessRequests resource.
type AgentAccessRequestsService struct {
	client *Client
}

// Approve: Approve a pending request, optionally for a limited time (expires_in_seconds). 409 when
// it is no longer pending. Emits agent.access_decided.
// POST /v1/agent_access_requests/{id}/approve.
func (s *AgentAccessRequestsService) Approve(ctx context.Context, id string, params AgentAccessRequestsApproveParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/agent_access_requests/"+url.PathEscape(id)+"/approve", nil, params, nil, opts...)
}

// Deny: Deny a pending request. 409 when it is no longer pending. Emits agent.access_decided.
// POST /v1/agent_access_requests/{id}/deny.
func (s *AgentAccessRequestsService) Deny(ctx context.Context, id string, params AgentAccessRequestsDenyParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/agent_access_requests/"+url.PathEscape(id)+"/deny", nil, params, nil, opts...)
}

// AgentAccessRequestsListQuery holds the query parameters of AgentAccessRequestsService.List.
type AgentAccessRequestsListQuery struct {
	// Request status to filter by.
	Status string
	// Restrict to one agent.
	AgentID string
	// Page size. Defaults to 50; values above 200 are capped at 200.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q AgentAccessRequestsListQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.AgentID != "" {
		v.Set("agent_id", q.AgentID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List agent access requests, newest first. Filter by status (pending, approved, denied,
// revoked) or agent_id.
// GET /v1/agent_access_requests.
func (s *AgentAccessRequestsService) List(ctx context.Context, query AgentAccessRequestsListQuery) (*AgentsListResult, error) {
	out := &AgentsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/agent_access_requests", query.values(), nil, out)
}
