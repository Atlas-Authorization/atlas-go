package atlas

import (
	"context"
	"net/url"
)

// MCPGatewaysService is the mcpGateways resource.
type MCPGatewaysService struct {
	client  *Client
	Budgets *MCPGatewaysBudgetsService
}

// List: List the MCP tool gateways of the instance.
// GET /v1/mcp_gateways.
func (s *MCPGatewaysService) List(ctx context.Context) (*AgentsGetResult, error) {
	out := &AgentsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/mcp_gateways", nil, nil, out)
}

// Create: Create an MCP gateway: one URL (`url` in the response) that fronts your MCP server.
// `tools` maps a tool name to its policy (allow, scopes the agent token must hold, argument
// conditions, approval, response masking); `default_policy` (deny by default) decides tools not
// listed. upstream_authorization is write-only and sent to the upstream as its Authorization
// header.
// POST /v1/mcp_gateways.
func (s *MCPGatewaysService) Create(ctx context.Context, params MCPGatewaysCreateParams, opts ...RequestOption) (*AgentsGetResult, error) {
	out := &AgentsGetResult{}
	return out, s.client.do(ctx, "POST", "/v1/mcp_gateways", nil, params, out, opts...)
}

// Get: Read one MCP gateway.
// GET /v1/mcp_gateways/{id}.
func (s *MCPGatewaysService) Get(ctx context.Context, id string) (*AgentsGetResult, error) {
	out := &AgentsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/mcp_gateways/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update an MCP gateway. Omitted fields keep their value; `tools` is replaced as a whole.
// `abac` turns on authorization of every tool call through the ABAC policy engine.
// PATCH /v1/mcp_gateways/{id}.
func (s *MCPGatewaysService) Update(ctx context.Context, id string, params MCPGatewaysUpdateParams, opts ...RequestOption) (*AgentsGetResult, error) {
	out := &AgentsGetResult{}
	return out, s.client.do(ctx, "PATCH", "/v1/mcp_gateways/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete an MCP gateway.
// DELETE /v1/mcp_gateways/{id}.
func (s *MCPGatewaysService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/mcp_gateways/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// MCPGatewaysBudgetsService is the mcpGateways budgets group of MCPGatewaysService.
type MCPGatewaysBudgetsService struct {
	client *Client
}

// List: The cross-call budgets of a gateway, newest first (at most 50): ceilings on how many
// calls, how much cost, or how many calls per window one agent or one session may make.
// GET /v1/mcp_gateways/{id}/budgets.
func (s *MCPGatewaysBudgetsService) List(ctx context.Context, id string, params ListParams) (*MCPGatewaysBudgetsListResult, error) {
	out := &MCPGatewaysBudgetsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets", params.values(), nil, out)
}

// Create: Add a budget. `metric` is `calls` (a count), `cost` (the sum of each call's cost:
// `cost_per_call`, or the number found at `cost_arg` in the call arguments, such as an amount) or
// `rate` (calls per `window_seconds`, required). `limit` is the ceiling. `window_seconds` makes
// the counter reset in fixed windows; without it a counter never resets (a per-session one ends
// with the session). `scope` is `agent` (each agent counts separately) or `session` (each session
// of each agent; the client must echo the `Mcp-Session-Id` from initialize). `agent_id` limits it
// to one agent and `tool` to one tool. A call is charged against every budget it touches at once,
// or against none; only a call that is allowed and about to run is charged.
// POST /v1/mcp_gateways/{id}/budgets.
func (s *MCPGatewaysBudgetsService) Create(ctx context.Context, id string, params MCPGatewaysBudgetsCreateParams, opts ...RequestOption) (*MCPGatewaysBudgetsListResultDataItem, error) {
	out := &MCPGatewaysBudgetsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets", nil, params, out, opts...)
}

// Get: Read one budget of an MCP gateway.
// GET /v1/mcp_gateways/{id}/budgets/{budgetId}.
func (s *MCPGatewaysBudgetsService) Get(ctx context.Context, id string, budgetID string) (*MCPGatewaysBudgetsListResultDataItem, error) {
	out := &MCPGatewaysBudgetsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets/"+url.PathEscape(budgetID), nil, nil, out)
}

// Update: Change a budget. Omitted fields keep their value. Raising the limit takes effect on the
// next call; counters are kept.
// PATCH /v1/mcp_gateways/{id}/budgets/{budgetId}.
func (s *MCPGatewaysBudgetsService) Update(ctx context.Context, id string, budgetID string, params MCPGatewaysBudgetsCreateParams, opts ...RequestOption) (*MCPGatewaysBudgetsListResultDataItem, error) {
	out := &MCPGatewaysBudgetsListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets/"+url.PathEscape(budgetID), nil, params, out, opts...)
}

// Delete: Delete a budget and stop counting against it.
// DELETE /v1/mcp_gateways/{id}/budgets/{budgetId}.
func (s *MCPGatewaysBudgetsService) Delete(ctx context.Context, id string, budgetID string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets/"+url.PathEscape(budgetID), nil, nil, nil, opts...)
}

// MCPGatewaysBudgetsUsageQuery holds the query parameters of MCPGatewaysBudgetsService.Usage.
type MCPGatewaysBudgetsUsageQuery struct {
	// The agent (machine) id. Optional when the budget names one agent.
	AgentID string
	// The Mcp-Session-Id, for a per-session budget.
	SessionID string
}

func (q MCPGatewaysBudgetsUsageQuery) values() url.Values {
	v := url.Values{}
	if q.AgentID != "" {
		v.Set("agent_id", q.AgentID)
	}
	if q.SessionID != "" {
		v.Set("session_id", q.SessionID)
	}
	return v
}

// Usage: What one agent has used of a budget right now, with the room left and when the window
// resets. A per-session budget also needs the `session_id` (the Mcp-Session-Id of that session).
// GET /v1/mcp_gateways/{id}/budgets/{budgetId}/usage.
func (s *MCPGatewaysBudgetsService) Usage(ctx context.Context, id string, budgetID string, query MCPGatewaysBudgetsUsageQuery) (*MCPGatewaysBudgetsUsageResult, error) {
	out := &MCPGatewaysBudgetsUsageResult{}
	return out, s.client.do(ctx, "GET", "/v1/mcp_gateways/"+url.PathEscape(id)+"/budgets/"+url.PathEscape(budgetID)+"/usage", query.values(), nil, out)
}
