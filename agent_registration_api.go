package atlas

import (
	"context"
)

// AgentRegistrationService is the agentRegistration resource.
type AgentRegistrationService struct {
	client *Client
}

// Get: Read the agent registration settings (enabled, allowed identity kinds, untrusted and
// trusted scopes, claim code lifetime).
// GET /v1/agent_registration.
func (s *AgentRegistrationService) Get(ctx context.Context) (*AgentRegistrationGetResult, error) {
	out := &AgentRegistrationGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/agent_registration", nil, nil, out)
}

// Replace: Update the agent registration settings. Partial: only the fields sent change.
// PUT /v1/agent_registration.
func (s *AgentRegistrationService) Replace(ctx context.Context, params AgentRegistrationReplaceParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PUT", "/v1/agent_registration", nil, params, nil, opts...)
}
