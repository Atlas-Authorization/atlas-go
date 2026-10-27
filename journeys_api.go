package atlas

import (
	"context"
	"net/url"
)

// JourneysService is the journeys resource.
type JourneysService struct {
	client *Client
}

// List: The sign-in journeys.
// GET /v1/flows.
func (s *JourneysService) List(ctx context.Context, params ListParams) (*JourneysListResult, error) {
	out := &JourneysListResult{}
	return out, s.client.do(ctx, "GET", "/v1/flows", params.values(), nil, out)
}

// Create: Create a sign-in journey (version 1, active unless activate is false). Steps run top to
// bottom once a sign-in has passed its factors: refusals (deny, require_method, require_mfa),
// required actions the user must finish first, Action calls that may refuse, session claims and
// the redirect after sign-in. Action steps must name workflow_step Actions. → 201.
// POST /v1/flows.
func (s *JourneysService) Create(ctx context.Context, params JourneysCreateParams, opts ...RequestOption) (*JourneysListResultDataItem, error) {
	out := &JourneysListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/flows", nil, params, out, opts...)
}

// Get: One journey with its active definition (else the latest).
// GET /v1/flows/{id}.
func (s *JourneysService) Get(ctx context.Context, id string) (*JourneysListResultDataItem, error) {
	out := &JourneysListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/flows/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a journey. A definition becomes the next version (immutable), active unless
// activate is false.
// PATCH /v1/flows/{id}.
func (s *JourneysService) Update(ctx context.Context, id string, params JourneysUpdateParams, opts ...RequestOption) (*JourneysListResultDataItem, error) {
	out := &JourneysListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/flows/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a journey and its versions.
// DELETE /v1/flows/{id}.
func (s *JourneysService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/flows/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// Versions: Every version of a journey, newest first.
// GET /v1/flows/{id}/versions.
func (s *JourneysService) Versions(ctx context.Context, id string, params ListParams) (*JourneysVersionsResult, error) {
	out := &JourneysVersionsResult{}
	return out, s.client.do(ctx, "GET", "/v1/flows/"+url.PathEscape(id)+"/versions", params.values(), nil, out)
}

// Activate: Make a version the active one (roll forward or back).
// POST /v1/flows/{id}/activate.
func (s *JourneysService) Activate(ctx context.Context, id string, params JourneysActivateParams, opts ...RequestOption) (*JourneysListResultDataItem, error) {
	out := &JourneysListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/flows/"+url.PathEscape(id)+"/activate", nil, params, out, opts...)
}

// Simulate: What-if: run a version (default the active one) for a user and a described sign-in
// (method, mfa_verified, ip, application_id) without changing anything. Returns the outcome
// (allowed, held or refused), the effects and a per-step trace.
// POST /v1/flows/{id}/simulate.
func (s *JourneysService) Simulate(ctx context.Context, id string, params JourneysSimulateParams, opts ...RequestOption) (*JourneysSimulateResult, error) {
	out := &JourneysSimulateResult{}
	return out, s.client.do(ctx, "POST", "/v1/flows/"+url.PathEscape(id)+"/simulate", nil, params, out, opts...)
}
