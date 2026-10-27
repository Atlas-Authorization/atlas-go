package atlas

import (
	"context"
	"net/url"
)

// WorkflowsService is the workflows resource.
type WorkflowsService struct {
	client *Client
}

// List: List lifecycle workflows: a trigger (cron, user created, inactive for N days, membership
// age, trial end, webhook event) plus ordered steps, run by the worker.
// GET /v1/workflows.
func (s *WorkflowsService) List(ctx context.Context, params ListParams) (*CursorPage[WorkflowsListItem], error) {
	out := &CursorPage[WorkflowsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/workflows", params.values(), nil, out)
}

// Create: Create a lifecycle workflow. Steps are notify, disable, delete, invite, add_to_org,
// remove_from_org, add_to_team, remove_from_team, add_to_group, remove_from_group (an instance
// group by id or slug) and call_action (an Action with the `workflow_step` trigger, which may be
// an `http` Action). Each subject runs once per workflow; the first failing step stops the run.
// POST /v1/workflows.
func (s *WorkflowsService) Create(ctx context.Context, params WorkflowsCreateParams, opts ...RequestOption) (*WorkflowsListItem, error) {
	out := &WorkflowsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/workflows", nil, params, out, opts...)
}

// Get: Read one lifecycle workflow.
// GET /v1/workflows/{id}.
func (s *WorkflowsService) Get(ctx context.Context, id string) (*WorkflowsListItem, error) {
	out := &WorkflowsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/workflows/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update a workflow's name, enabled flag, trigger or steps. Changing the trigger resets
// its cron slot and event cursor.
// PATCH /v1/workflows/{id}.
func (s *WorkflowsService) Update(ctx context.Context, id string, params WorkflowsCreateParams, opts ...RequestOption) (*WorkflowsListItem, error) {
	out := &WorkflowsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/workflows/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a workflow and its run history.
// DELETE /v1/workflows/{id}.
func (s *WorkflowsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/workflows/"+url.PathEscape(id), nil, nil, out, opts...)
}

// DryRun: Check what a workflow would do for a user (`user_id`; none for cron) without changing
// anything. Every step is validated against live data and reported as `would_run` or `failed`.
// POST /v1/workflows/{id}/dry_run.
func (s *WorkflowsService) DryRun(ctx context.Context, id string, params WorkflowsDryRunParams, opts ...RequestOption) (*WorkflowsDryRunResult, error) {
	out := &WorkflowsDryRunResult{}
	return out, s.client.do(ctx, "POST", "/v1/workflows/"+url.PathEscape(id)+"/dry_run", nil, params, out, opts...)
}

// Run: Run a workflow now for one user (`user_id`; none for cron), outside its trigger. Returns
// the finished run.
// POST /v1/workflows/{id}/run.
func (s *WorkflowsService) Run(ctx context.Context, id string, params WorkflowsDryRunParams, opts ...RequestOption) (*WorkflowsDryRunResult, error) {
	out := &WorkflowsDryRunResult{}
	return out, s.client.do(ctx, "POST", "/v1/workflows/"+url.PathEscape(id)+"/run", nil, params, out, opts...)
}

// Runs: Run history, newest first, dry runs included (`dry_run`).
// GET /v1/workflows/{id}/runs.
func (s *WorkflowsService) Runs(ctx context.Context, id string, params ListParams) (*CursorPage[WorkflowsDryRunResult], error) {
	out := &CursorPage[WorkflowsDryRunResult]{}
	return out, s.client.do(ctx, "GET", "/v1/workflows/"+url.PathEscape(id)+"/runs", params.values(), nil, out)
}
