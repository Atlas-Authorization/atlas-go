package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ResourcesService is the resources resource.
type ResourcesService struct {
	client      *Client
	Types       *ResourcesTypesService
	Assignments *ResourcesAssignmentsService
}

// ResourcesListQuery holds the query parameters of ResourcesService.List.
type ResourcesListQuery struct {
	// Only resources of this resource type key.
	Type string
	// Only the direct children of this resource id.
	ParentID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q ResourcesListQuery) values() url.Values {
	v := url.Values{}
	if q.Type != "" {
		v.Set("type", q.Type)
	}
	if q.ParentID != "" {
		v.Set("parent_id", q.ParentID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List resources, optionally filtered by `type` or `parent_id`.
// GET /v1/resources.
func (s *ResourcesService) List(ctx context.Context, query ResourcesListQuery) (*CursorPage[ResourcesListItem], error) {
	out := &CursorPage[ResourcesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/resources", query.values(), nil, out)
}

// Upsert: Create or update one resource by `type` + `external_id` (your own id for it). `parent`
// is `{id}` or `{type, external_id}` of an existing resource, or null; it must match the type’s
// `parent_type`.
// PUT /v1/resources.
func (s *ResourcesService) Upsert(ctx context.Context, params ResourcesUpsertParams, opts ...RequestOption) (*ResourcesListItem, error) {
	out := &ResourcesListItem{}
	return out, s.client.do(ctx, "PUT", "/v1/resources", nil, params, out, opts...)
}

// Sync: Discovery sync: upsert up to 500 resources in order (list parents before children).
// Idempotent; call it whenever your app creates or moves resources.
// POST /v1/resources/sync.
func (s *ResourcesService) Sync(ctx context.Context, params ResourcesSyncParams, opts ...RequestOption) (*CursorPage[ResourcesListItem], error) {
	out := &CursorPage[ResourcesListItem]{}
	return out, s.client.do(ctx, "POST", "/v1/resources/sync", nil, params, out, opts...)
}

// Get: Read one resource, with its type and parent.
// GET /v1/resources/{id}.
func (s *ResourcesService) Get(ctx context.Context, id string) (*ResourcesListItem, error) {
	out := &ResourcesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/resources/"+url.PathEscape(id), nil, nil, out)
}

// Delete: Delete a resource and its role assignments. Its children are detached to the root.
// DELETE /v1/resources/{id}.
func (s *ResourcesService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/resources/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// Check: Does `subject` hold `permission` on `resource`? A user subject also holds the roles of
// the organizations they belong to, plus any `groups` ids you pass. The response lists the grants
// that allow it.
// POST /v1/resource_checks.
func (s *ResourcesService) Check(ctx context.Context, params ResourcesCheckParams, opts ...RequestOption) (*ResourcesCheckResult, error) {
	out := &ResourcesCheckResult{}
	return out, s.client.do(ctx, "POST", "/v1/resource_checks", nil, params, out, opts...)
}

// CheckBatch: Up to 100 resource checks in one call.
// POST /v1/resource_checks/batch.
func (s *ResourcesService) CheckBatch(ctx context.Context, params ResourcesCheckBatchParams, opts ...RequestOption) (*CursorPage[ResourcesCheckResult], error) {
	out := &CursorPage[ResourcesCheckResult]{}
	return out, s.client.do(ctx, "POST", "/v1/resource_checks/batch", nil, params, out, opts...)
}

// Accessible: List the resources of an optional `type` on which `subject` holds `permission`,
// paged with `limit` and `starting_after` (the response carries `has_more` and `next_cursor`).
// POST /v1/resource_checks/list.
func (s *ResourcesService) Accessible(ctx context.Context, params ResourcesAccessibleParams, opts ...RequestOption) (*CursorPage[ResourcesListItem], error) {
	out := &CursorPage[ResourcesListItem]{}
	return out, s.client.do(ctx, "POST", "/v1/resource_checks/list", nil, params, out, opts...)
}

// ResourcesTypesService is the resources types group of ResourcesService.
type ResourcesTypesService struct {
	client *Client
}

// List: List the resource types (roles, permissions, parent type).
// GET /v1/resource_types.
func (s *ResourcesTypesService) List(ctx context.Context, params ListParams) (*CursorPage[ResourcesTypesListItem], error) {
	out := &CursorPage[ResourcesTypesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/resource_types", params.values(), nil, out)
}

// Create: Define a resource type: a `key`, its `roles` (each a set of permissions, optionally
// `includes` other roles), an optional `parent_type` resources nest under, and `inherit` (default
// true) controlling whether assignments on a parent flow down.
// POST /v1/resource_types.
func (s *ResourcesTypesService) Create(ctx context.Context, params ResourcesTypesCreateParams, opts ...RequestOption) (*ResourcesTypesListItem, error) {
	out := &ResourcesTypesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/resource_types", nil, params, out, opts...)
}

// Get: Read one resource type.
// GET /v1/resource_types/{key}.
func (s *ResourcesTypesService) Get(ctx context.Context, key string) (*ResourcesTypesListItem, error) {
	out := &ResourcesTypesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/resource_types/"+url.PathEscape(key), nil, nil, out)
}

// Update: Change a resource type’s name, roles, parent type or inheritance.
// PATCH /v1/resource_types/{key}.
func (s *ResourcesTypesService) Update(ctx context.Context, key string, params ResourcesTypesUpdateParams, opts ...RequestOption) (*ResourcesTypesListItem, error) {
	out := &ResourcesTypesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/resource_types/"+url.PathEscape(key), nil, params, out, opts...)
}

// Delete: Delete a resource type together with its resources and their role assignments.
// DELETE /v1/resource_types/{key}.
func (s *ResourcesTypesService) Delete(ctx context.Context, key string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/resource_types/"+url.PathEscape(key), nil, nil, nil, opts...)
}

// ResourcesAssignmentsService is the resources assignments group of ResourcesService.
type ResourcesAssignmentsService struct {
	client *Client
}

// ResourcesAssignmentsListQuery holds the query parameters of ResourcesAssignmentsService.List.
type ResourcesAssignmentsListQuery struct {
	// Only assignments on this resource id.
	ResourceID string
	// Only assignments to this kind of subject.
	SubjectType string
	// Only assignments to this subject id (a user id, group key or organization id).
	SubjectID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q ResourcesAssignmentsListQuery) values() url.Values {
	v := url.Values{}
	if q.ResourceID != "" {
		v.Set("resource_id", q.ResourceID)
	}
	if q.SubjectType != "" {
		v.Set("subject_type", q.SubjectType)
	}
	if q.SubjectID != "" {
		v.Set("subject_id", q.SubjectID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List role assignments, filtered by `resource_id`, `subject_type` or `subject_id`.
// GET /v1/resource_role_assignments.
func (s *ResourcesAssignmentsService) List(ctx context.Context, query ResourcesAssignmentsListQuery) (*CursorPage[ResourcesAssignmentsListItem], error) {
	out := &CursorPage[ResourcesAssignmentsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/resource_role_assignments", query.values(), nil, out)
}

// Assign: Assign a `role` on a `resource` to a `subject` (`{type: user|group|org, id}`). `inherit`
// (default true) also applies it to the resource’s descendants. Re-assigning the same role updates
// `inherit`.
// POST /v1/resource_role_assignments.
func (s *ResourcesAssignmentsService) Assign(ctx context.Context, params ResourcesAssignmentsAssignParams, opts ...RequestOption) (*ResourcesAssignmentsListItem, error) {
	out := &ResourcesAssignmentsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/resource_role_assignments", nil, params, out, opts...)
}

// Revoke: Revoke a role assignment.
// DELETE /v1/resource_role_assignments/{id}.
func (s *ResourcesAssignmentsService) Revoke(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/resource_role_assignments/"+url.PathEscape(id), nil, nil, nil, opts...)
}
