package atlas

import (
	"context"
	"net/http"
	"net/url"
)

// RolesService is the /v1/roles namespace.
type RolesService struct{ client *Client }

// Role is an instance role with its permission set.
type Role struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
	MemberCount int      `json:"member_count"`
	CreatedAt   int64    `json:"created_at"`
}

// Permission is a permission definition.
type Permission struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	IsSystem    bool    `json:"is_system"`
}

// CreateRoleParams is the body of POST /v1/roles.
type CreateRoleParams struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateRoleParams is the body of PATCH /v1/roles/:id. The key is immutable;
// supplying it must match the current value.
type UpdateRoleParams struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Key         string `json:"key,omitempty"`
}

// RolePermissionsResult is the reduced shape PUT /v1/roles/:id/permissions
// returns.
type RolePermissionsResult struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Permissions []string `json:"permissions"`
	Ignored     []string `json:"ignored"`
}

// List returns all roles. GET /v1/roles.
func (s *RolesService) List(ctx context.Context) (*ListPage[Role], error) {
	out := &ListPage[Role]{}
	return out, s.client.get(ctx, "/v1/roles", nil, out)
}

// Create creates a role. POST /v1/roles.
func (s *RolesService) Create(ctx context.Context, params CreateRoleParams, opts ...RequestOption) (*Role, error) {
	out := &Role{}
	return out, s.client.post(ctx, "/v1/roles", params, out, opts...)
}

// Update patches a role. PATCH /v1/roles/:id.
func (s *RolesService) Update(ctx context.Context, id string, params UpdateRoleParams) (*Role, error) {
	out := &Role{}
	return out, s.client.patch(ctx, "/v1/roles/"+url.PathEscape(id), params, out)
}

// SetPermissions replaces a role's permission set wholesale.
// PUT /v1/roles/:id/permissions.
func (s *RolesService) SetPermissions(ctx context.Context, id string, permissions []string) (*RolePermissionsResult, error) {
	out := &RolePermissionsResult{}
	body := map[string][]string{"permissions": permissions}
	return out, s.client.put(ctx, "/v1/roles/"+url.PathEscape(id)+"/permissions", body, out)
}

// DeleteRoleResult acknowledges a role deletion, reporting how many members were
// reassigned when ReassignTo was supplied.
type DeleteRoleResult struct {
	Object            string `json:"object"`
	ID                string `json:"id"`
	Deleted           bool   `json:"deleted"`
	MembersReassigned int    `json:"members_reassigned"`
}

// Delete removes a role. DELETE /v1/roles/:id. Pass a non-empty reassignTo to
// move every member onto another role first (atomic), so an in-use role can be
// retired; otherwise deleting a role people still hold fails with role_in_use.
func (s *RolesService) Delete(ctx context.Context, id, reassignTo string) (*DeleteRoleResult, error) {
	out := &DeleteRoleResult{}
	var q url.Values
	if reassignTo != "" {
		q = url.Values{"reassign_to": {reassignTo}}
	}
	return out, s.client.do(ctx, http.MethodDelete, "/v1/roles/"+url.PathEscape(id), q, nil, out)
}

// PermissionsService is the /v1/permissions namespace.
type PermissionsService struct{ client *Client }

// CreatePermissionParams is the body of POST /v1/permissions.
type CreatePermissionParams struct {
	Key         string `json:"key"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// List returns all permissions. GET /v1/permissions.
func (s *PermissionsService) List(ctx context.Context) (*ListPage[Permission], error) {
	out := &ListPage[Permission]{}
	return out, s.client.get(ctx, "/v1/permissions", nil, out)
}

// Create creates a permission. POST /v1/permissions.
func (s *PermissionsService) Create(ctx context.Context, params CreatePermissionParams, opts ...RequestOption) (*Permission, error) {
	out := &Permission{}
	return out, s.client.post(ctx, "/v1/permissions", params, out, opts...)
}

// UpdatePermissionParams is the body of PATCH /v1/permissions/:id. Only the
// name/description are mutable; the key is immutable.
type UpdatePermissionParams struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Key         string  `json:"key,omitempty"`
}

// Update relabels a custom permission. PATCH /v1/permissions/:id.
func (s *PermissionsService) Update(ctx context.Context, id string, params UpdatePermissionParams) (*Permission, error) {
	out := &Permission{}
	return out, s.client.patch(ctx, "/v1/permissions/"+url.PathEscape(id), params, out)
}

// Delete removes a custom permission. DELETE /v1/permissions/:id. Fails with
// role_in_use if a role still grants it.
func (s *PermissionsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/permissions/"+url.PathEscape(id), out)
}
