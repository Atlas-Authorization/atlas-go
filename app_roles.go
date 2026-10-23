package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// AppRolesService is the /v1/app_roles namespace: instance-wide user roles
// (not tied to any organization). A user's app roles ride on their session
// token as app_roles / app_permissions; check them offline with
// SessionClaims.HasAppRole / HasAppPermission.
type AppRolesService struct{ client *Client }

// AppRole is an app-level role and the permission keys it grants.
type AppRole struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	Permissions []string `json:"permissions"`
	// UsersCount is how many users hold the role (list and create only).
	UsersCount int   `json:"users_count,omitempty"`
	CreatedAt  int64 `json:"created_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// CreateAppRoleParams is the body of POST /v1/app_roles. Key is 2-64
// lowercase letters, digits, _ or -, starting with a letter.
type CreateAppRoleParams struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateAppRoleParams is the body of PATCH /v1/app_roles/:id.
type UpdateAppRoleParams struct {
	Name        string   `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// AppRoleHolder is one user holding an app role.
type AppRoleHolder struct {
	Object string `json:"object"`
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// UserAppRoles is a user's app roles and the union of their permissions (the
// app_roles / app_permissions session claims).
type UserAppRoles struct {
	Object      string    `json:"object"`
	UserID      string    `json:"user_id"`
	Roles       []AppRole `json:"roles"`
	RoleKeys    []string  `json:"role_keys"`
	Permissions []string  `json:"permissions"`
}

// SetUserAppRolesParams changes a user's app roles: Roles replaces the whole
// set; Add / Remove change it (role keys or ids). Send one form, not both.
type SetUserAppRolesParams struct {
	Roles  []string `json:"roles,omitempty"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// List returns the app roles with their holder counts. GET /v1/app_roles.
func (s *AppRolesService) List(ctx context.Context) (*CursorPage[AppRole], error) {
	out := &CursorPage[AppRole]{}
	return out, s.client.get(ctx, "/v1/app_roles", nil, out)
}

// Create creates an app role. POST /v1/app_roles.
func (s *AppRolesService) Create(ctx context.Context, params CreateAppRoleParams, opts ...RequestOption) (*AppRole, error) {
	out := &AppRole{}
	return out, s.client.post(ctx, "/v1/app_roles", params, out, opts...)
}

// Get fetches an app role by id or key. GET /v1/app_roles/:id.
func (s *AppRolesService) Get(ctx context.Context, idOrKey string) (*AppRole, error) {
	out := &AppRole{}
	return out, s.client.get(ctx, "/v1/app_roles/"+url.PathEscape(idOrKey), nil, out)
}

// Update renames a role or replaces its description or permissions.
// PATCH /v1/app_roles/:id.
func (s *AppRolesService) Update(ctx context.Context, idOrKey string, params UpdateAppRoleParams, opts ...RequestOption) (*AppRole, error) {
	out := &AppRole{}
	return out, s.client.patch(ctx, "/v1/app_roles/"+url.PathEscape(idOrKey), params, out, opts...)
}

// Delete deletes an app role; every holder loses it. DELETE /v1/app_roles/:id.
func (s *AppRolesService) Delete(ctx context.Context, idOrKey string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/app_roles/"+url.PathEscape(idOrKey), out, opts...)
}

// ListUsers returns the users holding a role, oldest assignment first.
// GET /v1/app_roles/:id/users.
func (s *AppRolesService) ListUsers(ctx context.Context, idOrKey string, limit, offset int) (*CursorPage[AppRoleHolder], error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	out := &CursorPage[AppRoleHolder]{}
	return out, s.client.get(ctx, "/v1/app_roles/"+url.PathEscape(idOrKey)+"/users", q, out)
}

// GetForUser returns a user's app roles and effective permissions.
// GET /v1/users/:id/app_roles.
func (s *AppRolesService) GetForUser(ctx context.Context, userID string) (*UserAppRoles, error) {
	out := &UserAppRoles{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(userID)+"/app_roles", nil, out)
}

// SetForUser replaces (Roles) or changes (Add / Remove) a user's app roles.
// POST /v1/users/:id/app_roles.
func (s *AppRolesService) SetForUser(ctx context.Context, userID string, params SetUserAppRolesParams, opts ...RequestOption) (*UserAppRoles, error) {
	out := &UserAppRoles{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(userID)+"/app_roles", params, out, opts...)
}

// RemoveFromUser takes one app role (id or key) from a user.
// DELETE /v1/users/:id/app_roles/:roleId.
func (s *AppRolesService) RemoveFromUser(ctx context.Context, userID, idOrKey string, opts ...RequestOption) (*UserAppRoles, error) {
	out := &UserAppRoles{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(userID)+"/app_roles/"+url.PathEscape(idOrKey), out, opts...)
}
