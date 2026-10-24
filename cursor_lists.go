package atlas

import (
	"context"
	"net/url"
)

// Every list route accepts limit + starting_after and answers next_cursor
// (offset paging is deprecated). These variants take ListParams for the lists
// whose original method took none, or a bare limit.

// ListWithParams returns one cursor page of an organization's memberships.
// GET /v1/organizations/:id/memberships.
func (s *OrgMembershipsService) ListWithParams(ctx context.Context, orgID string, params ListParams) (*CursorPage[OrganizationMembership], error) {
	out := &CursorPage[OrganizationMembership]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships", params.values(), out)
}

// ListUsersWithParams returns one cursor page of the users holding an app
// role. GET /v1/app_roles/:idOrKey/users.
func (s *AppRolesService) ListUsersWithParams(ctx context.Context, idOrKey string, params ListParams) (*CursorPage[AppRoleHolder], error) {
	out := &CursorPage[AppRoleHolder]{}
	return out, s.client.get(ctx, "/v1/app_roles/"+url.PathEscape(idOrKey)+"/users", params.values(), out)
}

// DeliveriesWithParams returns one cursor page of an endpoint's delivery log.
// GET /v1/logout_notify_endpoints/:id/deliveries.
func (s *LogoutNotifyEndpointsService) DeliveriesWithParams(ctx context.Context, id string, params ListParams) (*CursorPage[LogoutNotifyDelivery], error) {
	out := &CursorPage[LogoutNotifyDelivery]{}
	return out, s.client.get(ctx, "/v1/logout_notify_endpoints/"+url.PathEscape(id)+"/deliveries", params.values(), out)
}
