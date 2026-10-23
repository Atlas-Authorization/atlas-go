package atlas

import (
	"context"
	"net/url"
)

// --- Organization teams ------------------------------------------------------

// OrgTeamsService is /v1/organizations/:id/teams: sub-groups inside an
// organization.
type OrgTeamsService struct{ client *Client }

// Team is one team of an organization.
type Team struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Name           string  `json:"name"`
	Description    *string `json:"description"`
	MembersCount   int     `json:"members_count"`
	CreatedAt      int64   `json:"created_at"`
	UpdatedAt      int64   `json:"updated_at"`
}

// TeamMemberUser is the public profile of a team member.
type TeamMemberUser struct {
	ID        string  `json:"id"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	ImageURL  *string `json:"image_url"`
}

// TeamMember is one user's membership of a team.
type TeamMember struct {
	Object  string          `json:"object"`
	TeamID  string          `json:"team_id"`
	UserID  string          `json:"user_id"`
	User    *TeamMemberUser `json:"user,omitempty"`
	Deleted bool            `json:"deleted,omitempty"`
}

// TeamParams is the body of team create and update.
type TeamParams struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

func teamsPath(orgID string) string {
	return "/v1/organizations/" + url.PathEscape(orgID) + "/teams"
}

// List lists the organization's teams; a non-empty userID narrows to the
// teams that user is in. GET /v1/organizations/:id/teams.
func (s *OrgTeamsService) List(ctx context.Context, orgID, userID string) (*CursorPage[Team], error) {
	var q url.Values
	if userID != "" {
		q = url.Values{"user_id": {userID}}
	}
	out := &CursorPage[Team]{}
	return out, s.client.get(ctx, teamsPath(orgID), q, out)
}

// Create creates a team. POST /v1/organizations/:id/teams.
func (s *OrgTeamsService) Create(ctx context.Context, orgID string, params TeamParams, opts ...RequestOption) (*Team, error) {
	out := &Team{}
	return out, s.client.post(ctx, teamsPath(orgID), params, out, opts...)
}

// Get fetches one team. GET /v1/organizations/:id/teams/:teamId.
func (s *OrgTeamsService) Get(ctx context.Context, orgID, teamID string) (*Team, error) {
	out := &Team{}
	return out, s.client.get(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID), nil, out)
}

// Update renames a team or changes its description.
// PATCH /v1/organizations/:id/teams/:teamId.
func (s *OrgTeamsService) Update(ctx context.Context, orgID, teamID string, params TeamParams, opts ...RequestOption) (*Team, error) {
	out := &Team{}
	return out, s.client.patch(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID), params, out, opts...)
}

// Delete deletes a team (organization memberships stay).
// DELETE /v1/organizations/:id/teams/:teamId.
func (s *OrgTeamsService) Delete(ctx context.Context, orgID, teamID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID), out, opts...)
}

// ListMembers lists a team's members.
// GET /v1/organizations/:id/teams/:teamId/members.
func (s *OrgTeamsService) ListMembers(ctx context.Context, orgID, teamID string) (*CursorPage[TeamMember], error) {
	out := &CursorPage[TeamMember]{}
	return out, s.client.get(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID)+"/members", nil, out)
}

// AddMember adds an organization member to the team.
// POST /v1/organizations/:id/teams/:teamId/members.
func (s *OrgTeamsService) AddMember(ctx context.Context, orgID, teamID, userID string, opts ...RequestOption) (*TeamMember, error) {
	out := &TeamMember{}
	body := map[string]string{"user_id": userID}
	return out, s.client.post(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID)+"/members", body, out, opts...)
}

// RemoveMember removes a user from the team.
// DELETE /v1/organizations/:id/teams/:teamId/members/:userId.
func (s *OrgTeamsService) RemoveMember(ctx context.Context, orgID, teamID, userID string, opts ...RequestOption) (*TeamMember, error) {
	out := &TeamMember{}
	return out, s.client.del(ctx, teamsPath(orgID)+"/"+url.PathEscape(teamID)+"/members/"+url.PathEscape(userID), out, opts...)
}

// --- Organization-scoped roles ----------------------------------------------

// OrgRolesService is /v1/organizations/:id/roles: the roles an organization
// can assign — the instance roles plus its own custom roles.
type OrgRolesService struct{ client *Client }

// OrgRole is a role an organization can assign. OrganizationID is set for the
// organization's own custom roles and nil for instance-wide roles.
type OrgRole struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	Description    *string  `json:"description"`
	IsSystem       bool     `json:"is_system"`
	OrganizationID *string  `json:"organization_id"`
	Permissions    []string `json:"permissions"`
	MemberCount    int      `json:"member_count"`
	CreatedAt      int64    `json:"created_at"`
	UpdatedAt      int64    `json:"updated_at"`
}

// CreateOrgRoleParams is the body of POST /v1/organizations/:id/roles. The key
// must not be an instance role key or one of this organization's.
type CreateOrgRoleParams struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateOrgRoleParams is the body of PATCH /v1/organizations/:id/roles/:roleId.
type UpdateOrgRoleParams struct {
	Name        string   `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// DeleteOrgRoleResult acknowledges an org role deletion.
type DeleteOrgRoleResult struct {
	Object            string `json:"object"`
	ID                string `json:"id"`
	Key               string `json:"key"`
	Deleted           bool   `json:"deleted"`
	MembersReassigned int    `json:"members_reassigned"`
}

func orgRolesPath(orgID string) string {
	return "/v1/organizations/" + url.PathEscape(orgID) + "/roles"
}

// List lists the roles the organization can assign; own=true lists only its
// own custom roles. GET /v1/organizations/:id/roles.
func (s *OrgRolesService) List(ctx context.Context, orgID string, own bool) (*CursorPage[OrgRole], error) {
	var q url.Values
	if own {
		q = url.Values{"own": {"true"}}
	}
	out := &CursorPage[OrgRole]{}
	return out, s.client.get(ctx, orgRolesPath(orgID), q, out)
}

// Create creates a custom role for one organization.
// POST /v1/organizations/:id/roles.
func (s *OrgRolesService) Create(ctx context.Context, orgID string, params CreateOrgRoleParams, opts ...RequestOption) (*OrgRole, error) {
	out := &OrgRole{}
	return out, s.client.post(ctx, orgRolesPath(orgID), params, out, opts...)
}

// Update renames an organization role or replaces its permissions.
// PATCH /v1/organizations/:id/roles/:roleId.
func (s *OrgRolesService) Update(ctx context.Context, orgID, roleID string, params UpdateOrgRoleParams, opts ...RequestOption) (*OrgRole, error) {
	out := &OrgRole{}
	return out, s.client.patch(ctx, orgRolesPath(orgID)+"/"+url.PathEscape(roleID), params, out, opts...)
}

// Delete deletes one of the organization's own roles. A non-empty reassignTo
// (a role key) moves members and pending invitations first; without it a role
// in use is refused (409 ROLE_IN_USE). DELETE /v1/organizations/:id/roles/:roleId.
func (s *OrgRolesService) Delete(ctx context.Context, orgID, roleID, reassignTo string, opts ...RequestOption) (*DeleteOrgRoleResult, error) {
	var q url.Values
	if reassignTo != "" {
		q = url.Values{"reassign_to": {reassignTo}}
	}
	out := &DeleteOrgRoleResult{}
	return out, s.client.delQ(ctx, orgRolesPath(orgID)+"/"+url.PathEscape(roleID), q, out, opts...)
}

// --- Slugs and invitation resend ----------------------------------------------

// SlugCheck reports whether an organization slug is valid and free.
type SlugCheck struct {
	Object    string `json:"object"`
	Slug      string `json:"slug"`
	Valid     bool   `json:"valid"`
	Available bool   `json:"available"`
}

// GetBySlug fetches an organization by slug (case-insensitive).
// GET /v1/organizations/by_slug/:slug.
func (s *OrganizationsService) GetBySlug(ctx context.Context, slug string) (*Organization, error) {
	out := &Organization{}
	return out, s.client.get(ctx, "/v1/organizations/by_slug/"+url.PathEscape(slug), nil, out)
}

// CheckSlug checks whether a slug is valid and free.
// GET /v1/organizations/check_slug.
func (s *OrganizationsService) CheckSlug(ctx context.Context, slug string) (*SlugCheck, error) {
	out := &SlugCheck{}
	return out, s.client.get(ctx, "/v1/organizations/check_slug", url.Values{"slug": {slug}}, out)
}

// ResentInvitation is the acknowledgement of an invitation resend.
type ResentInvitation struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	Status         string `json:"status"`
	ExpiresAt      int64  `json:"expires_at"`
}

// Resend resends a pending invitation with a fresh expiry (same id and role).
// POST /v1/organizations/:id/invitations/:invitationId/resend.
func (s *OrgInvitationsService) Resend(ctx context.Context, orgID, invitationID string, opts ...RequestOption) (*ResentInvitation, error) {
	out := &ResentInvitation{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/invitations/"+url.PathEscape(invitationID)+"/resend", nil, out, opts...)
}
