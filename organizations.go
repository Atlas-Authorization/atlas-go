package atlas

import (
	"context"
	"net/url"
)

// OrganizationsService is the /v1/organizations namespace. Nested collections
// (Memberships, Invitations, Domains, GroupRoles) hang off it as sub-services.
type OrganizationsService struct {
	client *Client

	Memberships *OrgMembershipsService
	Invitations *OrgInvitationsService
	Domains     *OrgDomainsService
	GroupRoles  *OrgGroupRolesService
}

// Organization is an organization as the BAPI serves it.
type Organization struct {
	Object                string   `json:"object"`
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Slug                  string   `json:"slug"`
	ImageURL              *string  `json:"image_url"`
	PublicMetadata        Metadata `json:"public_metadata"`
	MaxAllowedMemberships int      `json:"max_allowed_memberships"`
	CreatedBy             string   `json:"created_by"`
	CreatedAt             int64    `json:"created_at"`
	UpdatedAt             int64    `json:"updated_at"`
}

// OrganizationMembership binds a user to an organization with a role.
type OrganizationMembership struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           string `json:"role"`
	CreatedAt      int64  `json:"created_at"`
}

// OrganizationInvitation is an invitation into an organization.
type OrganizationInvitation struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	Status         string `json:"status"`
	InviterUserID  string `json:"inviter_user_id"`
	ExpiresAt      int64  `json:"expires_at"`
	CreatedAt      int64  `json:"created_at"`
}

// OrgDomainVerification carries the DNS TXT record proving domain ownership.
type OrgDomainVerification struct {
	RecordName  string `json:"record_name"`
	RecordType  string `json:"record_type"`
	RecordValue string `json:"record_value"`
}

// OrgDomain is a verified/pending organization email domain.
type OrgDomain struct {
	Object         string                `json:"object"`
	ID             string                `json:"id"`
	OrganizationID string                `json:"organization_id"`
	Domain         string                `json:"domain"`
	Status         string                `json:"status"`
	AutoJoin       bool                  `json:"auto_join"`
	DefaultRoleID  *string               `json:"default_role_id"`
	Verification   OrgDomainVerification `json:"verification"`
	VerifiedAt     *int64                `json:"verified_at"`
	LastCheckedAt  *int64                `json:"last_checked_at"`
	CreatedAt      int64                 `json:"created_at"`
}

// OrganizationPolicy is the org security policy (§4.4).
type OrganizationPolicy struct {
	Object         string                 `json:"object"`
	OrganizationID string                 `json:"organization_id"`
	Policy         map[string]interface{} `json:"policy"`
}

// CreateOrganizationParams is the body of POST /v1/organizations.
type CreateOrganizationParams struct {
	Name                  string `json:"name"`
	Slug                  string `json:"slug"`
	CreatedBy             string `json:"created_by"`
	MaxAllowedMemberships *int   `json:"max_allowed_memberships,omitempty"`
}

// UpdateOrganizationParams is the body of PATCH /v1/organizations/:id.
type UpdateOrganizationParams struct {
	Name                  string   `json:"name,omitempty"`
	Slug                  string   `json:"slug,omitempty"`
	ImageURL              string   `json:"image_url,omitempty"`
	MaxAllowedMemberships *int     `json:"max_allowed_memberships,omitempty"`
	PublicMetadata        Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata       Metadata `json:"private_metadata,omitempty"`
}

// ReplaceOrganizationMetadataParams is the body of
// PUT /v1/organizations/:id/metadata.
type ReplaceOrganizationMetadataParams struct {
	PublicMetadata  Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata Metadata `json:"private_metadata,omitempty"`
}

// List returns one cursor page of organizations. GET /v1/organizations.
func (s *OrganizationsService) List(ctx context.Context, params ListParams) (*CursorPage[Organization], error) {
	out := &CursorPage[Organization]{}
	return out, s.client.get(ctx, "/v1/organizations", params.values(), out)
}

// Get fetches an organization. GET /v1/organizations/:id.
func (s *OrganizationsService) Get(ctx context.Context, id string) (*Organization, error) {
	out := &Organization{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id), nil, out)
}

// Create creates an organization. POST /v1/organizations.
func (s *OrganizationsService) Create(ctx context.Context, params CreateOrganizationParams, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	return out, s.client.post(ctx, "/v1/organizations", params, out, opts...)
}

// Update patches an organization. PATCH /v1/organizations/:id.
func (s *OrganizationsService) Update(ctx context.Context, id string, params UpdateOrganizationParams) (*Organization, error) {
	out := &Organization{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id), params, out)
}

// Delete removes an organization. DELETE /v1/organizations/:id.
func (s *OrganizationsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(id), out)
}

// UpdateMetadata replaces the named metadata bags wholesale.
// PUT /v1/organizations/:id/metadata.
func (s *OrganizationsService) UpdateMetadata(ctx context.Context, id string, params ReplaceOrganizationMetadataParams) (*Organization, error) {
	out := &Organization{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/metadata", params, out)
}

// UpdatePolicy patches an organization's security policy.
// PATCH /v1/organizations/:id/policy. Fields on this route are camelCase.
func (s *OrganizationsService) UpdatePolicy(ctx context.Context, id string, policy map[string]interface{}) (*OrganizationPolicy, error) {
	out := &OrganizationPolicy{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id)+"/policy", policy, out)
}

// OrgHierarchyNode is one org in an ancestor chain or child list.
type OrgHierarchyNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// OrganizationHierarchy is the ancestor chain (nearest first) + direct children.
type OrganizationHierarchy struct {
	Object         string             `json:"object"`
	OrganizationID string             `json:"organization_id"`
	Ancestors      []OrgHierarchyNode `json:"ancestors"`
	Children       []OrgHierarchyNode `json:"children"`
}

// OrganizationEntitlements is the org's active feature set, resolved from its
// plan + overrides against the instance catalog.
type OrganizationEntitlements struct {
	Object         string                 `json:"object"`
	OrganizationID string                 `json:"organization_id"`
	Plan           *string                `json:"plan"`
	Features       map[string]interface{} `json:"features"`
	Catalog        struct {
		Features interface{} `json:"features"`
		Plans    interface{} `json:"plans"`
	} `json:"catalog"`
}

// SetParent sets (or clears, with an empty parentOrganizationID) the org's
// parent in the B2B2B hierarchy. PUT /v1/organizations/:id/parent.
func (s *OrganizationsService) SetParent(ctx context.Context, id, parentOrganizationID string) (*Organization, error) {
	out := &Organization{}
	var parent *string
	if parentOrganizationID != "" {
		parent = &parentOrganizationID
	}
	body := map[string]*string{"parent_organization_id": parent}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/parent", body, out)
}

// Hierarchy returns an org's ancestor chain and direct children.
// GET /v1/organizations/:id/hierarchy.
func (s *OrganizationsService) Hierarchy(ctx context.Context, id string) (*OrganizationHierarchy, error) {
	out := &OrganizationHierarchy{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/hierarchy", nil, out)
}

// Entitlements returns an org's resolved feature set.
// GET /v1/organizations/:id/entitlements.
func (s *OrganizationsService) Entitlements(ctx context.Context, id string) (*OrganizationEntitlements, error) {
	out := &OrganizationEntitlements{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/entitlements", nil, out)
}

// --- Memberships -----------------------------------------------------------

// OrgMembershipsService is /v1/organizations/:id/memberships.
type OrgMembershipsService struct{ client *Client }

// AddMembershipParams is the body of POST .../memberships.
type AddMembershipParams struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// List lists an organization's memberships.
func (s *OrgMembershipsService) List(ctx context.Context, orgID string) (*CursorPage[OrganizationMembership], error) {
	out := &CursorPage[OrganizationMembership]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships", nil, out)
}

// Add adds a user to an organization.
func (s *OrgMembershipsService) Add(ctx context.Context, orgID string, params AddMembershipParams, opts ...RequestOption) (*OrganizationMembership, error) {
	out := &OrganizationMembership{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships", params, out, opts...)
}

// Update changes a member's role.
func (s *OrgMembershipsService) Update(ctx context.Context, orgID, userID, role string) (*OrganizationMembership, error) {
	out := &OrganizationMembership{}
	body := map[string]string{"role": role}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships/"+url.PathEscape(userID), body, out)
}

// Remove removes a member.
func (s *OrgMembershipsService) Remove(ctx context.Context, orgID, userID string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships/"+url.PathEscape(userID), out)
}

// --- Organization invitations ---------------------------------------------

// OrgInvitationsService is /v1/organizations/:id/invitations.
type OrgInvitationsService struct{ client *Client }

// CreateOrgInvitationParams is the body of POST .../invitations.
type CreateOrgInvitationParams struct {
	Email         string `json:"email"`
	Role          string `json:"role"`
	InviterUserID string `json:"inviter_user_id"`
}

// List lists an organization's invitations.
func (s *OrgInvitationsService) List(ctx context.Context, orgID string) (*ListPage[OrganizationInvitation], error) {
	out := &ListPage[OrganizationInvitation]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/invitations", nil, out)
}

// Create invites a user into an organization.
func (s *OrgInvitationsService) Create(ctx context.Context, orgID string, params CreateOrgInvitationParams, opts ...RequestOption) (*OrganizationInvitation, error) {
	out := &OrganizationInvitation{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/invitations", params, out, opts...)
}

// Revoke revokes an organization invitation.
func (s *OrgInvitationsService) Revoke(ctx context.Context, orgID, invitationID string) (*OrganizationInvitation, error) {
	out := &OrganizationInvitation{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/invitations/"+url.PathEscape(invitationID)+"/revoke", nil, out)
}

// --- Organization domains --------------------------------------------------

// OrgDomainsService is /v1/organizations/:id/domains.
type OrgDomainsService struct{ client *Client }

// CreateOrgDomainParams is the body of POST .../domains.
type CreateOrgDomainParams struct {
	Domain        string  `json:"domain"`
	AutoJoin      *bool   `json:"auto_join,omitempty"`
	DefaultRoleID *string `json:"default_role_id,omitempty"`
}

// List lists an organization's domains.
func (s *OrgDomainsService) List(ctx context.Context, orgID string) (*ListPage[OrgDomain], error) {
	out := &ListPage[OrgDomain]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains", nil, out)
}

// Create adds a domain to an organization.
func (s *OrgDomainsService) Create(ctx context.Context, orgID string, params CreateOrgDomainParams, opts ...RequestOption) (*OrgDomain, error) {
	out := &OrgDomain{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains", params, out, opts...)
}

// Verify triggers verification of an organization domain.
func (s *OrgDomainsService) Verify(ctx context.Context, orgID, domainID string) (*OrgDomain, error) {
	out := &OrgDomain{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID)+"/verify", nil, out)
}

// Delete removes an organization domain.
func (s *OrgDomainsService) Delete(ctx context.Context, orgID, domainID string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID), out)
}

// --- Group → role grants ---------------------------------------------------

// OrgGroupRolesService is the directory-group → role grant surface.
type OrgGroupRolesService struct{ client *Client }

// GroupRoleGrant is the acknowledgement of a group→role grant/revoke.
type GroupRoleGrant struct {
	Object         string `json:"object"`
	OrganizationID string `json:"organization_id"`
	GroupID        string `json:"group_id"`
	RoleID         string `json:"role_id"`
	Granted        bool   `json:"granted"`
	Deleted        bool   `json:"deleted"`
}

// Grant grants a role to a directory group.
// PUT /v1/organizations/:id/groups/:groupId/roles/:roleId.
func (s *OrgGroupRolesService) Grant(ctx context.Context, orgID, groupID, roleID string) (*GroupRoleGrant, error) {
	out := &GroupRoleGrant{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/groups/"+url.PathEscape(groupID)+"/roles/"+url.PathEscape(roleID), nil, out)
}

// Revoke revokes a group→role grant.
func (s *OrgGroupRolesService) Revoke(ctx context.Context, orgID, groupID, roleID string) (*GroupRoleGrant, error) {
	out := &GroupRoleGrant{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/groups/"+url.PathEscape(groupID)+"/roles/"+url.PathEscape(roleID), out)
}
