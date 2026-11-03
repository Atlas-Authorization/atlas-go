package atlas

import (
	"context"
	"encoding/json"
	"net/url"
)

// OrganizationsService is the /v1/organizations namespace. Nested collections
// (Memberships, Invitations, Domains, GroupRoles) hang off it as sub-services.
type OrganizationsService struct {
	client *Client

	Memberships      *OrgMembershipsService
	Invitations      *OrgInvitationsService
	Domains          *OrgDomainsService
	GroupRoles       *OrgGroupRolesService
	Teams            *OrgTeamsService
	Roles            *OrgRolesService
	WebhookEndpoints *OrganizationsWebhookEndpointsService
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
	// CreatedBy is "" for an organization your backend created with no creator.
	CreatedBy string `json:"created_by"`
	// ExternalID is your own id for this customer; unique per instance.
	ExternalID *string `json:"external_id"`
	// RoleMappings maps a role key to your product's name for it (the
	// org_role_mapped token claim).
	RoleMappings map[string]string `json:"role_mappings"`
	// OwnerInvitation is set on create with OwnerEmail only.
	OwnerInvitation *OrganizationOwnerInvitation `json:"owner_invitation,omitempty"`
	// SSO is set on Get: the organization's enterprise sign-in setup.
	SSO       *OrganizationSSO `json:"sso,omitempty"`
	CreatedAt int64            `json:"created_at"`
	UpdatedAt int64            `json:"updated_at"`
}

// OrganizationOwnerInvitation is the invitation sent to CreateOrganizationParams.OwnerEmail.
type OrganizationOwnerInvitation struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	ExpiresAt *int64 `json:"expires_at"`
}

// OrganizationSSO is the sso block of GET /v1/organizations/:id.
type OrganizationSSO struct {
	Connections []OrganizationSSOConnection `json:"connections"`
	// ScimBaseURL is the SCIM 2.0 base URL to give the organization's identity provider.
	ScimBaseURL string `json:"scim_base_url"`
}

// OrganizationSSOConnection is one connection in OrganizationSSO.
type OrganizationSSOConnection struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// Status is draft, active or disabled.
	Status string `json:"status"`
}

// OrganizationByDomain is GET /v1/organizations/by_domain/:domain: the owning
// organization and the matched domain.
type OrganizationByDomain struct {
	Organization
	Domain struct {
		Object     string `json:"object"`
		ID         string `json:"id"`
		Domain     string `json:"domain"`
		Status     string `json:"status"`
		VerifiedAt *int64 `json:"verified_at"`
	} `json:"domain"`
}

// ListOrganizationsParams filters GET /v1/organizations.
type ListOrganizationsParams struct {
	ListParams
	// ExternalID returns only the organization with this external_id.
	ExternalID string
	// Metadata are public_metadata equality filters, sent as metadata[key]=value (AND).
	Metadata map[string]string
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
	// VerificationMethods lists every way to prove the domain.
	VerificationMethods *OrgDomainVerificationMethods `json:"verification_methods,omitempty"`
	// VerificationMethod is dns_txt, well_known or email; nil while unverified.
	VerificationMethod *string `json:"verification_method"`
	// SentTo is set by SendVerificationEmail: the mailbox the code went to.
	SentTo        string `json:"sent_to,omitempty"`
	VerifiedAt    *int64 `json:"verified_at"`
	LastCheckedAt *int64 `json:"last_checked_at"`
	CreatedAt     int64  `json:"created_at"`
}

// OrgDomainVerificationMethods is OrgDomain.VerificationMethods.
type OrgDomainVerificationMethods struct {
	DNSTXT OrgDomainVerification `json:"dns_txt"`
	// WellKnown: serve Body as the whole response (200, text/plain) at URL.
	WellKnown struct {
		URL         string `json:"url"`
		Body        string `json:"body"`
		ContentType string `json:"content_type"`
	} `json:"well_known"`
	// Email: a code mailed to one of Addresses through your own email provider.
	Email struct {
		Addresses []string `json:"addresses"`
		SentTo    *string  `json:"sent_to"`
		ExpiresAt *int64   `json:"expires_at"`
	} `json:"email"`
}

// OrganizationPolicy is the org security policy (§4.4).
type OrganizationPolicy struct {
	Object         string                 `json:"object"`
	OrganizationID string                 `json:"organization_id"`
	Policy         map[string]interface{} `json:"policy"`
}

// CreateOrganizationParams is the body of POST /v1/organizations.
type CreateOrganizationParams struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
	// CreatedBy is seated with the creator role; leave it "" for a
	// backend-created organization with no members yet.
	CreatedBy             string   `json:"created_by,omitempty"`
	MaxAllowedMemberships *int     `json:"max_allowed_memberships,omitempty"`
	ExternalID            string   `json:"external_id,omitempty"`
	PublicMetadata        Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata       Metadata `json:"private_metadata,omitempty"`
	// OwnerEmail invites this address with the creator role (org:admin by default).
	OwnerEmail   string            `json:"owner_email,omitempty"`
	RoleMappings map[string]string `json:"role_mappings,omitempty"`
}

// UpsertOrganizationParams is the body of
// PUT /v1/organizations/by_external_id/:external_id: the create fields minus
// external_id (taken from the path). Name is required when the call creates;
// on an update only the fields set change and CreatedBy / OwnerEmail are ignored.
type UpsertOrganizationParams struct {
	Name                  string            `json:"name,omitempty"`
	Slug                  string            `json:"slug,omitempty"`
	ImageURL              string            `json:"image_url,omitempty"`
	CreatedBy             string            `json:"created_by,omitempty"`
	MaxAllowedMemberships *int              `json:"max_allowed_memberships,omitempty"`
	PublicMetadata        Metadata          `json:"public_metadata,omitempty"`
	PrivateMetadata       Metadata          `json:"private_metadata,omitempty"`
	OwnerEmail            string            `json:"owner_email,omitempty"`
	RoleMappings          map[string]string `json:"role_mappings,omitempty"`
}

// UpdateOrganizationParams is the body of PATCH /v1/organizations/:id.
type UpdateOrganizationParams struct {
	Name                  string   `json:"name,omitempty"`
	Slug                  string   `json:"slug,omitempty"`
	ImageURL              string   `json:"image_url,omitempty"`
	MaxAllowedMemberships *int     `json:"max_allowed_memberships,omitempty"`
	PublicMetadata        Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata       Metadata `json:"private_metadata,omitempty"`
	ExternalID            *string  `json:"external_id,omitempty"`
	// ClearExternalID sends external_id: null.
	ClearExternalID bool              `json:"-"`
	RoleMappings    map[string]string `json:"role_mappings,omitempty"`
	// ClearRoleMappings sends role_mappings: null.
	ClearRoleMappings bool `json:"-"`
}

// MarshalJSON sends external_id / role_mappings: null when ClearExternalID /
// ClearRoleMappings is set.
func (p UpdateOrganizationParams) MarshalJSON() ([]byte, error) {
	type plain UpdateOrganizationParams
	extra := map[string]interface{}{}
	if p.ClearExternalID {
		extra["external_id"] = nil
	}
	if p.ClearRoleMappings {
		extra["role_mappings"] = nil
	}
	if len(extra) == 0 {
		return json.Marshal(plain(p))
	}
	return marshalWithExtra(plain(p), extra)
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

// ListFiltered returns one cursor page of organizations matching an
// external_id and/or public_metadata filters. GET /v1/organizations.
func (s *OrganizationsService) ListFiltered(ctx context.Context, params ListOrganizationsParams) (*CursorPage[Organization], error) {
	q := params.ListParams.values()
	if params.ExternalID != "" {
		q.Set("external_id", params.ExternalID)
	}
	for k, v := range params.Metadata {
		q.Set("metadata["+k+"]", v)
	}
	out := &CursorPage[Organization]{}
	return out, s.client.get(ctx, "/v1/organizations", q, out)
}

// Get fetches an organization, with its sso block. GET /v1/organizations/:id.
func (s *OrganizationsService) Get(ctx context.Context, id string) (*Organization, error) {
	out := &Organization{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id), nil, out)
}

// FindByDomain returns the organization owning a domain (or an email
// address's domain). Verified domains only unless includeUnverified.
// GET /v1/organizations/by_domain/:domain.
func (s *OrganizationsService) FindByDomain(ctx context.Context, domain string, includeUnverified bool) (*OrganizationByDomain, error) {
	var q url.Values
	if includeUnverified {
		q = url.Values{"include_unverified": {"true"}}
	}
	out := &OrganizationByDomain{}
	return out, s.client.get(ctx, "/v1/organizations/by_domain/"+url.PathEscape(domain), q, out)
}

// GetPolicy reads an organization's security policy.
// GET /v1/organizations/:id/policy.
func (s *OrganizationsService) GetPolicy(ctx context.Context, id string) (*OrgPolicyResult, error) {
	out := &OrgPolicyResult{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/policy", nil, out)
}

// Create creates an organization. POST /v1/organizations.
func (s *OrganizationsService) Create(ctx context.Context, params CreateOrganizationParams, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	return out, s.client.post(ctx, "/v1/organizations", params, out, opts...)
}

// Update patches an organization. PATCH /v1/organizations/:id.
func (s *OrganizationsService) Update(ctx context.Context, id string, params UpdateOrganizationParams, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id), params, out, opts...)
}

// UpsertByExternalID creates the organization with this external_id (201) or
// updates it (200). Parallel calls for one id create exactly one organization.
// PUT /v1/organizations/by_external_id/:external_id.
func (s *OrganizationsService) UpsertByExternalID(ctx context.Context, externalID string, params UpsertOrganizationParams, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	return out, s.client.put(ctx, "/v1/organizations/by_external_id/"+url.PathEscape(externalID), params, out, opts...)
}

// Delete removes an organization. DELETE /v1/organizations/:id.
func (s *OrganizationsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(id), out, opts...)
}

// UpdateMetadata replaces the named metadata bags wholesale.
// PUT /v1/organizations/:id/metadata.
func (s *OrganizationsService) UpdateMetadata(ctx context.Context, id string, params ReplaceOrganizationMetadataParams, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/metadata", params, out, opts...)
}

// UpdatePolicy patches an organization's security policy from a raw map (a nil
// value clears a key). See SetPolicy for the typed form.
// PATCH /v1/organizations/:id/policy. Fields on this route are camelCase.
func (s *OrganizationsService) UpdatePolicy(ctx context.Context, id string, policy map[string]interface{}, opts ...RequestOption) (*OrganizationPolicy, error) {
	out := &OrganizationPolicy{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id)+"/policy", policy, out, opts...)
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

// OrganizationEntitlements is the org's effective entitlement: the resolved
// plan, feature keys and numeric limits, with sales-led overrides applied and
// plan limits merged. Plan is nil (and Features/Limits empty) when the org
// holds no entitlement.
type OrganizationEntitlements struct {
	Object         string                 `json:"object"`
	OrganizationID string                 `json:"organization_id"`
	Plan           *string                `json:"plan"`
	Features       []string               `json:"features"`
	Limits         map[string]interface{} `json:"limits"`
	// Deprecated: the API no longer returns a catalog on this route; always
	// empty.
	Catalog struct {
		Features interface{} `json:"features"`
		Plans    interface{} `json:"plans"`
	} `json:"catalog"`
}

// SetParent sets (or clears, with an empty parentOrganizationID) the org's
// parent in the B2B2B hierarchy. PUT /v1/organizations/:id/parent.
func (s *OrganizationsService) SetParent(ctx context.Context, id, parentOrganizationID string, opts ...RequestOption) (*Organization, error) {
	out := &Organization{}
	var parent *string
	if parentOrganizationID != "" {
		parent = &parentOrganizationID
	}
	body := map[string]*string{"parent_organization_id": parent}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/parent", body, out, opts...)
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
func (s *OrgMembershipsService) Update(ctx context.Context, orgID, userID, role string, opts ...RequestOption) (*OrganizationMembership, error) {
	out := &OrganizationMembership{}
	body := map[string]string{"role": role}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships/"+url.PathEscape(userID), body, out, opts...)
}

// Remove removes a member.
func (s *OrgMembershipsService) Remove(ctx context.Context, orgID, userID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/memberships/"+url.PathEscape(userID), out, opts...)
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
func (s *OrgInvitationsService) Revoke(ctx context.Context, orgID, invitationID string, opts ...RequestOption) (*OrganizationInvitation, error) {
	out := &OrganizationInvitation{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/invitations/"+url.PathEscape(invitationID)+"/revoke", nil, out, opts...)
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

// Verify runs the DNS TXT check of an organization domain now.
func (s *OrgDomainsService) Verify(ctx context.Context, orgID, domainID string, opts ...RequestOption) (*OrgDomain, error) {
	out := &OrgDomain{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID)+"/verify", nil, out, opts...)
}

// VerifyOrgDomainParams is the body of POST .../domains/:domainId/verify.
type VerifyOrgDomainParams struct {
	// Method is dns_txt (default), well_known (fetches the file) or email.
	Method string `json:"method,omitempty"`
	// Code is the emailed code (Method email).
	Code string `json:"code,omitempty"`
}

// VerifyWith verifies an organization domain by the given method.
// POST /v1/organizations/:id/domains/:domainId/verify.
func (s *OrgDomainsService) VerifyWith(ctx context.Context, orgID, domainID string, params VerifyOrgDomainParams, opts ...RequestOption) (*OrgDomain, error) {
	out := &OrgDomain{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID)+"/verify", params, out, opts...)
}

// SendVerificationEmail emails a 6-digit code to an administrative mailbox at
// the domain (address: admin, administrator, hostmaster, postmaster or
// webmaster; "" = admin) through the instance's own email provider.
// POST /v1/organizations/:id/domains/:domainId/verification_email.
func (s *OrgDomainsService) SendVerificationEmail(ctx context.Context, orgID, domainID, address string, opts ...RequestOption) (*OrgDomain, error) {
	body := map[string]string{}
	if address != "" {
		body["address"] = address
	}
	out := &OrgDomain{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID)+"/verification_email", body, out, opts...)
}

// Delete removes an organization domain.
func (s *OrgDomainsService) Delete(ctx context.Context, orgID, domainID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/domains/"+url.PathEscape(domainID), out, opts...)
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
func (s *OrgGroupRolesService) Grant(ctx context.Context, orgID, groupID, roleID string, opts ...RequestOption) (*GroupRoleGrant, error) {
	out := &GroupRoleGrant{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/groups/"+url.PathEscape(groupID)+"/roles/"+url.PathEscape(roleID), nil, out, opts...)
}

// Revoke revokes a group→role grant.
func (s *OrgGroupRolesService) Revoke(ctx context.Context, orgID, groupID, roleID string, opts ...RequestOption) (*GroupRoleGrant, error) {
	out := &GroupRoleGrant{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/groups/"+url.PathEscape(groupID)+"/roles/"+url.PathEscape(roleID), out, opts...)
}
