package atlas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// MachinesService is /v1/machines: named machine (M2M) identities and the
// device registry. EnrolmentTokens hangs off it.
type MachinesService struct {
	client *Client

	EnrolmentTokens *MachineEnrolmentTokensService
}

// Machine is a machine identity / enrolled device.
type Machine struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	OrganizationID *string `json:"organization_id"`
	OwnerUserID    *string `json:"owner_user_id"`
	// Data is the trusted data bag set at creation (distinct from Metadata).
	Data Metadata `json:"data,omitempty"`
	// Status is the stored lifecycle state: active, pending or revoked.
	Status string `json:"status"`
	// OwnerUsable reports whether the owning user is usable (true with no owner).
	OwnerUsable bool `json:"owner_usable"`
	// EffectiveStatus is active, owner_suspended, pending or revoked.
	EffectiveStatus string  `json:"effective_status"`
	DeviceKey       *string `json:"device_key"`
	PublicKeyJKT    *string `json:"public_key_jkt"`
	// Metadata is device-reported (hostname, os, app_version, last_seen_at).
	Metadata   Metadata `json:"metadata"`
	EnrolledAt *int64   `json:"enrolled_at"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

// MachineWithSecret reveals the mk_ secret once, on create or rotate.
type MachineWithSecret struct {
	// SealedFields carries the sealed_* values when the request named a secret recipient.
	SealedFields
	Machine
	Secret string `json:"secret"`
}

// CreateMachineParams is the body of POST /v1/machines.
type CreateMachineParams struct {
	Name        string   `json:"name"`
	OwnerUserID string   `json:"owner_user_id,omitempty"`
	Data        Metadata `json:"data,omitempty"`
}

// ListMachinesParams filters GET /v1/machines.
type ListMachinesParams struct {
	ListParams
	// Status is active, pending or revoked.
	Status         string
	Hostname       string
	OwnerUserID    string
	OrganizationID string
	// Metadata matches devices whose metadata contains these key/values (sent as
	// a JSON object).
	Metadata map[string]interface{}
}

func (p ListMachinesParams) values() (url.Values, error) {
	v := p.ListParams.values()
	if p.Status != "" {
		v.Set("status", p.Status)
	}
	if p.Hostname != "" {
		v.Set("hostname", p.Hostname)
	}
	if p.OwnerUserID != "" {
		v.Set("owner_user_id", p.OwnerUserID)
	}
	if p.OrganizationID != "" {
		v.Set("organization_id", p.OrganizationID)
	}
	if p.Metadata != nil {
		encoded, err := json.Marshal(p.Metadata)
		if err != nil {
			return nil, fmt.Errorf("atlas: encoding metadata filter: %w", err)
		}
		v.Set("metadata", string(encoded))
	}
	return v, nil
}

// List lists machine identities. GET /v1/machines.
func (s *MachinesService) List(ctx context.Context, params ListMachinesParams) (*CursorPage[Machine], error) {
	q, err := params.values()
	if err != nil {
		return nil, err
	}
	out := &CursorPage[Machine]{}
	return out, s.client.get(ctx, "/v1/machines", q, out)
}

// Create creates a named machine; the response reveals the mk_ secret once.
// POST /v1/machines.
func (s *MachinesService) Create(ctx context.Context, params CreateMachineParams, opts ...RequestOption) (*MachineWithSecret, error) {
	out := &MachineWithSecret{}
	return out, s.client.post(ctx, "/v1/machines", params, out, opts...)
}

// Get fetches one machine. GET /v1/machines/:id.
func (s *MachinesService) Get(ctx context.Context, id string) (*Machine, error) {
	out := &Machine{}
	return out, s.client.get(ctx, "/v1/machines/"+url.PathEscape(id), nil, out)
}

// Rename renames a machine. PATCH /v1/machines/:id.
func (s *MachinesService) Rename(ctx context.Context, id, name string, opts ...RequestOption) (*Machine, error) {
	out := &Machine{}
	body := map[string]string{"name": name}
	return out, s.client.patch(ctx, "/v1/machines/"+url.PathEscape(id), body, out, opts...)
}

// Delete deletes a machine identity. DELETE /v1/machines/:id.
func (s *MachinesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/machines/"+url.PathEscape(id), out, opts...)
}

// MergeMetadata merges device metadata into a machine.
// PATCH /v1/machines/:id/metadata.
func (s *MachinesService) MergeMetadata(ctx context.Context, id string, metadata Metadata, opts ...RequestOption) (*Machine, error) {
	out := &Machine{}
	body := map[string]interface{}{"metadata": metadata}
	return out, s.client.patch(ctx, "/v1/machines/"+url.PathEscape(id)+"/metadata", body, out, opts...)
}

// Approve approves a pending device (pending → active).
// POST /v1/machines/:id/approve.
func (s *MachinesService) Approve(ctx context.Context, id string, opts ...RequestOption) (*Machine, error) {
	out := &Machine{}
	return out, s.client.post(ctx, "/v1/machines/"+url.PathEscape(id)+"/approve", nil, out, opts...)
}

// Revoke revokes a device; its key stops minting tokens immediately.
// POST /v1/machines/:id/revoke.
func (s *MachinesService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*Machine, error) {
	out := &Machine{}
	return out, s.client.post(ctx, "/v1/machines/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}

// RotateSecret rotates the mk_ secret; the new one is revealed once.
// POST /v1/machines/:id/rotate_secret.
func (s *MachinesService) RotateSecret(ctx context.Context, id string, opts ...RequestOption) (*MachineWithSecret, error) {
	out := &MachineWithSecret{}
	return out, s.client.post(ctx, "/v1/machines/"+url.PathEscape(id)+"/rotate_secret", nil, out, opts...)
}

// RotateKey registers a new device public key (SPKI PEM).
// POST /v1/machines/:id/rotate_key.
func (s *MachinesService) RotateKey(ctx context.Context, id, publicKeyPEM string, opts ...RequestOption) (*Machine, error) {
	out := &Machine{}
	body := map[string]string{"public_key_pem": publicKeyPEM}
	return out, s.client.post(ctx, "/v1/machines/"+url.PathEscape(id)+"/rotate_key", body, out, opts...)
}

// MachineOrganizationMembership is the organization a machine is enrolled in.
type MachineOrganizationMembership struct {
	Object           string  `json:"object"`
	OrganizationID   string  `json:"organization_id"`
	OrganizationSlug string  `json:"organization_slug"`
	Role             *string `json:"role"`
	Plan             *string `json:"plan"`
	JoinedAt         int64   `json:"joined_at"`
}

// ListOrganizationMemberships lists the (zero or one) organizations a machine
// belongs to. GET /v1/machines/:id/organization_memberships.
func (s *MachinesService) ListOrganizationMemberships(ctx context.Context, id string, params ListParams) (*CursorPage[MachineOrganizationMembership], error) {
	out := &CursorPage[MachineOrganizationMembership]{}
	return out, s.client.get(ctx, "/v1/machines/"+url.PathEscape(id)+"/organization_memberships", params.values(), out)
}

// MachineGrant lets a machine obtain tokens for one resource server, up to its scopes.
type MachineGrant struct {
	Object           string   `json:"object"`
	ID               string   `json:"id"`
	MachineID        string   `json:"machine_id"`
	ResourceServerID string   `json:"resource_server_id"`
	Scopes           []string `json:"scopes"`
	CreatedAt        int64    `json:"created_at"`
	UpdatedAt        int64    `json:"updated_at"`
}

// CreateMachineGrantParams is the body of POST /v1/machines/:id/grants. Scopes
// must be defined on the resource server; ScopePresets names its scope_presets,
// unioned with Scopes. The expanded list is what is stored.
type CreateMachineGrantParams struct {
	ResourceServerID string   `json:"resource_server_id"`
	Scopes           []string `json:"scopes,omitempty"`
	ScopePresets     []string `json:"scope_presets,omitempty"`
}

// ListGrants lists the resource servers a machine may obtain tokens for.
// GET /v1/machines/:id/grants.
func (s *MachinesService) ListGrants(ctx context.Context, id string) (*ListPage[MachineGrant], error) {
	out := &ListPage[MachineGrant]{}
	return out, s.client.get(ctx, "/v1/machines/"+url.PathEscape(id)+"/grants", nil, out)
}

// CreateGrant authorizes a machine for a resource server; a second grant on the
// same server is a 409. POST /v1/machines/:id/grants.
func (s *MachinesService) CreateGrant(ctx context.Context, id string, params CreateMachineGrantParams, opts ...RequestOption) (*MachineGrant, error) {
	out := &MachineGrant{}
	return out, s.client.post(ctx, "/v1/machines/"+url.PathEscape(id)+"/grants", params, out, opts...)
}

// DeleteGrant revokes a grant; a token already issued lasts until it expires.
// DELETE /v1/machines/:id/grants/:grantId.
func (s *MachinesService) DeleteGrant(ctx context.Context, id, grantID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/machines/"+url.PathEscape(id)+"/grants/"+url.PathEscape(grantID), out, opts...)
}

// MachineMembership is a machine as an organization member with a role.
type MachineMembership struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	MachineID      string `json:"machine_id"`
	// Role is the organization role key.
	Role      string `json:"role"`
	RoleID    string `json:"role_id"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// AddMachineToOrganizationParams is the body of POST
// /v1/organizations/:id/machine_memberships. Role defaults to org:member.
type AddMachineToOrganizationParams struct {
	MachineID string `json:"machine_id"`
	Role      string `json:"role,omitempty"`
}

// ListOrganizationMembers lists the machines that are members of an organization.
// GET /v1/organizations/:id/machine_memberships.
func (s *MachinesService) ListOrganizationMembers(ctx context.Context, organizationID string, params ListParams) (*CursorPage[MachineMembership], error) {
	out := &CursorPage[MachineMembership]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/machine_memberships", params.values(), out)
}

// AddToOrganization makes a machine a member of an organization.
// POST /v1/organizations/:id/machine_memberships.
func (s *MachinesService) AddToOrganization(ctx context.Context, organizationID string, params AddMachineToOrganizationParams, opts ...RequestOption) (*MachineMembership, error) {
	out := &MachineMembership{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/machine_memberships", params, out, opts...)
}

// UpdateOrganizationRole changes a machine's role; new tokens carry the new role.
// PATCH /v1/organizations/:id/machine_memberships/:machineId.
func (s *MachinesService) UpdateOrganizationRole(ctx context.Context, organizationID, machineID, role string, opts ...RequestOption) (*MachineMembership, error) {
	out := &MachineMembership{}
	body := map[string]string{"role": role}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/machine_memberships/"+url.PathEscape(machineID), body, out, opts...)
}

// RemoveFromOrganization removes a machine from an organization.
// DELETE /v1/organizations/:id/machine_memberships/:machineId.
func (s *MachinesService) RemoveFromOrganization(ctx context.Context, organizationID, machineID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/machine_memberships/"+url.PathEscape(machineID), out, opts...)
}

// M2MTokenVerification is the verdict of VerifyToken. Audience, Scopes,
// OrganizationID, OrgRole, OrgPermissions and ExpiresAt are set for a machine JWT.
type M2MTokenVerification struct {
	Object         string   `json:"object"`
	Valid          bool     `json:"valid"`
	MachineID      string   `json:"machine_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Audience       *string  `json:"audience,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	OrganizationID *string  `json:"organization_id,omitempty"`
	OrgRole        *string  `json:"org_role,omitempty"`
	OrgPermissions []string `json:"org_permissions,omitempty"`
	ExpiresAt      *int64   `json:"expires_at,omitempty"`
	// Grants and OrganizationMemberships are what the machine holds now.
	Grants []struct {
		ResourceServerID string   `json:"resource_server_id"`
		Audience         string   `json:"audience"`
		Scopes           []string `json:"scopes"`
	} `json:"grants,omitempty"`
	OrganizationMemberships []struct {
		OrganizationID string `json:"organization_id"`
		Role           string `json:"role"`
	} `json:"organization_memberships,omitempty"`
}

// VerifyToken verifies a presented machine secret or machine JWT. POST /v1/m2m_tokens/verify.
func (s *MachinesService) VerifyToken(ctx context.Context, token string, opts ...RequestOption) (*M2MTokenVerification, error) {
	out := &M2MTokenVerification{}
	body := map[string]string{"token": token}
	return out, s.client.post(ctx, "/v1/m2m_tokens/verify", body, out, opts...)
}

// MachineEnrolmentTokensService is /v1/machine_enrolment_tokens.
type MachineEnrolmentTokensService struct{ client *Client }

// MachineEnrolmentToken is an enrolment token (never the secret, except on
// create).
type MachineEnrolmentToken struct {
	Object           string   `json:"object"`
	ID               string   `json:"id"`
	OrganizationID   *string  `json:"organization_id"`
	MaxUses          int      `json:"max_uses"`
	Uses             int      `json:"uses"`
	ExpiresAt        int64    `json:"expires_at"`
	RequiresApproval bool     `json:"requires_approval"`
	Data             Metadata `json:"data,omitempty"`
	OwnerUserID      *string  `json:"owner_user_id,omitempty"`
	SingleSession    bool     `json:"single_session,omitempty"`
	MaxMachines      *int     `json:"max_machines,omitempty"`
	ConsumedAt       *int64   `json:"consumed_at,omitempty"`
	CreatedAt        int64    `json:"created_at"`
	// Token is the reveal-once met_ secret, present only on create.
	Token string `json:"token,omitempty"`
}

// CreateMachineEnrolmentTokenParams is the body of POST /v1/machine_enrolment_tokens.
type CreateMachineEnrolmentTokenParams struct {
	OrganizationID   string   `json:"organization_id,omitempty"`
	MaxUses          int      `json:"max_uses,omitempty"`
	ExpiresInSeconds int      `json:"expires_in_seconds,omitempty"`
	RequiresApproval bool     `json:"requires_approval,omitempty"`
	Data             Metadata `json:"data,omitempty"`
	OwnerUserID      string   `json:"owner_user_id,omitempty"`
	// SingleSession restricts the token to a single enrolment session.
	SingleSession bool `json:"single_session,omitempty"`
	MaxMachines   int  `json:"max_machines,omitempty"`
}

// ListMachineEnrolmentTokensParams filters GET /v1/machine_enrolment_tokens.
type ListMachineEnrolmentTokensParams struct {
	ListParams
	OrganizationID string
}

// Create mints an enrolment token; Token is revealed once.
// POST /v1/machine_enrolment_tokens.
func (s *MachineEnrolmentTokensService) Create(ctx context.Context, params CreateMachineEnrolmentTokenParams, opts ...RequestOption) (*MachineEnrolmentToken, error) {
	out := &MachineEnrolmentToken{}
	return out, s.client.post(ctx, "/v1/machine_enrolment_tokens", params, out, opts...)
}

// List lists enrolment tokens, newest first. GET /v1/machine_enrolment_tokens.
func (s *MachineEnrolmentTokensService) List(ctx context.Context, params ListMachineEnrolmentTokensParams) (*CursorPage[MachineEnrolmentToken], error) {
	q := params.ListParams.values()
	if params.OrganizationID != "" {
		q.Set("organization_id", params.OrganizationID)
	}
	out := &CursorPage[MachineEnrolmentToken]{}
	return out, s.client.get(ctx, "/v1/machine_enrolment_tokens", q, out)
}

// Delete deletes an enrolment token. DELETE /v1/machine_enrolment_tokens/:id.
func (s *MachineEnrolmentTokensService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/machine_enrolment_tokens/"+url.PathEscape(id), out, opts...)
}
