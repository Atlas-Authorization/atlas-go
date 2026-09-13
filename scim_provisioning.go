package atlas

import (
	"context"
	"net/url"
)

// SCIMProvisioningService is the /v1/scim_provisioning_targets namespace — the
// OUTBOUND SCIM provisioning targets Atlas pushes users/groups out to. The
// bearer token is write-only; a read reports only HasBearerToken.
type SCIMProvisioningService struct{ client *Client }

// SCIMProvisioningTarget is a downstream SCIM 2.0 endpoint.
type SCIMProvisioningTarget struct {
	Object              string                 `json:"object"`
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	BaseURL             string                 `json:"base_url"`
	HasBearerToken      bool                   `json:"has_bearer_token"`
	Enabled             bool                   `json:"enabled"`
	AttributeMapping    map[string]interface{} `json:"attribute_mapping"`
	DeprovisionAction   string                 `json:"deprovision_action"`
	Status              string                 `json:"status"`
	Cursor              *string                `json:"cursor"`
	ConsecutiveFailures int                    `json:"consecutive_failures"`
	LastError           *string                `json:"last_error"`
	LastSyncedAt        *int64                 `json:"last_synced_at"`
	CreatedAt           int64                  `json:"created_at"`
	UpdatedAt           int64                  `json:"updated_at"`
}

// CreateSCIMProvisioningTargetParams is the body of POST .../scim_provisioning_targets.
type CreateSCIMProvisioningTargetParams struct {
	Name              string                 `json:"name"`
	BaseURL           string                 `json:"base_url"`
	BearerToken       string                 `json:"bearer_token"`
	AttributeMapping  map[string]interface{} `json:"attribute_mapping,omitempty"`
	DeprovisionAction string                 `json:"deprovision_action,omitempty"`
	Enabled           *bool                  `json:"enabled,omitempty"`
}

// UpdateSCIMProvisioningTargetParams is the body of PATCH .../:id.
type UpdateSCIMProvisioningTargetParams struct {
	Name              string                 `json:"name,omitempty"`
	BaseURL           string                 `json:"base_url,omitempty"`
	BearerToken       string                 `json:"bearer_token,omitempty"`
	AttributeMapping  map[string]interface{} `json:"attribute_mapping,omitempty"`
	DeprovisionAction string                 `json:"deprovision_action,omitempty"`
	Enabled           *bool                  `json:"enabled,omitempty"`
	Status            string                 `json:"status,omitempty"`
}

// SCIMProvisioningTestResult is the connectivity/auth probe's outcome.
type SCIMProvisioningTestResult struct {
	Object string  `json:"object"`
	ID     string  `json:"id"`
	OK     bool    `json:"ok"`
	Status *int    `json:"status"`
	Error  *string `json:"error"`
}

// SCIMProvisioningSyncResult is the result of forcing one user's sync.
type SCIMProvisioningSyncResult struct {
	Object   string  `json:"object"`
	ID       string  `json:"id"`
	UserID   string  `json:"user_id"`
	Action   string  `json:"action"`
	OK       bool    `json:"ok"`
	Status   *int    `json:"status"`
	RemoteID *string `json:"remote_id"`
	Error    *string `json:"error"`
}

// SCIMProvisioningGroupSyncResult is the result of forcing one org's sync.
type SCIMProvisioningGroupSyncResult struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Action         string  `json:"action"`
	OK             bool    `json:"ok"`
	Status         *int    `json:"status"`
	RemoteID       *string `json:"remote_id"`
	MemberCount    int     `json:"member_count"`
	Error          *string `json:"error"`
}

// List returns the provisioning targets. GET /v1/scim_provisioning_targets.
func (s *SCIMProvisioningService) List(ctx context.Context) (*ListPage[SCIMProvisioningTarget], error) {
	out := &ListPage[SCIMProvisioningTarget]{}
	return out, s.client.get(ctx, "/v1/scim_provisioning_targets", nil, out)
}

// Get returns one target. GET /v1/scim_provisioning_targets/:id.
func (s *SCIMProvisioningService) Get(ctx context.Context, id string) (*SCIMProvisioningTarget, error) {
	out := &SCIMProvisioningTarget{}
	return out, s.client.get(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id), nil, out)
}

// Create creates a target. POST /v1/scim_provisioning_targets.
func (s *SCIMProvisioningService) Create(ctx context.Context, params CreateSCIMProvisioningTargetParams, opts ...RequestOption) (*SCIMProvisioningTarget, error) {
	out := &SCIMProvisioningTarget{}
	return out, s.client.post(ctx, "/v1/scim_provisioning_targets", params, out, opts...)
}

// Update patches a target. PATCH /v1/scim_provisioning_targets/:id.
func (s *SCIMProvisioningService) Update(ctx context.Context, id string, params UpdateSCIMProvisioningTargetParams) (*SCIMProvisioningTarget, error) {
	out := &SCIMProvisioningTarget{}
	return out, s.client.patch(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id), params, out)
}

// Delete removes a target. DELETE /v1/scim_provisioning_targets/:id.
func (s *SCIMProvisioningService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id), out)
}

// Test probes connectivity + auth to the downstream. POST .../:id/test.
func (s *SCIMProvisioningService) Test(ctx context.Context, id string) (*SCIMProvisioningTestResult, error) {
	out := &SCIMProvisioningTestResult{}
	return out, s.client.post(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id)+"/test", nil, out)
}

// SyncUser forces one user's sync now. POST .../:id/sync_user.
func (s *SCIMProvisioningService) SyncUser(ctx context.Context, id, userID string) (*SCIMProvisioningSyncResult, error) {
	out := &SCIMProvisioningSyncResult{}
	body := map[string]string{"user_id": userID}
	return out, s.client.post(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id)+"/sync_user", body, out)
}

// SyncGroup forces one org's (group) sync now. POST .../:id/sync_group.
func (s *SCIMProvisioningService) SyncGroup(ctx context.Context, id, organizationID string) (*SCIMProvisioningGroupSyncResult, error) {
	out := &SCIMProvisioningGroupSyncResult{}
	body := map[string]string{"organization_id": organizationID}
	return out, s.client.post(ctx, "/v1/scim_provisioning_targets/"+url.PathEscape(id)+"/sync_group", body, out)
}
