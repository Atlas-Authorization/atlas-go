package atlas

import (
	"context"
	"net/url"
)

// GetSync: Read the directory-sync settings of an organization LDAP / Active Directory connection
// (schedule, filters, group-to-role mapping, disable-on-removal).
// GET /v1/org_ldap_connections/{id}/sync.
func (s *OrgLDAPConnectionsService) GetSync(ctx context.Context, id string) (*OrgLDAPConnectionsGetSyncResult, error) {
	out := &OrgLDAPConnectionsGetSyncResult{}
	return out, s.client.do(ctx, "GET", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/sync", nil, nil, out)
}

// SetSync: Set the directory-sync settings. Fields you omit keep their value. Enabling requires an
// active connection and schedules the first run immediately; disabling clears the schedule. Role
// mappings are matched in order, by group DN.
// PUT /v1/org_ldap_connections/{id}/sync.
func (s *OrgLDAPConnectionsService) SetSync(ctx context.Context, id string, params OrgLDAPConnectionsSetSyncParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PUT", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/sync", nil, params, nil, opts...)
}

// GetRelay: Which relay agent an organization LDAP connection reaches its directory through, if
// any.
// GET /v1/org_ldap_connections/{id}/relay.
func (s *OrgLDAPConnectionsService) GetRelay(ctx context.Context, id string) (*OrgLDAPConnectionsGetRelayResult, error) {
	out := &OrgLDAPConnectionsGetRelayResult{}
	return out, s.client.do(ctx, "GET", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/relay", nil, nil, out)
}

// SetRelay: Route an LDAP connection through a relay agent (agent_id), or back to a direct
// connection (null). The agent must be active and allow the LDAP server.
// PUT /v1/org_ldap_connections/{id}/relay.
func (s *OrgLDAPConnectionsService) SetRelay(ctx context.Context, id string, params OrgLDAPConnectionsSetRelayParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PUT", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/relay", nil, params, nil, opts...)
}

// OrgLDAPConnectionsSyncRunsService is the orgLdapConnections syncRuns group of OrgLDAPConnectionsService.
type OrgLDAPConnectionsSyncRunsService struct {
	client *Client
}

// Create: Queue a sync run now (202). `full` (default) lists the whole directory and, when
// disable-on-removal is on, bans users that left it; `delta` only reads entries changed since the
// last successful run. Refused with 409 while another run is queued or running.
// POST /v1/org_ldap_connections/{id}/sync_runs.
func (s *OrgLDAPConnectionsSyncRunsService) Create(ctx context.Context, id string, params OrgLDAPConnectionsSyncRunsCreateParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/sync_runs", nil, params, nil, opts...)
}

// List: The sync run log, newest first, with per-run counts (seen, created, updated, skipped,
// disabled, role changes, groups, errors) and any failure message.
// GET /v1/org_ldap_connections/{id}/sync_runs.
func (s *OrgLDAPConnectionsSyncRunsService) List(ctx context.Context, id string, params ListParams) (*OrgLDAPConnectionsSyncRunsListResult, error) {
	out := &OrgLDAPConnectionsSyncRunsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/sync_runs", params.values(), nil, out)
}

// Get: Read one LDAP directory sync run with its counts and error.
// GET /v1/org_ldap_connections/{id}/sync_runs/{runId}.
func (s *OrgLDAPConnectionsSyncRunsService) Get(ctx context.Context, id string, runID string) (*OrgLDAPConnectionsSyncRunsListResultDataItem, error) {
	out := &OrgLDAPConnectionsSyncRunsListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/org_ldap_connections/"+url.PathEscape(id)+"/sync_runs/"+url.PathEscape(runID), nil, nil, out)
}
