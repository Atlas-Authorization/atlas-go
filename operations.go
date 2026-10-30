package atlas

import (
	"context"
	"encoding/json"
	"net/url"
)

// ── CAPTCHA (/v1/captcha/verify) ────────────────────────────────────────────

// CaptchaService verifies CAPTCHA tokens server-side against the instance's
// configured provider ("captcha anywhere").
type CaptchaService struct{ client *Client }

// CaptchaVerifyParams is the body of POST /v1/captcha/verify. Action selects a
// per-action provider override; RemoteIP forwards the end-user's IP.
type CaptchaVerifyParams struct {
	Token    string `json:"token"`
	Action   string `json:"action,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`
}

// CaptchaVerification is the verdict. It fails closed: an unconfigured
// provider or a provider error is Success=false. Verdict is pass, fail,
// low_score or edge (edge-enforced providers); Meta carries the provider's
// reason codes for your own risk pipeline.
type CaptchaVerification struct {
	Object      string                 `json:"object"`
	Success     bool                   `json:"success"`
	Action      *string                `json:"action"`
	Provider    string                 `json:"provider"`
	Score       *float64               `json:"score,omitempty"`
	Verdict     string                 `json:"verdict,omitempty"`
	ChallengeTS string                 `json:"challenge_ts,omitempty"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// Verify verifies a CAPTCHA token. POST /v1/captcha/verify.
func (s *CaptchaService) Verify(ctx context.Context, params CaptchaVerifyParams, opts ...RequestOption) (*CaptchaVerification, error) {
	out := &CaptchaVerification{}
	return out, s.client.post(ctx, "/v1/captcha/verify", params, out, opts...)
}

// ── Test mode (/v1/test_instance, /v1/test_users/purge, /v1/testing_tokens) ──

// TestingService holds the test-mode helpers: the paired development
// instance, bulk disposal of test users, and testing tokens.
type TestingService struct{ client *Client }

// TestInstance is the paired development (test-mode) instance. SecretKey is
// present only when it was just minted (first creation or a rotation) — save
// it, it is not returned again.
type TestInstance struct {
	Object         string `json:"object"`
	InstanceID     string `json:"instance_id"`
	Environment    string `json:"environment"`
	PublishableKey string `json:"publishable_key"`
	Created        bool   `json:"created"`
	SecretKey      string `json:"secret_key,omitempty"`
}

// TestUsersPurge reports one purge batch; loop while HasMore.
type TestUsersPurge struct {
	Object  string `json:"object"`
	Purged  int    `json:"purged"`
	HasMore bool   `json:"has_more"`
}

// TestingToken is a short-lived signed token that lets automated tests skip
// the human-only CAPTCHA on a development instance.
type TestingToken struct {
	Object    string `json:"object"`
	JWT       string `json:"jwt"`
	TokenUse  string `json:"token_use"`
	ExpiresIn int    `json:"expires_in"`
}

// TestInstance gets (creating on first call) this production instance's
// paired development sibling; rotateSecret mints a fresh sk_test.
// POST /v1/test_instance.
func (s *TestingService) TestInstance(ctx context.Context, rotateSecret bool, opts ...RequestOption) (*TestInstance, error) {
	out := &TestInstance{}
	body := map[string]interface{}{}
	if rotateSecret {
		body["rotate_secret"] = true
	}
	return out, s.client.post(ctx, "/v1/test_instance", body, out, opts...)
}

// PurgeTestUsers soft-deletes up to limit test users (emails carrying a
// reserved test token) on a development instance; 0 uses the server default.
// POST /v1/test_users/purge.
func (s *TestingService) PurgeTestUsers(ctx context.Context, limit int, opts ...RequestOption) (*TestUsersPurge, error) {
	out := &TestUsersPurge{}
	body := map[string]interface{}{}
	if limit > 0 {
		body["limit"] = limit
	}
	return out, s.client.post(ctx, "/v1/test_users/purge", body, out, opts...)
}

// CreateTestingToken mints a testing token (development instances only).
// POST /v1/testing_tokens.
func (s *TestingService) CreateTestingToken(ctx context.Context, opts ...RequestOption) (*TestingToken, error) {
	out := &TestingToken{}
	return out, s.client.post(ctx, "/v1/testing_tokens", nil, out, opts...)
}

// CreateSignInURLParams is the body of POST /v1/testing/sign_in_url.
type CreateSignInURLParams struct {
	UserID string `json:"user_id"`
	// RedirectURL is where the browser lands: an allowed origin or localhost.
	RedirectURL string `json:"redirect_url"`
	// ExpiresInSeconds is 1 to 300 (0 = the default 60).
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
}

// CreateSignInURL returns a ready one-time URL that signs a browser in as the
// user and lands on RedirectURL (object testing_sign_in_url). Development
// instances only (403 TESTING_UNAVAILABLE otherwise).
// POST /v1/testing/sign_in_url.
func (s *TestingService) CreateSignInURL(ctx context.Context, params CreateSignInURLParams, opts ...RequestOption) (*BrowserTicket, error) {
	out := &BrowserTicket{}
	return out, s.client.post(ctx, "/v1/testing/sign_in_url", params, out, opts...)
}

// ── MCP (/v1/mcp, /v1/mcp_connector) ────────────────────────────────────────

// MCPService is the Model Context Protocol surface: the management MCP server
// your key may call, and the remote MCP connector configuration.
type MCPService struct{ client *Client }

// MCPDescriptor describes the MCP server and the tools this key may call.
type MCPDescriptor struct {
	Object                 string                   `json:"object"`
	ProtocolVersion        string                   `json:"protocol_version"`
	Server                 map[string]interface{}   `json:"server"`
	Capabilities           map[string]interface{}   `json:"capabilities"`
	Tools                  []map[string]interface{} `json:"tools"`
	RateLimit              interface{}              `json:"rate_limit,omitempty"`
	RecommendedAgentScopes []string                 `json:"recommended_agent_scopes,omitempty"`
}

// MCPRequest is a JSON-RPC 2.0 request: initialize, tools/list, tools/call,
// ping. JSONRPC defaults to "2.0" when empty.
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPError is a JSON-RPC error object.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPResponse is a JSON-RPC 2.0 response.
type MCPResponse struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      interface{}            `json:"id"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   *MCPError              `json:"error,omitempty"`
}

// MCPConnector is the remote MCP connector configuration plus computed
// discovery values.
type MCPConnector struct {
	Object               string   `json:"object"`
	Enabled              bool     `json:"enabled"`
	Name                 *string  `json:"name"`
	ExposedScopes        []string `json:"exposed_scopes"`
	DynamicRegistration  bool     `json:"dynamic_registration"`
	AllowedRedirectHosts []string `json:"allowed_redirect_hosts"`
	DiscoveryURL         *string  `json:"discovery_url"`
	Resource             *string  `json:"resource"`
	ResourceServerExists bool     `json:"resource_server_exists"`
}

// UpdateMCPConnectorParams configures the connector; only the fields you send
// change. ExposedScopes is a subset of profile, email, mfa, sessions,
// organizations.
type UpdateMCPConnectorParams struct {
	Enabled              *bool    `json:"enabled,omitempty"`
	Name                 *string  `json:"name,omitempty"`
	ExposedScopes        []string `json:"exposed_scopes,omitempty"`
	DynamicRegistration  *bool    `json:"dynamic_registration,omitempty"`
	AllowedRedirectHosts []string `json:"allowed_redirect_hosts,omitempty"`
}

// Describe returns the MCP server descriptor. GET /v1/mcp.
func (s *MCPService) Describe(ctx context.Context) (*MCPDescriptor, error) {
	out := &MCPDescriptor{}
	return out, s.client.get(ctx, "/v1/mcp", nil, out)
}

// Call sends one JSON-RPC request to the MCP endpoint. POST /v1/mcp.
func (s *MCPService) Call(ctx context.Context, req MCPRequest, opts ...RequestOption) (*MCPResponse, error) {
	if req.JSONRPC == "" {
		req.JSONRPC = "2.0"
	}
	out := &MCPResponse{}
	return out, s.client.post(ctx, "/v1/mcp", req, out, opts...)
}

// GetConnector reads the remote MCP connector. GET /v1/mcp_connector.
func (s *MCPService) GetConnector(ctx context.Context) (*MCPConnector, error) {
	out := &MCPConnector{}
	return out, s.client.get(ctx, "/v1/mcp_connector", nil, out)
}

// UpdateConnector configures the remote MCP connector. PUT /v1/mcp_connector.
func (s *MCPService) UpdateConnector(ctx context.Context, params UpdateMCPConnectorParams, opts ...RequestOption) (*MCPConnector, error) {
	out := &MCPConnector{}
	return out, s.client.put(ctx, "/v1/mcp_connector", params, out, opts...)
}

// DisableConnector disables the connector, keeping its stored preferences.
// DELETE /v1/mcp_connector.
func (s *MCPService) DisableConnector(ctx context.Context, opts ...RequestOption) (*MCPConnector, error) {
	out := &MCPConnector{}
	return out, s.client.del(ctx, "/v1/mcp_connector", out, opts...)
}

// ── Lazy migration (/v1/legacy_auth_connection) ─────────────────────────────

// LegacyAuthService manages the lazy-migration (legacy-auth / custom-DB)
// connection: a sign-in that misses checks your old system's verify URL.
type LegacyAuthService struct{ client *Client }

// LegacyAuthConnection is the connection as read back. Configured is false
// (and every other field empty) when none exists. The signing secret is never
// returned, only HasSigningSecret. CreatedAt/UpdatedAt are timestamps as the
// server renders them (ISO-8601 strings).
type LegacyAuthConnection struct {
	Object           string      `json:"object"`
	Configured       *bool       `json:"configured,omitempty"`
	ID               string      `json:"id,omitempty"`
	Enabled          bool        `json:"enabled"`
	VerifyURL        string      `json:"verify_url,omitempty"`
	HasSigningSecret bool        `json:"has_signing_secret"`
	ImportOnLogin    bool        `json:"import_on_login"`
	TimeoutMS        int         `json:"timeout_ms,omitempty"`
	Strategy         string      `json:"strategy,omitempty"`
	CreatedAt        interface{} `json:"created_at,omitempty"`
	UpdatedAt        interface{} `json:"updated_at,omitempty"`
	Deleted          *bool       `json:"deleted,omitempty"`
}

// IsConfigured reports whether a connection exists.
func (c *LegacyAuthConnection) IsConfigured() bool {
	if c.Configured != nil {
		return *c.Configured
	}
	return c.ID != ""
}

// PutLegacyAuthConnectionParams creates or replaces the connection.
// SigningSecret is write-only; Strategy is "password".
type PutLegacyAuthConnectionParams struct {
	Enabled       *bool  `json:"enabled,omitempty"`
	VerifyURL     string `json:"verify_url"`
	SigningSecret string `json:"signing_secret,omitempty"`
	ImportOnLogin *bool  `json:"import_on_login,omitempty"`
	TimeoutMS     int    `json:"timeout_ms,omitempty"`
	Strategy      string `json:"strategy,omitempty"`
}

// Get reads the connection. GET /v1/legacy_auth_connection.
func (s *LegacyAuthService) Get(ctx context.Context) (*LegacyAuthConnection, error) {
	out := &LegacyAuthConnection{}
	return out, s.client.get(ctx, "/v1/legacy_auth_connection", nil, out)
}

// Put creates or replaces the connection. PUT /v1/legacy_auth_connection.
func (s *LegacyAuthService) Put(ctx context.Context, params PutLegacyAuthConnectionParams, opts ...RequestOption) (*LegacyAuthConnection, error) {
	out := &LegacyAuthConnection{}
	return out, s.client.put(ctx, "/v1/legacy_auth_connection", params, out, opts...)
}

// Delete removes the connection. DELETE /v1/legacy_auth_connection.
func (s *LegacyAuthService) Delete(ctx context.Context, opts ...RequestOption) (*LegacyAuthConnection, error) {
	out := &LegacyAuthConnection{}
	return out, s.client.del(ctx, "/v1/legacy_auth_connection", out, opts...)
}

// ── Organization LDAP connections (/v1/org_ldap_connections) ─────────────────

// OrgLDAPConnectionsService manages organization-owned LDAP / Active Directory
// connections (one per organization). The bind password is write-only.
type OrgLDAPConnectionsService struct {
	client   *Client
	SyncRuns *OrgLDAPConnectionsSyncRunsService
}

// LDAPAttributeMapping maps directory attributes onto user fields; Email is
// required.
type LDAPAttributeMapping struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Username  string `json:"username,omitempty"`
}

// OrgLDAPConnection is an organization-owned LDAP connection. Status is
// draft, active or disabled.
type OrgLDAPConnection struct {
	Object          string               `json:"object"`
	ID              string               `json:"id"`
	OrganizationID  string               `json:"organization_id"`
	Status          string               `json:"status"`
	URL             string               `json:"url"`
	BindDN          string               `json:"bind_dn"`
	BaseDN          string               `json:"base_dn"`
	UserFilter      string               `json:"user_filter"`
	StartTLS        bool                 `json:"start_tls"`
	Attributes      LDAPAttributeMapping `json:"attributes"`
	HasBindPassword bool                 `json:"has_bind_password"`
	DefaultRoleID   *string              `json:"default_role_id"`
	CreatedAt       int64                `json:"created_at"`
	UpdatedAt       int64                `json:"updated_at"`
}

// OrgLDAPConnectionParams is the body of create (POST) and update (PATCH).
// On update only the fields you set change; set ClearDefaultRoleID to send
// default_role_id: null.
type OrgLDAPConnectionParams struct {
	OrganizationID     string                `json:"organization_id,omitempty"`
	Status             string                `json:"status,omitempty"`
	URL                string                `json:"url,omitempty"`
	BindDN             string                `json:"bind_dn,omitempty"`
	BaseDN             string                `json:"base_dn,omitempty"`
	UserFilter         string                `json:"user_filter,omitempty"`
	StartTLS           *bool                 `json:"start_tls,omitempty"`
	Attributes         *LDAPAttributeMapping `json:"attributes,omitempty"`
	BindPassword       string                `json:"bind_password,omitempty"`
	DefaultRoleID      string                `json:"default_role_id,omitempty"`
	ClearDefaultRoleID bool                  `json:"-"`
}

// MarshalJSON renders default_role_id: null when ClearDefaultRoleID is set.
func (p OrgLDAPConnectionParams) MarshalJSON() ([]byte, error) {
	type alias OrgLDAPConnectionParams
	raw, err := json.Marshal(alias(p))
	if err != nil || !p.ClearDefaultRoleID {
		return raw, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["default_role_id"] = nil
	return json.Marshal(m)
}

// OrgLDAPConnectionTest is the result of a bind test.
type OrgLDAPConnectionTest struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// List returns connections, optionally for one organization.
// GET /v1/org_ldap_connections.
func (s *OrgLDAPConnectionsService) List(ctx context.Context, organizationID string) (*CursorPage[OrgLDAPConnection], error) {
	var q url.Values
	if organizationID != "" {
		q = url.Values{"organization_id": {organizationID}}
	}
	out := &CursorPage[OrgLDAPConnection]{}
	return out, s.client.get(ctx, "/v1/org_ldap_connections", q, out)
}

// Create creates a connection. POST /v1/org_ldap_connections.
func (s *OrgLDAPConnectionsService) Create(ctx context.Context, params OrgLDAPConnectionParams, opts ...RequestOption) (*OrgLDAPConnection, error) {
	out := &OrgLDAPConnection{}
	return out, s.client.post(ctx, "/v1/org_ldap_connections", params, out, opts...)
}

// Get fetches one connection. GET /v1/org_ldap_connections/:id.
func (s *OrgLDAPConnectionsService) Get(ctx context.Context, id string) (*OrgLDAPConnection, error) {
	out := &OrgLDAPConnection{}
	return out, s.client.get(ctx, "/v1/org_ldap_connections/"+url.PathEscape(id), nil, out)
}

// Update updates a connection. PATCH /v1/org_ldap_connections/:id.
func (s *OrgLDAPConnectionsService) Update(ctx context.Context, id string, params OrgLDAPConnectionParams, opts ...RequestOption) (*OrgLDAPConnection, error) {
	out := &OrgLDAPConnection{}
	return out, s.client.patch(ctx, "/v1/org_ldap_connections/"+url.PathEscape(id), params, out, opts...)
}

// Delete deletes a connection. DELETE /v1/org_ldap_connections/:id.
func (s *OrgLDAPConnectionsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/org_ldap_connections/"+url.PathEscape(id), out, opts...)
}

// Test attempts a service-account bind; bindPassword optionally tests a
// candidate password without saving it. POST /v1/org_ldap_connections/:id/test.
func (s *OrgLDAPConnectionsService) Test(ctx context.Context, id, bindPassword string, opts ...RequestOption) (*OrgLDAPConnectionTest, error) {
	out := &OrgLDAPConnectionTest{}
	body := map[string]string{}
	if bindPassword != "" {
		body["bind_password"] = bindPassword
	}
	return out, s.client.post(ctx, "/v1/org_ldap_connections/"+url.PathEscape(id)+"/test", body, out, opts...)
}

// ── Proof-Carrying Authority admin (/v1/pca/*) ──────────────────────────────

// PCAService holds the instance-admin controls for Proof-Carrying Authority:
// trusted attestor keys, the kill switch, capability revocation, and denying
// pending step-ups.
type PCAService struct{ client *Client }

// PCAAttestors is the trusted software-attestor key list.
type PCAAttestors struct {
	Object              string   `json:"object"`
	TrustedAttestorKeys []string `json:"trusted_attestor_keys"`
}

// PCAFreeze reports the kill-switch state.
type PCAFreeze struct {
	Object string `json:"object"`
	Frozen bool   `json:"frozen"`
}

// PCARevocation acknowledges a capability revocation.
type PCARevocation struct {
	Object   string `json:"object"`
	GrantRef string `json:"grant_ref"`
	CapID    string `json:"cap_id"`
	Revoked  bool   `json:"revoked"`
}

// PCAStepUp is a step-up approval request. Status is pending, approved,
// denied or expired; timestamps are ISO-8601.
type PCAStepUp struct {
	Object       string      `json:"object"`
	StepUpID     string      `json:"stepup_id"`
	GrantRef     string      `json:"grant_ref"`
	ActionDigest string      `json:"action_digest"`
	RequiredT    int         `json:"required_t"`
	Status       string      `json:"status"`
	Shares       []string    `json:"shares"`
	CreatedAt    string      `json:"created_at"`
	ExpiresAt    string      `json:"expires_at"`
	Receipt      interface{} `json:"receipt,omitempty"`
}

// GetAttestors reads the trusted attestor keys. GET /v1/pca/attestors.
func (s *PCAService) GetAttestors(ctx context.Context) (*PCAAttestors, error) {
	out := &PCAAttestors{}
	return out, s.client.get(ctx, "/v1/pca/attestors", nil, out)
}

// SetAttestors replaces the trusted attestor keys (empty = attestation not
// enforced). PUT /v1/pca/attestors.
func (s *PCAService) SetAttestors(ctx context.Context, keys []string, opts ...RequestOption) (*PCAAttestors, error) {
	if keys == nil {
		keys = []string{}
	}
	out := &PCAAttestors{}
	return out, s.client.put(ctx, "/v1/pca/attestors", map[string]interface{}{"trusted_attestor_keys": keys}, out, opts...)
}

// Freeze engages the instance-wide kill switch. POST /v1/pca/freeze.
func (s *PCAService) Freeze(ctx context.Context, reason string, opts ...RequestOption) (*PCAFreeze, error) {
	out := &PCAFreeze{}
	body := map[string]string{}
	if reason != "" {
		body["reason"] = reason
	}
	return out, s.client.post(ctx, "/v1/pca/freeze", body, out, opts...)
}

// Unfreeze clears the kill switch. DELETE /v1/pca/freeze.
func (s *PCAService) Unfreeze(ctx context.Context, opts ...RequestOption) (*PCAFreeze, error) {
	out := &PCAFreeze{}
	return out, s.client.del(ctx, "/v1/pca/freeze", out, opts...)
}

// Revoke revokes a capability id under a grant (revoking the grant ref itself
// revokes the whole grant). POST /v1/pca/revocations.
func (s *PCAService) Revoke(ctx context.Context, grantRef, capID string, opts ...RequestOption) (*PCARevocation, error) {
	out := &PCARevocation{}
	body := map[string]string{"grant_ref": grantRef, "cap_id": capID}
	return out, s.client.post(ctx, "/v1/pca/revocations", body, out, opts...)
}

// DenyStepUp denies a pending step-up. POST /v1/pca/stepups/:id/deny.
func (s *PCAService) DenyStepUp(ctx context.Context, id, reason string, opts ...RequestOption) (*PCAStepUp, error) {
	out := &PCAStepUp{}
	body := map[string]string{}
	if reason != "" {
		body["reason"] = reason
	}
	return out, s.client.post(ctx, "/v1/pca/stepups/"+url.PathEscape(id)+"/deny", body, out, opts...)
}
