package atlas

import (
	"context"
	"net/url"
)

// --- Organization settings values + the instance-wide settings schema ----

// OrganizationSettings is one organization's settings document.
type OrganizationSettings struct {
	Object         string                 `json:"object"`
	OrganizationID string                 `json:"organization_id"`
	Values         map[string]interface{} `json:"values"`
	// Version is monotonic per organization; 0 when nothing is set yet.
	Version   int     `json:"version"`
	UpdatedBy *string `json:"updated_by"`
	UpdatedAt *int64  `json:"updated_at"`
}

// GetSettings fetches an organization's settings values.
// GET /v1/organizations/:id/settings.
func (s *OrganizationsService) GetSettings(ctx context.Context, id string) (*OrganizationSettings, error) {
	out := &OrganizationSettings{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/settings", nil, out)
}

// ReplaceSettings writes an organization's whole settings document, validated
// against the registered schema (422 SETTINGS_INVALID on mismatch).
// PUT /v1/organizations/:id/settings.
func (s *OrganizationsService) ReplaceSettings(ctx context.Context, id string, values map[string]interface{}, opts ...RequestOption) (*OrganizationSettings, error) {
	out := &OrganizationSettings{}
	body := map[string]interface{}{"values": values}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/settings", body, out, opts...)
}

// MergeSettings merges a partial object into an organization's settings (RFC
// 7396 shallow merge): a key set to nil is removed, other keys set/overwrite,
// untouched keys are kept. PATCH /v1/organizations/:id/settings.
func (s *OrganizationsService) MergeSettings(ctx context.Context, id string, values map[string]interface{}, opts ...RequestOption) (*OrganizationSettings, error) {
	out := &OrganizationSettings{}
	body := map[string]interface{}{"values": values}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(id)+"/settings", body, out, opts...)
}

// OrganizationSettingsSchemaService is /v1/organization_settings_schema: the
// instance-wide JSON Schema every organization's settings are validated against.
type OrganizationSettingsSchemaService struct{ client *Client }

// OrganizationSettingsSchema is the registered schema and its version.
type OrganizationSettingsSchema struct {
	Object    string                 `json:"object"`
	Schema    map[string]interface{} `json:"schema"`
	Version   int                    `json:"version"`
	UpdatedAt int64                  `json:"updated_at"`
}

// Get fetches the registered schema (404 if none).
// GET /v1/organization_settings_schema.
func (s *OrganizationSettingsSchemaService) Get(ctx context.Context) (*OrganizationSettingsSchema, error) {
	out := &OrganizationSettingsSchema{}
	return out, s.client.get(ctx, "/v1/organization_settings_schema", nil, out)
}

// Register registers the schema for the first time.
// POST /v1/organization_settings_schema.
func (s *OrganizationSettingsSchemaService) Register(ctx context.Context, schema map[string]interface{}, opts ...RequestOption) (*OrganizationSettingsSchema, error) {
	out := &OrganizationSettingsSchema{}
	body := map[string]interface{}{"schema": schema}
	return out, s.client.post(ctx, "/v1/organization_settings_schema", body, out, opts...)
}

// Replace replaces the schema, bumping its version.
// PUT /v1/organization_settings_schema.
func (s *OrganizationSettingsSchemaService) Replace(ctx context.Context, schema map[string]interface{}, opts ...RequestOption) (*OrganizationSettingsSchema, error) {
	out := &OrganizationSettingsSchema{}
	body := map[string]interface{}{"schema": schema}
	return out, s.client.put(ctx, "/v1/organization_settings_schema", body, out, opts...)
}

// --- Branding overlay -----------------------------------------------------

// OrganizationBranding is an organization's hosted-page branding overlay. Nil
// fields inherit the instance brand.
type OrganizationBranding struct {
	Object         string  `json:"object"`
	OrganizationID string  `json:"organization_id"`
	DisplayName    *string `json:"display_name"`
	LogoURL        *string `json:"logo_url"`
	PrimaryColor   *string `json:"primary_color"`
	SupportURL     *string `json:"support_url"`
	CustomDomain   *string `json:"custom_domain"`
	UpdatedAt      *int64  `json:"updated_at"`
}

// UpdateOrganizationBrandingParams is a partial merge: a set field overrides the
// instance brand; ClearFields names fields to clear (sent as null).
type UpdateOrganizationBrandingParams struct {
	DisplayName  *string
	LogoURL      *string
	PrimaryColor *string
	SupportURL   *string
	CustomDomain *string
	// ClearFields lists wire field names ("logo_url", …) to reset to the
	// instance brand.
	ClearFields []string
}

func (p UpdateOrganizationBrandingParams) body() map[string]interface{} {
	b := map[string]interface{}{}
	set := func(k string, v *string) {
		if v != nil {
			b[k] = *v
		}
	}
	set("display_name", p.DisplayName)
	set("logo_url", p.LogoURL)
	set("primary_color", p.PrimaryColor)
	set("support_url", p.SupportURL)
	set("custom_domain", p.CustomDomain)
	for _, f := range p.ClearFields {
		b[f] = nil
	}
	return b
}

// GetBranding reads an organization's branding overlay.
// GET /v1/organizations/:id/branding.
func (s *OrganizationsService) GetBranding(ctx context.Context, id string) (*OrganizationBranding, error) {
	out := &OrganizationBranding{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/branding", nil, out)
}

// UpdateBranding merges into an organization's branding overlay.
// PUT /v1/organizations/:id/branding.
func (s *OrganizationsService) UpdateBranding(ctx context.Context, id string, params UpdateOrganizationBrandingParams, opts ...RequestOption) (*OrganizationBranding, error) {
	out := &OrganizationBranding{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(id)+"/branding", params.body(), out, opts...)
}

// --- Audit streams --------------------------------------------------------

// OrgAuditStream is an organization's audit-event forwarding destination.
type OrgAuditStream struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	URL            string `json:"url"`
	Format         string `json:"format"`
	Active         bool   `json:"active"`
	HasSecret      bool   `json:"has_secret"`
	CreatedAt      int64  `json:"created_at"`
}

// CreateOrgAuditStreamParams is the body of POST /v1/organizations/:id/audit_streams.
type CreateOrgAuditStreamParams struct {
	URL string `json:"url"`
	// Secret is the shared HMAC-SHA256 signing secret (min 16 chars), write-only.
	Secret string `json:"secret"`
	// Format is a shape hint for the collector (default "json").
	Format string `json:"format,omitempty"`
}

// ListAuditStreams lists an organization's audit stream destinations.
// GET /v1/organizations/:id/audit_streams.
func (s *OrganizationsService) ListAuditStreams(ctx context.Context, id string) (*CursorPage[OrgAuditStream], error) {
	out := &CursorPage[OrgAuditStream]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(id)+"/audit_streams", nil, out)
}

// CreateAuditStream registers an audit stream destination for one organization.
// POST /v1/organizations/:id/audit_streams.
func (s *OrganizationsService) CreateAuditStream(ctx context.Context, id string, params CreateOrgAuditStreamParams, opts ...RequestOption) (*OrgAuditStream, error) {
	out := &OrgAuditStream{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(id)+"/audit_streams", params, out, opts...)
}

// DeleteAuditStream deletes an organization's audit stream destination.
// DELETE /v1/organizations/:id/audit_streams/:streamId.
func (s *OrganizationsService) DeleteAuditStream(ctx context.Context, id, streamID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(id)+"/audit_streams/"+url.PathEscape(streamID), out, opts...)
}

// --- End-user (reader) pool -----------------------------------------------

// OrganizationEndUser is a reader in an organization's end-user pool.
type OrganizationEndUser struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	UserID         string   `json:"user_id"`
	Status         string   `json:"status"`
	Source         string   `json:"source"`
	PublicMetadata Metadata `json:"public_metadata"`
	ApprovedAt     *int64   `json:"approved_at"`
	CreatedAt      int64    `json:"created_at"`
	UpdatedAt      int64    `json:"updated_at"`
}

// ListEndUsersParams filters GET /v1/organizations/:orgId/end_users.
type ListEndUsersParams struct {
	ListParams
	// Status is "active", "pending" or "blocked".
	Status string
}

// AddEndUserParams is the body of POST /v1/organizations/:orgId/end_users.
type AddEndUserParams struct {
	UserID string `json:"user_id"`
	// Status: active (default), pending or blocked.
	Status string `json:"status,omitempty"`
	// Source: hosted, federated, token_exchange (default) or import.
	Source string `json:"source,omitempty"`
}

// ListEndUsers lists an organization's end-user pool.
// GET /v1/organizations/:orgId/end_users.
func (s *OrganizationsService) ListEndUsers(ctx context.Context, orgID string, params ListEndUsersParams) (*CursorPage[OrganizationEndUser], error) {
	q := params.ListParams.values()
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	out := &CursorPage[OrganizationEndUser]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/end_users", q, out)
}

// AddEndUser attaches an instance user to the pool as a reader.
// POST /v1/organizations/:orgId/end_users.
func (s *OrganizationsService) AddEndUser(ctx context.Context, orgID string, params AddEndUserParams, opts ...RequestOption) (*OrganizationEndUser, error) {
	out := &OrganizationEndUser{}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/end_users", params, out, opts...)
}

// UpdateEndUserStatus approves (active), gates (pending) or blocks a reader.
// PATCH /v1/organizations/:orgId/end_users/:userId.
func (s *OrganizationsService) UpdateEndUserStatus(ctx context.Context, orgID, userID, status string, opts ...RequestOption) (*OrganizationEndUser, error) {
	out := &OrganizationEndUser{}
	body := map[string]string{"status": status}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/end_users/"+url.PathEscape(userID), body, out, opts...)
}

// RemoveEndUser removes a reader from the pool.
// DELETE /v1/organizations/:orgId/end_users/:userId.
func (s *OrganizationsService) RemoveEndUser(ctx context.Context, orgID, userID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/end_users/"+url.PathEscape(userID), out, opts...)
}

// --- Reader domain ----------------------------------------------------------

// ReaderDomain is a host bound to an organization's reader pool.
type ReaderDomain struct {
	Object               string  `json:"object"`
	ID                   string  `json:"id"`
	Role                 string  `json:"role"`
	Host                 string  `json:"host"`
	Status               string  `json:"status"`
	Action               *string `json:"action"`
	Live                 bool    `json:"live"`
	CNAMETarget          *string `json:"cname_target"`
	LastCheckedAt        *int64  `json:"last_checked_at"`
	LastObservedTarget   *string `json:"last_observed_target"`
	FailureReason        *string `json:"failure_reason"`
	CertificateExpiresAt *int64  `json:"certificate_expires_at"`
	CookieDomain         *string `json:"cookie_domain"`
}

// ReaderDomainInstruction is one DNS record to publish.
type ReaderDomainInstruction struct {
	Role    string `json:"role"`
	Host    string `json:"host"`
	Type    string `json:"type"`
	Target  string `json:"target"`
	Purpose string `json:"purpose"`
}

// ReaderDomainBinding is a newly bound reader domain plus its DNS instructions.
type ReaderDomainBinding struct {
	ReaderDomain
	Instructions []ReaderDomainInstruction `json:"instructions"`
	Note         string                    `json:"note"`
}

// ListReaderDomains lists the organization's reader domain(s).
// GET /v1/organizations/:orgId/reader_domain.
func (s *OrganizationsService) ListReaderDomains(ctx context.Context, orgID string) (*CursorPage[ReaderDomain], error) {
	out := &CursorPage[ReaderDomain]{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/reader_domain", nil, out)
}

// BindReaderDomain binds a host to the organization's reader pool; publish the
// returned CNAME, then verify with Domains.Verify.
// POST /v1/organizations/:orgId/reader_domain.
func (s *OrganizationsService) BindReaderDomain(ctx context.Context, orgID, host string, opts ...RequestOption) (*ReaderDomainBinding, error) {
	out := &ReaderDomainBinding{}
	body := map[string]string{"host": host}
	return out, s.client.post(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/reader_domain", body, out, opts...)
}

// RemoveReaderDomain removes the organization's reader domain binding.
// DELETE /v1/organizations/:orgId/reader_domain.
func (s *OrganizationsService) RemoveReaderDomain(ctx context.Context, orgID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/organizations/"+url.PathEscape(orgID)+"/reader_domain", out, opts...)
}
