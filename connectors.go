package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ConnectorsService is the /v1/connectors namespace — community connector
// profiles you publish to the connector directory, plus installing and rating
// published connectors on your own instance. Directory browses the unified
// directory (built-in providers plus published community connectors).
type ConnectorsService struct{ client *Client }

// Connector is one of your community connector profiles. The shared client
// secret is never returned (only SharedClientID).
type Connector struct {
	Object                string                   `json:"object"`
	ID                    string                   `json:"id"`
	Slug                  string                   `json:"slug"`
	DisplayName           string                   `json:"display_name"`
	LogoURL               *string                  `json:"logo_url"`
	Tagline               *string                  `json:"tagline"`
	Description           *string                  `json:"description"`
	Category              string                   `json:"category"`
	Tags                  []string                 `json:"tags"`
	WebsiteURL            *string                  `json:"website_url"`
	DocsURL               *string                  `json:"docs_url"`
	SupportURL            *string                  `json:"support_url"`
	SetupGuide            *string                  `json:"setup_guide"`
	Protocol              string                   `json:"protocol"`
	AuthorizationEndpoint *string                  `json:"authorization_endpoint"`
	TokenEndpoint         *string                  `json:"token_endpoint"`
	UserinfoEndpoint      *string                  `json:"userinfo_endpoint"`
	Issuer                *string                  `json:"issuer"`
	DefaultScopes         []string                 `json:"default_scopes"`
	APIScopes             []map[string]interface{} `json:"api_scopes"`
	CredentialFields      []map[string]interface{} `json:"credential_fields"`
	ShareModes            []string                 `json:"share_modes"`
	SharedClientID        *string                  `json:"shared_client_id"`
	SharedRevoked         bool                     `json:"shared_revoked"`
	IdPIssuer             *string                  `json:"idp_issuer"`
	IdPAutoRegister       bool                     `json:"idp_auto_register"`
	// Status is draft, published, unlisted or banned.
	Status       string  `json:"status"`
	Verified     bool    `json:"verified"`
	Featured     bool    `json:"featured"`
	InstallCount int     `json:"install_count"`
	ViewCount    int     `json:"view_count"`
	RatingAvg    float64 `json:"rating_avg"`
	RatingCount  int     `json:"rating_count"`
	CreatedAt    int64   `json:"created_at"`
	UpdatedAt    int64   `json:"updated_at"`
	// InstallsDisabled is set on a shared-credentials revoke: how many installs
	// were switched off.
	InstallsDisabled *int `json:"installs_disabled,omitempty"`
}

// ConnectorParams is the body of POST /v1/connectors (Slug and DisplayName
// required) and PATCH /v1/connectors/:id (every field optional). ShareModes is a
// subset of prefill, full_shared, full_idp.
type ConnectorParams struct {
	Slug                  string                   `json:"slug,omitempty"`
	DisplayName           string                   `json:"display_name,omitempty"`
	LogoURL               string                   `json:"logo_url,omitempty"`
	Tagline               string                   `json:"tagline,omitempty"`
	Description           string                   `json:"description,omitempty"`
	Category              string                   `json:"category,omitempty"`
	Tags                  []string                 `json:"tags,omitempty"`
	WebsiteURL            string                   `json:"website_url,omitempty"`
	DocsURL               string                   `json:"docs_url,omitempty"`
	SupportURL            string                   `json:"support_url,omitempty"`
	Screenshots           []interface{}            `json:"screenshots,omitempty"`
	SetupGuide            string                   `json:"setup_guide,omitempty"`
	Protocol              string                   `json:"protocol,omitempty"`
	AuthorizationEndpoint string                   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string                   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string                   `json:"userinfo_endpoint,omitempty"`
	Issuer                string                   `json:"issuer,omitempty"`
	DefaultScopes         []string                 `json:"default_scopes,omitempty"`
	APIScopes             []map[string]interface{} `json:"api_scopes,omitempty"`
	CredentialFields      []map[string]interface{} `json:"credential_fields,omitempty"`
	AuthorizationParams   map[string]interface{}   `json:"authorization_params,omitempty"`
	Quirks                map[string]interface{}   `json:"quirks,omitempty"`
	ShareModes            []string                 `json:"share_modes,omitempty"`
	IdPInstanceID         string                   `json:"idp_instance_id,omitempty"`
	IdPIssuer             string                   `json:"idp_issuer,omitempty"`
	IdPAutoRegister       *bool                    `json:"idp_auto_register,omitempty"`
}

// ConnectorSharedCredentialsParams sets / rotates (ClientID + ClientSecret) or
// revokes (Revoke) a connector's full_shared OAuth credentials.
type ConnectorSharedCredentialsParams struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Revoke       bool   `json:"revoke,omitempty"`
}

// ConnectorInstallParams is the body of POST /v1/connectors/:slug/install.
// ShareMode is prefill, full_shared or full_idp; prefill needs your own client
// credentials.
type ConnectorInstallParams struct {
	ShareMode    string   `json:"share_mode"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// ConnectorInstall is the result of installing a connector.
type ConnectorInstall struct {
	Object           string `json:"object"`
	Connector        string `json:"connector"`
	ShareMode        string `json:"share_mode"`
	ProviderKey      string `json:"provider_key,omitempty"`
	NeedsCredentials bool   `json:"needs_credentials,omitempty"`
}

// ConnectorReview is the result of rating a connector.
type ConnectorReview struct {
	Object    string `json:"object"`
	Connector string `json:"connector"`
	Rating    int    `json:"rating"`
}

// DirectoryEntry is one entry in the unified connector directory. Source is
// "builtin" or "community"; Key is the provider key to configure.
type DirectoryEntry struct {
	Source           string                   `json:"source"`
	Key              string                   `json:"key"`
	Slug             string                   `json:"slug"`
	DisplayName      string                   `json:"displayName"`
	Category         string                   `json:"category"`
	Tagline          *string                  `json:"tagline"`
	Description      *string                  `json:"description"`
	LogoURL          *string                  `json:"logoUrl"`
	WebsiteURL       *string                  `json:"websiteUrl"`
	DocsURL          *string                  `json:"docsUrl"`
	Verified         bool                     `json:"verified"`
	Featured         bool                     `json:"featured"`
	InstallCount     int                      `json:"installCount"`
	RatingAvg        float64                  `json:"ratingAvg"`
	RatingCount      int                      `json:"ratingCount"`
	RankScore        float64                  `json:"rankScore"`
	DefaultScopes    []string                 `json:"defaultScopes"`
	APIScopes        []map[string]interface{} `json:"apiScopes"`
	CredentialFields []map[string]interface{} `json:"credentialFields"`
	ShareModes       []string                 `json:"shareModes"`
}

// DirectoryParams filters GET /v1/directory.
type DirectoryParams struct {
	Category     string
	VerifiedOnly bool
	Query        string
	Limit        int
	Offset       int
}

func (p DirectoryParams) values() url.Values {
	v := url.Values{}
	if p.Category != "" {
		v.Set("category", p.Category)
	}
	if p.VerifiedOnly {
		v.Set("verified", "true")
	}
	if p.Query != "" {
		v.Set("q", p.Query)
	}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		v.Set("offset", strconv.Itoa(p.Offset))
	}
	return v
}

// List returns your own connector profiles. GET /v1/connectors.
func (s *ConnectorsService) List(ctx context.Context) (*ListPage[Connector], error) {
	out := &ListPage[Connector]{}
	return out, s.client.get(ctx, "/v1/connectors", nil, out)
}

// Create creates a connector profile (draft). POST /v1/connectors.
func (s *ConnectorsService) Create(ctx context.Context, params ConnectorParams, opts ...RequestOption) (*Connector, error) {
	out := &Connector{}
	return out, s.client.post(ctx, "/v1/connectors", params, out, opts...)
}

// Get fetches one of your connector profiles. GET /v1/connectors/:id.
func (s *ConnectorsService) Get(ctx context.Context, id string) (*Connector, error) {
	out := &Connector{}
	return out, s.client.get(ctx, "/v1/connectors/"+url.PathEscape(id), nil, out)
}

// Update edits a connector profile. PATCH /v1/connectors/:id.
func (s *ConnectorsService) Update(ctx context.Context, id string, params ConnectorParams, opts ...RequestOption) (*Connector, error) {
	out := &Connector{}
	return out, s.client.patch(ctx, "/v1/connectors/"+url.PathEscape(id), params, out, opts...)
}

// Delete deletes a connector profile and its installs, reviews and reports.
// DELETE /v1/connectors/:id.
func (s *ConnectorsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/connectors/"+url.PathEscape(id), out, opts...)
}

// Publish lists a connector in the public directory.
// POST /v1/connectors/:id/publish.
func (s *ConnectorsService) Publish(ctx context.Context, id string, opts ...RequestOption) (*Connector, error) {
	out := &Connector{}
	return out, s.client.post(ctx, "/v1/connectors/"+url.PathEscape(id)+"/publish", nil, out, opts...)
}

// Unlist removes a published connector from the directory without deleting it.
// POST /v1/connectors/:id/unlist.
func (s *ConnectorsService) Unlist(ctx context.Context, id string, opts ...RequestOption) (*Connector, error) {
	out := &Connector{}
	return out, s.client.post(ctx, "/v1/connectors/"+url.PathEscape(id)+"/unlist", nil, out, opts...)
}

// SetSharedCredentials sets, rotates or revokes the full_shared credentials.
// POST /v1/connectors/:id/shared_credentials.
func (s *ConnectorsService) SetSharedCredentials(ctx context.Context, id string, params ConnectorSharedCredentialsParams, opts ...RequestOption) (*Connector, error) {
	out := &Connector{}
	return out, s.client.post(ctx, "/v1/connectors/"+url.PathEscape(id)+"/shared_credentials", params, out, opts...)
}

// Install enables a published connector on your instance.
// POST /v1/connectors/:slug/install.
func (s *ConnectorsService) Install(ctx context.Context, slug string, params ConnectorInstallParams, opts ...RequestOption) (*ConnectorInstall, error) {
	out := &ConnectorInstall{}
	return out, s.client.post(ctx, "/v1/connectors/"+url.PathEscape(slug)+"/install", params, out, opts...)
}

// Review rates a connector you installed (rating 1–5, optional text).
// POST /v1/connectors/:slug/reviews.
func (s *ConnectorsService) Review(ctx context.Context, slug string, rating int, text string, opts ...RequestOption) (*ConnectorReview, error) {
	out := &ConnectorReview{}
	body := map[string]interface{}{"rating": rating}
	if text != "" {
		body["body"] = text
	}
	return out, s.client.post(ctx, "/v1/connectors/"+url.PathEscape(slug)+"/reviews", body, out, opts...)
}

// Directory browses the unified connector directory, popular first.
// GET /v1/directory.
func (s *ConnectorsService) Directory(ctx context.Context, params DirectoryParams) (*ListPage[DirectoryEntry], error) {
	out := &ListPage[DirectoryEntry]{}
	return out, s.client.get(ctx, "/v1/directory", params.values(), out)
}
