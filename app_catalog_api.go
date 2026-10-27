package atlas

import (
	"context"
	"net/url"
)

// AppCatalogService is the appCatalog resource.
type AppCatalogService struct {
	client *Client
}

// Presets: List the app presets: about 100 SAML apps (Slack, GitHub, Snowflake, Notion, HubSpot
// and more) and about 45 OpenID Connect apps (Grafana, GitLab, Argo CD, Vault, Cloudflare Zero
// Trust and more), each with its protocol, category, the parameters it needs, whether its values
// were confirmed in the vendor's docs (verified) and that page (source_url).
// GET /v1/app_catalog.
func (s *AppCatalogService) Presets(ctx context.Context, params ListParams) (*AppCatalogPresetsResult, error) {
	out := &AppCatalogPresetsResult{}
	return out, s.client.do(ctx, "GET", "/v1/app_catalog", params.values(), nil, out)
}

// Installed: List the installed apps (SAML and OpenID Connect) with their email-domain allow-list
// and assignment.
// GET /v1/app_catalog/installed.
func (s *AppCatalogService) Installed(ctx context.Context, params ListParams) (*AppCatalogInstalledResult, error) {
	out := &AppCatalogInstalledResult{}
	return out, s.client.do(ctx, "GET", "/v1/app_catalog/installed", params.values(), nil, out)
}

// Install: Install a catalog app from its preset and params, with an optional name, installed_id,
// allowed_email_domains and assignment. A SAML preset becomes a SAML service provider; an OIDC
// preset registers a confidential OAuth client with the preset's redirect URIs and returns
// client_id, client_secret (shown once), redirect_uri and issuer to paste into the app. 409 if the
// installed_id exists. → 201.
// POST /v1/app_catalog/{id}/install.
func (s *AppCatalogService) Install(ctx context.Context, id string, params AppCatalogInstallParams, opts ...RequestOption) (*AppCatalogInstalledResultDataItem, error) {
	out := &AppCatalogInstalledResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/app_catalog/"+url.PathEscape(id)+"/install", nil, params, out, opts...)
}

// Update: Change an installed app's name, allowed_email_domains or assignment. Assignment applies
// to the launcher and to single sign-on: someone not assigned is refused with 403.
// PATCH /v1/app_catalog/installed/{id}.
func (s *AppCatalogService) Update(ctx context.Context, id string, params AppCatalogUpdateParams, opts ...RequestOption) (*AppCatalogInstalledResultDataItem, error) {
	out := &AppCatalogInstalledResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/app_catalog/installed/"+url.PathEscape(id), nil, params, out, opts...)
}

// Uninstall: Uninstall an app: it disappears from the launcher and Atlas stops signing people in
// to it (an OIDC app's OAuth client and its grants are deleted).
// DELETE /v1/app_catalog/installed/{id}.
func (s *AppCatalogService) Uninstall(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/app_catalog/installed/"+url.PathEscape(id), nil, nil, nil, opts...)
}
