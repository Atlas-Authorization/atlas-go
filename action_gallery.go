package atlas

import (
	"context"
	"net/url"
)

// ActionGalleryService is the community Actions gallery: browse reusable
// Action templates (first-party and community), install one into the instance
// as a DISABLED action, and keep installed actions up to date.
type ActionGalleryService struct{ client *Client }

// ActionTemplatesService publishes your own Action templates to the gallery
// (staff review them before they are listed).
type ActionTemplatesService struct{ client *Client }

// ActionTemplateSecret is a secret a template reads, declared by NAME; values
// are never part of a template.
type ActionTemplateSecret struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// ActionGalleryEntry is one template in the gallery. Source is "builtin" or
// "community"; Trigger is any Action trigger (also pre_organization_create,
// pre_member_add, pre_invitation_create); UsesHTTP is true when the code sends
// outbound requests with api.http.
type ActionGalleryEntry struct {
	Object   string   `json:"object"`
	Source   string   `json:"source"`
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	Summary  string   `json:"summary"`
	Trigger  string   `json:"trigger"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	License  string   `json:"license"`
	Author   struct {
		Name       string `json:"name"`
		FirstParty bool   `json:"first_party"`
	} `json:"author"`
	Verified      bool                   `json:"verified"`
	Featured      bool                   `json:"featured"`
	InstallCount  int64                  `json:"install_count"`
	LatestVersion string                 `json:"latest_version"`
	UsesHTTP      bool                   `json:"uses_http"`
	Secrets       []ActionTemplateSecret `json:"secrets"`
	UpdatedAt     *int64                 `json:"updated_at"`
}

// ActionGalleryDetail is one template with its code and versions.
type ActionGalleryDetail struct {
	ActionGalleryEntry
	Description   string  `json:"description"`
	Code          string  `json:"code"`
	Changelog     *string `json:"changelog"`
	RepositoryURL *string `json:"repository_url"`
	Versions      []struct {
		Version    string  `json:"version"`
		Changelog  *string `json:"changelog"`
		ReleasedAt *int64  `json:"released_at"`
	} `json:"versions"`
}

// ActionGalleryFilter narrows the gallery list.
type ActionGalleryFilter struct {
	Q        string
	Category string
	Trigger  string
	Source   string
}

func (f ActionGalleryFilter) values() url.Values {
	v := url.Values{}
	for k, val := range map[string]string{"q": f.Q, "category": f.Category, "trigger": f.Trigger, "source": f.Source} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

// InstallTemplateParams installs a template. Version is a specific approved
// version (default: the latest); Name the action's name (default: the
// template's); Secrets values for the secrets the template declares.
type InstallTemplateParams struct {
	Version string            `json:"version,omitempty"`
	Name    string            `json:"name,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

// ActionGalleryInstallResult is the new action (disabled and not bound to
// any flow yet) plus the required secrets still missing.
type ActionGalleryInstallResult struct {
	Object   string `json:"object"`
	Action   Action `json:"action"`
	Template struct {
		Slug    string `json:"slug"`
		Source  string `json:"source"`
		Version string `json:"version"`
	} `json:"template"`
	InstallID      string   `json:"install_id"`
	MissingSecrets []string `json:"missing_secrets"`
}

// ActionGalleryInstallation is an action installed from the gallery, with its
// update status.
type ActionGalleryInstallation struct {
	Object                string   `json:"object"`
	ActionID              string   `json:"action_id"`
	ActionName            string   `json:"action_name"`
	Enabled               bool     `json:"enabled"`
	Trigger               string   `json:"trigger"`
	Source                string   `json:"source"`
	TemplateSlug          string   `json:"template_slug"`
	InstalledVersion      string   `json:"installed_version"`
	LatestVersion         *string  `json:"latest_version"`
	UpdateAvailable       bool     `json:"update_available"`
	MissingSecrets        []string `json:"missing_secrets"`
	UpdateRequiresSecrets []string `json:"update_requires_secrets"`
	InstalledAt           int64    `json:"installed_at"`
	UpdatedAt             int64    `json:"updated_at"`
}

// ActionGalleryUpdateResult: Updated is false when the action already runs
// the latest version.
type ActionGalleryUpdateResult struct {
	Object      string `json:"object"`
	Updated     bool   `json:"updated"`
	Action      Action `json:"action"`
	FromVersion string `json:"from_version,omitempty"`
	Version     string `json:"version"`
}

// List returns the gallery, best first. GET /v1/action_gallery.
func (s *ActionGalleryService) List(ctx context.Context, filter ActionGalleryFilter) (*ListPage[ActionGalleryEntry], error) {
	out := &ListPage[ActionGalleryEntry]{}
	return out, s.client.get(ctx, "/v1/action_gallery", filter.values(), out)
}

// Get returns one template with its code, secret names and versions.
// GET /v1/action_gallery/:slug.
func (s *ActionGalleryService) Get(ctx context.Context, slug string) (*ActionGalleryDetail, error) {
	out := &ActionGalleryDetail{}
	return out, s.client.get(ctx, "/v1/action_gallery/"+url.PathEscape(slug), nil, out)
}

// Install installs a template as a new, disabled action. Supply its secrets,
// bind it, then enable it. POST /v1/action_gallery/:slug/install.
func (s *ActionGalleryService) Install(ctx context.Context, slug string, params InstallTemplateParams, opts ...RequestOption) (*ActionGalleryInstallResult, error) {
	out := &ActionGalleryInstallResult{}
	return out, s.client.post(ctx, "/v1/action_gallery/"+url.PathEscape(slug)+"/install", params, out, opts...)
}

// Installs lists the actions installed from the gallery, with update status.
// GET /v1/action_gallery_installs.
func (s *ActionGalleryService) Installs(ctx context.Context) (*ListPage[ActionGalleryInstallation], error) {
	out := &ListPage[ActionGalleryInstallation]{}
	return out, s.client.get(ctx, "/v1/action_gallery_installs", nil, out)
}

// Update moves an installed action to its template's latest version; secrets
// supplies any secret the new version requires.
// POST /v1/actions/:id/gallery_update.
func (s *ActionGalleryService) Update(ctx context.Context, actionID string, secrets map[string]string, opts ...RequestOption) (*ActionGalleryUpdateResult, error) {
	body := map[string]interface{}{}
	if len(secrets) > 0 {
		body["secrets"] = secrets
	}
	out := &ActionGalleryUpdateResult{}
	return out, s.client.post(ctx, "/v1/actions/"+url.PathEscape(actionID)+"/gallery_update", body, out, opts...)
}

// ActionTemplateVersion is one version of a template you publish. Status is
// draft, pending_review, approved or rejected; ReviewNote says why staff
// rejected it.
type ActionTemplateVersion struct {
	Object      string                 `json:"object"`
	Version     string                 `json:"version"`
	Status      string                 `json:"status"`
	Trigger     string                 `json:"trigger"`
	Secrets     []ActionTemplateSecret `json:"secrets"`
	Changelog   *string                `json:"changelog"`
	ReviewNote  *string                `json:"review_note"`
	Code        string                 `json:"code"`
	SubmittedAt *int64                 `json:"submitted_at"`
	ReviewedAt  *int64                 `json:"reviewed_at"`
	CreatedAt   int64                  `json:"created_at"`
	// Deleted is set on a version delete.
	Deleted bool `json:"deleted,omitempty"`
}

// ActionTemplate is a template this instance publishes. Status is draft,
// in_review, published, unlisted, rejected or banned.
type ActionTemplate struct {
	Object        string                  `json:"object"`
	ID            string                  `json:"id"`
	Slug          string                  `json:"slug"`
	Name          string                  `json:"name"`
	AuthorName    string                  `json:"author_name"`
	Summary       string                  `json:"summary"`
	Description   *string                 `json:"description"`
	Category      string                  `json:"category"`
	Tags          []string                `json:"tags"`
	Trigger       string                  `json:"trigger"`
	License       string                  `json:"license"`
	RepositoryURL *string                 `json:"repository_url"`
	Status        string                  `json:"status"`
	LatestVersion *string                 `json:"latest_version"`
	Verified      bool                    `json:"verified"`
	Featured      bool                    `json:"featured"`
	InstallCount  int64                   `json:"install_count"`
	ViewCount     int64                   `json:"view_count"`
	PublishedAt   *int64                  `json:"published_at"`
	CreatedAt     int64                   `json:"created_at"`
	UpdatedAt     int64                   `json:"updated_at"`
	Versions      []ActionTemplateVersion `json:"versions"`
}

// ActionTemplateParams is a template listing (create needs Slug, Name,
// AuthorName and Trigger). License is an SPDX id. On create the first
// version may come in the same call (Version, Code, Secrets, Changelog,
// Submit sends it to review).
type ActionTemplateParams struct {
	Slug          string                 `json:"slug,omitempty"`
	Name          string                 `json:"name,omitempty"`
	AuthorName    string                 `json:"author_name,omitempty"`
	Summary       string                 `json:"summary,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Category      string                 `json:"category,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Trigger       string                 `json:"trigger,omitempty"`
	License       string                 `json:"license,omitempty"`
	RepositoryURL string                 `json:"repository_url,omitempty"`
	Version       string                 `json:"version,omitempty"`
	Code          string                 `json:"code,omitempty"`
	Secrets       []ActionTemplateSecret `json:"secrets,omitempty"`
	Changelog     string                 `json:"changelog,omitempty"`
	Submit        bool                   `json:"submit,omitempty"`
}

// NewTemplateVersionParams adds a version: Version is MAJOR.MINOR.PATCH,
// higher than every existing one; Submit sends it to review right away.
type NewTemplateVersionParams struct {
	Version   string                 `json:"version"`
	Code      string                 `json:"code"`
	Secrets   []ActionTemplateSecret `json:"secrets,omitempty"`
	Changelog string                 `json:"changelog,omitempty"`
	Submit    bool                   `json:"submit,omitempty"`
}

func actionTemplatePath(id string) string { return "/v1/action_templates/" + url.PathEscape(id) }

// List returns your templates. GET /v1/action_templates.
func (s *ActionTemplatesService) List(ctx context.Context) (*ListPage[ActionTemplate], error) {
	out := &ListPage[ActionTemplate]{}
	return out, s.client.get(ctx, "/v1/action_templates", nil, out)
}

// Create creates a template. POST /v1/action_templates.
func (s *ActionTemplatesService) Create(ctx context.Context, params ActionTemplateParams, opts ...RequestOption) (*ActionTemplate, error) {
	out := &ActionTemplate{}
	return out, s.client.post(ctx, "/v1/action_templates", params, out, opts...)
}

// Get returns a template. GET /v1/action_templates/:id.
func (s *ActionTemplatesService) Get(ctx context.Context, id string) (*ActionTemplate, error) {
	out := &ActionTemplate{}
	return out, s.client.get(ctx, actionTemplatePath(id), nil, out)
}

// Update patches the listing. PATCH /v1/action_templates/:id.
func (s *ActionTemplatesService) Update(ctx context.Context, id string, params ActionTemplateParams, opts ...RequestOption) (*ActionTemplate, error) {
	out := &ActionTemplate{}
	return out, s.client.patch(ctx, actionTemplatePath(id), params, out, opts...)
}

// Delete deletes a template. DELETE /v1/action_templates/:id.
func (s *ActionTemplatesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, actionTemplatePath(id), out, opts...)
}

// AddVersion adds a version. POST /v1/action_templates/:id/versions.
func (s *ActionTemplatesService) AddVersion(ctx context.Context, id string, params NewTemplateVersionParams, opts ...RequestOption) (*ActionTemplateVersion, error) {
	out := &ActionTemplateVersion{}
	return out, s.client.post(ctx, actionTemplatePath(id)+"/versions", params, out, opts...)
}

// SubmitVersion sends a draft version to review.
// POST /v1/action_templates/:id/versions/:version/submit.
func (s *ActionTemplatesService) SubmitVersion(ctx context.Context, id, version string, opts ...RequestOption) (*ActionTemplateVersion, error) {
	out := &ActionTemplateVersion{}
	return out, s.client.post(ctx, actionTemplatePath(id)+"/versions/"+url.PathEscape(version)+"/submit", nil, out, opts...)
}

// DeleteVersion deletes a version.
// DELETE /v1/action_templates/:id/versions/:version.
func (s *ActionTemplatesService) DeleteVersion(ctx context.Context, id, version string, opts ...RequestOption) (*ActionTemplateVersion, error) {
	out := &ActionTemplateVersion{}
	return out, s.client.del(ctx, actionTemplatePath(id)+"/versions/"+url.PathEscape(version), out, opts...)
}

// Publish lists an approved template again after unlisting it.
// POST /v1/action_templates/:id/publish.
func (s *ActionTemplatesService) Publish(ctx context.Context, id string, opts ...RequestOption) (*ActionTemplate, error) {
	out := &ActionTemplate{}
	return out, s.client.post(ctx, actionTemplatePath(id)+"/publish", nil, out, opts...)
}

// Unlist hides a template from the gallery (installs keep working).
// POST /v1/action_templates/:id/unlist.
func (s *ActionTemplatesService) Unlist(ctx context.Context, id string, opts ...RequestOption) (*ActionTemplate, error) {
	out := &ActionTemplate{}
	return out, s.client.post(ctx, actionTemplatePath(id)+"/unlist", nil, out, opts...)
}
