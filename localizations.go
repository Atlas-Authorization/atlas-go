package atlas

import (
	"context"
	"net/url"
)

// LocalizationsService is the /v1/localizations namespace — per-locale overrides
// the render paths resolve at send/render time. Timestamps are ISO strings.
type LocalizationsService struct{ client *Client }

// Localization is a per-locale override row.
type Localization struct {
	Object       string                 `json:"object"`
	ID           string                 `json:"id"`
	ResourceType string                 `json:"resource_type"`
	ResourceName string                 `json:"resource_name"`
	Locale       string                 `json:"locale"`
	Content      map[string]interface{} `json:"content"`
	Enabled      bool                   `json:"enabled"`
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
}

// ListLocalizationsParams filters the list. GET /v1/localizations.
type ListLocalizationsParams struct {
	ResourceType string
	ResourceName string
	Locale       string
}

func (p ListLocalizationsParams) values() url.Values {
	v := url.Values{}
	if p.ResourceType != "" {
		v.Set("resource_type", p.ResourceType)
	}
	if p.ResourceName != "" {
		v.Set("resource_name", p.ResourceName)
	}
	if p.Locale != "" {
		v.Set("locale", p.Locale)
	}
	return v
}

// CreateLocalizationParams is the body of POST /v1/localizations.
type CreateLocalizationParams struct {
	ResourceType string                 `json:"resource_type"`
	ResourceName string                 `json:"resource_name"`
	Locale       string                 `json:"locale"`
	Content      map[string]interface{} `json:"content"`
	Enabled      *bool                  `json:"enabled,omitempty"`
}

// UpdateLocalizationParams is the body of PATCH /v1/localizations/:id.
type UpdateLocalizationParams struct {
	Content map[string]interface{} `json:"content,omitempty"`
	Enabled *bool                  `json:"enabled,omitempty"`
}

// List returns localization rows. GET /v1/localizations.
func (s *LocalizationsService) List(ctx context.Context, params ListLocalizationsParams) (*ListPage[Localization], error) {
	out := &ListPage[Localization]{}
	return out, s.client.get(ctx, "/v1/localizations", params.values(), out)
}

// Create creates a localization row. POST /v1/localizations.
func (s *LocalizationsService) Create(ctx context.Context, params CreateLocalizationParams, opts ...RequestOption) (*Localization, error) {
	out := &Localization{}
	return out, s.client.post(ctx, "/v1/localizations", params, out, opts...)
}

// Get returns one row. GET /v1/localizations/:id.
func (s *LocalizationsService) Get(ctx context.Context, id string) (*Localization, error) {
	out := &Localization{}
	return out, s.client.get(ctx, "/v1/localizations/"+url.PathEscape(id), nil, out)
}

// Update patches a row. PATCH /v1/localizations/:id.
func (s *LocalizationsService) Update(ctx context.Context, id string, params UpdateLocalizationParams) (*Localization, error) {
	out := &Localization{}
	return out, s.client.patch(ctx, "/v1/localizations/"+url.PathEscape(id), params, out)
}

// Delete removes a row. DELETE /v1/localizations/:id.
func (s *LocalizationsService) Delete(ctx context.Context, id string) error {
	return s.client.del(ctx, "/v1/localizations/"+url.PathEscape(id), nil)
}
