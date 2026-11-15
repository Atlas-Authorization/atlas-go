package atlas

import (
	"context"
	"encoding/json"
	"net/url"
)

// JWTTemplateSettings are a template's mint settings as the API reads them
// back. LifetimeSeconds and Audience are nil when the instance default applies.
type JWTTemplateSettings struct {
	LifetimeSeconds *int64  `json:"lifetime_seconds"`
	Audience        *string `json:"audience"`
	// Algorithm is RS256 or HS256.
	Algorithm string `json:"algorithm"`
	// HasSigningSecret is true when an HS256 shared secret is stored (it is
	// never returned).
	HasSigningSecret bool `json:"has_signing_secret"`
}

// JWTTemplateWithSettings is a JWT template with its mint settings.
type JWTTemplateWithSettings struct {
	Object   string              `json:"object"`
	Name     string              `json:"name"`
	Claims   map[string]string   `json:"claims"`
	Settings JWTTemplateSettings `json:"settings"`
}

// JWTTemplateSettingsInput sets a template's mint settings. Nil fields are left
// as they are; ClearLifetime and ClearAudience send null to go back to the
// instance default. LifetimeSeconds is 10 to 86400.
type JWTTemplateSettingsInput struct {
	LifetimeSeconds *int64
	ClearLifetime   bool
	Audience        *string
	ClearAudience   bool
	// Algorithm is RS256 or HS256 ("" leaves it).
	Algorithm string
	// SigningSecret is the HS256 shared secret, at least 16 characters. Write-only.
	SigningSecret string
}

// MarshalJSON sends only the fields that are set.
func (s JWTTemplateSettingsInput) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	switch {
	case s.ClearLifetime:
		m["lifetime_seconds"] = nil
	case s.LifetimeSeconds != nil:
		m["lifetime_seconds"] = *s.LifetimeSeconds
	}
	switch {
	case s.ClearAudience:
		m["audience"] = nil
	case s.Audience != nil:
		m["audience"] = *s.Audience
	}
	if s.Algorithm != "" {
		m["algorithm"] = s.Algorithm
	}
	if s.SigningSecret != "" {
		m["signing_secret"] = s.SigningSecret
	}
	return json.Marshal(m)
}

// CreateJWTTemplateWithSettingsParams is the body of POST /v1/jwt_templates with
// mint settings.
type CreateJWTTemplateWithSettingsParams struct {
	Name     string                    `json:"name"`
	Claims   map[string]string         `json:"claims"`
	Settings *JWTTemplateSettingsInput `json:"settings,omitempty"`
}

// UpdateJWTTemplateParams is the body of PATCH /v1/jwt_templates/:name: claims,
// settings, or both. The name is the key and cannot change.
type UpdateJWTTemplateParams struct {
	Claims   map[string]string         `json:"claims,omitempty"`
	Settings *JWTTemplateSettingsInput `json:"settings,omitempty"`
}

// CreateWithSettings creates a template with its mint settings.
// POST /v1/jwt_templates.
func (s *JWTTemplatesService) CreateWithSettings(ctx context.Context, params CreateJWTTemplateWithSettingsParams, opts ...RequestOption) (*JWTTemplateWithSettings, error) {
	out := &JWTTemplateWithSettings{}
	return out, s.client.post(ctx, "/v1/jwt_templates", params, out, opts...)
}

// GetWithSettings fetches a template with its mint settings.
// GET /v1/jwt_templates/:name.
func (s *JWTTemplatesService) GetWithSettings(ctx context.Context, name string) (*JWTTemplateWithSettings, error) {
	out := &JWTTemplateWithSettings{}
	return out, s.client.get(ctx, "/v1/jwt_templates/"+url.PathEscape(name), nil, out)
}

// ListWithSettings returns every template with its mint settings.
// GET /v1/jwt_templates.
func (s *JWTTemplatesService) ListWithSettings(ctx context.Context) (*ListPage[JWTTemplateWithSettings], error) {
	out := &ListPage[JWTTemplateWithSettings]{}
	return out, s.client.get(ctx, "/v1/jwt_templates", nil, out)
}

// UpdateWithSettings changes a template's claims and/or mint settings.
// PATCH /v1/jwt_templates/:name.
func (s *JWTTemplatesService) UpdateWithSettings(ctx context.Context, name string, params UpdateJWTTemplateParams, opts ...RequestOption) (*JWTTemplateWithSettings, error) {
	out := &JWTTemplateWithSettings{}
	return out, s.client.patch(ctx, "/v1/jwt_templates/"+url.PathEscape(name), params, out, opts...)
}
