package atlas

import (
	"context"
	"net/url"
)

// JWTTemplatesService is the /v1/jwt_templates namespace. Templates are keyed by
// name.
type JWTTemplatesService struct{ client *Client }

// JwtTemplate is a named claim template.
type JwtTemplate struct {
	Object string            `json:"object"`
	Name   string            `json:"name"`
	Claims map[string]string `json:"claims"`
}

// CreateJwtTemplateParams is the body of POST /v1/jwt_templates.
type CreateJwtTemplateParams struct {
	Name   string            `json:"name"`
	Claims map[string]string `json:"claims"`
}

// JwtTemplateDeleteResult is the acknowledgement of a delete.
type JwtTemplateDeleteResult struct {
	Object  string `json:"object"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

// List returns all JWT templates. GET /v1/jwt_templates.
func (s *JWTTemplatesService) List(ctx context.Context) (*ListPage[JwtTemplate], error) {
	out := &ListPage[JwtTemplate]{}
	return out, s.client.get(ctx, "/v1/jwt_templates", nil, out)
}

// Get fetches a template by name. GET /v1/jwt_templates/:name.
func (s *JWTTemplatesService) Get(ctx context.Context, name string) (*JwtTemplate, error) {
	out := &JwtTemplate{}
	return out, s.client.get(ctx, "/v1/jwt_templates/"+url.PathEscape(name), nil, out)
}

// Create creates a JWT template. POST /v1/jwt_templates.
func (s *JWTTemplatesService) Create(ctx context.Context, params CreateJwtTemplateParams, opts ...RequestOption) (*JwtTemplate, error) {
	out := &JwtTemplate{}
	return out, s.client.post(ctx, "/v1/jwt_templates", params, out, opts...)
}

// Update replaces a template's claims (the name is the key).
// PATCH /v1/jwt_templates/:name.
func (s *JWTTemplatesService) Update(ctx context.Context, name string, claims map[string]string) (*JwtTemplate, error) {
	out := &JwtTemplate{}
	body := map[string]map[string]string{"claims": claims}
	return out, s.client.patch(ctx, "/v1/jwt_templates/"+url.PathEscape(name), body, out)
}

// Delete removes a JWT template. DELETE /v1/jwt_templates/:name.
func (s *JWTTemplatesService) Delete(ctx context.Context, name string) (*JwtTemplateDeleteResult, error) {
	out := &JwtTemplateDeleteResult{}
	return out, s.client.del(ctx, "/v1/jwt_templates/"+url.PathEscape(name), out)
}
