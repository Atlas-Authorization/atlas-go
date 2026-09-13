package atlas

import (
	"context"
	"net/url"
)

// LTIPlatformsService is the /v1/lti_platforms namespace — LTI 1.3 platform (LMS)
// registrations. Every field is a public trust anchor, so there is no
// reveal-once.
type LTIPlatformsService struct{ client *Client }

// LTIPlatform is an LTI 1.3 platform registration.
type LTIPlatform struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	OrganizationID *string  `json:"organization_id"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	AuthLoginURL   string   `json:"auth_login_url"`
	JWKSURI        string   `json:"jwks_uri"`
	DeploymentIDs  []string `json:"deployment_ids"`
	CreatedAt      int64    `json:"created_at"`
	UpdatedAt      int64    `json:"updated_at"`
}

// CreateLTIPlatformParams is the body of POST /v1/lti_platforms.
type CreateLTIPlatformParams struct {
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	AuthLoginURL   string   `json:"auth_login_url"`
	JWKSURI        string   `json:"jwks_uri"`
	DeploymentIDs  []string `json:"deployment_ids"`
	OrganizationID string   `json:"organization_id,omitempty"`
}

// UpdateLTIPlatformParams is the body of PATCH /v1/lti_platforms/:id.
type UpdateLTIPlatformParams struct {
	AuthLoginURL  string   `json:"auth_login_url,omitempty"`
	JWKSURI       string   `json:"jwks_uri,omitempty"`
	DeploymentIDs []string `json:"deployment_ids,omitempty"`
	// OrganizationID: pass a pointer to null (via the map form) to unbind. Use a
	// non-empty string to bind.
	OrganizationID *string `json:"organization_id,omitempty"`
}

// List returns the LTI platforms. GET /v1/lti_platforms.
func (s *LTIPlatformsService) List(ctx context.Context) (*ListPage[LTIPlatform], error) {
	out := &ListPage[LTIPlatform]{}
	return out, s.client.get(ctx, "/v1/lti_platforms", nil, out)
}

// Get returns one platform. GET /v1/lti_platforms/:id.
func (s *LTIPlatformsService) Get(ctx context.Context, id string) (*LTIPlatform, error) {
	out := &LTIPlatform{}
	return out, s.client.get(ctx, "/v1/lti_platforms/"+url.PathEscape(id), nil, out)
}

// Create creates a platform. POST /v1/lti_platforms.
func (s *LTIPlatformsService) Create(ctx context.Context, params CreateLTIPlatformParams, opts ...RequestOption) (*LTIPlatform, error) {
	out := &LTIPlatform{}
	return out, s.client.post(ctx, "/v1/lti_platforms", params, out, opts...)
}

// Update patches a platform. PATCH /v1/lti_platforms/:id.
func (s *LTIPlatformsService) Update(ctx context.Context, id string, params UpdateLTIPlatformParams) (*LTIPlatform, error) {
	out := &LTIPlatform{}
	return out, s.client.patch(ctx, "/v1/lti_platforms/"+url.PathEscape(id), params, out)
}

// Delete removes a platform. DELETE /v1/lti_platforms/:id.
func (s *LTIPlatformsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/lti_platforms/"+url.PathEscape(id), out)
}
