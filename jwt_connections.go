package atlas

import (
	"context"
	"net/url"
)

// JWTConnectionsService is the /v1/jwt_connections namespace: trusted-JWT
// connections. Your system signs a short-lived JWT and sends the person to
// the connection's LoginURL.
type JWTConnectionsService struct{ client *Client }

// JWTConnection is a trusted-JWT connection. Status is draft, active or
// disabled.
type JWTConnection struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	OrganizationID *string `json:"organization_id"`
	Status         string  `json:"status"`
	JWKSURI        *string `json:"jwks_uri"`
	Issuer         *string `json:"issuer"`
	Audience       *string `json:"audience"`
	EmailClaim     string  `json:"email_claim"`
	MaxAgeSeconds  int     `json:"max_age_seconds"`
	DefaultRoleID  *string `json:"default_role_id"`
	// LoginURL: send the person here with ?token=<jwt>&redirect_url=<your app URL>.
	LoginURL  string `json:"login_url"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// JWTConnectionParams is the body of create (POST) and update (PATCH). On
// update only the fields you set change.
type JWTConnectionParams struct {
	OrganizationID *string `json:"organization_id,omitempty"`
	Status         string  `json:"status,omitempty"`
	// JWKSURI is an https URL serving your public signing keys (RS / PS / ES / EdDSA).
	JWKSURI  string `json:"jwks_uri,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	// EmailClaim defaults to email.
	EmailClaim string `json:"email_claim,omitempty"`
	// MaxAgeSeconds bounds exp − iat: 30–3600, default 300.
	MaxAgeSeconds *int    `json:"max_age_seconds,omitempty"`
	DefaultRoleID *string `json:"default_role_id,omitempty"`
}

// List returns the trusted-JWT connections. GET /v1/jwt_connections.
func (s *JWTConnectionsService) List(ctx context.Context) (*ListPage[JWTConnection], error) {
	out := &ListPage[JWTConnection]{}
	return out, s.client.get(ctx, "/v1/jwt_connections", nil, out)
}

// Get returns one connection. GET /v1/jwt_connections/:id.
func (s *JWTConnectionsService) Get(ctx context.Context, id string) (*JWTConnection, error) {
	out := &JWTConnection{}
	return out, s.client.get(ctx, "/v1/jwt_connections/"+url.PathEscape(id), nil, out)
}

// Create creates a connection. POST /v1/jwt_connections.
func (s *JWTConnectionsService) Create(ctx context.Context, params JWTConnectionParams, opts ...RequestOption) (*JWTConnection, error) {
	out := &JWTConnection{}
	return out, s.client.post(ctx, "/v1/jwt_connections", params, out, opts...)
}

// Update patches a connection. PATCH /v1/jwt_connections/:id.
func (s *JWTConnectionsService) Update(ctx context.Context, id string, params JWTConnectionParams, opts ...RequestOption) (*JWTConnection, error) {
	out := &JWTConnection{}
	return out, s.client.patch(ctx, "/v1/jwt_connections/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes a connection. DELETE /v1/jwt_connections/:id.
func (s *JWTConnectionsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/jwt_connections/"+url.PathEscape(id), out, opts...)
}

// JWTSignInURL is where to send the person's browser to sign in with a trusted
// JWT (GET /v1/sso/jwt/:connectionId). loginURL is the connection's LoginURL. A
// URL, not an API call: the token works once, and the 302 carries a one-time
// ticket that has to reach the browser.
func JWTSignInURL(loginURL, token, redirectURL string) (string, error) {
	u, err := url.Parse(loginURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("token", token)
	q.Set("redirect_url", redirectURL)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
