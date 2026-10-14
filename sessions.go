package atlas

import (
	"context"
	"net/url"
)

// SessionsService is the /v1/sessions namespace.
type SessionsService struct{ client *Client }

// Session is a session as the BAPI serves it.
type Session struct {
	Object                   string  `json:"object"`
	ID                       string  `json:"id"`
	UserID                   string  `json:"user_id"`
	Status                   string  `json:"status"`
	LastActiveOrganizationID *string `json:"last_active_organization_id"`
	ImpersonatedBy           *string `json:"impersonated_by"`
	LastActiveAt             int64   `json:"last_active_at"`
	ExpireAt                 int64   `json:"expire_at"`
	AbandonAt                int64   `json:"abandon_at"`
	// IdleExpiresAt is epoch ms when the session ends from inactivity unless
	// there is activity first (same value as AbandonAt).
	IdleExpiresAt int64 `json:"idle_expires_at,omitempty"`
	CreatedAt     int64 `json:"created_at"`
}

// TouchedSession is the session after a keep-alive touch.
type TouchedSession struct {
	Session
	// Extended is true when this touch moved the inactivity window; false when
	// a touch within the last 60 seconds already had.
	Extended bool `json:"extended"`
}

// Touch keeps a session alive from your backend: it slides the inactivity
// window as if the user had just loaded a page. It never extends past the
// absolute expiry and never revives an ended session (409 SESSION_REVOKED,
// SESSION_IDLE_EXPIRED or SESSION_EXPIRED). At most one effective write per
// minute, so calling it on every request is safe. POST /v1/sessions/:id/touch.
func (s *SessionsService) Touch(ctx context.Context, id string, opts ...RequestOption) (*TouchedSession, error) {
	out := &TouchedSession{}
	return out, s.client.post(ctx, "/v1/sessions/"+url.PathEscape(id)+"/touch", nil, out, opts...)
}

// RevokeSessionResult is the acknowledgement of a single session revoke.
type RevokeSessionResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// SessionActor records who is acting as the user in an impersonated session.
type SessionActor struct {
	Sub string `json:"sub"`
}

// CreateSessionParams is the body of POST /v1/sessions.
type CreateSessionParams struct {
	UserID string        `json:"user_id"`
	Actor  *SessionActor `json:"actor,omitempty"`
}

// MintedSession is a freshly-minted session. Unlike a listed Session it carries
// the bearer JWT and refresh token in-body, returned by design for headless use.
type MintedSession struct {
	Object         string        `json:"object"`
	ID             string        `json:"id"`
	UserID         string        `json:"user_id"`
	JWT            string        `json:"jwt"`
	RefreshToken   string        `json:"refresh_token"`
	ExpiresIn      int64         `json:"expires_in"`
	ImpersonatedBy *SessionActor `json:"impersonated_by,omitempty"`
}

// Create mints a session for a user without the sign-in flow. POST /v1/sessions.
// Returns the bearer JWT + refresh token in-body. Refused for a banned user.
func (s *SessionsService) Create(ctx context.Context, params CreateSessionParams, opts ...RequestOption) (*MintedSession, error) {
	out := &MintedSession{}
	return out, s.client.post(ctx, "/v1/sessions", params, out, opts...)
}

// List returns the sessions for one user. GET /v1/sessions?user_id=. The BAPI
// requires a user_id.
func (s *SessionsService) List(ctx context.Context, userID string) (*ListPage[Session], error) {
	out := &ListPage[Session]{}
	q := url.Values{}
	q.Set("user_id", userID)
	return out, s.client.get(ctx, "/v1/sessions", q, out)
}

// Get fetches a single session. GET /v1/sessions/:id.
func (s *SessionsService) Get(ctx context.Context, id string) (*Session, error) {
	out := &Session{}
	return out, s.client.get(ctx, "/v1/sessions/"+url.PathEscape(id), nil, out)
}

// Revoke revokes a session. POST /v1/sessions/:id/revoke.
func (s *SessionsService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*RevokeSessionResult, error) {
	out := &RevokeSessionResult{}
	return out, s.client.post(ctx, "/v1/sessions/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}
