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
	// CustomData is the custom per-session data your backend (or a post_login
	// Action) attached; nil when none.
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
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
	// CustomData attaches custom per-session data (a JSON object, at most 2 KB).
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
	// Mode is session (the default) or browser_ticket. With browser_ticket the
	// response is a BrowserTicket, not a MintedSession: use CreateBrowserTicket.
	Mode string `json:"mode,omitempty"`
	// RedirectURL and ExpiresInSeconds apply to mode browser_ticket.
	RedirectURL      string `json:"redirect_url,omitempty"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

// Session create modes.
const (
	SessionModeSession       = "session"
	SessionModeBrowserTicket = "browser_ticket"
)

// CreateBrowserTicketParams is the input of CreateBrowserTicket.
type CreateBrowserTicketParams struct {
	// UserID is the user the browser signs in as.
	UserID string
	// RedirectURL is where the ready URL lands (one of the instance's allowed
	// origins). Without it the response has no URL.
	RedirectURL string
	// ExpiresInSeconds is the ticket lifetime, 1 to 300 (0 = the default 60).
	ExpiresInSeconds int
}

// BrowserTicket is a one-time browser sign-in ticket. Redeem Ticket with
// POST /v1/client/sign_ins {strategy:"ticket"}, or open URL in the browser.
// On development instances only, the exchange of one ticket is replayable by
// the same client for 10 seconds.
type BrowserTicket struct {
	// Object is browser_ticket (testing_sign_in_url from
	// TestingService.CreateSignInURL).
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	Ticket      string  `json:"ticket"`
	URL         *string `json:"url"`
	RedirectURL *string `json:"redirect_url"`
	ExpiresIn   int     `json:"expires_in"`
	// ExpiresAt is ISO 8601.
	ExpiresAt string `json:"expires_at"`
}

// MintedSession is a freshly-minted session. Unlike a listed Session it carries
// the bearer JWT and refresh token in-body, returned by design for headless use.
type MintedSession struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	JWT            string                 `json:"jwt"`
	RefreshToken   string                 `json:"refresh_token"`
	ExpiresIn      int64                  `json:"expires_in"`
	ImpersonatedBy *SessionActor          `json:"impersonated_by,omitempty"`
	CustomData     map[string]interface{} `json:"custom_data,omitempty"`
}

// Create mints a session for a user without the sign-in flow. POST /v1/sessions.
// Returns the bearer JWT + refresh token in-body. Refused for a banned user.
func (s *SessionsService) Create(ctx context.Context, params CreateSessionParams, opts ...RequestOption) (*MintedSession, error) {
	out := &MintedSession{}
	return out, s.client.post(ctx, "/v1/sessions", params, out, opts...)
}

// CreateBrowserTicket mints a one-time ticket that signs a browser in as the
// user (support handoffs, E2E). No session is minted here. Successor of
// SignInTokensService.Create. POST /v1/sessions with mode browser_ticket.
func (s *SessionsService) CreateBrowserTicket(ctx context.Context, params CreateBrowserTicketParams, opts ...RequestOption) (*BrowserTicket, error) {
	out := &BrowserTicket{}
	body := CreateSessionParams{UserID: params.UserID, Mode: SessionModeBrowserTicket, RedirectURL: params.RedirectURL, ExpiresInSeconds: params.ExpiresInSeconds}
	return out, s.client.post(ctx, "/v1/sessions", body, out, opts...)
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

// SetCustomData replaces a session's custom data (nil clears it). At most
// 2 KB; only an active session can be changed. Not for secrets: the signed-in
// user can read it. Sends the session.updated webhook.
// PUT /v1/sessions/:id/custom_data.
func (s *SessionsService) SetCustomData(ctx context.Context, id string, data map[string]interface{}, opts ...RequestOption) (*Session, error) {
	out := &Session{}
	body := map[string]interface{}{"custom_data": data}
	return out, s.client.put(ctx, "/v1/sessions/"+url.PathEscape(id)+"/custom_data", body, out, opts...)
}

// UpdateCustomData merges keys into a session's custom data; a key set to nil
// is removed. PATCH /v1/sessions/:id/custom_data.
func (s *SessionsService) UpdateCustomData(ctx context.Context, id string, patch map[string]interface{}, opts ...RequestOption) (*Session, error) {
	out := &Session{}
	body := map[string]interface{}{"custom_data": patch}
	return out, s.client.patch(ctx, "/v1/sessions/"+url.PathEscape(id)+"/custom_data", body, out, opts...)
}
