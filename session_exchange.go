package atlas

import (
	"context"
	"net/url"
)

// SessionExchangeAppsService is /v1/session_exchange_apps: downstream apps that
// exchange an Atlas session for their own, and receive a signed back-channel
// logout_token when the Atlas session ends.
type SessionExchangeAppsService struct{ client *Client }

// SessionExchangeApp is a registered session-exchange app.
type SessionExchangeApp struct {
	Object               string `json:"object"`
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	BackchannelLogoutURI string `json:"backchannel_logout_uri"`
	// Audience is the aud claim the logout_token carries.
	Audience  string `json:"audience"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// CreateSessionExchangeAppParams is the body of POST /v1/session_exchange_apps.
type CreateSessionExchangeAppParams struct {
	Name string `json:"name"`
	// BackchannelLogoutURI is a public https endpoint.
	BackchannelLogoutURI string `json:"backchannel_logout_uri"`
	// Audience overrides the logout_token aud (defaults to the app id).
	Audience string `json:"audience,omitempty"`
}

// UpdateSessionExchangeAppParams is the body of PATCH /v1/session_exchange_apps/:id.
// Nil fields are left unchanged; ClearAudience resets the audience to the
// default (the app id).
type UpdateSessionExchangeAppParams struct {
	Name                 *string
	BackchannelLogoutURI *string
	Audience             *string
	ClearAudience        bool
}

func (p UpdateSessionExchangeAppParams) body() map[string]interface{} {
	b := map[string]interface{}{}
	if p.Name != nil {
		b["name"] = *p.Name
	}
	if p.BackchannelLogoutURI != nil {
		b["backchannel_logout_uri"] = *p.BackchannelLogoutURI
	}
	if p.Audience != nil {
		b["audience"] = *p.Audience
	}
	if p.ClearAudience {
		b["audience"] = nil
	}
	return b
}

// List lists session-exchange apps. GET /v1/session_exchange_apps.
func (s *SessionExchangeAppsService) List(ctx context.Context) (*CursorPage[SessionExchangeApp], error) {
	out := &CursorPage[SessionExchangeApp]{}
	return out, s.client.get(ctx, "/v1/session_exchange_apps", nil, out)
}

// Create registers a session-exchange app. POST /v1/session_exchange_apps.
func (s *SessionExchangeAppsService) Create(ctx context.Context, params CreateSessionExchangeAppParams, opts ...RequestOption) (*SessionExchangeApp, error) {
	out := &SessionExchangeApp{}
	return out, s.client.post(ctx, "/v1/session_exchange_apps", params, out, opts...)
}

// Get fetches one session-exchange app. GET /v1/session_exchange_apps/:id.
func (s *SessionExchangeAppsService) Get(ctx context.Context, id string) (*SessionExchangeApp, error) {
	out := &SessionExchangeApp{}
	return out, s.client.get(ctx, "/v1/session_exchange_apps/"+url.PathEscape(id), nil, out)
}

// Update changes an app's name, logout URI or audience.
// PATCH /v1/session_exchange_apps/:id.
func (s *SessionExchangeAppsService) Update(ctx context.Context, id string, params UpdateSessionExchangeAppParams, opts ...RequestOption) (*SessionExchangeApp, error) {
	out := &SessionExchangeApp{}
	return out, s.client.patch(ctx, "/v1/session_exchange_apps/"+url.PathEscape(id), params.body(), out, opts...)
}

// Delete deletes a session-exchange app. DELETE /v1/session_exchange_apps/:id.
func (s *SessionExchangeAppsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/session_exchange_apps/"+url.PathEscape(id), out, opts...)
}

// SessionTemplateToken is a JWT minted from a named JWT template.
type SessionTemplateToken struct {
	Object    string `json:"object"`
	JWT       string `json:"jwt"`
	ExpiresIn int    `json:"expires_in"`
}

// CreateTemplateToken mints a named JWT-template token for a session (the
// reserved name "session" is refused). POST /v1/sessions/:id/tokens/:template.
func (s *SessionsService) CreateTemplateToken(ctx context.Context, id, template string, opts ...RequestOption) (*SessionTemplateToken, error) {
	out := &SessionTemplateToken{}
	return out, s.client.post(ctx, "/v1/sessions/"+url.PathEscape(id)+"/tokens/"+url.PathEscape(template), nil, out, opts...)
}

// RedirectURLsService is /v1/redirect_urls: the allowlisted OAuth/SSO
// redirect URLs.
type RedirectURLsService struct{ client *Client }

// RedirectURL is one allowlisted redirect URL.
type RedirectURL struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	URL       string `json:"url"`
	CreatedAt int64  `json:"created_at"`
}

// List lists the allowlisted redirect URLs. GET /v1/redirect_urls.
func (s *RedirectURLsService) List(ctx context.Context) (*CursorPage[RedirectURL], error) {
	out := &CursorPage[RedirectURL]{}
	return out, s.client.get(ctx, "/v1/redirect_urls", nil, out)
}

// Create adds a redirect URL (idempotent on the URL). POST /v1/redirect_urls.
func (s *RedirectURLsService) Create(ctx context.Context, redirectURL string, opts ...RequestOption) (*RedirectURL, error) {
	out := &RedirectURL{}
	body := map[string]string{"url": redirectURL}
	return out, s.client.post(ctx, "/v1/redirect_urls", body, out, opts...)
}

// Get fetches one redirect URL. GET /v1/redirect_urls/:id.
func (s *RedirectURLsService) Get(ctx context.Context, id string) (*RedirectURL, error) {
	out := &RedirectURL{}
	return out, s.client.get(ctx, "/v1/redirect_urls/"+url.PathEscape(id), nil, out)
}

// Delete removes a redirect URL. DELETE /v1/redirect_urls/:id.
func (s *RedirectURLsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/redirect_urls/"+url.PathEscape(id), out, opts...)
}

// TicketsService is /v1/tickets: one-time capability tickets.
type TicketsService struct{ client *Client }

// CreateTicketParams is the body of POST /v1/tickets.
type CreateTicketParams struct {
	// Payload is arbitrary JSON returned to whoever redeems the ticket.
	Payload interface{} `json:"payload,omitempty"`
	// TTLSeconds is the lifetime, clamped to 86400.
	TTLSeconds int `json:"ttl_seconds"`
	// SingleUse defaults to true server-side.
	SingleUse *bool  `json:"single_use,omitempty"`
	BoundUser string `json:"bound_user,omitempty"`
	BoundOrg  string `json:"bound_org,omitempty"`
}

// Ticket is a minted ticket; Ticket (the tkt_ secret) is returned only here.
type Ticket struct {
	Object    string  `json:"object"`
	ID        string  `json:"id"`
	Ticket    string  `json:"ticket"`
	SingleUse bool    `json:"single_use"`
	BoundUser *string `json:"bound_user"`
	BoundOrg  *string `json:"bound_org"`
	CreatedAt int64   `json:"created_at"`
	ExpiresAt int64   `json:"expires_at"`
}

// RedeemTicketParams is the body of POST /v1/tickets/redeem.
type RedeemTicketParams struct {
	Ticket  string `json:"ticket"`
	ForUser string `json:"for_user,omitempty"`
	ForOrg  string `json:"for_org,omitempty"`
}

// TicketRedemption is a redeemed ticket's payload.
type TicketRedemption struct {
	Object    string      `json:"object"`
	ID        string      `json:"id"`
	Payload   interface{} `json:"payload"`
	SingleUse bool        `json:"single_use"`
}

// Create mints a capability ticket. POST /v1/tickets.
func (s *TicketsService) Create(ctx context.Context, params CreateTicketParams, opts ...RequestOption) (*Ticket, error) {
	out := &Ticket{}
	return out, s.client.post(ctx, "/v1/tickets", params, out, opts...)
}

// Redeem redeems a ticket server-to-server and returns its payload. An
// expired, already-redeemed or unknown ticket is a 404. POST /v1/tickets/redeem.
func (s *TicketsService) Redeem(ctx context.Context, params RedeemTicketParams, opts ...RequestOption) (*TicketRedemption, error) {
	out := &TicketRedemption{}
	return out, s.client.post(ctx, "/v1/tickets/redeem", params, out, opts...)
}
