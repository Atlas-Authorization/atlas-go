package atlas

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---- the session cookie -----------------------------------------------------

// RPSession is the signed-in user the relying party keeps in its session
// cookie. The cookie is signed (HMAC-SHA256), not encrypted: it carries the
// identity claims below, never a token unless StoreIDToken is on.
type RPSession struct {
	Sub           string `json:"sub"`
	SID           string `json:"sid,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	ExternalID    string `json:"external_id,omitempty"`
	OrgID         string `json:"org_id,omitempty"`
	OrgRole       string `json:"org_role,omitempty"`
	// AuthTime is when the user last authenticated, epoch seconds.
	AuthTime int64 `json:"auth_time,omitempty"`
	// IDToken is set only with RPConfig.StoreIDToken.
	IDToken string `json:"id_token,omitempty"`
	// LastTouchedAt is when the Atlas session was last kept alive, epoch milliseconds.
	LastTouchedAt int64 `json:"touched_at,omitempty"`
	// IssuedAt and ExpiresAt are epoch seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

const rpSessionPrefix = "v1."

// rpMaxCookieValue keeps a session cookie under what browsers accept.
const rpMaxCookieValue = 3800

// NewSession builds the session for a verified sign-in (the lifetime is SessionMaxAge).
func (rp *RelyingParty) NewSession(result *RPCallbackResult) *RPSession {
	now := rp.now()
	s := &RPSession{
		Sub: result.User.Sub, SID: result.User.SID, Email: result.User.Email, EmailVerified: result.User.EmailVerified,
		Name: result.User.Name, ExternalID: result.User.ExternalID, OrgID: result.User.OrgID, OrgRole: result.User.OrgRole,
		AuthTime: result.User.AuthTime, LastTouchedAt: now.UnixMilli(),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(rp.cfg.SessionMaxAge).Unix(),
	}
	if rp.cfg.StoreIDToken {
		s.IDToken = result.Tokens.IDToken
	}
	return s
}

func rpSign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return rpB64(mac.Sum(nil))
}

// SealSession signs a session into a cookie value with the first session secret.
func (rp *RelyingParty) SealSession(s *RPSession) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	body := rpSessionPrefix + rpB64(payload)
	value := body + "." + rpSign(rp.cfg.SessionSecrets[0], body)
	if len(value) > rpMaxCookieValue {
		return "", rpErr(RPErrInvalidSession, "the session is too large for a cookie (%d bytes); turn off StoreIDToken", len(value))
	}
	return value, nil
}

// OpenSession verifies a cookie value against every session secret (so a
// rotated secret keeps working) and checks its expiry. The error is an *RPError
// with code invalid_session.
func (rp *RelyingParty) OpenSession(value string) (*RPSession, error) {
	bad := func(why string) error { return rpErr(RPErrInvalidSession, "%s", why) }
	i := strings.LastIndex(value, ".")
	if i < 0 || !strings.HasPrefix(value, rpSessionPrefix) {
		return nil, bad("the session cookie is malformed")
	}
	body, sig := value[:i], value[i+1:]
	ok := false
	for _, secret := range rp.cfg.SessionSecrets {
		// Every secret is tried (no early exit) so the match position does not leak.
		if hmac.Equal([]byte(rpSign(secret, body)), []byte(sig)) {
			ok = true
		}
	}
	if !ok {
		return nil, bad("the session cookie signature does not verify")
	}
	raw, err := base64urlDecode(strings.TrimPrefix(body, rpSessionPrefix))
	if err != nil {
		return nil, bad("the session cookie is malformed")
	}
	var s RPSession
	if json.Unmarshal(raw, &s) != nil || s.Sub == "" {
		return nil, bad("the session cookie is malformed")
	}
	if rp.now().Unix() >= s.ExpiresAt {
		return nil, bad("the session has expired")
	}
	if rp.sidRevoked(s.SID) {
		return nil, bad("the session was ended by a back-channel logout")
	}
	return &s, nil
}

// SessionCookie returns the Set-Cookie for a session: HttpOnly, SameSite=Lax,
// Secure when the redirect URI is https, expiring with the session.
func (rp *RelyingParty) SessionCookie(s *RPSession) (*http.Cookie, error) {
	value, err := rp.SealSession(s)
	if err != nil {
		return nil, err
	}
	maxAge := int(s.ExpiresAt - rp.now().Unix())
	if maxAge < 1 {
		maxAge = 1
	}
	return &http.Cookie{
		Name: rp.cfg.SessionCookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: rp.secureCookie, SameSite: http.SameSiteLaxMode,
	}, nil
}

// ClearSessionCookie returns the Set-Cookie that removes the session cookie.
func (rp *RelyingParty) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name: rp.cfg.SessionCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: rp.secureCookie, SameSite: http.SameSiteLaxMode,
	}
}

// SessionFromRequest reads and verifies the session cookie of a request. A
// missing cookie is an *RPError with code invalid_session too.
func (rp *RelyingParty) SessionFromRequest(r *http.Request) (*RPSession, error) {
	c, err := r.Cookie(rp.cfg.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, rpErr(RPErrInvalidSession, "there is no session cookie")
	}
	return rp.OpenSession(c.Value)
}

// ---- revoked sids (back-channel logout) ---------------------------------------

// shortcut: the ended-sid set is per process; run a shared RPSidStore and end
// app sessions in OnBackchannelLogout when you run several servers.
func (rp *RelyingParty) markSidRevoked(sid string) {
	if sid == "" {
		return
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	now := rp.now()
	for k, exp := range rp.revokedSids {
		if !exp.After(now) {
			delete(rp.revokedSids, k)
		}
	}
	rp.revokedSids[sid] = now.Add(rp.cfg.SessionMaxAge)
}

func (rp *RelyingParty) sidRevoked(sid string) bool {
	if sid == "" {
		return false
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	exp, ok := rp.revokedSids[sid]
	return ok && exp.After(rp.now())
}

// BindSession records that your app session appSessionID is backed by the Atlas
// sid (User.SID from the callback), until expiresAt. Call it when you create
// your app session. Needs SidStore.
func (rp *RelyingParty) BindSession(ctx context.Context, sid, appSessionID string, expiresAt time.Time) error {
	if rp.cfg.SidStore == nil {
		return rpErr(RPErrNotConfigured, "BindSession: SidStore is not configured")
	}
	if sid == "" || appSessionID == "" {
		return rpErr(RPErrInvalidRequest, "BindSession: sid and appSessionID are required")
	}
	return rp.cfg.SidStore.Bind(ctx, sid, appSessionID, expiresAt)
}

// ---- keep-alive, revoke, end ---------------------------------------------------

// Touch statuses.
const (
	RPTouchSkipped = "skipped"
	RPTouchTouched = "touched"
	RPTouchEnded   = "ended"
)

// RPTouchResult is the outcome of TouchIfDue.
type RPTouchResult struct {
	// Status is RPTouchSkipped (touched less than TouchInterval ago: nothing
	// sent), RPTouchTouched (Atlas slid the idle window) or RPTouchEnded (the
	// Atlas session has ended: end your own session too).
	Status string
	// LastTouchedAt is the time to store as your last touch.
	LastTouchedAt time.Time
	// IdleExpiresAt is the new idle deadline, when Atlas reported one.
	IdleExpiresAt string
	// Reason, with RPTouchEnded: revoked, idle_expired, expired or not_found.
	Reason string
}

func rpErrorsCode(body []byte) string {
	var env struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &env) == nil && len(env.Errors) > 0 {
		return env.Errors[0].Code
	}
	return ""
}

func (rp *RelyingParty) sessionAPICall(ctx context.Context, sid, action string) (int, []byte, error) {
	if rp.cfg.SecretKey == "" {
		return 0, nil, rpErr(RPErrNotConfigured, "SecretKey is not configured")
	}
	if sid == "" {
		return 0, nil, rpErr(RPErrInvalidRequest, "a session id (sid) is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.apiURL+"/v1/sessions/"+url.PathEscape(sid)+"/"+action, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+rp.cfg.SecretKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return rp.rpDo(req)
}

func (rp *RelyingParty) rpDo(req *http.Request) (int, []byte, error) {
	resp, err := rp.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// appSessionCall is the app's own sign-in, authenticated like the token
// endpoint ({issuer}/oauth2/session/touch or /end).
func (rp *RelyingParty) appSessionCall(ctx context.Context, sid, action, caller string) (int, []byte, error) {
	if rp.cfg.ClientAuth == RPClientAuthNone || rp.cfg.ClientSecret == "" {
		return 0, nil, rpErr(RPErrNotConfigured, "%s: configure ClientSecret (the app's client credentials) or SecretKey; a public client cannot call it", caller)
	}
	if sid == "" {
		return 0, nil, rpErr(RPErrInvalidRequest, "a session id (sid) is required")
	}
	form := url.Values{}
	form.Set("sid", sid)
	if rp.cfg.ClientAuth == RPClientAuthPost {
		form.Set("client_id", rp.cfg.ClientID)
		form.Set("client_secret", rp.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpStripSlash(rp.cfg.Issuer)+"/oauth2/session/"+action, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if rp.cfg.ClientAuth == RPClientAuthBasic {
		creds := url.QueryEscape(rp.cfg.ClientID) + ":" + url.QueryEscape(rp.cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	return rp.rpDo(req)
}

func rpOAuthFailure(status int, body []byte) error {
	var m map[string]interface{}
	_ = json.Unmarshal(body, &m)
	e := rpErr(RPErrSessionCallFailed, "The issuer answered %d.", status)
	e.Status = status
	e.OAuthError = rpString(m["error"])
	e.Description = rpString(m["error_description"])
	if e.Description != "" {
		e.Message = e.Description
	}
	return e
}

// TouchIfDue keeps the Atlas session alive while the user is active in your
// app, at most once per TouchInterval per session. Call it on each
// authenticated request with the sid and the time you last touched (the zero
// time at first). With a SecretKey it touches the Atlas session
// (POST /v1/sessions/{id}/touch); without one but with a ClientSecret it
// touches this app's own sign-in (POST {issuer}/oauth2/session/touch), where a
// sid with no live sign-in of this app is RPTouchEnded / not_found. A key,
// scope or availability problem is returned as an error, not as "ended".
func (rp *RelyingParty) TouchIfDue(ctx context.Context, sid string, lastTouchedAt time.Time) (*RPTouchResult, error) {
	now := rp.now()
	if !lastTouchedAt.IsZero() && now.Sub(lastTouchedAt) < rp.touchEvery && !now.Before(lastTouchedAt) {
		return &RPTouchResult{Status: RPTouchSkipped, LastTouchedAt: lastTouchedAt}, nil
	}
	if rp.cfg.SecretKey == "" {
		status, body, err := rp.appSessionCall(ctx, sid, "touch", "TouchIfDue")
		if err != nil {
			return nil, err
		}
		if status >= 200 && status < 300 {
			var m map[string]interface{}
			_ = json.Unmarshal(body, &m)
			idle := ""
			switch v := m["idle_expires_at"].(type) {
			case string:
				idle = v
			case float64:
				idle = time.UnixMilli(int64(v)).UTC().Format(time.RFC3339)
			}
			return &RPTouchResult{Status: RPTouchTouched, LastTouchedAt: now, IdleExpiresAt: idle}, nil
		}
		var m map[string]interface{}
		_ = json.Unmarshal(body, &m)
		if status == http.StatusNotFound && rpString(m["error"]) == "session_not_found" {
			return &RPTouchResult{Status: RPTouchEnded, Reason: "not_found"}, nil
		}
		return nil, rpOAuthFailure(status, body)
	}
	status, body, err := rp.sessionAPICall(ctx, sid, "touch")
	if err != nil {
		return nil, err
	}
	switch {
	case status >= 200 && status < 300:
		var m map[string]interface{}
		_ = json.Unmarshal(body, &m)
		return &RPTouchResult{Status: RPTouchTouched, LastTouchedAt: now, IdleExpiresAt: rpString(m["idle_expires_at"])}, nil
	case status == http.StatusNotFound:
		return &RPTouchResult{Status: RPTouchEnded, Reason: "not_found"}, nil
	case status == http.StatusConflict:
		reason := "expired"
		switch rpErrorsCode(body) {
		case "SESSION_REVOKED":
			reason = "revoked"
		case "SESSION_IDLE_EXPIRED":
			reason = "idle_expired"
		}
		return &RPTouchResult{Status: RPTouchEnded, Reason: reason}, nil
	}
	return nil, parseError(status, body)
}

// RevokeSession ends the Atlas session server-side (POST /v1/sessions/{id}/revoke);
// every app signed in through it gets a back-channel logout. It returns
// "revoked" (also for an already-ended session) or "not_found" (this instance
// has no such session: check you use the same instance's secret key). Other
// failures are errors.
func (rp *RelyingParty) RevokeSession(ctx context.Context, sid string) (string, error) {
	status, body, err := rp.sessionAPICall(ctx, sid, "revoke")
	if err != nil {
		return "", err
	}
	switch {
	case status >= 200 && status < 300:
		return "revoked", nil
	case status == http.StatusNotFound:
		return "not_found", nil
	}
	return "", parseError(status, body)
}

// EndAppSession ends THIS app's sign-in under sid with the app's client
// credentials (POST {issuer}/oauth2/session/end): its refresh grants are
// revoked and Atlas sends the app a back-channel logout. The Atlas session and
// other apps are untouched. It returns "ended" or "not_found". Needs ClientSecret.
func (rp *RelyingParty) EndAppSession(ctx context.Context, sid string) (string, error) {
	status, body, err := rp.appSessionCall(ctx, sid, "end", "EndAppSession")
	if err != nil {
		return "", err
	}
	if status >= 200 && status < 300 {
		return "ended", nil
	}
	var m map[string]interface{}
	_ = json.Unmarshal(body, &m)
	if status == http.StatusNotFound && rpString(m["error"]) == "session_not_found" {
		return "not_found", nil
	}
	return "", rpOAuthFailure(status, body)
}

// ---- sign-out -------------------------------------------------------------------

// RPSignOutOptions are the inputs of SignOut.
type RPSignOutOptions struct {
	// IDToken lets Atlas end the session without asking (id_token_hint).
	IDToken string
	// SID is the Atlas session id. With a SecretKey it is revoked server-side
	// before the redirect.
	SID string
	// PostLogoutRedirectURI overrides the configured one.
	PostLogoutRedirectURI string
	// State is echoed back on the post-logout redirect.
	State string
}

// SignOut ends the Atlas session and returns where to redirect the browser. With
// a sid and a SecretKey it revokes the session server-side first, then returns
// the {issuer}/oauth2/logout URL. With ServerSignOut one call ends this app's
// grants and the Atlas session and the location is the post-logout URI (or
// "/") itself. End your own session (clear your cookie) as well.
func (rp *RelyingParty) SignOut(ctx context.Context, opts RPSignOutOptions) (string, error) {
	post := opts.PostLogoutRedirectURI
	if post == "" {
		post = rp.cfg.PostLogoutRedirectURI
	}
	if opts.SID != "" {
		rp.markSidRevoked(opts.SID)
	}
	if rp.cfg.ServerSignOut && opts.SID != "" && rp.cfg.SecretKey != "" {
		payload, err := json.Marshal(map[string]string{"sid": opts.SID})
		if err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.apiURL+"/v1/oauth_clients/"+url.PathEscape(rp.cfg.ClientID)+"/logout", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+rp.cfg.SecretKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		status, body, err := rp.rpDo(req)
		if err != nil {
			return "", err
		}
		// 404: this instance has no such session any more, so there is nothing left to end.
		if (status < 200 || status >= 300) && status != http.StatusNotFound {
			return "", parseError(status, body)
		}
		if post == "" {
			post = "/"
		}
		target, err := url.Parse(post)
		if err != nil {
			return "", rpErr(RPErrInvalidRequest, "PostLogoutRedirectURI is not a URL")
		}
		if opts.State != "" {
			q := target.Query()
			q.Set("state", opts.State)
			target.RawQuery = q.Encode()
		}
		return target.String(), nil
	}
	if opts.SID != "" && rp.cfg.SecretKey != "" {
		if _, err := rp.RevokeSession(ctx, opts.SID); err != nil {
			return "", err
		}
	}
	disc, err := rp.discover(ctx)
	if err != nil {
		return "", err
	}
	if disc.EndSessionEndpoint == "" {
		return "", rpErr(RPErrDiscoveryFailed, "The issuer does not advertise an end_session_endpoint.")
	}
	u, err := url.Parse(disc.EndSessionEndpoint)
	if err != nil {
		return "", rpErr(RPErrDiscoveryFailed, "The end_session_endpoint is not a URL.")
	}
	q := u.Query()
	q.Set("client_id", rp.cfg.ClientID)
	if opts.IDToken != "" {
		q.Set("id_token_hint", opts.IDToken)
	}
	if post != "" {
		q.Set("post_logout_redirect_uri", post)
	}
	if opts.State != "" {
		q.Set("state", opts.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
