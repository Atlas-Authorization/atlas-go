package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type rpCtxKey struct{}

// RPContextWithSession returns a copy of ctx carrying the session, for callers
// composing their own middleware on top of this one.
func RPContextWithSession(ctx context.Context, s *RPSession) context.Context {
	return context.WithValue(ctx, rpCtxKey{}, s)
}

// RPSessionFromContext returns the session Middleware (or OptionalSession)
// stored on the request context, and whether there was one.
func RPSessionFromContext(ctx context.Context) (*RPSession, bool) {
	s, ok := ctx.Value(rpCtxKey{}).(*RPSession)
	return s, ok && s != nil
}

func rpRedirect(w http.ResponseWriter, location string, cookies ...*http.Cookie) {
	for _, c := range cookies {
		if c != nil {
			http.SetCookie(w, c)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func rpPlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// Handler serves the relying party's routes on the full request path: GET on
// SignInPath starts a sign-in, GET on the callback path (the path of RedirectURI)
// finishes it and sets the session cookie, GET or POST on SignOutPath signs
// out, and POST on BackchannelLogoutPath (when set) receives back-channel
// logout. Any other request is a 404. It is a plain http.Handler: mount it on
// net/http, chi (r.Mount), gin (gin.WrapH) or echo (echo.WrapHandler).
func (rp *RelyingParty) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case rp.cfg.BackchannelLogoutPath != "" && path == rp.cfg.BackchannelLogoutPath && r.Method == http.MethodPost:
			rp.BackchannelLogout().ServeHTTP(w, r)
		case path == rp.cfg.SignInPath && r.Method == http.MethodGet:
			rp.serveStart(w, r)
		case path == rp.callbackPath && r.Method == http.MethodGet:
			rp.serveCallback(w, r)
		case path == rp.cfg.SignOutPath && (r.Method == http.MethodGet || r.Method == http.MethodPost):
			rp.serveSignOut(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func rpDigits(s string) bool {
	if s == "" || len(s) > 9 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// StartOptionsFromRequest reads the sign-in options a browser may pass on the
// sign-in URL: prompt, login_hint, ui_locales, organization, max_age, a safe
// return_to (an unsafe one is dropped, never an error) and the ForwardParams.
func (rp *RelyingParty) StartOptionsFromRequest(r *http.Request) RPStartOptions {
	q := r.URL.Query()
	opts := RPStartOptions{
		Prompt: q.Get("prompt"), LoginHint: q.Get("login_hint"), UILocales: q.Get("ui_locales"), Organization: q.Get("organization"),
	}
	if v := q.Get("return_to"); v != "" && RPIsSafeReturnTo(v) {
		opts.ReturnTo = v
	}
	if v := q.Get("max_age"); rpDigits(v) {
		if n, err := strconv.Atoi(v); err == nil {
			opts.MaxAge = &n
		}
	}
	for _, name := range rp.cfg.ForwardParams {
		if v := q.Get(name); v != "" && len(v) <= rpMaxForwardedValue {
			if opts.ExtraParams == nil {
				opts.ExtraParams = map[string]string{}
			}
			opts.ExtraParams[name] = v
		}
	}
	return opts
}

func (rp *RelyingParty) serveStart(w http.ResponseWriter, r *http.Request) {
	res, err := rp.Start(r.Context(), rp.StartOptionsFromRequest(r))
	if err != nil {
		rpPlain(w, http.StatusBadGateway, "Sign-in is temporarily unavailable. Please try again.")
		return
	}
	rpRedirect(w, res.URL, res.Cookie)
}

func (rp *RelyingParty) serveCallback(w http.ResponseWriter, r *http.Request) {
	res, err := rp.Callback(r.Context(), r)
	if err != nil {
		var re *RPError
		if !errors.As(err, &re) {
			rpPlain(w, http.StatusInternalServerError, "Sign-in failed.")
			return
		}
		if re.ClearCookie != nil {
			http.SetCookie(w, re.ClearCookie)
		}
		if rp.cfg.OnSignInError != nil {
			rp.cfg.OnSignInError(w, r, re)
			return
		}
		status := http.StatusBadRequest
		if re.Code == RPErrDiscoveryFailed {
			status = http.StatusBadGateway
		}
		rpPlain(w, status, "Sign-in failed. Please try again.")
		return
	}
	http.SetCookie(w, res.ClearCookie)
	if rp.cfg.OnSignedIn != nil && rp.cfg.OnSignedIn(w, r, res) {
		return
	}
	cookie, err := rp.SessionCookie(rp.NewSession(res))
	if err != nil {
		rpPlain(w, http.StatusInternalServerError, "Sign-in failed.")
		return
	}
	target := res.ReturnTo
	if target == "" {
		target = rp.cfg.AfterSignInPath
	}
	rpRedirect(w, target, cookie)
}

func (rp *RelyingParty) serveSignOut(w http.ResponseWriter, r *http.Request) {
	opts := RPSignOutOptions{State: r.URL.Query().Get("state")}
	if sess, err := rp.SessionFromRequest(r); err == nil {
		opts.SID, opts.IDToken = sess.SID, sess.IDToken
	}
	http.SetCookie(w, rp.ClearSessionCookie())
	loc, err := rp.SignOut(r.Context(), opts)
	if err != nil {
		rpPlain(w, http.StatusBadGateway, "Sign-out could not be completed. Please try again.")
		return
	}
	rpRedirect(w, loc)
}

// ---- middleware ---------------------------------------------------------------

func (rp *RelyingParty) canTouch() bool {
	if rp.cfg.DisableTouch {
		return false
	}
	return rp.cfg.SecretKey != "" || (rp.cfg.ClientSecret != "" && rp.cfg.ClientAuth != RPClientAuthNone)
}

// Middleware requires a valid session cookie: it puts the RPSession on the
// request context (RPSessionFromContext) and calls next. With no valid session
// it answers OnUnauthenticated (default: a redirect to SignInPath carrying
// return_to for GET and HEAD, 401 otherwise). While a SecretKey or ClientSecret
// is configured it also keeps the Atlas session alive (TouchIfDue) and ends the
// local session when Atlas says the session has ended. A failed keep-alive call
// (the API is down) does not sign the user out.
func (rp *RelyingParty) Middleware(next http.Handler) http.Handler {
	return rp.sessionMiddleware(next, true)
}

// OptionalSession is Middleware that lets a request without a session through
// (RPSessionFromContext then reports false).
func (rp *RelyingParty) OptionalSession(next http.Handler) http.Handler {
	return rp.sessionMiddleware(next, false)
}

func (rp *RelyingParty) sessionMiddleware(next http.Handler, require bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func() {
			if require {
				rp.unauthenticated(w, r)
				return
			}
			next.ServeHTTP(w, r)
		}
		sess, err := rp.SessionFromRequest(r)
		if err != nil {
			deny()
			return
		}
		if rp.canTouch() && sess.SID != "" {
			var last time.Time
			if sess.LastTouchedAt > 0 {
				last = time.UnixMilli(sess.LastTouchedAt)
			}
			res, terr := rp.TouchIfDue(r.Context(), sess.SID, last)
			if terr == nil {
				switch res.Status {
				case RPTouchEnded:
					http.SetCookie(w, rp.ClearSessionCookie())
					deny()
					return
				case RPTouchTouched:
					sess.LastTouchedAt = res.LastTouchedAt.UnixMilli()
					if c, cerr := rp.SessionCookie(sess); cerr == nil {
						http.SetCookie(w, c)
					}
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(RPContextWithSession(r.Context(), sess)))
	})
}

func (rp *RelyingParty) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if rp.cfg.OnUnauthenticated != nil {
		rp.cfg.OnUnauthenticated(w, r)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		loc := rp.cfg.SignInPath
		if back := r.URL.RequestURI(); RPIsSafeReturnTo(back) {
			loc += "?return_to=" + url.QueryEscape(back)
		}
		rpRedirect(w, loc)
		return
	}
	rpPlain(w, http.StatusUnauthorized, "Unauthorized")
}

// ---- back-channel logout ------------------------------------------------------

// BackchannelLogout returns the receiver for the client's backchannel_logout_uri
// (the same handler as BackchannelLogoutHandler, built from the issuer's
// discovery document on first use, with an in-process jti replay guard). It
// verifies the logout_token, takes the app sessions bound to its sid from
// SidStore, ends the local session for that sid, and passes the app sessions to
// OnBackchannelLogout. It answers 200 when handled (or a replay), 400 for a bad
// token, 503 with Retry-After when the keys could not be loaded or the callback
// failed.
func (rp *RelyingParty) BackchannelLogout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, err := rp.backchannelHandler(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "temporarily_unavailable", "error_description": "the issuer's keys could not be loaded"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (rp *RelyingParty) backchannelHandler(ctx context.Context) (http.Handler, error) {
	rp.mu.Lock()
	h := rp.bcHandler
	rp.mu.Unlock()
	if h != nil {
		return h, nil
	}
	disc, err := rp.discover(ctx)
	if err != nil {
		return nil, err
	}
	verifier, err := NewLogoutTokenVerifier(LogoutTokenVerifierOptions{
		JWKS:        rp.jwksFor(disc.JWKSURI),
		Issuer:      disc.Issuer,
		ClientID:    rp.cfg.ClientID,
		ReplayGuard: &MemoryReplayGuard{Now: rp.cfg.Now},
		Now:         rp.cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	built, err := BackchannelLogoutHandler(BackchannelLogoutHandlerOptions{Verifier: verifier, OnLogout: rp.onBackchannelLogout})
	if err != nil {
		return nil, err
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if rp.bcHandler == nil {
		rp.bcHandler = built
	}
	return rp.bcHandler, nil
}

func (rp *RelyingParty) onBackchannelLogout(ctx context.Context, claims *LogoutTokenClaims) error {
	rp.markSidRevoked(claims.Sid)
	var ids []string
	store := rp.cfg.SidStore
	if claims.Sid != "" && store != nil {
		taken, err := store.Take(ctx, claims.Sid)
		if err != nil {
			return err
		}
		ids = taken
	}
	if cb := rp.cfg.OnBackchannelLogout; cb != nil {
		if err := cb(ctx, ids, claims); err != nil {
			// Put the bindings back so Atlas's retry finds them.
			for _, id := range ids {
				_ = store.Bind(ctx, claims.Sid, id, rp.now().Add(24*time.Hour))
			}
			return err
		}
	}
	return nil
}
