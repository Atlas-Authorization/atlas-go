package atlas

// Cross-property SSO handshake — the second property's server-side redeem step.
//
// When a satellite (a property on a DIFFERENT registrable domain than the main
// app) has no local session, a route-protection helper bounces the browser
// through GET {fapiOrigin}/v1/client/handshake, which — if the user has an
// Atlas session — redirects back with
//
//	?__atlas_hs=ok&__atlas_hu=<userId>&__atlas_hn=<nonce>
//
// RedeemHandshake exchanges that single-use nonce for a fresh session,
// server-to-server, so the tokens come back in the response BODY (never a URL).
// The caller sets them as its OWN first-party cookies.
//
// PKCE binding (RFC 7636, S256). The nonce rides __atlas_hn on a redirect URL,
// which routinely lands in access logs, Referer headers, and browser history —
// so it must NOT be a bearer credential on its own. HandshakeRedirectURL mints a
// PKCE pair, sends only the code_challenge on the outbound URL, and hands the
// caller the verifier to stash server-side (an HttpOnly __atlas_hv cookie).
// RedeemHandshake then presents that verifier in the POST body; the server binds
// the session to the subject the nonce was minted for and admits the redeem only
// when sha256(verifier) matches the stored challenge. A leaked return URL is
// therefore inert without the cookie-held verifier. The full round trip:
//
//	// Outbound: no local session — bounce through the handshake, stash verifier.
//	if url, verifier, ok := atlas.HandshakeRedirectURL(r, "https://id.atlasauth.net", "pk_live_…"); ok {
//		http.SetCookie(w, &http.Cookie{
//			Name: "__atlas_hv", Value: verifier,
//			Path: "/", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: true,
//		})
//		http.Redirect(w, r, url, http.StatusFound)
//		return
//	}
//
//	// Return leg: redeem the nonce with the stashed verifier.
//	p, ok := atlas.ReadHandshakeParams(r.URL.String())
//	if ok {
//		hv, _ := r.Cookie("__atlas_hv")
//		s, _ := atlas.RedeemHandshake(ctx, atlas.RedeemHandshakeParams{
//			FapiOrigin:     "https://id.atlasauth.net",
//			PublishableKey: "pk_live_…",
//			UserID:         p.UserID,
//			Nonce:          p.Nonce,
//			CodeVerifier:   hv.Value,
//		})
//		if s != nil {
//			http.SetCookie(w, &http.Cookie{
//				Name: "__session", Value: s.JWT,
//				Path: "/", SameSite: http.SameSiteLaxMode, Secure: true,
//			})
//			http.SetCookie(w, &http.Cookie{
//				Name: "__atlas_rt", Value: s.RefreshToken,
//				Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: true,
//			})
//		}
//	}
//
// (Same-registrable-domain SUBDOMAINS don't need this — the handshake sets a
// parent-domain cookie directly; this is only the cross-domain path.)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Handshake query-parameter names appended to the return URL by
// GET {fapiOrigin}/v1/client/handshake.
const (
	handshakeStatusParam = "__atlas_hs"
	handshakeUserParam   = "__atlas_hu"
	handshakeNonceParam  = "__atlas_hn"
	handshakeStatusOK    = "ok"
	// handshakeChallengeParam carries the PKCE S256 code_challenge on the
	// OUTBOUND handshake URL. The matching verifier never rides a URL.
	handshakeChallengeParam = "code_challenge"
	// HandshakeVerifierCookie is the recommended name for the HttpOnly cookie
	// that stashes the PKCE verifier between HandshakeRedirectURL and
	// RedeemHandshake. It is documentation-only — the SDK never reads it for
	// you; the caller wires the cookie and passes the value as CodeVerifier.
	HandshakeVerifierCookie = "__atlas_hv"
)

// PKCE is a code_verifier / code_challenge pair for the S256 method (RFC 7636).
// The verifier is the secret the caller stashes server-side; the challenge is
// the only half that may travel on the (loggable) handshake URL.
type PKCE struct {
	// Verifier is base64url(no padding) of 32 random bytes — stash it in an
	// HttpOnly cookie, never in a URL.
	Verifier string
	// Challenge is base64url(no padding) of SHA-256(ASCII(Verifier)) — append it
	// to the handshake URL as code_challenge.
	Challenge string
}

// GeneratePKCE mints a PKCE S256 pair (RFC 7636) for the cross-property
// handshake. Why this exists: the handshake nonce (__atlas_hn) is delivered on a
// redirect URL, which routinely leaks into access logs, Referer headers, and
// browser history — so on its own it must not be enough to mint a session. The
// verifier is a fresh secret held server-side (an HttpOnly cookie); only its
// SHA-256 digest (the challenge) is exposed on the outbound URL. At redeem the
// server recomputes base64url(sha256(verifier)) and admits the exchange only if
// it equals the stored challenge, so a stolen return URL is inert without the
// cookie-held verifier.
//
// The verifier is base64url(no padding) of 32 cryptographically-random bytes
// (well inside RFC 7636's 43–128 unreserved-character range); the challenge is
// base64url(no padding) of the SHA-256 of the verifier's ASCII bytes. It returns
// a non-nil error only if the system CSPRNG fails — the caller must abort the
// handshake in that case rather than fall back to an unbound nonce.
func GeneratePKCE() (verifier string, challenge string, err error) {
	seed := make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(seed)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// HandshakeParams are the handshake return values read off a satellite's return
// URL by ReadHandshakeParams: the authenticated user id and the single-use
// nonce to redeem with RedeemHandshake.
type HandshakeParams struct {
	UserID string
	Nonce  string
}

// RedeemHandshakeParams is the input to RedeemHandshake. UserID and Nonce come
// from ReadHandshakeParams; FapiOrigin and PublishableKey identify the instance.
type RedeemHandshakeParams struct {
	// FapiOrigin is the Atlas Frontend API origin, e.g. https://id.atlasauth.net.
	FapiOrigin string
	// PublishableKey is the instance publishable key (pk_…), sent as
	// X-Publishable-Key.
	PublishableKey string
	// UserID is the __atlas_hu value from the return URL. Since PKCE binding,
	// the server treats this as advisory: the session is issued for the subject
	// the nonce was minted for, not for whatever UserID is passed here.
	UserID string
	// Nonce is the single-use __atlas_hn value from the return URL.
	Nonce string
	// CodeVerifier is the PKCE verifier that HandshakeRedirectURL returned and
	// the caller stashed (the __atlas_hv HttpOnly cookie). The server admits the
	// redeem only when base64url(sha256(CodeVerifier)) matches the code_challenge
	// sent on the outbound handshake URL, so a leaked return URL cannot be
	// redeemed without it.
	CodeVerifier string
	// HTTPClient overrides the HTTP client used for the redeem call (for
	// timeouts, proxies, or a mock transport in tests). Optional.
	HTTPClient *http.Client
}

// HandshakeSession is a redeemed handshake — the cookie VALUES a satellite's
// HTTP handler sets as its own first-party cookies (__session=JWT,
// __atlas_rt=RefreshToken HttpOnly).
type HandshakeSession struct {
	// JWT is the __session value (script-readable, short-lived).
	JWT string
	// RefreshToken is the __atlas_rt value, set as an HttpOnly cookie.
	RefreshToken string
	SessionID    string
	// ExpiresIn is the seconds until the __session JWT expires.
	ExpiresIn int
}

// redeemHandshakeBody is the POST body for /v1/client/handshake/redeem.
type redeemHandshakeBody struct {
	UserID       string `json:"user_id"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

// redeemHandshakeResponse is the 2xx response envelope.
type redeemHandshakeResponse struct {
	JWT          string `json:"jwt"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
	ExpiresIn    int    `json:"expires_in"`
}

// RedeemHandshake exchanges a single-use handshake nonce for a fresh session by
// POSTing to {FapiOrigin}/v1/client/handshake/redeem with the X-Publishable-Key
// header and a {"user_id","nonce","code_verifier"} JSON body. The code_verifier
// is the PKCE secret stashed by HandshakeRedirectURL (the __atlas_hv cookie);
// without it — or with one whose SHA-256 doesn't match the challenge sent on the
// outbound URL — the server refuses the redeem (see GeneratePKCE for why).
//
// It returns a nil session (and nil error) when the nonce/verifier is
// missing/expired/already used/mismatched, or on a transport error: a rejected
// redeem is a signed-out signal, not an error that should take the page down.
// The caller should fall back to the sign-in redirect when the session is nil.
func RedeemHandshake(ctx context.Context, params RedeemHandshakeParams) (*HandshakeSession, error) {
	endpoint := strings.TrimRight(params.FapiOrigin, "/") + "/v1/client/handshake/redeem"

	encoded, err := json.Marshal(redeemHandshakeBody{
		UserID:       params.UserID,
		Nonce:        params.Nonce,
		CodeVerifier: params.CodeVerifier,
	})
	if err != nil {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Publishable-Key", params.PublishableKey)

	hc := params.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}

	var body redeemHandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, nil
	}
	// A 2xx with no tokens is still a signed-out signal, not a session.
	if body.JWT == "" || body.RefreshToken == "" {
		return nil, nil
	}

	return &HandshakeSession{
		JWT:          body.JWT,
		RefreshToken: body.RefreshToken,
		SessionID:    body.SessionID,
		ExpiresIn:    body.ExpiresIn,
	}, nil
}

// ReadHandshakeParams extracts the handshake return values from a full URL or a
// bare query string. It returns the params and true only when __atlas_hs is "ok"
// and both __atlas_hu (user id) and __atlas_hn (nonce) are present; otherwise it
// returns the zero HandshakeParams and false.
func ReadHandshakeParams(rawURLOrQuery string) (HandshakeParams, bool) {
	query := rawURLOrQuery
	if i := strings.Index(query, "?"); i >= 0 {
		query = query[i+1:]
	}
	// A leading '?' left after slicing (or on a bare "?a=b") is not part of the
	// query itself.
	query = strings.TrimPrefix(query, "?")

	values, err := url.ParseQuery(query)
	if err != nil {
		return HandshakeParams{}, false
	}
	if values.Get(handshakeStatusParam) != handshakeStatusOK {
		return HandshakeParams{}, false
	}
	userID := values.Get(handshakeUserParam)
	nonce := values.Get(handshakeNonceParam)
	if userID == "" || nonce == "" {
		return HandshakeParams{}, false
	}
	return HandshakeParams{UserID: userID, Nonce: nonce}, true
}

// HandshakeRedirectURL is the cross-property handshake trigger for a
// route-protection helper (the peer of AtlasBackend.AuthenticateRequest). When a
// protected request has no valid local session, call this before the sign-in
// redirect: a user already signed in on a sibling property is admitted here with
// no login screen.
//
// It returns the URL to redirect to —
// {fapiOrigin}/v1/client/handshake?publishable_key={pk}&redirect_url={currentURL}&code_challenge={challenge}
// — the PKCE verifier to stash server-side, and true. It returns "", "", false
// UNLESS the redirect should proceed: the request already carries the __atlas_hs
// marker (the handshake has already run this round trip, so don't loop), r/r.URL
// is nil, or the CSPRNG failed while minting the PKCE pair — in each case the
// caller falls through to the normal sign-in redirect. The marker is the loop
// guard: it ensures the browser is bounced through the handshake at most once.
//
// The caller MUST stash the returned verifier server-side (an HttpOnly
// __atlas_hv cookie) and pass it back as RedeemHandshakeParams.CodeVerifier on
// the return leg — the challenge on this URL is redeemable only by presenting
// that verifier:
//
//	if url, verifier, ok := atlas.HandshakeRedirectURL(r, fapiOrigin, pk); ok {
//		http.SetCookie(w, &http.Cookie{
//			Name: atlas.HandshakeVerifierCookie, Value: verifier,
//			Path: "/", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: true,
//		})
//		http.Redirect(w, r, url, http.StatusFound)
//		return
//	}
//	// …on the return leg, read it back:
//	// hv, _ := r.Cookie(atlas.HandshakeVerifierCookie) → RedeemHandshakeParams.CodeVerifier
func HandshakeRedirectURL(r *http.Request, fapiOrigin, publishableKey string) (redirectURL string, verifier string, ok bool) {
	if r == nil || r.URL == nil {
		return "", "", false
	}
	// Already handshook this round trip — don't loop.
	if r.URL.Query().Get(handshakeStatusParam) != "" {
		return "", "", false
	}

	// Mint the PKCE pair up front: a CSPRNG failure means we cannot bind the
	// nonce, so refuse the handshake rather than emit an unbound (loggable) one.
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return "", "", false
	}

	hs := strings.TrimRight(fapiOrigin, "/") + "/v1/client/handshake"
	q := url.Values{}
	q.Set("publishable_key", publishableKey)
	q.Set("redirect_url", requestURL(r))
	q.Set(handshakeChallengeParam, challenge)
	return hs + "?" + q.Encode(), verifier, true
}

// requestURL reconstructs the absolute URL of an incoming server request, which
// http.Request.URL does not carry (it holds only the path and query). Scheme and
// host are read from the request and common reverse-proxy headers.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
