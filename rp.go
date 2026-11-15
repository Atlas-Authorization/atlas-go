package atlas

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A server-side relying party for the Atlas hosted redirect (OpenID Connect
// authorization code flow with PKCE). RelyingParty starts the sign-in, finishes
// it at the callback (state, nonce, PKCE, ID-token checks against the issuer's
// published keys), keeps the Atlas session alive, signs out, and ships net/http
// handlers and middleware that work with chi, gin and echo (via http.Handler).
//
//	rp, err := atlas.NewRelyingParty(atlas.RPConfig{
//		Issuer:       "https://auth.example.com",
//		ClientID:     "client_123",
//		ClientSecret: os.Getenv("ATLAS_CLIENT_SECRET"),
//		RedirectURI:  "https://app.example.com/auth/callback",
//		Secret:       os.Getenv("SESSION_SECRET"), // 32+ characters
//		SecretKey:    os.Getenv("ATLAS_SECRET_KEY"),
//	})
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", rp.Handler())
//	mux.Handle("/", rp.Middleware(app))

// RPClientAuth is how the relying party authenticates at the token endpoint.
type RPClientAuth string

const (
	// RPClientAuthBasic sends the client credentials in an Authorization header (the default with a secret).
	RPClientAuthBasic RPClientAuth = "client_secret_basic"
	// RPClientAuthPost sends the client credentials in the form body.
	RPClientAuthPost RPClientAuth = "client_secret_post"
	// RPClientAuthNone is a public client: no secret.
	RPClientAuthNone RPClientAuth = "none"
)

// RPErrorCode is a stable failure code of the relying party.
type RPErrorCode string

const (
	RPErrStateMismatch             RPErrorCode = "state_mismatch"
	RPErrIssuerMismatch            RPErrorCode = "issuer_mismatch"
	RPErrInvalidRequest            RPErrorCode = "invalid_request"
	RPErrInvalidToken              RPErrorCode = "invalid_token"
	RPErrTokenExchangeFailed       RPErrorCode = "token_exchange_failed"
	RPErrAccessDenied              RPErrorCode = "access_denied"
	RPErrDiscoveryFailed           RPErrorCode = "discovery_failed"
	RPErrReauthenticationRequired  RPErrorCode = "reauthentication_required"
	RPErrSubjectMismatch           RPErrorCode = "subject_mismatch"
	RPErrNotConfigured             RPErrorCode = "not_configured"
	RPErrSessionCallFailed         RPErrorCode = "session_call_failed"
	RPErrInvalidSession            RPErrorCode = "invalid_session"
	rpDefaultFlowCookie                        = "atlas_oidc"
	rpDefaultSessionCookie                     = "atlas_session"
	rpFlowMaxAgeSeconds                        = 600
	rpDiscoveryTTL                             = time.Hour
	rpDiscoveryRetry                           = time.Minute
	rpDefaultTouchInterval                     = 5 * time.Minute
	rpDefaultSessionMaxAge                     = 24 * time.Hour
	rpMaxForwardedValue                        = 512
	rpFlowSealedPrefix                         = "s1."
	rpDefaultClockToleranceSeconds int64       = 60
	// RPConfirmNowWindowSeconds is how long a RequireRecentAuth(..., 0) confirmation counts.
	RPConfirmNowWindowSeconds int64 = 60
)

// RPError is returned by the relying party for every sign-in failure. Branch on
// Code with errors.As.
type RPError struct {
	Code RPErrorCode
	// Message is a human-readable cause.
	Message string
	// OAuthError and Description are the OAuth error and error_description from
	// the authorization or token endpoint, when there was one.
	OAuthError  string
	Description string
	// Status is the HTTP status of the token endpoint's answer (token_exchange_failed).
	Status int
	// ClearCookie removes the flow cookie. Callback sets it on every error;
	// send it with your error response so a failed sign-in leaves nothing behind.
	ClearCookie *http.Cookie
	// Err is the underlying cause, when there is one.
	Err error
}

func (e *RPError) Error() string { return "atlas: relying party: " + string(e.Code) + ": " + e.Message }

// Unwrap returns the underlying cause.
func (e *RPError) Unwrap() error { return e.Err }

func rpErr(code RPErrorCode, format string, args ...interface{}) *RPError {
	return &RPError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// RPConfig configures a RelyingParty.
type RPConfig struct {
	// Issuer is your instance's issuer: https:// plus its frontend API host. Required.
	Issuer string
	// ClientID is the OAuth client id. Required.
	ClientID string
	// ClientSecret is the client secret (a confidential client). Without
	// SecretKey it also authenticates TouchIfDue and EndAppSession.
	ClientSecret string
	// ClientAuth is the token-endpoint authentication. Default basic with a
	// secret, none without.
	ClientAuth RPClientAuth
	// RedirectURI is the callback URL, registered on the client exactly. Must
	// be https (http only for localhost). Required.
	RedirectURI string
	// Secret seals the short-lived sign-in cookie and, unless SessionSecrets
	// is set, signs the session cookie. At least 32 characters. Required.
	Secret string
	// SessionSecrets signs the session cookie: the first signs, every one
	// verifies, so you can rotate by putting a new secret first and removing
	// the old one later. Default: Secret.
	SessionSecrets []string
	// Scope is the requested scope. Default "openid profile email".
	Scope string
	// AfterSignInPath is where the callback sends the browser when the sign-in
	// carried no return path. Default "/".
	AfterSignInPath string
	// PostLogoutRedirectURI is where Atlas sends the browser after sign-out.
	// Must be registered on the client exactly.
	PostLogoutRedirectURI string
	// SecretKey is the instance secret key (sk_..., scope sessions:write).
	// Used to touch and revoke the Atlas session. A Sign in with Atlas app has
	// none: leave it empty and TouchIfDue uses the client credentials.
	SecretKey string
	// APIURL is the Backend API origin. Default https://api.atlasauth.net.
	APIURL string
	// ServerSignOut ends this app's grants and the Atlas session with one
	// server call (POST /v1/oauth_clients/{id}/logout; the key needs
	// oauth_clients:write too) and redirects straight to PostLogoutRedirectURI.
	ServerSignOut bool
	// TouchInterval is the minimum time between two keep-alive calls for one
	// session. Default 5 minutes.
	TouchInterval time.Duration
	// DisableTouch turns off the keep-alive Middleware otherwise performs when
	// a SecretKey or ClientSecret is configured.
	DisableTouch bool
	// ForwardParams are more query parameters passed from your sign-in URL to
	// the authorize endpoint unchanged (for example "ref"). Values over 512
	// characters are dropped. The parameters this helper owns are refused.
	ForwardParams []string

	// FlowCookieName is the sign-in cookie name. Default "atlas_oidc".
	FlowCookieName string
	// SessionCookieName is the session cookie name. Default "atlas_session".
	SessionCookieName string
	// SessionMaxAge is how long a session cookie lives. Default 24 hours.
	SessionMaxAge time.Duration
	// StoreIDToken keeps the ID token in the session cookie, so sign-out can
	// send id_token_hint. It makes the cookie larger (keep it under 4 KB).
	StoreIDToken bool

	// SignInPath, SignOutPath and BackchannelLogoutPath are the routes
	// Handler answers. Defaults: /auth/sign-in, /auth/sign-out, and the path of
	// RedirectURI for the callback. BackchannelLogoutPath is off when empty.
	SignInPath            string
	SignOutPath           string
	BackchannelLogoutPath string

	// SidStore records which of your app sessions each Atlas sid backs (see
	// BindSession), so a back-channel logout can end them.
	SidStore RPSidStore
	// OnBackchannelLogout is called with the app sessions to end: those bound
	// to the token's sid in SidStore (taken out of it), or none when there is
	// no store, no binding or no sid (then end by claims.Sub). Returning an
	// error answers 503 and keeps the bindings, so Atlas retries.
	OnBackchannelLogout func(ctx context.Context, appSessionIDs []string, claims *LogoutTokenClaims) error
	// OnSignedIn runs after a verified sign-in, before the session cookie is
	// set. Return true after writing the response yourself (the sign-in cookie
	// is already cleared on w); return false to let Handler set the session
	// cookie and redirect.
	OnSignedIn func(w http.ResponseWriter, r *http.Request, result *RPCallbackResult) bool
	// OnSignInError answers a failed callback. Default: a plain 400.
	OnSignInError func(w http.ResponseWriter, r *http.Request, err *RPError)
	// OnUnauthenticated answers a Middleware request with no valid session.
	// Default: a redirect to SignInPath for GET and HEAD, otherwise 401.
	OnUnauthenticated func(w http.ResponseWriter, r *http.Request)

	// HTTPClient makes every call to the issuer and the API. Default http.DefaultClient.
	HTTPClient *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// RPSidStore maps an Atlas sid to the session ids of your app.
type RPSidStore interface {
	// Bind remembers that appSessionID belongs to sid until expiresAt.
	Bind(ctx context.Context, sid, appSessionID string, expiresAt time.Time) error
	// Take returns AND removes every unexpired app session bound to sid.
	Take(ctx context.Context, sid string) ([]string, error)
}

// RPMemorySidStore is an in-process RPSidStore; its zero value is ready to use.
// Use a shared store when you run more than one server.
type RPMemorySidStore struct {
	mu    sync.Mutex
	bySid map[string]map[string]time.Time
	// Now overrides the clock, for tests.
	Now func() time.Time
}

func (m *RPMemorySidStore) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *RPMemorySidStore) sweep(now time.Time) {
	for sid, apps := range m.bySid {
		for id, exp := range apps {
			if !exp.After(now) {
				delete(apps, id)
			}
		}
		if len(apps) == 0 {
			delete(m.bySid, sid)
		}
	}
}

// Bind implements RPSidStore.
func (m *RPMemorySidStore) Bind(_ context.Context, sid, appSessionID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bySid == nil {
		m.bySid = map[string]map[string]time.Time{}
	}
	m.sweep(m.now())
	apps := m.bySid[sid]
	if apps == nil {
		apps = map[string]time.Time{}
		m.bySid[sid] = apps
	}
	apps[appSessionID] = expiresAt
	return nil
}

// Take implements RPSidStore.
func (m *RPMemorySidStore) Take(_ context.Context, sid string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.now())
	apps := m.bySid[sid]
	delete(m.bySid, sid)
	out := make([]string, 0, len(apps))
	for id := range apps {
		out = append(out, id)
	}
	return out, nil
}

// RPUser is who signed in: the ID-token claims an app needs.
type RPUser struct {
	Sub string
	// NamespacedSub is issuer#sub: unique across issuers.
	NamespacedSub string
	// SID is the Atlas session id. Keep it on your session: touch, revoke and
	// back-channel logout all name it.
	SID   string
	Email string
	// EmailVerified is true only when the ID token says so.
	EmailVerified bool
	Name          string
	// ExternalID is your own id for the user, when the token carries one.
	ExternalID string
	// OrgID and OrgRole are the organization the sign-in was made in, if any.
	OrgID   string
	OrgRole string
	// AuthTime is when the user last authenticated, epoch seconds (0 when the
	// token has none). Store it for RequireRecentAuth.
	AuthTime int64
}

// RPTokens are the tokens of the authorization code exchange.
type RPTokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	// ExpiresAt is when the access token expires.
	ExpiresAt time.Time
}

// RPCallbackResult is a verified sign-in.
type RPCallbackResult struct {
	User   RPUser
	Tokens RPTokens
	// Claims is every verified ID-token claim.
	Claims map[string]interface{}
	// Organization is the organization the sign-in was made in (org_*), or nil.
	Organization *RPOrganization
	// Organizations is every membership (orgs) when the organizations scope was
	// requested, else nil.
	Organizations []RPOrganizationMembership
	// SSO is the enterprise SSO connection the user signed in through (sso_*), or nil.
	SSO *RPSsoContext
	// ReturnTo is the return path Start was given, or "".
	ReturnTo string
	// ClearCookie removes the flow cookie. Send it with your response.
	ClearCookie *http.Cookie
}

// RPStartOptions are per-sign-in overrides for Start.
type RPStartOptions struct {
	// Prompt is the OIDC prompt (login, none, consent, select_account, create).
	Prompt string
	// LoginHint prefills the sign-in page.
	LoginHint string
	// UILocales is the language for the hosted pages.
	UILocales string
	// AudienceHint is sent as audience_hint.
	AudienceHint string
	// Organization is the organization (id or slug) the sign-in must be made in.
	Organization string
	// MaxAge requires the user to have authenticated within this many seconds;
	// the callback then refuses an older auth_time. 0 forces a fresh sign-in.
	MaxAge *int
	// ReturnTo is a same-site path to come back to; anything else is refused.
	ReturnTo string
	// ExpectedSub is the sub this sign-in must end as (a step-up).
	ExpectedSub string
	// Scope overrides the configured scope.
	Scope string
	// ExtraParams are more authorize parameters; the ones this helper owns are ignored.
	ExtraParams map[string]string
}

// RPStartResult is a started sign-in.
type RPStartResult struct {
	// URL is where to redirect the browser.
	URL string
	// Cookie is the sealed flow cookie to send with the redirect.
	Cookie *http.Cookie
	State  string
	Nonce  string
}

// RPRecentAuthOptions are the inputs of RequireRecentAuth.
type RPRecentAuthOptions struct {
	// Sub is the signed-in user's sub: the re-authentication must come back as the same user.
	Sub string
	// AuthTime is the auth_time you stored at sign-in (0 when unknown).
	AuthTime int64
	// ReturnTo is where to come back to. Default: the request's own path and query.
	ReturnTo string
}

// RelyingParty is the Atlas hosted-redirect relying party. Create it once at
// startup with NewRelyingParty; it is safe for concurrent use.
type RelyingParty struct {
	cfg          RPConfig
	hc           *http.Client
	callbackPath string
	secureCookie bool
	flowKey      []byte
	apiURL       string
	touchEvery   time.Duration

	mu          sync.Mutex
	disc        *rpDiscovery
	discAt      time.Time
	discErr     error
	discErrAt   time.Time
	jwksCaches  map[string]*JWKSCache
	bcHandler   http.Handler
	revokedSids map[string]time.Time
}

// rpOwnedParams are the authorize parameters the helper sets itself.
var rpOwnedParams = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "state": true, "nonce": true,
	"code_challenge": true, "code_challenge_method": true,
}

// rpNotForwardable are the names ForwardParams may not list.
var rpNotForwardable = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "state": true, "nonce": true,
	"code_challenge": true, "code_challenge_method": true, "scope": true, "return_to": true,
	"id_token_hint": true, "request": true, "request_uri": true,
}

var rpParamName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// NewRelyingParty validates cfg and builds the relying party.
func NewRelyingParty(cfg RPConfig) (*RelyingParty, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("atlas: NewRelyingParty requires Issuer")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("atlas: NewRelyingParty requires ClientID")
	}
	if len(cfg.Secret) < 32 {
		return nil, errors.New("atlas: NewRelyingParty requires Secret of at least 32 characters to seal the sign-in cookie")
	}
	redirect, err := rpParseRedirectURI(cfg.RedirectURI)
	if err != nil {
		return nil, err
	}
	if cfg.AfterSignInPath == "" {
		cfg.AfterSignInPath = "/"
	}
	if !RPIsSafeReturnTo(cfg.AfterSignInPath) {
		return nil, errors.New("atlas: NewRelyingParty: AfterSignInPath must be a path starting with a single /")
	}
	for _, name := range cfg.ForwardParams {
		if !rpParamName.MatchString(name) || rpNotForwardable[name] {
			return nil, fmt.Errorf("atlas: NewRelyingParty: ForwardParams cannot forward %q", name)
		}
	}
	if len(cfg.SessionSecrets) == 0 {
		cfg.SessionSecrets = []string{cfg.Secret}
	}
	for _, s := range cfg.SessionSecrets {
		if len(s) < 32 {
			return nil, errors.New("atlas: NewRelyingParty: every session secret must be at least 32 characters")
		}
	}
	if cfg.ClientAuth == "" {
		if cfg.ClientSecret != "" {
			cfg.ClientAuth = RPClientAuthBasic
		} else {
			cfg.ClientAuth = RPClientAuthNone
		}
	}
	if cfg.FlowCookieName == "" {
		cfg.FlowCookieName = rpDefaultFlowCookie
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = rpDefaultSessionCookie
	}
	if cfg.SessionMaxAge <= 0 {
		cfg.SessionMaxAge = rpDefaultSessionMaxAge
	}
	if cfg.SignInPath == "" {
		cfg.SignInPath = "/auth/sign-in"
	}
	if cfg.SignOutPath == "" {
		cfg.SignOutPath = "/auth/sign-out"
	}
	touchEvery := cfg.TouchInterval
	if touchEvery <= 0 {
		touchEvery = rpDefaultTouchInterval
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	api := cfg.APIURL
	if api == "" {
		api = DefaultBaseURL
	}
	mac := hmac.New(sha256.New, []byte(cfg.Secret))
	mac.Write([]byte("atlas-oidc-flow-cookie/v1"))
	return &RelyingParty{
		cfg:          cfg,
		hc:           hc,
		callbackPath: redirect.Path,
		secureCookie: redirect.Scheme == "https",
		flowKey:      mac.Sum(nil),
		apiURL:       strings.TrimRight(api, "/"),
		touchEvery:   touchEvery,
		jwksCaches:   map[string]*JWKSCache{},
		revokedSids:  map[string]time.Time{},
	}, nil
}

func (rp *RelyingParty) now() time.Time {
	if rp.cfg.Now != nil {
		return rp.cfg.Now()
	}
	return time.Now()
}

// ---- helpers ----------------------------------------------------------------

func rpParseRedirectURI(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("atlas: NewRelyingParty requires RedirectURI")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("atlas: RedirectURI must be an absolute URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && rpIsLoopback(u.Hostname())) {
		return nil, errors.New("atlas: RedirectURI must be https (http is accepted only for localhost)")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func rpIsLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func rpSecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && rpIsLoopback(u.Hostname()))
}

// RPIsSafeReturnTo reports whether value is a plain same-site path: one leading
// slash, no scheme or authority, no backslash or control characters. Anything
// else could become an open redirect.
func RPIsSafeReturnTo(value string) bool {
	if value == "" || value[0] != '/' {
		return false
	}
	if len(value) > 1 && (value[1] == '/' || value[1] == '\\') {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\\' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func rpStripSlash(s string) string { return strings.TrimRight(s, "/") }

func rpRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func rpB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rpEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func rpNumber(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func rpString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func rpNormaliseScope(scope string) string {
	if strings.TrimSpace(scope) == "" {
		scope = "openid profile email"
	}
	seen := map[string]bool{}
	parts := []string{}
	for _, p := range strings.Fields(scope) {
		if !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	if !seen["openid"] {
		parts = append([]string{"openid"}, parts...)
	}
	return strings.Join(parts, " ")
}

// ---- discovery --------------------------------------------------------------

type rpDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func (rp *RelyingParty) discover(ctx context.Context) (*rpDiscovery, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	now := rp.now()
	if rp.disc != nil && now.Sub(rp.discAt) < rpDiscoveryTTL {
		return rp.disc, nil
	}
	if rp.disc == nil && rp.discErr != nil && now.Sub(rp.discErrAt) < rpDiscoveryRetry {
		return nil, rp.discErr
	}
	doc, err := rp.fetchDiscovery(ctx)
	if err != nil {
		if rp.disc != nil {
			// Keep serving the document we already had through an outage.
			return rp.disc, nil
		}
		rp.discErr, rp.discErrAt = err, now
		return nil, err
	}
	rp.disc, rp.discAt, rp.discErr = doc, now, nil
	return doc, nil
}

func (rp *RelyingParty) fetchDiscovery(ctx context.Context) (*rpDiscovery, error) {
	issuer := rpStripSlash(rp.cfg.Issuer)
	target := issuer + "/.well-known/openid-configuration"
	fail := func(cause error, format string, args ...interface{}) *RPError {
		e := rpErr(RPErrDiscoveryFailed, "OIDC discovery at %s failed: %s", target, fmt.Sprintf(format, args...))
		e.Err = cause
		return e
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fail(err, "%v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := rp.hc.Do(req)
	if err != nil {
		return nil, fail(err, "%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fail(nil, "HTTP %d", resp.StatusCode)
	}
	var doc rpDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fail(err, "the response is not JSON")
	}
	// OIDC Discovery 4.3: the document must be for the issuer we asked about.
	if rpStripSlash(doc.Issuer) != issuer {
		return nil, fail(nil, "its issuer (%s) is not %s", doc.Issuer, issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI} {
		if v == "" {
			return nil, fail(nil, "it has no %s", name)
		}
		if !rpSecureURL(v) {
			return nil, fail(nil, "its %s is not an https URL", name)
		}
	}
	return &doc, nil
}

func (rp *RelyingParty) jwksFor(uri string) *JWKSCache {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	c := rp.jwksCaches[uri]
	if c == nil {
		c = NewJWKSCache(JWKSCacheOptions{URL: uri, HTTPClient: rp.hc, Now: rp.cfg.Now})
		rp.jwksCaches[uri] = c
	}
	return c
}

// ---- flow cookie ------------------------------------------------------------

type rpFlow struct {
	S string `json:"s"`
	N string `json:"n"`
	V string `json:"v"`
	R string `json:"r"`
	I string `json:"i"`
	C string `json:"c"`
	T int64  `json:"t"`
	M *int   `json:"m,omitempty"`
	U string `json:"u,omitempty"`
	X string `json:"x,omitempty"`
}

func (rp *RelyingParty) sealFlow(f rpFlow) (string, error) {
	plain, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(rp.flowKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	return rpFlowSealedPrefix + rpB64(iv) + "." + rpB64(gcm.Seal(nil, iv, plain, nil)), nil
}

func (rp *RelyingParty) openFlow(value string) *rpFlow {
	if !strings.HasPrefix(value, rpFlowSealedPrefix) {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(value, rpFlowSealedPrefix), ".")
	if len(parts) != 2 {
		return nil
	}
	iv, err1 := base64urlDecode(parts[0])
	data, err2 := base64urlDecode(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	block, err := aes.NewCipher(rp.flowKey)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(iv) != gcm.NonceSize() {
		return nil
	}
	plain, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return nil
	}
	var f rpFlow
	if json.Unmarshal(plain, &f) != nil {
		return nil
	}
	if f.S == "" || f.N == "" || f.V == "" || f.R == "" || f.I == "" || f.C == "" || f.T == 0 {
		return nil
	}
	if f.M != nil && *f.M < 0 {
		return nil
	}
	return &f
}

func (rp *RelyingParty) flowCookie(value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     rp.cfg.FlowCookieName,
		Value:    value,
		Path:     rp.callbackPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   rp.secureCookie,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge <= 0 {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	return c
}

func (rp *RelyingParty) clearFlowCookie() *http.Cookie { return rp.flowCookie("", 0) }

// ---- start ------------------------------------------------------------------

// Start begins a sign-in: it builds the authorize URL (state, nonce and PKCE
// S256) and the sealed flow cookie. Redirect to URL and set Cookie.
func (rp *RelyingParty) Start(ctx context.Context, opts RPStartOptions) (*RPStartResult, error) {
	disc, err := rp.discover(ctx)
	if err != nil {
		return nil, err
	}
	if opts.MaxAge != nil && *opts.MaxAge < 0 {
		return nil, rpErr(RPErrInvalidRequest, "MaxAge must be a whole number of seconds, 0 or more")
	}
	if opts.ReturnTo != "" && !RPIsSafeReturnTo(opts.ReturnTo) {
		return nil, rpErr(RPErrInvalidRequest, "ReturnTo must be a path on this site, starting with a single /")
	}
	state, err := rpRandomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := rpRandomToken()
	if err != nil {
		return nil, err
	}
	verifier, err := rpRandomToken()
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	scope := opts.Scope
	if scope == "" {
		scope = rp.cfg.Scope
	}

	u, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		return nil, rpErr(RPErrDiscoveryFailed, "the authorization_endpoint is not a URL")
	}
	q := u.Query()
	for k, v := range opts.ExtraParams {
		if !rpOwnedParams[k] {
			q.Set(k, v)
		}
	}
	q.Set("response_type", "code")
	q.Set("client_id", rp.cfg.ClientID)
	q.Set("redirect_uri", rp.cfg.RedirectURI)
	q.Set("scope", rpNormaliseScope(scope))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", rpB64(challenge[:]))
	q.Set("code_challenge_method", "S256")
	if opts.Prompt != "" {
		q.Set("prompt", opts.Prompt)
	}
	if opts.LoginHint != "" {
		q.Set("login_hint", opts.LoginHint)
	}
	if opts.AudienceHint != "" {
		q.Set("audience_hint", opts.AudienceHint)
	}
	if opts.Organization != "" {
		q.Set("organization", opts.Organization)
	}
	if opts.UILocales != "" {
		q.Set("ui_locales", opts.UILocales)
	}
	if opts.MaxAge != nil {
		q.Set("max_age", strconv.Itoa(*opts.MaxAge))
	}
	u.RawQuery = q.Encode()

	sealed, err := rp.sealFlow(rpFlow{
		S: state, N: nonce, V: verifier, R: rp.cfg.RedirectURI, I: rpStripSlash(rp.cfg.Issuer), C: rp.cfg.ClientID,
		T: rp.now().Unix(), M: opts.MaxAge, U: opts.ReturnTo, X: opts.ExpectedSub,
	})
	if err != nil {
		return nil, err
	}
	return &RPStartResult{URL: u.String(), Cookie: rp.flowCookie(sealed, rpFlowMaxAgeSeconds), State: state, Nonce: nonce}, nil
}

// RequireRecentAuth is the step-up check: it returns nil when authTime is
// within maxAgeSeconds, otherwise a started sign-in that asks the same user to
// authenticate again (max_age, plus prompt=login for 0). The callback then
// refuses another user or an old auth_time; store the new User.AuthTime. 0 asks
// unless the user authenticated in the last RPConfirmNowWindowSeconds seconds,
// so the request that returns from the confirmation goes through.
func (rp *RelyingParty) RequireRecentAuth(ctx context.Context, r *http.Request, maxAgeSeconds int, opts RPRecentAuthOptions) (*RPStartResult, error) {
	if maxAgeSeconds < 0 {
		return nil, rpErr(RPErrInvalidRequest, "maxAgeSeconds must be 0 or more")
	}
	if opts.Sub == "" {
		return nil, rpErr(RPErrInvalidRequest, "RPRecentAuthOptions.Sub is required")
	}
	allowed := int64(maxAgeSeconds)
	if maxAgeSeconds == 0 {
		allowed = RPConfirmNowWindowSeconds
	}
	if opts.AuthTime > 0 && rp.now().Unix()-opts.AuthTime <= allowed {
		return nil, nil
	}
	returnTo := opts.ReturnTo
	if returnTo == "" && r != nil && r.URL != nil {
		returnTo = r.URL.RequestURI()
	}
	start := RPStartOptions{MaxAge: &maxAgeSeconds, ExpectedSub: opts.Sub}
	if maxAgeSeconds == 0 {
		start.Prompt = "login"
	}
	if RPIsSafeReturnTo(returnTo) {
		start.ReturnTo = returnTo
	}
	return rp.Start(ctx, start)
}

// ---- callback ---------------------------------------------------------------

// Callback finishes a sign-in at the redirect URI: the flow cookie and state,
// the issuer (RFC 9207), the code exchange with PKCE and client authentication,
// and the ID token (algorithm pinned to RS256/ES256, iss, aud/azp, exp/iat,
// nonce, at_hash). The error is always an *RPError carrying ClearCookie.
func (rp *RelyingParty) Callback(ctx context.Context, r *http.Request) (*RPCallbackResult, error) {
	clearCk := rp.clearFlowCookie()
	res, err := rp.runCallback(ctx, r)
	if err != nil {
		var re *RPError
		if !errors.As(err, &re) {
			re = &RPError{Code: RPErrInvalidRequest, Message: err.Error(), Err: err}
		}
		re.ClearCookie = clearCk
		return nil, re
	}
	res.ClearCookie = clearCk
	return res, nil
}

func (rp *RelyingParty) runCallback(ctx context.Context, r *http.Request) (*RPCallbackResult, error) {
	query := r.URL.Query()
	issuer := rpStripSlash(rp.cfg.Issuer)

	// The flow cookie first: without it nothing in the query can be trusted.
	cookie, cerr := r.Cookie(rp.cfg.FlowCookieName)
	if cerr != nil || cookie.Value == "" {
		return nil, rpErr(RPErrStateMismatch, "The sign-in flow cookie is missing or expired. Start sign-in again.")
	}
	flow := rp.openFlow(cookie.Value)
	if flow == nil {
		return nil, rpErr(RPErrStateMismatch, "The sign-in flow cookie could not be read. Start sign-in again.")
	}
	state := query.Get("state")
	if state == "" || !rpEqual(state, flow.S) {
		return nil, rpErr(RPErrStateMismatch, "The state returned to the callback does not match this browser's sign-in.")
	}
	nowSec := rp.now().Unix()
	if nowSec-flow.T > rpFlowMaxAgeSeconds {
		return nil, rpErr(RPErrStateMismatch, "This sign-in took longer than 10 minutes. Start sign-in again.")
	}
	if flow.I != issuer || flow.C != rp.cfg.ClientID || flow.R != rp.cfg.RedirectURI {
		return nil, rpErr(RPErrStateMismatch, "This sign-in was started for a different issuer, client or redirect URI.")
	}
	// RFC 9207: an authorization server that names itself must be the one we sent the user to.
	if returned := query.Get("iss"); returned != "" && rpStripSlash(returned) != issuer {
		return nil, rpErr(RPErrIssuerMismatch, "The callback came from %s, not %s.", returned, issuer)
	}
	if oauthErr := query.Get("error"); oauthErr != "" {
		desc := query.Get("error_description")
		e := rpErr(RPErrAccessDenied, "Sign-in did not complete: %s.", oauthErr)
		e.OAuthError, e.Description = oauthErr, desc
		return nil, e
	}
	code := query.Get("code")
	if code == "" {
		return nil, rpErr(RPErrInvalidRequest, "The callback has no code parameter.")
	}

	disc, err := rp.discover(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := rp.exchangeCode(ctx, disc, code, flow.V)
	if err != nil {
		return nil, err
	}
	claims, err := rp.verifyIDToken(ctx, disc, tokens.idToken, flow.N, tokens.accessToken)
	if err != nil {
		return nil, err
	}

	sub := rpString(claims["sub"])
	var authTime int64
	hasAuthTime := false
	if f, ok := rpNumber(claims["auth_time"]); ok {
		authTime, hasAuthTime = int64(f), true
	}
	if flow.M != nil {
		// OIDC Core 3.1.2.1: with max_age the client must check auth_time itself.
		if !hasAuthTime || nowSec-authTime > int64(*flow.M)+rpDefaultClockToleranceSeconds {
			return nil, rpErr(RPErrReauthenticationRequired, "The sign-in is older than the %d seconds this request allowed (max_age). Ask the user to sign in again.", *flow.M)
		}
	}
	if flow.X != "" && !rpEqual(sub, flow.X) {
		return nil, rpErr(RPErrSubjectMismatch, "A different user signed in than the one asked to confirm it is them.")
	}

	expiresAt := time.Unix(int64(claims["exp"].(float64)), 0)
	if tokens.expiresIn > 0 {
		expiresAt = rp.now().Add(time.Duration(tokens.expiresIn * float64(time.Second)))
	}
	user := RPUser{
		Sub:           sub,
		NamespacedSub: issuer + "#" + sub,
		SID:           rpString(claims["sid"]),
		Email:         rpString(claims["email"]),
		EmailVerified: claims["email_verified"] == true,
		Name:          rpString(claims["name"]),
		ExternalID:    rpString(claims["external_id"]),
		OrgID:         rpString(claims["org_id"]),
		AuthTime:      authTime,
	}
	if user.OrgID != "" {
		user.OrgRole = rpString(claims["org_role"])
	}
	returnTo := ""
	if flow.U != "" && RPIsSafeReturnTo(flow.U) {
		returnTo = flow.U
	}
	return &RPCallbackResult{
		User: user,
		Tokens: RPTokens{
			IDToken: tokens.idToken, AccessToken: tokens.accessToken, RefreshToken: tokens.refreshToken, ExpiresAt: expiresAt,
		},
		Claims:        claims,
		Organization:  RPOrganizationOf(claims),
		Organizations: RPOrganizationsOf(claims),
		SSO:           RPSsoOf(claims),
		ReturnTo:      returnTo,
	}, nil
}

type rpTokenResponse struct {
	idToken      string
	accessToken  string
	refreshToken string
	expiresIn    float64
}

func (rp *RelyingParty) exchangeCode(ctx context.Context, disc *rpDiscovery, code, verifier string) (*rpTokenResponse, error) {
	method := rp.cfg.ClientAuth
	if method != RPClientAuthNone && rp.cfg.ClientSecret == "" {
		return nil, rpErr(RPErrTokenExchangeFailed, "ClientAuth %q needs ClientSecret.", string(method))
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", rp.cfg.RedirectURI)
	form.Set("code_verifier", verifier)
	if method != RPClientAuthBasic {
		form.Set("client_id", rp.cfg.ClientID)
		if method == RPClientAuthPost {
			form.Set("client_secret", rp.cfg.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, rpErr(RPErrTokenExchangeFailed, "%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == RPClientAuthBasic {
		// RFC 6749 2.3.1: both halves are form-encoded before Basic encoding.
		creds := url.QueryEscape(rp.cfg.ClientID) + ":" + url.QueryEscape(rp.cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	resp, err := rp.hc.Do(req)
	if err != nil {
		e := rpErr(RPErrTokenExchangeFailed, "The token endpoint could not be reached: %v.", err)
		e.Err = err
		return nil, e
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		oauthErr, desc := rpString(body["error"]), rpString(body["error_description"])
		msg := fmt.Sprintf("The token endpoint answered %d", resp.StatusCode)
		if oauthErr != "" {
			msg += " " + oauthErr
		}
		if desc != "" {
			msg += ": " + desc
		}
		e := rpErr(RPErrTokenExchangeFailed, "%s.", msg)
		e.OAuthError, e.Description, e.Status = oauthErr, desc, resp.StatusCode
		return nil, e
	}
	idToken, access := rpString(body["id_token"]), rpString(body["access_token"])
	if idToken == "" || access == "" {
		e := rpErr(RPErrTokenExchangeFailed, "The token response has no id_token. Request the openid scope.")
		e.Status = resp.StatusCode
		return nil, e
	}
	out := &rpTokenResponse{idToken: idToken, accessToken: access, refreshToken: rpString(body["refresh_token"])}
	switch v := body["expires_in"].(type) {
	case float64:
		out.expiresIn = v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			out.expiresIn = f
		}
	}
	return out, nil
}

// VerifyIDToken checks an ID token on its own (for an app that does its own
// code exchange): the same checks Callback makes. nonce is the one sent on the
// authorize request; accessToken is optional (at_hash is checked when both it
// and the claim are present). It returns the verified claims.
func (rp *RelyingParty) VerifyIDToken(ctx context.Context, idToken, nonce, accessToken string) (map[string]interface{}, error) {
	disc, err := rp.discover(ctx)
	if err != nil {
		return nil, err
	}
	return rp.verifyIDToken(ctx, disc, idToken, nonce, accessToken)
}

func (rp *RelyingParty) verifyIDToken(ctx context.Context, disc *rpDiscovery, idToken, nonce, accessToken string) (map[string]interface{}, error) {
	invalid := func(format string, args ...interface{}) *RPError {
		return rpErr(RPErrInvalidToken, "The ID token was refused: "+format+".", args...)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 || parts[0] == "" {
		return nil, invalid("it is not a JWT")
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, invalid("it is not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil {
		return nil, invalid("it is not a JWT")
	}
	// Pinned before any key lookup, so "none" and HS* never get near a key.
	if !contains(SigningAlgs, header.Alg) {
		return nil, invalid("its algorithm is %s, not RS256 or ES256", header.Alg)
	}
	set := rp.jwksFor(disc.JWKSURI).get(ctx, header.Kid)
	if set == nil || len(set.Keys) == 0 {
		return nil, rpErr(RPErrDiscoveryFailed, "The issuer's signing keys could not be fetched from %s.", disc.JWKSURI)
	}
	haveKey := hasJWSKey(set, header.Alg, header.Kid)
	if !haveKey {
		return nil, invalid("no published key matches it")
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil || !verifyJWSSignature(set, header.Alg, header.Kid, parts[0]+"."+parts[1], sig) {
		return nil, invalid("its signature does not verify")
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, invalid("it is not a JWT")
	}
	var claims map[string]interface{}
	if json.Unmarshal(payloadRaw, &claims) != nil || claims == nil {
		return nil, invalid("it is not a JWT")
	}

	tol := rpDefaultClockToleranceSeconds
	now := rp.now().Unix()
	if rpStripSlash(rpString(claims["iss"])) != rpStripSlash(disc.Issuer) {
		return nil, invalid("its issuer is not the configured issuer")
	}
	if !audienceContains(claims["aud"], rp.cfg.ClientID) {
		return nil, invalid("its audience is not this client")
	}
	if rpString(claims["sub"]) == "" {
		return nil, invalid("its sub claim is invalid")
	}
	exp, okExp := rpNumber(claims["exp"])
	iat, okIat := rpNumber(claims["iat"])
	if !okExp || !okIat {
		return nil, invalid("its exp or iat claim is missing")
	}
	if now > int64(exp)+tol {
		return nil, invalid("it has expired")
	}
	if int64(iat) > now+tol {
		return nil, invalid("it was issued in the future")
	}
	if nbf, ok := rpNumber(claims["nbf"]); ok && int64(nbf) > now+tol {
		return nil, invalid("it is not valid yet")
	}
	// OIDC Core 3.1.3.7 (4)-(5): several audiences need an azp, and any azp must be us.
	if aud, ok := claims["aud"].([]interface{}); ok && len(aud) > 1 && claims["azp"] == nil {
		return nil, invalid("it has several audiences and no azp")
	}
	if azp, present := claims["azp"]; present && rpString(azp) != rp.cfg.ClientID {
		return nil, invalid("its azp is not this client")
	}
	if n := rpString(claims["nonce"]); n == "" || !rpEqual(n, nonce) {
		return nil, invalid("its nonce does not match this sign-in")
	}
	if atHash := rpString(claims["at_hash"]); accessToken != "" && atHash != "" {
		digest := sha256.Sum256([]byte(accessToken))
		if !rpEqual(rpB64(digest[:16]), atHash) {
			return nil, invalid("its at_hash does not match the access token")
		}
	}
	return claims, nil
}
