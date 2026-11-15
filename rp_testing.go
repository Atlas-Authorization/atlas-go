package atlas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RPTestTamper makes the next token a test issuer signs wrong in one way, to
// exercise the relying party's refusals.
type RPTestTamper struct {
	// WrongNonce replaces the nonce.
	WrongNonce bool
	// NoNonce leaves the nonce out.
	NoNonce bool
	// WrongAudience replaces aud.
	WrongAudience bool
	// WrongIssuer replaces iss.
	WrongIssuer bool
	// Expired makes the token expire an hour before it was issued.
	Expired bool
}

// RPTestIssuer is an offline OpenID issuer for testing an app built on
// RelyingParty, with no network and no Atlas account. It serves discovery, the
// JWKS, authorize, token (PKCE and client authentication checked), userinfo,
// end-session, and the app-session touch and end endpoints, and signs ID tokens
// and back-channel logout tokens with ES256 by default, or any of RS256, ES256,
// ES384, PS256 and EdDSA through NewRPTestIssuerAlg.
//
//	iss := atlas.NewRPTestIssuer("client_test")
//	defer iss.Close()
//	rp, _ := atlas.NewRelyingParty(iss.Config("http://127.0.0.1:3000/auth/callback", secret))
//	started, _ := rp.Start(ctx, atlas.RPStartOptions{})
//	callbackURL, _ := iss.Authorize(started.URL) // the user signs in
type RPTestIssuer struct {
	// URL is the issuer URL (an httptest server).
	URL string
	// ClientID is the only client the issuer serves.
	ClientID string
	// ClientSecret is the secret the token endpoint wants (Basic or in the body).
	ClientSecret string
	// PublicClient lets the token endpoint skip the client secret (PKCE only).
	PublicClient bool
	// Now is the clock for iat and exp (default time.Now).
	Now func() time.Time
	// Alg is the signing algorithm (RS256, ES256, ES384, PS256 or EdDSA); set it
	// with NewRPTestIssuerAlg.
	Alg string

	// DefaultClaims are merged into every ID token under the explicit claims,
	// over the built-in defaults (sub, sid, email, ...).
	DefaultClaims map[string]interface{}
	// MutateClaims edits the whole ID token payload just before it is signed.
	MutateClaims func(map[string]interface{})
	// RawIDToken, when set, is what the token endpoint returns as id_token.
	RawIDToken string
	// AccessToken and RefreshToken, when set, replace the random tokens the
	// token endpoint issues.
	AccessToken, RefreshToken string
	// TokenStatus, when non-zero, makes the token endpoint fail with that HTTP
	// status (an invalid_grant error).
	TokenStatus int
	// SessionTouchStatus and SessionTouchBody script POST /v1/sessions/{sid}/touch
	// (the API call RPConfig.SecretKey enables); zero and "" mean 200 and a
	// far-future idle_expires_at.
	SessionTouchStatus int
	SessionTouchBody   string
	// AppTouchStatus and AppTouchBody script the app-session touch endpoint; when
	// AppTouchStatus is non-zero the live-sid check and client authentication are
	// skipped and the end endpoint answers 200.
	AppTouchStatus int
	AppTouchBody   string

	srv *httptest.Server
	key *rpTestKey

	mu         sync.Mutex
	codes      map[string]rpTestPendingCode
	access     map[string]map[string]interface{}
	liveSids   map[string]bool
	nextClaims map[string]interface{}
	nextTamper RPTestTamper
	lastAuth   url.Values

	lastTokenForm                     url.Values
	lastTokenAuth, lastSessionAuth    string
	lastAppTouchAuth, oauthClientBody string
	lastAppTouchForm                  url.Values
	touchCalls, revokeCalls           int
	oauthClientCalls, appEndCalls     int
}

type rpTestPendingCode struct {
	redirectURI, nonce, challenge string
}

// NewRPTestIssuer starts a test issuer for clientID that signs with ES256.
// Close it when done.
func NewRPTestIssuer(clientID string) *RPTestIssuer {
	return NewRPTestIssuerAlg(clientID, "ES256")
}

// NewRPTestIssuerAlg is NewRPTestIssuer signing with alg: RS256, ES256, ES384,
// PS256 or EdDSA. It panics on any other alg.
func NewRPTestIssuerAlg(clientID, alg string) *RPTestIssuer {
	key := newRPTestKey(alg)
	iss := &RPTestIssuer{
		ClientID: clientID, ClientSecret: "rp-test-secret", Now: time.Now, Alg: alg, key: key,
		codes: map[string]rpTestPendingCode{}, access: map[string]map[string]interface{}{}, liveSids: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", iss.serveDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", iss.serveJWKS)
	mux.HandleFunc("/oauth2/authorize", iss.serveAuthorize)
	mux.HandleFunc("/oauth2/token", iss.serveToken)
	mux.HandleFunc("/oauth2/userinfo", iss.serveUserinfo)
	mux.HandleFunc("/oauth2/logout", iss.serveEndSession)
	mux.HandleFunc("/oauth2/session/touch", iss.serveSession)
	mux.HandleFunc("/oauth2/session/end", iss.serveSession)
	mux.HandleFunc("/v1/sessions/", iss.serveAPISession)
	mux.HandleFunc("/v1/oauth_clients/", iss.serveAPIOAuthClient)
	iss.srv = httptest.NewServer(mux)
	iss.URL = iss.srv.URL
	return iss
}

// Close stops the server.
func (i *RPTestIssuer) Close() { i.srv.Close() }

// HTTPClient is the client to give RPConfig.HTTPClient.
func (i *RPTestIssuer) HTTPClient() *http.Client { return i.srv.Client() }

// Config is an RPConfig wired to this issuer.
func (i *RPTestIssuer) Config(redirectURI, secret string) RPConfig {
	return RPConfig{
		Issuer: i.URL, ClientID: i.ClientID, ClientSecret: i.ClientSecret,
		RedirectURI: redirectURI, Secret: secret, HTTPClient: i.HTTPClient(), APIURL: i.URL,
	}
}

// NextClaims merges claims into the ID token of the next code redeemed at the
// token endpoint (then clears them).
func (i *RPTestIssuer) NextClaims(c map[string]interface{}) {
	i.mu.Lock()
	i.nextClaims = c
	i.mu.Unlock()
}

// NextTamper breaks the ID token of the next code redeemed (then clears it).
func (i *RPTestIssuer) NextTamper(t RPTestTamper) {
	i.mu.Lock()
	i.nextTamper = t
	i.mu.Unlock()
}

// LiveSids are the sids the touch and end endpoints treat as live sign-ins.
func (i *RPTestIssuer) LiveSids() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := []string{}
	for s := range i.liveSids {
		out = append(out, s)
	}
	return out
}

// LastAuthorizeRequest is the query of the last authorize request: state, nonce,
// code_challenge, scope, organization and the rest.
func (i *RPTestIssuer) LastAuthorizeRequest() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastAuth
}

// LastTokenForm is the form of the last token request.
func (i *RPTestIssuer) LastTokenForm() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastTokenForm
}

// LastTokenAuth is the Authorization header of the last token request.
func (i *RPTestIssuer) LastTokenAuth() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastTokenAuth
}

// SessionTouchCalls counts POST /v1/sessions/{sid}/touch calls.
func (i *RPTestIssuer) SessionTouchCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.touchCalls
}

// SessionRevokeCalls counts POST /v1/sessions/{sid}/revoke calls.
func (i *RPTestIssuer) SessionRevokeCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.revokeCalls
}

// LastSessionAuth is the Authorization header of the last /v1/sessions call.
func (i *RPTestIssuer) LastSessionAuth() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastSessionAuth
}

// OAuthClientCalls counts calls under /v1/oauth_clients/ (the server-side
// logout call) and LastOAuthClientBody is the last one's body.
func (i *RPTestIssuer) OAuthClientCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.oauthClientCalls
}

// LastOAuthClientBody is the body of the last /v1/oauth_clients/ call.
func (i *RPTestIssuer) LastOAuthClientBody() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.oauthClientBody
}

// LastAppTouchForm is the form of the last app-session touch call.
func (i *RPTestIssuer) LastAppTouchForm() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastAppTouchForm
}

// LastAppTouchAuth is the Authorization header of the last app-session touch.
func (i *RPTestIssuer) LastAppTouchAuth() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastAppTouchAuth
}

// AppEndCalls counts app-session end calls.
func (i *RPTestIssuer) AppEndCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.appEndCalls
}

// Authorize plays the user signing in: pass the authorize URL Start returned,
// get the callback URL (code, state, iss) to request with the sign-in cookie.
func (i *RPTestIssuer) Authorize(authorizeURL string) (string, error) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", err
	}
	return i.issueCode(u.Query())
}

func (i *RPTestIssuer) issueCode(q url.Values) (string, error) {
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		return "", errors.New("atlas: RPTestIssuer: the authorize URL has no redirect_uri")
	}
	if q.Get("client_id") != i.ClientID {
		return "", fmt.Errorf("atlas: RPTestIssuer: client_id %q is not %q", q.Get("client_id"), i.ClientID)
	}
	code := "code_" + rpTestRandom()
	i.mu.Lock()
	i.codes[code] = rpTestPendingCode{redirectURI: redirect, nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	i.lastAuth = q
	i.mu.Unlock()
	back, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	bq := back.Query()
	bq.Set("code", code)
	if q.Has("state") {
		bq.Set("state", q.Get("state"))
	}
	bq.Set("iss", i.URL)
	back.RawQuery = bq.Encode()
	return back.String(), nil
}

// IDToken signs an ID token: iss, aud, sub, iat, exp, auth_time, sid, email,
// email_verified, then claims. Its sid becomes live for touch and end.
func (i *RPTestIssuer) IDToken(claims map[string]interface{}) string {
	return i.IDTokenWith(claims, RPTestTamper{})
}

// IDTokenWith is IDToken with a deliberate defect.
func (i *RPTestIssuer) IDTokenWith(claims map[string]interface{}, t RPTestTamper) string {
	iat := i.Now().Unix()
	p := map[string]interface{}{
		"iss": i.URL, "aud": i.ClientID, "sub": "user_test", "iat": iat, "exp": iat + 3600, "auth_time": iat,
		"sid": "sid_test", "email": "user@example.com", "email_verified": true,
	}
	for k, v := range i.DefaultClaims {
		p[k] = v
	}
	for k, v := range claims {
		p[k] = v
	}
	if t.Expired {
		p["iat"], p["exp"] = iat-7200, iat-3600
	}
	if t.WrongAudience {
		p["aud"] = "someone_else"
	}
	if t.WrongIssuer {
		p["iss"] = "https://evil.example"
	}
	if t.WrongNonce {
		p["nonce"] = "wrong-nonce"
	}
	if t.NoNonce {
		delete(p, "nonce")
	}
	if i.MutateClaims != nil {
		i.MutateClaims(p)
	}
	if sid, ok := p["sid"].(string); ok {
		i.mu.Lock()
		i.liveSids[sid] = true
		i.mu.Unlock()
	}
	return i.key.jws("JWT", p)
}

// LogoutToken signs a back-channel logout token for sid (and sub), as Atlas
// POSTs it.
func (i *RPTestIssuer) LogoutToken(sid, sub string) string {
	return i.LogoutTokenWith(sid, sub, RPTestTamper{})
}

// LogoutTokenWith is LogoutToken with a deliberate defect (WrongAudience,
// WrongIssuer, Expired apply).
func (i *RPTestIssuer) LogoutTokenWith(sid, sub string, t RPTestTamper) string {
	iat := i.Now().Unix()
	p := map[string]interface{}{
		"iss": i.URL, "aud": i.ClientID, "iat": iat, "exp": iat + 120, "jti": rpTestRandom(), "sid": sid,
		"events": map[string]interface{}{BackchannelLogoutEvent: map[string]interface{}{}},
	}
	if sub != "" {
		p["sub"] = sub
	}
	if t.Expired {
		p["iat"], p["exp"] = iat-7200, iat-3600
	}
	if t.WrongAudience {
		p["aud"] = "someone_else"
	}
	if t.WrongIssuer {
		p["iss"] = "https://evil.example"
	}
	return i.key.jws("logout+jwt", p)
}

func rpTestRandom() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// rpTestKey is a signing key for one JWS algorithm, with its public JWK.
type rpTestKey struct {
	alg  string
	sign func(input string) []byte
	jwk  map[string]interface{}
}

func rpTestPad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// newRPTestKey generates a key for alg and panics on an unsupported alg or a
// failing random source.
func newRPTestKey(alg string) *rpTestKey {
	k := &rpTestKey{alg: alg}
	pub := map[string]interface{}{"kid": "rp-test-key", "alg": alg, "use": "sig"}
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	switch alg {
	case "RS256", "PS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		pub["kty"], pub["n"], pub["e"] = "RSA", rpB64(priv.N.Bytes()), rpB64(big.NewInt(int64(priv.E)).Bytes())
		k.sign = func(in string) []byte {
			d := sha256.Sum256([]byte(in))
			var sig []byte
			var err error
			if alg == "RS256" {
				sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d[:])
			} else {
				sig, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			}
			must(err)
			return sig
		}
	case "ES256", "ES384":
		curve, crv, size := elliptic.P256(), "P-256", 32
		if alg == "ES384" {
			curve, crv, size = elliptic.P384(), "P-384", 48
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		must(err)
		pub["kty"], pub["crv"] = "EC", crv
		pub["x"], pub["y"] = rpB64(rpTestPad(priv.X.Bytes(), size)), rpB64(rpTestPad(priv.Y.Bytes(), size))
		k.sign = func(in string) []byte {
			var digest []byte
			if alg == "ES384" {
				d := sha512.Sum384([]byte(in))
				digest = d[:]
			} else {
				d := sha256.Sum256([]byte(in))
				digest = d[:]
			}
			r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
			must(err)
			return append(rpTestPad(r.Bytes(), size), rpTestPad(s.Bytes(), size)...)
		}
	case "EdDSA":
		pk, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		pub["kty"], pub["crv"], pub["x"] = "OKP", "Ed25519", rpB64(pk)
		k.sign = func(in string) []byte { return ed25519.Sign(priv, []byte(in)) }
	default:
		panic("atlas: RPTestIssuer: unsupported alg " + alg)
	}
	k.jwk = pub
	return k
}

// jws signs claims as a compact JWS of the given typ.
func (k *rpTestKey) jws(typ string, claims map[string]interface{}) string {
	h, _ := json.Marshal(map[string]string{"alg": k.alg, "kid": "rp-test-key", "typ": typ})
	p, _ := json.Marshal(claims)
	in := rpB64(h) + "." + rpB64(p)
	return in + "." + rpB64(k.sign(in))
}

func rpTestJSONResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (i *RPTestIssuer) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	rpTestJSONResponse(w, 200, map[string]interface{}{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + "/oauth2/authorize",
		"token_endpoint":                        i.URL + "/oauth2/token",
		"userinfo_endpoint":                     i.URL + "/oauth2/userinfo",
		"jwks_uri":                              i.URL + "/.well-known/jwks.json",
		"end_session_endpoint":                  i.URL + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{i.Alg},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (i *RPTestIssuer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	rpTestJSONResponse(w, 200, map[string]interface{}{"keys": []map[string]interface{}{i.key.jwk}})
}

// serveAuthorize is the browser hop: it records the request and redirects back
// with a code, as if the user had signed in.
func (i *RPTestIssuer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	back, err := i.issueCode(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, back, http.StatusFound)
}

// clientOK checks client authentication like the token endpoint: Basic or a
// client_secret in the body, unless PublicClient.
func (i *RPTestIssuer) clientOK(r *http.Request) bool {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != i.ClientID {
		return false
	}
	if i.PublicClient {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(i.ClientSecret)) == 1
}

func (i *RPTestIssuer) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rpTestJSONResponse(w, 405, map[string]string{"error": "invalid_request"})
		return
	}
	_ = r.ParseForm()
	i.mu.Lock()
	i.lastTokenForm, i.lastTokenAuth = r.PostForm, r.Header.Get("Authorization")
	i.mu.Unlock()
	if i.TokenStatus != 0 {
		rpTestJSONResponse(w, i.TokenStatus, map[string]string{"error": "invalid_grant", "error_description": "code expired"})
		return
	}
	if !i.clientOK(r) {
		rpTestJSONResponse(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		rpTestJSONResponse(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	code := r.PostForm.Get("code")
	i.mu.Lock()
	pending, ok := i.codes[code]
	delete(i.codes, code) // single use
	claims, tamper := i.nextClaims, i.nextTamper
	if ok {
		i.nextClaims, i.nextTamper = nil, RPTestTamper{}
	}
	i.mu.Unlock()
	if !ok || pending.redirectURI != r.PostForm.Get("redirect_uri") {
		rpTestJSONResponse(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	if pending.challenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if rpB64(sum[:]) != pending.challenge {
			rpTestJSONResponse(w, 400, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}
	access := i.AccessToken
	if access == "" {
		access = "at_" + rpTestRandom()
	}
	sum := sha256.Sum256([]byte(access))
	p := map[string]interface{}{"at_hash": rpB64(sum[:16])}
	if pending.nonce != "" {
		p["nonce"] = pending.nonce
	}
	for k, v := range claims {
		p[k] = v
	}
	idToken := i.IDTokenWith(p, tamper)
	if i.RawIDToken != "" {
		idToken = i.RawIDToken
	}
	refresh := i.RefreshToken
	if refresh == "" {
		refresh = "rt_" + rpTestRandom()
	}
	var decoded map[string]interface{}
	if parts := strings.Split(idToken, "."); len(parts) == 3 {
		if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(raw, &decoded)
		}
	}
	i.mu.Lock()
	i.access[access] = decoded
	i.mu.Unlock()
	rpTestJSONResponse(w, 200, map[string]interface{}{
		"access_token": access, "token_type": "Bearer", "expires_in": 3600,
		"refresh_token": refresh, "id_token": idToken,
	})
}

func (i *RPTestIssuer) serveUserinfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	i.mu.Lock()
	claims, ok := i.access[token]
	i.mu.Unlock()
	if !ok {
		rpTestJSONResponse(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	out := map[string]interface{}{}
	for k, v := range claims {
		switch k {
		case "iss", "aud", "iat", "exp", "nonce", "at_hash", "auth_time":
		default:
			out[k] = v
		}
	}
	rpTestJSONResponse(w, 200, out)
}

// serveEndSession redirects to post_logout_redirect_uri (with state) like the
// real end-session endpoint.
func (i *RPTestIssuer) serveEndSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("post_logout_redirect_uri")
	if target == "" {
		rpTestJSONResponse(w, 200, map[string]bool{"ok": true})
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "bad post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Has("state") {
		uq := u.Query()
		uq.Set("state", q.Get("state"))
		u.RawQuery = uq.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// serveSession answers the app-session touch and end calls for live sids.
func (i *RPTestIssuer) serveSession(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ending := strings.HasSuffix(r.URL.Path, "/end")
	i.mu.Lock()
	if ending {
		i.appEndCalls++
	} else {
		i.lastAppTouchForm, i.lastAppTouchAuth = r.PostForm, r.Header.Get("Authorization")
	}
	i.mu.Unlock()
	if i.AppTouchStatus != 0 {
		if ending {
			rpTestJSONResponse(w, 200, map[string]bool{"ok": true})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(i.AppTouchStatus)
		_, _ = w.Write([]byte(i.AppTouchBody))
		return
	}
	if !i.clientOK(r) {
		rpTestJSONResponse(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	sid := strings.TrimSpace(r.PostForm.Get("sid"))
	if sid == "" {
		rpTestJSONResponse(w, 400, map[string]string{"error": "invalid_request", "error_description": "Missing sid."})
		return
	}
	i.mu.Lock()
	live := i.liveSids[sid]
	if live && ending {
		delete(i.liveSids, sid)
	}
	i.mu.Unlock()
	if !live {
		rpTestJSONResponse(w, 404, map[string]string{"error": "session_not_found", "error_description": "No live sign-in of this app has that sid."})
		return
	}
	if ending {
		rpTestJSONResponse(w, 200, map[string]interface{}{"object": "oauth_session", "sid": sid, "active": false, "ended": true, "grants_revoked": 0, "backchannel_logouts": 1})
		return
	}
	rpTestJSONResponse(w, 200, map[string]interface{}{
		"object": "oauth_session", "sid": sid, "active": true, "grants_touched": 0,
		"idle_expires_at": i.Now().Add(30 * 24 * time.Hour).UnixMilli(), "expires_at": nil,
	})
}

// serveAPISession answers the Backend API session calls RPConfig.SecretKey
// turns on: touch (scripted by SessionTouchStatus / SessionTouchBody) and revoke.
func (i *RPTestIssuer) serveAPISession(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	i.lastSessionAuth = r.Header.Get("Authorization")
	revoke := strings.HasSuffix(r.URL.Path, "/revoke")
	if revoke {
		i.revokeCalls++
	} else {
		i.touchCalls++
	}
	i.mu.Unlock()
	if revoke {
		rpTestJSONResponse(w, 200, map[string]string{"object": "session"})
		return
	}
	status, body := i.SessionTouchStatus, i.SessionTouchBody
	if status == 0 {
		status = 200
	}
	if body == "" {
		body = `{"idle_expires_at":"2030-01-01T00:00:00Z"}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// serveAPIOAuthClient answers the server-side logout call under /v1/oauth_clients/.
func (i *RPTestIssuer) serveAPIOAuthClient(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)
	i.mu.Lock()
	i.oauthClientCalls++
	i.oauthClientBody = string(buf[:n])
	i.mu.Unlock()
	rpTestJSONResponse(w, 200, map[string]bool{"ok": true})
}
