package atlas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---- the shared fake issuer ---------------------------------------------------------

// newRPTestIssuer is an RPTestIssuer for client_1 with the claims and tokens
// these tests assert on.
func newRPTestIssuer(t *testing.T) *RPTestIssuer {
	t.Helper()
	iss := NewRPTestIssuer("client_1")
	iss.ClientSecret = "shh"
	iss.AccessToken, iss.RefreshToken = "at_1", "rt_1"
	iss.AppTouchStatus, iss.AppTouchBody = 200, `{}`
	iss.DefaultClaims = map[string]interface{}{
		"sub": "user_1", "sid": "sess_1", "email": "ada@example.com", "name": "Ada", "org_id": "org_1", "org_role": "admin",
	}
	t.Cleanup(iss.Close)
	return iss
}

// rpTestAuthorize plays the user signing in at authorizeURL and returns the code.
func rpTestAuthorize(t *testing.T, iss *RPTestIssuer, authorizeURL string) string {
	t.Helper()
	back, err := iss.Authorize(authorizeURL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	u, err := url.Parse(back)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

func newRPTest(t *testing.T, iss *RPTestIssuer, mod func(*RPConfig)) *RelyingParty {
	t.Helper()
	cfg := RPConfig{
		Issuer: iss.URL, ClientID: "client_1", ClientSecret: "shh", RedirectURI: "http://127.0.0.1:3000/auth/callback",
		Secret: strings.Repeat("s", 40), HTTPClient: iss.HTTPClient(), APIURL: iss.URL,
	}
	if mod != nil {
		mod(&cfg)
	}
	rp, err := NewRelyingParty(cfg)
	if err != nil {
		t.Fatalf("NewRelyingParty: %v", err)
	}
	return rp
}

// rpTestCallback starts a sign-in and calls Callback with what a browser would send back.
func rpTestCallback(t *testing.T, rp *RelyingParty, iss *RPTestIssuer, so RPStartOptions, tweak func(q url.Values, req *http.Request)) (*RPCallbackResult, error) {
	t.Helper()
	start, err := rp.Start(context.Background(), so)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	back, err := iss.Authorize(start.URL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	bu, err := url.Parse(back)
	if err != nil {
		t.Fatal(err)
	}
	q := bu.Query()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/auth/callback", nil)
	req.AddCookie(start.Cookie)
	if tweak != nil {
		tweak(q, req)
	}
	req.URL.RawQuery = q.Encode()
	return rp.Callback(context.Background(), req)
}

func rpTestCode(err error) RPErrorCode {
	var re *RPError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

// ---- construction ------------------------------------------------------------------

func TestRPNewRelyingPartyValidation(t *testing.T) {
	good := RPConfig{Issuer: "https://auth.example.com", ClientID: "c", RedirectURI: "https://app.example.com/cb", Secret: strings.Repeat("x", 32)}
	if _, err := NewRelyingParty(good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	cases := map[string]func(c *RPConfig){
		"no issuer":            func(c *RPConfig) { c.Issuer = "" },
		"no client":            func(c *RPConfig) { c.ClientID = "" },
		"short secret":         func(c *RPConfig) { c.Secret = "short" },
		"http redirect":        func(c *RPConfig) { c.RedirectURI = "http://app.example.com/cb" },
		"relative redirect":    func(c *RPConfig) { c.RedirectURI = "/cb" },
		"open after sign-in":   func(c *RPConfig) { c.AfterSignInPath = "//evil.example" },
		"owned forward param":  func(c *RPConfig) { c.ForwardParams = []string{"state"} },
		"odd forward param":    func(c *RPConfig) { c.ForwardParams = []string{"a b"} },
		"short session secret": func(c *RPConfig) { c.SessionSecrets = []string{"short"} },
	}
	for name, mod := range cases {
		c := good
		mod(&c)
		if _, err := NewRelyingParty(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	local := good
	local.RedirectURI = "http://localhost:3000/cb"
	if _, err := NewRelyingParty(local); err != nil {
		t.Errorf("a localhost http redirect must be accepted: %v", err)
	}
}

func TestRPIsSafeReturnTo(t *testing.T) {
	for _, ok := range []string{"/", "/a", "/a/b?x=1#y"} {
		if !RPIsSafeReturnTo(ok) {
			t.Errorf("%q should be safe", ok)
		}
	}
	for _, bad := range []string{"", "a", "//evil.example", "/\\evil.example", "https://evil.example", "/a\nb", "/a\\b"} {
		if RPIsSafeReturnTo(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// ---- start ---------------------------------------------------------------------------

func TestRPStartBuildsAuthorizeURL(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) { c.ForwardParams = []string{"ref"} })
	maxAge := 300
	res, err := rp.Start(context.Background(), RPStartOptions{
		Prompt: "login", LoginHint: "ada@example.com", Organization: "acme", UILocales: "fr", MaxAge: &maxAge, ReturnTo: "/dash",
		ExtraParams: map[string]string{"ref": "abc", "state": "evil", "x": "1"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(res.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.URL, iss.URL+"/oauth2/authorize?") {
		t.Fatalf("unexpected authorize URL %s", res.URL)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "client_1", "redirect_uri": "http://127.0.0.1:3000/auth/callback",
		"scope": "openid profile email", "code_challenge_method": "S256", "prompt": "login", "login_hint": "ada@example.com",
		"organization": "acme", "ui_locales": "fr", "max_age": "300", "ref": "abc", "x": "1",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("state") != res.State || q.Get("state") == "evil" {
		t.Errorf("state must be the generated one, got %q", q.Get("state"))
	}
	if q.Get("nonce") != res.Nonce || q.Get("code_challenge") == "" {
		t.Errorf("nonce or code_challenge missing")
	}
	c := res.Cookie
	if c.Name != "atlas_oidc" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/auth/callback" || c.MaxAge != 600 {
		t.Errorf("unexpected flow cookie %+v", c)
	}
	if c.Secure {
		t.Errorf("a plain-http localhost callback must not set Secure")
	}
	if !strings.HasPrefix(c.Value, "s1.") || strings.Contains(c.Value, "client_1") {
		t.Errorf("flow cookie must be sealed, got %q", c.Value)
	}
	if _, err := rp.Start(context.Background(), RPStartOptions{ReturnTo: "//evil.example"}); rpTestCode(err) != RPErrInvalidRequest {
		t.Errorf("an unsafe ReturnTo must be refused, got %v", err)
	}
	if _, err := rp.Start(context.Background(), RPStartOptions{Scope: "email"}); err != nil {
		t.Errorf("Start with scope: %v", err)
	}
}

func TestRPStartSecureCookieOnHTTPS(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) { c.RedirectURI = "https://app.example.com/auth/callback" })
	res, err := rp.Start(context.Background(), RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cookie.Secure {
		t.Errorf("an https callback must set Secure")
	}
}

func TestRPStartDiscoveryFailure(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) { c.Issuer = iss.URL + "/nowhere" })
	if _, err := rp.Start(context.Background(), RPStartOptions{}); rpTestCode(err) != RPErrDiscoveryFailed {
		t.Fatalf("want discovery_failed, got %v", err)
	}
}

// ---- callback -------------------------------------------------------------------------

func TestRPCallbackHappyPath(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	res, err := rpTestCallback(t, rp, iss, RPStartOptions{ReturnTo: "/dash"}, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	u := res.User
	if u.Sub != "user_1" || u.SID != "sess_1" || u.Email != "ada@example.com" || !u.EmailVerified || u.Name != "Ada" || u.OrgID != "org_1" || u.OrgRole != "admin" || u.AuthTime == 0 {
		t.Errorf("unexpected user %+v", u)
	}
	if u.NamespacedSub != iss.URL+"#user_1" {
		t.Errorf("namespaced sub = %q", u.NamespacedSub)
	}
	if res.ReturnTo != "/dash" {
		t.Errorf("return_to = %q", res.ReturnTo)
	}
	if res.Tokens.AccessToken != "at_1" || res.Tokens.RefreshToken != "rt_1" || res.Tokens.IDToken == "" || !res.Tokens.ExpiresAt.After(time.Now()) {
		t.Errorf("unexpected tokens %+v", res.Tokens)
	}
	if res.ClearCookie == nil || res.ClearCookie.MaxAge >= 0 {
		t.Errorf("the flow cookie must be cleared")
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("client_1:shh"))
	if iss.LastTokenAuth() != basic {
		t.Errorf("token endpoint auth = %q", iss.LastTokenAuth())
	}
	if iss.LastTokenForm().Get("grant_type") != "authorization_code" || !strings.HasPrefix(iss.LastTokenForm().Get("code"), "code_") ||
		iss.LastTokenForm().Get("redirect_uri") != "http://127.0.0.1:3000/auth/callback" || iss.LastTokenForm().Get("client_id") != "" {
		t.Errorf("unexpected token form %v", iss.LastTokenForm())
	}
	if iss.LastTokenForm().Get("code_verifier") == "" {
		t.Errorf("PKCE verifier missing")
	}
}

func TestRPCallbackPKCEChallengeMatchesVerifier(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	start, err := rp.Start(context.Background(), RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.URL)
	authCode := rpTestAuthorize(t, iss, start.URL)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/auth/callback?code="+authCode+"&state="+start.State, nil)
	req.AddCookie(start.Cookie)
	if _, err := rp.Callback(context.Background(), req); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	sum := sha256.Sum256([]byte(iss.LastTokenForm().Get("code_verifier")))
	if rpB64(sum[:]) != u.Query().Get("code_challenge") {
		t.Errorf("code_challenge is not S256(code_verifier)")
	}
}

func TestRPCallbackPostAndPublicClientAuth(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) { c.ClientAuth = RPClientAuthPost })
	if _, err := rpTestCallback(t, rp, iss, RPStartOptions{}, nil); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if iss.LastTokenForm().Get("client_id") != "client_1" || iss.LastTokenForm().Get("client_secret") != "shh" || iss.LastTokenAuth() != "" {
		t.Errorf("client_secret_post not used: %v / %q", iss.LastTokenForm(), iss.LastTokenAuth())
	}
	iss.PublicClient = true // the registered client is public: PKCE only, no secret
	pub := newRPTest(t, iss, func(c *RPConfig) { c.ClientSecret = "" })
	if _, err := rpTestCallback(t, pub, iss, RPStartOptions{}, nil); err != nil {
		t.Fatalf("public client Callback: %v", err)
	}
	if iss.LastTokenForm().Get("client_id") != "client_1" || iss.LastTokenForm().Get("client_secret") != "" || iss.LastTokenAuth() != "" {
		t.Errorf("a public client must send only client_id: %v / %q", iss.LastTokenForm(), iss.LastTokenAuth())
	}
}

func TestRPCallbackRefusals(t *testing.T) {
	zero := 0
	cases := []struct {
		name  string
		code  RPErrorCode
		start RPStartOptions
		setup func(iss *RPTestIssuer)
		tweak func(q url.Values, req *http.Request)
	}{
		{name: "state mismatch", code: RPErrStateMismatch, tweak: func(q url.Values, req *http.Request) { q.Set("state", "other") }},
		{name: "missing state", code: RPErrStateMismatch, tweak: func(q url.Values, req *http.Request) { q.Del("state") }},
		{name: "no flow cookie", code: RPErrStateMismatch, tweak: func(q url.Values, req *http.Request) { req.Header.Del("Cookie") }},
		{name: "garbage flow cookie", code: RPErrStateMismatch, tweak: func(q url.Values, req *http.Request) {
			req.Header.Set("Cookie", "atlas_oidc=s1.AAAA.BBBB")
		}},
		{name: "plain flow cookie downgrade", code: RPErrStateMismatch, tweak: func(q url.Values, req *http.Request) {
			req.Header.Set("Cookie", "atlas_oidc=p1."+rpB64([]byte(`{"s":"x"}`)))
		}},
		{name: "wrong iss parameter", code: RPErrIssuerMismatch, tweak: func(q url.Values, req *http.Request) { q.Set("iss", "https://evil.example") }},
		{name: "authorization error", code: RPErrAccessDenied, tweak: func(q url.Values, req *http.Request) {
			q.Set("error", "access_denied")
			q.Del("code")
		}},
		{name: "no code", code: RPErrInvalidRequest, tweak: func(q url.Values, req *http.Request) { q.Del("code") }},
		{name: "token endpoint error", code: RPErrTokenExchangeFailed, setup: func(iss *RPTestIssuer) { iss.TokenStatus = 400 }},
		{name: "nonce mismatch", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["nonce"] = "someone-else" }
		}},
		{name: "no nonce", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { delete(c, "nonce") }
		}},
		{name: "wrong audience", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["aud"] = "other_client" }
		}},
		{name: "several audiences without azp", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["aud"] = []string{"client_1", "other"} }
		}},
		{name: "wrong azp", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["azp"] = "other_client" }
		}},
		{name: "wrong issuer claim", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["iss"] = "https://evil.example" }
		}},
		{name: "expired", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["exp"] = time.Now().Unix() - 3600 }
		}},
		{name: "issued in the future", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["iat"] = time.Now().Unix() + 3600 }
		}},
		{name: "bad at_hash", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" }
		}},
		{name: "no sub", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { delete(c, "sub") }
		}},
		{name: "alg none", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.RawIDToken = rpB64([]byte(`{"alg":"none"}`)) + "." + rpB64([]byte(`{"sub":"user_1"}`)) + "."
		}},
		{name: "alg HS256", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			iss.RawIDToken = rpB64([]byte(`{"alg":"HS256","kid":"k1"}`)) + "." + rpB64([]byte(`{"sub":"user_1"}`)) + ".c2ln"
		}},
		{name: "forged signature", code: RPErrInvalidToken, setup: func(iss *RPTestIssuer) {
			now := time.Now().Unix()
			iss.RawIDToken = newRPTestKey("ES256").jws("JWT", map[string]interface{}{
				"iss": iss.URL, "sub": "user_1", "aud": "client_1", "iat": now, "exp": now + 60, "nonce": "ignored",
			})
		}},
		{name: "max_age with an old auth_time", code: RPErrReauthenticationRequired, start: RPStartOptions{MaxAge: &zero}, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { c["auth_time"] = time.Now().Unix() - 3600 }
		}},
		{name: "max_age without auth_time", code: RPErrReauthenticationRequired, start: RPStartOptions{MaxAge: &zero}, setup: func(iss *RPTestIssuer) {
			iss.MutateClaims = func(c map[string]interface{}) { delete(c, "auth_time") }
		}},
		{name: "another user confirmed", code: RPErrSubjectMismatch, start: RPStartOptions{ExpectedSub: "user_2"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			iss := newRPTestIssuer(t)
			rp := newRPTest(t, iss, nil)
			if tc.setup != nil {
				tc.setup(iss)
			}
			res, err := rpTestCallback(t, rp, iss, tc.start, tc.tweak)
			if err == nil {
				t.Fatalf("expected %s, got a sign-in for %+v", tc.code, res.User)
			}
			var re *RPError
			if !errors.As(err, &re) {
				t.Fatalf("error is not an *RPError: %v", err)
			}
			if re.Code != tc.code {
				t.Errorf("code = %s (%s), want %s", re.Code, re.Message, tc.code)
			}
			if re.ClearCookie == nil || re.ClearCookie.MaxAge >= 0 {
				t.Errorf("every failure must carry a cookie that clears the flow")
			}
		})
	}
}

func TestRPCallbackMaxAgeAcceptsFreshAuth(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	maxAge := 120
	if _, err := rpTestCallback(t, rp, iss, RPStartOptions{MaxAge: &maxAge, ExpectedSub: "user_1"}, nil); err != nil {
		t.Fatalf("a fresh sign-in for the expected user must pass: %v", err)
	}
}

func TestRPCallbackFlowCookieExpires(t *testing.T) {
	iss := newRPTestIssuer(t)
	clock := time.Now()
	rp := newRPTest(t, iss, func(c *RPConfig) { c.Now = func() time.Time { return clock } })
	start, err := rp.Start(context.Background(), RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(11 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/auth/callback?code=c&state="+start.State, nil)
	req.AddCookie(start.Cookie)
	if _, err := rp.Callback(context.Background(), req); rpTestCode(err) != RPErrStateMismatch {
		t.Fatalf("a sign-in older than ten minutes must be refused, got %v", err)
	}
}

func TestRPVerifyIDTokenStandalone(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	now := time.Now().Unix()
	token := iss.key.jws("JWT", map[string]interface{}{
		"iss": iss.URL, "sub": "u", "aud": []string{"client_1"}, "iat": now, "exp": now + 60, "nonce": "n1",
	})
	claims, err := rp.VerifyIDToken(context.Background(), token, "n1", "")
	if err != nil || claims["sub"] != "u" {
		t.Fatalf("VerifyIDToken: %v %v", claims, err)
	}
	if _, err := rp.VerifyIDToken(context.Background(), token, "n2", ""); rpTestCode(err) != RPErrInvalidToken {
		t.Fatalf("a wrong nonce must be refused, got %v", err)
	}
}

// ---- step-up ----------------------------------------------------------------------------

func TestRPRequireRecentAuth(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	now := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/settings?tab=security", nil)

	if res, err := rp.RequireRecentAuth(context.Background(), req, 300, RPRecentAuthOptions{Sub: "user_1", AuthTime: now - 10}); err != nil || res != nil {
		t.Fatalf("a recent auth_time needs no step-up: %v %v", res, err)
	}
	if res, err := rp.RequireRecentAuth(context.Background(), req, 0, RPRecentAuthOptions{Sub: "user_1", AuthTime: now - 5}); err != nil || res != nil {
		t.Fatalf("0 passes inside the confirmation window: %v %v", res, err)
	}
	res, err := rp.RequireRecentAuth(context.Background(), req, 60, RPRecentAuthOptions{Sub: "user_1", AuthTime: now - 600})
	if err != nil || res == nil {
		t.Fatalf("an old auth_time must start a step-up: %v %v", res, err)
	}
	u, _ := url.Parse(res.URL)
	if u.Query().Get("max_age") != "60" || u.Query().Get("prompt") != "" {
		t.Errorf("unexpected step-up URL %s", res.URL)
	}
	res, err = rp.RequireRecentAuth(context.Background(), req, 0, RPRecentAuthOptions{Sub: "user_1", AuthTime: now - 600})
	if err != nil || res == nil {
		t.Fatalf("expected a step-up: %v", err)
	}
	u, _ = url.Parse(res.URL)
	if u.Query().Get("max_age") != "0" || u.Query().Get("prompt") != "login" {
		t.Errorf("0 must force a login: %s", res.URL)
	}
	if _, err := rp.RequireRecentAuth(context.Background(), req, 60, RPRecentAuthOptions{AuthTime: now}); rpTestCode(err) != RPErrInvalidRequest {
		t.Errorf("Sub is required, got %v", err)
	}

	// The callback of a step-up refuses another user and carries the return path.
	authCode := rpTestAuthorize(t, iss, res.URL)
	rq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/auth/callback?code="+authCode+"&state="+res.State, nil)
	rq.AddCookie(res.Cookie)
	out, err := rp.Callback(context.Background(), rq)
	if err != nil {
		t.Fatalf("step-up Callback: %v", err)
	}
	if out.ReturnTo != "/settings?tab=security" {
		t.Errorf("return_to = %q", out.ReturnTo)
	}
}

// ---- the session cookie -------------------------------------------------------------------

func TestRPSessionSealOpenRotationAndTamper(t *testing.T) {
	iss := newRPTestIssuer(t)
	oldSecret, newSecret := strings.Repeat("o", 32), strings.Repeat("n", 32)
	before := newRPTest(t, iss, func(c *RPConfig) { c.SessionSecrets = []string{oldSecret} })
	sess := &RPSession{Sub: "user_1", SID: "sess_1", Email: "a@b.co", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	value, err := before.SealSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	got, err := before.OpenSession(value)
	if err != nil || got.Sub != "user_1" || got.SID != "sess_1" {
		t.Fatalf("OpenSession: %+v %v", got, err)
	}

	rotated := newRPTest(t, iss, func(c *RPConfig) { c.SessionSecrets = []string{newSecret, oldSecret} })
	if _, err := rotated.OpenSession(value); err != nil {
		t.Errorf("a session signed with the old secret must still open during rotation: %v", err)
	}
	fresh, err := rotated.SealSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	retired := newRPTest(t, iss, func(c *RPConfig) { c.SessionSecrets = []string{newSecret} })
	if _, err := retired.OpenSession(fresh); err != nil {
		t.Errorf("a session signed with the new secret must open: %v", err)
	}
	if _, err := retired.OpenSession(value); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("a session signed with a retired secret must be refused, got %v", err)
	}

	tampered := value[:len(value)-2] + "AA"
	if _, err := before.OpenSession(tampered); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("a tampered signature must be refused, got %v", err)
	}
	parts := strings.Split(value, ".")
	forged := parts[0] + "." + rpB64([]byte(`{"sub":"admin","exp":99999999999}`)) + "." + parts[2]
	if _, err := before.OpenSession(forged); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("a tampered payload must be refused, got %v", err)
	}
	for _, junk := range []string{"", "nonsense", "v1.", "v1.a.b", "v2." + parts[1] + "." + parts[2]} {
		if _, err := before.OpenSession(junk); rpTestCode(err) != RPErrInvalidSession {
			t.Errorf("%q must be refused, got %v", junk, err)
		}
	}

	clock := time.Now()
	timed := newRPTest(t, iss, func(c *RPConfig) {
		c.SessionSecrets = []string{oldSecret}
		c.Now = func() time.Time { return clock }
	})
	clock = clock.Add(2 * time.Hour)
	if _, err := timed.OpenSession(value); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("an expired session must be refused, got %v", err)
	}
}

func TestRPSessionCookieAttributes(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.RedirectURI = "https://app.example.com/auth/callback"
		c.SessionCookieName = "app_sess"
	})
	now := time.Now()
	c, err := rp.SessionCookie(&RPSession{Sub: "u", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "app_sess" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge < 3500 || c.MaxAge > 3600 {
		t.Errorf("unexpected session cookie %+v", c)
	}
	if clr := rp.ClearSessionCookie(); clr.MaxAge >= 0 || clr.Name != "app_sess" {
		t.Errorf("unexpected clearing cookie %+v", clr)
	}
	huge := &RPSession{Sub: "u", Name: strings.Repeat("x", 5000), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	if _, err := rp.SealSession(huge); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("an oversized session must be refused, got %v", err)
	}
}

// ---- touch --------------------------------------------------------------------------------

func TestRPTouchIfDueWithSecretKey(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) { c.SecretKey = "sk_test_1" })
	ctx := context.Background()

	recent := time.Now().Add(-time.Minute)
	res, err := rp.TouchIfDue(ctx, "sess_1", recent)
	if err != nil || res.Status != RPTouchSkipped || !res.LastTouchedAt.Equal(recent) || iss.SessionTouchCalls() != 0 {
		t.Fatalf("a recent touch must be skipped: %+v %v (%d calls)", res, err, iss.SessionTouchCalls())
	}
	res, err = rp.TouchIfDue(ctx, "sess_1", time.Time{})
	if err != nil || res.Status != RPTouchTouched || res.IdleExpiresAt != "2030-01-01T00:00:00Z" || iss.SessionTouchCalls() != 1 {
		t.Fatalf("expected a touch: %+v %v", res, err)
	}
	if iss.LastSessionAuth() != "Bearer sk_test_1" {
		t.Errorf("touch auth = %q", iss.LastSessionAuth())
	}
	res, err = rp.TouchIfDue(ctx, "sess_1", time.Now().Add(-10*time.Minute))
	if err != nil || res.Status != RPTouchTouched {
		t.Fatalf("an old touch is due again: %+v %v", res, err)
	}

	cases := []struct {
		status int
		body   string
		reason string
	}{
		{404, `{"errors":[{"code":"NOT_FOUND","message":"x"}]}`, "not_found"},
		{409, `{"errors":[{"code":"SESSION_REVOKED","message":"x"}]}`, "revoked"},
		{409, `{"errors":[{"code":"SESSION_IDLE_EXPIRED","message":"x"}]}`, "idle_expired"},
		{409, `{"errors":[{"code":"SESSION_EXPIRED","message":"x"}]}`, "expired"},
	}
	for _, tc := range cases {
		iss.SessionTouchStatus, iss.SessionTouchBody = tc.status, tc.body
		res, err = rp.TouchIfDue(ctx, "sess_1", time.Time{})
		if err != nil || res.Status != RPTouchEnded || res.Reason != tc.reason {
			t.Errorf("%d %s: got %+v %v, want ended/%s", tc.status, tc.body, res, err, tc.reason)
		}
	}
	iss.SessionTouchStatus, iss.SessionTouchBody = 500, `{"errors":[{"code":"INTERNAL","message":"boom"}]}`
	_, err = rp.TouchIfDue(ctx, "sess_1", time.Time{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Errorf("an API failure is an error, not 'ended': %v", err)
	}
	if _, err := rp.TouchIfDue(ctx, "", time.Time{}); rpTestCode(err) != RPErrInvalidRequest {
		t.Errorf("a missing sid is an error, got %v", err)
	}
}

func TestRPTouchIfDueWithClientCredentials(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, nil)
	ctx := context.Background()
	res, err := rp.TouchIfDue(ctx, "sess_1", time.Time{})
	if err != nil || res.Status != RPTouchTouched {
		t.Fatalf("expected a touch: %+v %v", res, err)
	}
	if iss.LastAppTouchForm().Get("sid") != "sess_1" || iss.LastAppTouchAuth() != "Basic "+base64.StdEncoding.EncodeToString([]byte("client_1:shh")) {
		t.Errorf("unexpected app touch call: %v %q", iss.LastAppTouchForm(), iss.LastAppTouchAuth())
	}
	iss.AppTouchStatus, iss.AppTouchBody = 404, `{"error":"session_not_found"}`
	res, err = rp.TouchIfDue(ctx, "sess_1", time.Time{})
	if err != nil || res.Status != RPTouchEnded || res.Reason != "not_found" {
		t.Errorf("an unknown sign-in is ended/not_found: %+v %v", res, err)
	}
	iss.AppTouchStatus, iss.AppTouchBody = 503, `{"error":"temporarily_unavailable"}`
	if _, err := rp.TouchIfDue(ctx, "sess_1", time.Time{}); rpTestCode(err) != RPErrSessionCallFailed {
		t.Errorf("an outage is an error, got %v", err)
	}
	if out, err := rp.EndAppSession(ctx, "sess_1"); err != nil || out != "ended" || iss.AppEndCalls() != 1 {
		t.Errorf("EndAppSession: %q %v", out, err)
	}
	pub := newRPTest(t, iss, func(c *RPConfig) { c.ClientSecret = "" })
	if _, err := pub.TouchIfDue(ctx, "sess_1", time.Time{}); rpTestCode(err) != RPErrNotConfigured {
		t.Errorf("a public client with no key cannot touch, got %v", err)
	}
}

// ---- sign-out -----------------------------------------------------------------------------

func TestRPSignOut(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.SecretKey = "sk_test_1"
		c.PostLogoutRedirectURI = "https://app.example.com/bye"
	})
	loc, err := rp.SignOut(context.Background(), RPSignOutOptions{SID: "sess_1", IDToken: "idt", State: "st"})
	if err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	if iss.SessionRevokeCalls() != 1 {
		t.Errorf("the Atlas session must be revoked server-side, got %d calls", iss.SessionRevokeCalls())
	}
	u, _ := url.Parse(loc)
	if !strings.HasPrefix(loc, iss.URL+"/oauth2/logout?") || u.Query().Get("id_token_hint") != "idt" || u.Query().Get("client_id") != "client_1" ||
		u.Query().Get("post_logout_redirect_uri") != "https://app.example.com/bye" || u.Query().Get("state") != "st" {
		t.Errorf("unexpected logout URL %s", loc)
	}

	srv := newRPTest(t, iss, func(c *RPConfig) {
		c.SecretKey = "sk_test_1"
		c.ServerSignOut = true
		c.PostLogoutRedirectURI = "/bye"
	})
	before := iss.SessionRevokeCalls()
	loc, err = srv.SignOut(context.Background(), RPSignOutOptions{SID: "sess_1", State: "st"})
	if err != nil {
		t.Fatalf("server sign-out: %v", err)
	}
	if iss.OAuthClientCalls() != 1 || !strings.Contains(iss.LastOAuthClientBody(), "sess_1") || iss.SessionRevokeCalls() != before {
		t.Errorf("server sign-out must make the one logout call: %d %q", iss.OAuthClientCalls(), iss.LastOAuthClientBody())
	}
	if loc != "/bye?state=st" {
		t.Errorf("location = %q", loc)
	}
}

// ---- net/http ------------------------------------------------------------------------------

func rpTestCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestRPHandlerSignInCallbackSignOutAndMiddleware(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.SecretKey = "sk_test_1"
		c.ForwardParams = []string{"ref"}
		c.PostLogoutRedirectURI = "https://app.example.com/bye"
	})
	h := rp.Handler()

	// sign-in
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/sign-in?return_to=/private&ref=abc&evil=1&max_age=900&return_to2=x", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("sign-in status = %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(rec.Header().Get("Location"), iss.URL+"/oauth2/authorize?") || loc.Query().Get("ref") != "abc" || loc.Query().Get("evil") != "" || loc.Query().Get("max_age") != "900" {
		t.Fatalf("unexpected authorize redirect %s", rec.Header().Get("Location"))
	}
	flow := rpTestCookie(rec.Result(), "atlas_oidc")
	if flow == nil {
		t.Fatal("no flow cookie")
	}
	authCode := rpTestAuthorize(t, iss, rec.Header().Get("Location"))

	// callback
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+authCode+"&state="+loc.Query().Get("state"), nil)
	req.AddCookie(flow)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/private" {
		t.Fatalf("callback = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	sess := rpTestCookie(rec.Result(), "atlas_session")
	if sess == nil || !sess.HttpOnly {
		t.Fatalf("no session cookie: %+v", sess)
	}
	if clr := rpTestCookie(rec.Result(), "atlas_oidc"); clr == nil || clr.MaxAge >= 0 {
		t.Errorf("the flow cookie must be cleared on the callback response")
	}

	// middleware: with a session
	var seen *RPSession
	app := rp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := RPSessionFromContext(r.Context())
		if !ok {
			t.Errorf("no session on the request context")
			return
		}
		seen = s
		w.WriteHeader(http.StatusNoContent)
	}))
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(sess)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen == nil || seen.Sub != "user_1" || seen.SID != "sess_1" || seen.Email != "ada@example.com" {
		t.Fatalf("middleware with a session: %d %+v", rec.Code, seen)
	}

	// middleware: without
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private?x=1", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/auth/sign-in?return_to=%2Fprivate%3Fx%3D1" {
		t.Errorf("no session on GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/private", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no session on POST = %d", rec.Code)
	}
	bad := &http.Cookie{Name: "atlas_session", Value: sess.Value[:len(sess.Value)-3] + "AAA"}
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(bad)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("a forged cookie must not pass: %d", rec.Code)
	}

	// middleware: the Atlas session ended
	opened, err := rp.OpenSession(sess.Value)
	if err != nil {
		t.Fatal(err)
	}
	opened.LastTouchedAt = time.Now().Add(-time.Hour).UnixMilli()
	stale, err := rp.SessionCookie(opened)
	if err != nil {
		t.Fatal(err)
	}
	iss.SessionTouchStatus, iss.SessionTouchBody = 409, `{"errors":[{"code":"SESSION_REVOKED","message":"x"}]}`
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(stale)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("an ended Atlas session must sign the user out here too: %d", rec.Code)
	}
	if clr := rpTestCookie(rec.Result(), "atlas_session"); clr == nil || clr.MaxAge >= 0 {
		t.Errorf("the session cookie must be cleared")
	}

	// middleware: a touch refreshes the cookie
	iss.SessionTouchStatus, iss.SessionTouchBody = 200, `{}`
	calls := iss.SessionTouchCalls()
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(stale)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || iss.SessionTouchCalls() != calls+1 {
		t.Errorf("a due touch must be made: %d (%d calls)", rec.Code, iss.SessionTouchCalls()-calls)
	}
	if refreshed := rpTestCookie(rec.Result(), "atlas_session"); refreshed == nil {
		t.Errorf("the touched session cookie must be refreshed")
	}

	// sign-out
	req = httptest.NewRequest(http.MethodGet, "/auth/sign-out", nil)
	req.AddCookie(sess)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), iss.URL+"/oauth2/logout?") || iss.SessionRevokeCalls() != 1 {
		t.Errorf("sign-out = %d %q (%d revokes)", rec.Code, rec.Header().Get("Location"), iss.SessionRevokeCalls())
	}
	if clr := rpTestCookie(rec.Result(), "atlas_session"); clr == nil || clr.MaxAge >= 0 {
		t.Errorf("sign-out must clear the session cookie")
	}

	// other paths
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/elsewhere", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("other paths are a 404, got %d", rec.Code)
	}
}

func TestRPHandlerCallbackFailureAndHooks(t *testing.T) {
	iss := newRPTestIssuer(t)
	var hookErr *RPError
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.OnSignInError = func(w http.ResponseWriter, r *http.Request, err *RPError) {
			hookErr = err
			w.WriteHeader(http.StatusTeapot)
		}
	})
	rec := httptest.NewRecorder()
	rp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state=nope", nil))
	if rec.Code != http.StatusTeapot || hookErr == nil || hookErr.Code != RPErrStateMismatch {
		t.Errorf("OnSignInError not used: %d %+v", rec.Code, hookErr)
	}

	plain := newRPTest(t, iss, nil)
	rec = httptest.NewRecorder()
	plain.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a failed callback is a 400, got %d", rec.Code)
	}

	signed := false
	hooked := newRPTest(t, iss, func(c *RPConfig) {
		c.OnSignedIn = func(w http.ResponseWriter, r *http.Request, res *RPCallbackResult) bool {
			signed = res.User.Sub == "user_1"
			w.WriteHeader(http.StatusAccepted)
			return true
		}
	})
	start, err := hooked.Start(context.Background(), RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	authCode := rpTestAuthorize(t, iss, start.URL)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+authCode+"&state="+start.State, nil)
	req.AddCookie(start.Cookie)
	rec = httptest.NewRecorder()
	hooked.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || !signed || rpTestCookie(rec.Result(), "atlas_session") != nil {
		t.Errorf("OnSignedIn must take over the response: %d signed=%v", rec.Code, signed)
	}
}

func TestRPOptionalSessionAndCustomUnauthenticated(t *testing.T) {
	iss := newRPTestIssuer(t)
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.OnUnauthenticated = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := RPSessionFromContext(r.Context()); ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	rec := httptest.NewRecorder()
	rp.OptionalSession(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusAccepted {
		t.Errorf("optional session without a cookie = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	rp.Middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("custom OnUnauthenticated = %d", rec.Code)
	}
	if _, ok := RPSessionFromContext(context.Background()); ok {
		t.Errorf("an empty context has no session")
	}
}

// ---- back-channel logout ---------------------------------------------------------------------

func rpTestLogoutToken(iss *RPTestIssuer, sid, jti string) string {
	return iss.key.jws("logout+jwt", map[string]interface{}{
		"iss": iss.URL, "aud": "client_1", "iat": time.Now().Unix(), "jti": jti,
		"events": map[string]interface{}{BackchannelLogoutEvent: map[string]interface{}{}}, "sid": sid,
	})
}

func rpTestPost(h http.Handler, path, token string) *httptest.ResponseRecorder {
	form := url.Values{"logout_token": {token}}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRPBackchannelLogout(t *testing.T) {
	iss := newRPTestIssuer(t)
	var gotIDs []string
	var gotClaims *LogoutTokenClaims
	fail := false
	store := &RPMemorySidStore{}
	rp := newRPTest(t, iss, func(c *RPConfig) {
		c.BackchannelLogoutPath = "/auth/backchannel"
		c.SidStore = store
		c.OnBackchannelLogout = func(ctx context.Context, ids []string, claims *LogoutTokenClaims) error {
			if fail {
				return errors.New("db down")
			}
			gotIDs, gotClaims = ids, claims
			return nil
		}
	})
	h := rp.Handler()
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	if err := rp.BindSession(ctx, "sess_1", "app_a", exp); err != nil {
		t.Fatal(err)
	}
	if err := rp.BindSession(ctx, "sess_1", "app_b", exp); err != nil {
		t.Fatal(err)
	}
	if err := rp.BindSession(ctx, "", "x", exp); rpTestCode(err) != RPErrInvalidRequest {
		t.Errorf("BindSession needs a sid, got %v", err)
	}

	// A signed session cookie for that sid is valid until the logout arrives.
	now := time.Now()
	cookieValue, err := rp.SealSession(&RPSession{Sub: "user_1", SID: "sess_1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.OpenSession(cookieValue); err != nil {
		t.Fatalf("session must open before the logout: %v", err)
	}

	// The callback failing answers 503 and keeps the bindings for Atlas's retry.
	fail = true
	if rec := rpTestPost(h, "/auth/backchannel", rpTestLogoutToken(iss, "sess_1", "jti_fail")); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a failing callback = %d", rec.Code)
	}
	fail = false

	rec := rpTestPost(h, "/auth/backchannel", rpTestLogoutToken(iss, "sess_1", "jti_1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d %s", rec.Code, rec.Body.String())
	}
	if len(gotIDs) != 2 || gotClaims == nil || gotClaims.Sid != "sess_1" {
		t.Errorf("OnBackchannelLogout got %v %+v", gotIDs, gotClaims)
	}
	if left, _ := store.Take(ctx, "sess_1"); len(left) != 0 {
		t.Errorf("the bindings must be taken out of the store, left %v", left)
	}
	if _, err := rp.OpenSession(cookieValue); rpTestCode(err) != RPErrInvalidSession {
		t.Errorf("a session of a logged-out sid must no longer open, got %v", err)
	}

	// A replay of the same token is answered 200 without calling the callback again.
	gotIDs = nil
	if rec := rpTestPost(h, "/auth/backchannel", rpTestLogoutToken(iss, "sess_1", "jti_1")); rec.Code != http.StatusOK || gotIDs != nil {
		t.Errorf("a replayed token is answered 200 without ending anything: %d %v", rec.Code, gotIDs)
	}

	// A bad token is a 400.
	if rec := rpTestPost(h, "/auth/backchannel", "not.a.jwt"); rec.Code != http.StatusBadRequest {
		t.Errorf("a bad token = %d", rec.Code)
	}
	forged := iss.key.jws("logout+jwt", map[string]interface{}{
		"iss": "https://evil.example", "aud": "client_1", "iat": time.Now().Unix(), "jti": "j9", "sid": "s",
		"events": map[string]interface{}{BackchannelLogoutEvent: map[string]interface{}{}},
	})
	if rec := rpTestPost(h, "/auth/backchannel", forged); rec.Code != http.StatusBadRequest {
		t.Errorf("a token from another issuer = %d", rec.Code)
	}
}

func TestRPMemorySidStoreExpiry(t *testing.T) {
	clock := time.Now()
	s := &RPMemorySidStore{Now: func() time.Time { return clock }}
	ctx := context.Background()
	_ = s.Bind(ctx, "sid", "a", clock.Add(time.Minute))
	_ = s.Bind(ctx, "sid", "b", clock.Add(time.Hour))
	clock = clock.Add(10 * time.Minute)
	got, err := s.Take(ctx, "sid")
	if err != nil || len(got) != 1 || got[0] != "b" {
		t.Fatalf("Take = %v %v", got, err)
	}
	if again, _ := s.Take(ctx, "sid"); len(again) != 0 {
		t.Errorf("Take removes what it returns, got %v", again)
	}
}
