package atlas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBetterAuthImportsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"better_auth_import","id":"bai_1","status":"ready","data":[{"id":"bai_1"}],"kid":"k1","compact":"k1:pub"}`)

	key, err := c.BetterAuthImports.GetPublicKey(ctx)
	if err != nil || key.Compact != "k1:pub" {
		t.Fatalf("GetPublicKey = %+v, %v", key, err)
	}
	rec.expect(t, "GET", "/v1/better_auth_imports/public_key")
	_, _ = c.BetterAuthImports.RotatePublicKey(ctx)
	rec.expect(t, "POST", "/v1/better_auth_imports/public_key/rotate")
	on := true
	_, _ = c.BetterAuthImports.Create(ctx, CreateBetterAuthImportParams{Options: &BetterAuthImportOptions{ImportSessions: &on, OnEmailConflict: "link"}})
	rec.expect(t, "POST", "/v1/better_auth_imports")
	if opts, _ := rec.Body["options"].(map[string]interface{}); opts["import_sessions"] != true || opts["on_email_conflict"] != "link" {
		t.Errorf("create body = %v", rec.Body)
	}
	page, _ := c.BetterAuthImports.List(ctx, ListParams{Limit: 5, StartingAfter: "bai_0"})
	rec.expect(t, "GET", "/v1/better_auth_imports")
	if rec.Query != "limit=5&starting_after=bai_0" || len(page.Data) != 1 {
		t.Errorf("list query=%q page=%+v", rec.Query, page)
	}
	_, _ = c.BetterAuthImports.Get(ctx, "bai_1")
	rec.expect(t, "GET", "/v1/better_auth_imports/bai_1")
	_, _ = c.BetterAuthImports.UploadPart(ctx, "bai_1", 2, []byte("line\n"))
	rec.expect(t, "PUT", "/v1/better_auth_imports/bai_1/parts/2")
	if rec.RawBody != "line\n" || !strings.HasPrefix(rec.ContentType, "text/plain") {
		t.Errorf("part body=%q type=%q", rec.RawBody, rec.ContentType)
	}
	_, _ = c.BetterAuthImports.Finalize(ctx, "bai_1")
	rec.expect(t, "POST", "/v1/better_auth_imports/bai_1/finalize")
	_, _ = c.BetterAuthImports.DryRun(ctx, "bai_1", CreateBetterAuthImportParams{})
	rec.expect(t, "POST", "/v1/better_auth_imports/bai_1/dry_run")
	_, _ = c.BetterAuthImports.Apply(ctx, "bai_1", ApplyBetterAuthImportParams{ConfirmConflicts: true})
	rec.expect(t, "POST", "/v1/better_auth_imports/bai_1/apply")
	if rec.Body["confirm_conflicts"] != true {
		t.Errorf("apply body = %v", rec.Body)
	}
	_, _ = c.BetterAuthImports.Delete(ctx, "bai_1")
	rec.expect(t, "DELETE", "/v1/better_auth_imports/bai_1")
	_, _ = c.BetterAuthImports.ListJWKS(ctx)
	rec.expect(t, "GET", "/v1/better_auth_imports/jwks")
	_, _ = c.BetterAuthImports.DeleteJWK(ctx, "kid_1")
	rec.expect(t, "DELETE", "/v1/better_auth_imports/jwks/kid_1")
}

func TestSplitBundleParts(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, `{"n":%d,"pad":"%s"}`+"\n", i, strings.Repeat("x", i%7))
	}
	bundle := sb.String()
	parts := SplitBundleParts([]byte(bundle), 256)
	if len(parts) < 2 {
		t.Fatalf("parts = %d", len(parts))
	}
	var joined strings.Builder
	for _, p := range parts {
		if len(p) > 256 || p[len(p)-1] != '\n' {
			t.Errorf("part of %d bytes / no trailing newline", len(p))
		}
		joined.Write(p)
	}
	if joined.String() != bundle {
		t.Error("parts do not rejoin to the bundle")
	}
	got := SplitBundleParts([]byte("a\r\n\n\nb\n"), 1024)
	if len(got) != 1 || string(got[0]) != "a\nb\n" {
		t.Errorf("blank/CRLF handling = %q", got)
	}
	got = SplitBundleParts([]byte("aa\n"+strings.Repeat("b", 50)+"\ncc\n"), 10)
	if len(got) != 3 || len(got[1]) != 51 {
		t.Errorf("oversized line = %q", got)
	}
	if len(SplitBundleParts(nil, 0)) != 0 {
		t.Error("empty bundle should have no parts")
	}
}

func TestBetterAuthImportsUploadAndWait(t *testing.T) {
	var mu sync.Mutex
	var parts []string
	var created map[string]interface{}
	finalized, polls := 0, 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/better_auth_imports":
			_ = json.Unmarshal(raw, &created)
			_, _ = w.Write([]byte(`{"id":"bai_1","status":"uploading"}`))
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/better_auth_imports/bai_1/parts/"):
			if want := fmt.Sprintf("/v1/better_auth_imports/bai_1/parts/%d", len(parts)+1); r.URL.Path != want {
				t.Errorf("part path %s, want %s", r.URL.Path, want)
			}
			parts = append(parts, string(raw))
			_, _ = w.Write([]byte(`{"object":"better_auth_import_part"}`))
		case r.URL.Path == "/v1/better_auth_imports/bai_1/finalize":
			finalized++
			_, _ = w.Write([]byte(`{"id":"bai_1","status":"analyzing"}`))
		case r.Method == "GET" && r.URL.Path == "/v1/better_auth_imports/bai_1":
			polls++
			status := map[int]string{1: "analyzing", 2: "queued", 3: "applying"}[polls]
			if status == "" {
				status = "completed"
			}
			_, _ = fmt.Fprintf(w, `{"id":"bai_1","status":%q}`, status)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()
	var bundle strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&bundle, `{"line":%d}`+"\n", i)
	}
	var seen [][2]int
	imp, err := c.BetterAuthImports.Upload(ctx, []byte(bundle.String()), UploadBetterAuthBundleOptions{
		Options:   &BetterAuthImportOptions{Models: []string{"user"}},
		PartBytes: 64,
		OnPart:    func(n, of int) { seen = append(seen, [2]int{n, of}) },
	})
	if err != nil || imp.Status != "analyzing" || finalized != 1 {
		t.Fatalf("Upload = %+v, %v (finalized %d)", imp, err, finalized)
	}
	if strings.Join(parts, "") != bundle.String() || len(seen) != len(parts) || seen[len(seen)-1] != [2]int{len(parts), len(parts)} {
		t.Errorf("parts=%d seen=%v", len(parts), seen)
	}
	for _, p := range parts {
		if len(p) > 64 {
			t.Errorf("part of %d bytes", len(p))
		}
	}
	if opts, _ := created["options"].(map[string]interface{}); opts == nil {
		t.Errorf("create body = %v", created)
	}
	var progress []string
	done, err := c.BetterAuthImports.WaitFor(ctx, "bai_1", WaitForBetterAuthImportOptions{
		Interval:   time.Millisecond,
		OnProgress: func(i *BetterAuthImport) { progress = append(progress, i.Status) },
	})
	if err != nil || done.Status != "completed" || strings.Join(progress, ",") != "analyzing,queued,applying,completed" {
		t.Fatalf("WaitFor = %+v, %v, %v", done, err, progress)
	}
	if _, err := c.BetterAuthImports.Upload(ctx, []byte("\n\n"), UploadBetterAuthBundleOptions{}); err == nil {
		t.Error("an empty bundle should be refused")
	}
}

func TestBetterAuthImportsWaitForTimeoutAndCancel(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"bai_1","status":"applying"}`))
	})
	if _, err := c.BetterAuthImports.WaitFor(context.Background(), "bai_1", WaitForBetterAuthImportOptions{Interval: time.Millisecond, Timeout: time.Nanosecond}); err == nil || !strings.Contains(err.Error(), "applying") {
		t.Errorf("timeout err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.BetterAuthImports.WaitFor(ctx, "bai_1", WaitForBetterAuthImportOptions{Interval: time.Hour}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel err = %v", err)
	}
}

func TestBetterAuthBridgeSettings(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"better_auth_bridge","enabled":true,"live_fallback":{"has_secret":true},"stats":{"exchanged":3}}`)
	got, err := c.BetterAuthBridge.Get(ctx)
	if err != nil || !got.Enabled || !got.LiveFallback.HasSecret || got.Stats.Exchanged != 3 {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	rec.expect(t, "GET", "/v1/migrations/better_auth/bridge")
	on := true
	ends := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	base := "https://app.example.com/api/auth"
	_, _ = c.BetterAuthBridge.Update(ctx, UpdateBetterAuthBridgeParams{
		Enabled: &on, EndsAt: &ends, CookiePrefix: "app",
		LiveFallback: &BetterAuthLiveFallbackParams{Enabled: &on, BaseURL: &base, ClearSecret: true},
	})
	rec.expect(t, "PUT", "/v1/migrations/better_auth/bridge")
	lf, _ := rec.Body["live_fallback"].(map[string]interface{})
	if rec.Body["ends_at"] != "2027-01-01T00:00:00Z" || rec.Body["cookie_prefix"] != "app" || lf["base_url"] != base {
		t.Errorf("update body = %v", rec.Body)
	}
	if v, ok := lf["secret"]; !ok || v != nil {
		t.Errorf("ClearSecret should send secret:null, got %v", lf)
	}
	_, _ = c.BetterAuthBridge.Update(ctx, UpdateBetterAuthBridgeParams{ClearEndsAt: true})
	if v, ok := rec.Body["ends_at"]; !ok || v != nil || len(rec.Body) != 1 {
		t.Errorf("ClearEndsAt body = %v", rec.Body)
	}
	_, _ = c.BetterAuthBridge.Delete(ctx)
	rec.expect(t, "DELETE", "/v1/migrations/better_auth/bridge")
}

type exchangeServer struct {
	status int
	body   string
	last   *http.Request
	raw    map[string]interface{}
	calls  int
}

func newExchangeClient(t *testing.T, s *exchangeServer) *Client {
	return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != BetterAuthExchangePath {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		s.calls++
		s.last = r
		raw, _ := io.ReadAll(r.Body)
		s.raw = nil
		_ = json.Unmarshal(raw, &s.raw)
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	})
}

const sessionTokensJSON = `{"object":"session_tokens","jwt":"j.w.t","refresh_token":"rt_1","session_id":"sess_1","user_id":"user_1","expires_in":60}`

func refusalJSON(code, outcome string) string {
	meta := ""
	if outcome != "" {
		meta = fmt.Sprintf(`,"meta":{"bridge_outcome":%q}`, outcome)
	}
	return fmt.Sprintf(`{"errors":[{"code":%q,"message":"x"%s}]}`, code, meta)
}

func TestExchangeBetterAuthSession(t *testing.T) {
	s := &exchangeServer{status: 200, body: sessionTokensJSON}
	c := newExchangeClient(t, s)
	res := c.ExchangeBetterAuthSession(context.Background(), BetterAuthExchangeParams{Token: "tok.sig", ClientIP: "203.0.113.9", UserAgent: "Mozilla/5.0", NotRemembered: true})
	if res.Kind != BetterAuthExchangeSession || res.JWT != "j.w.t" || res.RefreshToken != "rt_1" || res.SessionID != "sess_1" || res.UserID != "user_1" || res.ExpiresIn != 60 {
		t.Fatalf("result = %+v", res)
	}
	if s.last.Header.Get("Authorization") != "Bearer sk_test_123" || s.last.Header.Get("X-Atlas-Client-IP") != "203.0.113.9" || s.last.Header.Get("X-Atlas-Client-User-Agent") != "Mozilla/5.0" {
		t.Errorf("headers = %v", s.last.Header)
	}
	if s.raw["token"] != "tok.sig" || s.raw["remember"] != false {
		t.Errorf("body = %v", s.raw)
	}
	_ = c.ExchangeBetterAuthSession(context.Background(), BetterAuthExchangeParams{Token: "t"})
	if s.last.Header.Get("X-Atlas-Client-IP") != "" || s.last.Header.Get("X-Atlas-Client-User-Agent") != "" {
		t.Error("absent forwarding headers should not be sent")
	}
	if _, ok := s.raw["remember"]; ok {
		t.Error("remember should be omitted by default")
	}

	cases := []struct {
		status         int
		body, outcome  string
		wantHTTPStatus int
	}{
		{400, refusalJSON("VERIFICATION_FAILED", "invalid"), "invalid", 400},
		{400, refusalJSON("VERIFICATION_FAILED", "reused"), "reused", 400},
		{400, refusalJSON("VERIFICATION_EXPIRED", "expired"), "expired", 400},
		{403, refusalJSON("FORBIDDEN", "closed"), "closed", 403},
		{429, refusalJSON("RATE_LIMITED", ""), "rate_limited", 429},
		{503, refusalJSON("INTERNAL", ""), "unavailable", 503},
		{403, refusalJSON("FORBIDDEN", "brand_new"), "unavailable", 403},
	}
	for _, tc := range cases {
		s.status, s.body = tc.status, tc.body
		res := c.ExchangeBetterAuthSession(context.Background(), BetterAuthExchangeParams{Token: "t"})
		if res.Kind != BetterAuthExchangeRefused || res.Outcome != tc.outcome || res.HTTPStatus != tc.wantHTTPStatus {
			t.Errorf("%d %s → %+v", tc.status, tc.body, res)
		}
	}
	s.status, s.body = 200, `{"object":"sign_in_attempt","id":"sia_1","status":"needs_second_factor"}`
	res = c.ExchangeBetterAuthSession(context.Background(), BetterAuthExchangeParams{Token: "t"})
	if res.Kind != BetterAuthExchangeNeedsMFA || res.AttemptID != "sia_1" || res.Status != "needs_second_factor" {
		t.Errorf("needs_mfa = %+v", res)
	}

	dead := New("sk_test_123", WithBaseURL("http://127.0.0.1:1"))
	if res := dead.ExchangeBetterAuthSession(context.Background(), BetterAuthExchangeParams{Token: "t"}); res.Kind != BetterAuthExchangeRefused || res.Outcome != "unavailable" || res.HTTPStatus != 0 {
		t.Errorf("transport failure = %+v", res)
	}
}

func TestBetterAuthCookieNames(t *testing.T) {
	tokens, all := BetterAuthCookieNames("")
	if tokens[0] != "__Secure-better-auth.session_token" || tokens[1] != "better-auth.session_token" || len(all) != 8 {
		t.Errorf("names = %v %v", tokens, all)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "better-auth.session_token=plain; __Secure-better-auth.session_token=secure")
	if got := ReadBetterAuthSessionCookie(r, "", ""); got != "secure" {
		t.Errorf("read = %q", got)
	}
	r.Header.Set("Cookie", "my.sess=v")
	if got := ReadBetterAuthSessionCookie(r, "", "my.sess"); got != "v" {
		t.Errorf("custom name = %q", got)
	}
}

func cookieMap(res *http.Response) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, ck := range res.Cookies() {
		out[ck.Name] = ck
	}
	return out
}

func TestBetterAuthBridgeMiddleware(t *testing.T) {
	s := &exchangeServer{status: 200, body: sessionTokensJSON}
	c := newExchangeClient(t, s)
	if _, err := NewBetterAuthBridge(BetterAuthBridgeOptions{}); err == nil {
		t.Error("a bridge without a client should be refused")
	}
	bridge, _ := NewBetterAuthBridge(BetterAuthBridgeOptions{Client: c, BetterAuthCookieDomain: ".example.com", SignInURL: "https://app.example.com/sign-in?r=1"})
	h := bridge.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))
	serve := func(method, cookie string) *http.Response {
		r := httptest.NewRequest(method, "https://app.example.com/page?x=1", nil)
		r.Header.Set("Cookie", cookie)
		r.Header.Set("User-Agent", "UA")
		r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result()
	}

	res := serve("GET", "better-auth.session_token=tok.sig")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/page?x=1" {
		t.Fatalf("signed_in = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	cks := cookieMap(res)
	if cks["__session"].Value != "j.w.t" || !cks["__session"].Secure || !cks["__atlas_rt"].HttpOnly || cks["__atlas_rt"].Value != "rt_1" {
		t.Errorf("atlas cookies = %+v %+v", cks["__session"], cks["__atlas_rt"])
	}
	if ck := cks["__Secure-better-auth.session_token"]; ck == nil || ck.MaxAge >= 0 || !ck.Secure || ck.Domain != "example.com" {
		t.Errorf("cleared cookie = %+v", ck)
	}
	if s.last.Header.Get("X-Atlas-Client-IP") != "198.51.100.7" || s.last.Header.Get("X-Atlas-Client-User-Agent") != "UA" || s.raw["token"] != "tok.sig" {
		t.Errorf("forwarded = %v / %v", s.last.Header, s.raw)
	}

	calls := s.calls
	for _, ck := range []string{"other=1", "better-auth.session_token=t; __session=x", "better-auth.session_token=t; __atlas_rt=r"} {
		if res := serve("GET", ck); res.StatusCode != 200 {
			t.Errorf("%q should pass through, got %d", ck, res.StatusCode)
		}
	}
	if res := serve("POST", "better-auth.session_token=t"); res.StatusCode != 200 {
		t.Errorf("POST should pass through, got %d", res.StatusCode)
	}
	if s.calls != calls {
		t.Error("no exchange expected without a cookie, with an Atlas session, or on POST")
	}

	s.body = `{"object":"sign_in_attempt","id":"sia_1","status":"needs_mfa_enrollment"}`
	res = serve("GET", "better-auth.session_token=t")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "https://app.example.com/sign-in?__atlas_attempt=sia_1&__atlas_status=needs_mfa_enrollment&r=1" {
		t.Errorf("needs_mfa = %d %s", res.StatusCode, res.Header.Get("Location"))
	}

	s.status, s.body = 400, refusalJSON("VERIFICATION_FAILED", "reused")
	res = serve("GET", "better-auth.session_token=t")
	if res.StatusCode != 200 || cookieMap(res)["better-auth.session_token"] == nil {
		t.Errorf("final refusal should clear and continue: %d %v", res.StatusCode, res.Cookies())
	}
	for _, rr := range []struct {
		status int
		body   string
	}{{403, refusalJSON("FORBIDDEN", "closed")}, {429, refusalJSON("RATE_LIMITED", "")}, {500, refusalJSON("INTERNAL", "")}} {
		s.status, s.body = rr.status, rr.body
		res = serve("GET", "better-auth.session_token=t")
		if res.StatusCode != 200 || len(res.Cookies()) != 0 {
			t.Errorf("non-final refusal %d should keep cookies, got %v", rr.status, res.Cookies())
		}
	}
}

// ── Legacy issuers ───────────────────────────────────────────────────────────

const baIssuer = "https://old.example.test"

type legacyKeys struct {
	ed   ed25519.PrivateKey
	p256 *ecdsa.PrivateKey
	p521 *ecdsa.PrivateKey
	rsa  *rsa.PrivateKey
}

func newLegacyKeys(t *testing.T) *legacyKeys {
	t.Helper()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &legacyKeys{ed: ed, p256: p256, p521: p521, rsa: rk}
}

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func (k *legacyKeys) jwks() []byte {
	ecJWK := func(kid, crv string, pub *ecdsa.PublicKey, size int) map[string]string {
		return map[string]string{"kid": kid, "kty": "EC", "crv": crv, "x": b64(pad(pub.X.Bytes(), size)), "y": b64(pad(pub.Y.Bytes(), size))}
	}
	keys := []map[string]string{
		{"kid": "k-EdDSA", "kty": "OKP", "crv": "Ed25519", "x": b64(k.ed.Public().(ed25519.PublicKey))},
		ecJWK("k-ES256", "P-256", &k.p256.PublicKey, 32),
		ecJWK("k-ES512", "P-521", &k.p521.PublicKey, 66),
		{"kid": "k-RS256", "kty": "RSA", "n": b64(k.rsa.N.Bytes()), "e": b64(big.NewInt(int64(k.rsa.E)).Bytes())},
	}
	raw, _ := json.Marshal(map[string]interface{}{"keys": keys})
	return raw
}

func (k *legacyKeys) sign(t *testing.T, alg, kid string, claims map[string]interface{}) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(p)
	var sig []byte
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(k.ed, []byte(input))
	case "ES256", "ES512":
		key, size := k.p256, 32
		var digest []byte
		if alg == "ES512" {
			key, size = k.p521, 66
			d := sha512.Sum512([]byte(input))
			digest = d[:]
		} else {
			d := sha256.Sum256([]byte(input))
			digest = d[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		sig = append(pad(r.Bytes(), size), pad(s.Bytes(), size)...)
	case "RS256", "PS256":
		d := sha256.Sum256([]byte(input))
		var err error
		if alg == "RS256" {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, d[:])
		} else {
			sig, err = rsa.SignPSS(rand.Reader, k.rsa, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return input + "." + b64(sig)
}

func baClaims(now time.Time, over map[string]interface{}) map[string]interface{} {
	c := map[string]interface{}{"iss": baIssuer, "aud": baIssuer, "sub": "ba_user_1", "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func legacyBackend(t *testing.T, keys *legacyKeys, now time.Time, mutate func(*LegacyIssuer)) *AtlasBackend {
	t.Helper()
	entry := LegacyIssuer{
		Issuer: baIssuer, JWKS: keys.jwks(), Audience: []string{baIssuer}, Until: now.Add(24 * time.Hour),
		ResolveSubject: func(_ context.Context, sub string, _ map[string]interface{}) (string, error) {
			if sub == "ba_user_1" {
				return "user_atlas_1", nil
			}
			return "", nil
		},
	}
	if mutate != nil {
		mutate(&entry)
	}
	b, err := NewAtlasBackend(AtlasBackendOptions{JWKSURL: "https://id.atlas.test/.well-known/jwks.json", Issuer: "https://id.atlas.test", Now: func() time.Time { return now }, LegacyIssuers: []LegacyIssuer{entry}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLegacyIssuerAcceptsBetterAuthAlgorithms(t *testing.T) {
	keys := newLegacyKeys(t)
	now := time.Now()
	b := legacyBackend(t, keys, now, nil)
	for _, alg := range []string{"EdDSA", "ES256", "ES512", "RS256", "PS256"} {
		kid := "k-" + alg
		if alg == "PS256" {
			kid = "k-RS256"
		}
		claims, err := b.Verify(context.Background(), keys.sign(t, alg, kid, baClaims(now, map[string]interface{}{"sid": "ba_sess"})))
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		legacy, _ := claims.Raw["legacy"].(map[string]interface{})
		if claims.Sub != "user_atlas_1" || claims.Sid != "ba_sess" || claims.Raw["external_id"] != "ba_user_1" || legacy["issuer"] != baIssuer || legacy["kind"] != "better_auth" || legacy["sub"] != "ba_user_1" {
			t.Errorf("%s claims = %+v", alg, claims)
		}
	}
}

func TestLegacyIssuerRefusals(t *testing.T) {
	keys := newLegacyKeys(t)
	now := time.Now()
	b := legacyBackend(t, keys, now, nil)
	cases := map[string]string{
		"no exp":         keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, map[string]interface{}{"exp": nil})),
		"expired":        keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, map[string]interface{}{"exp": now.Add(-time.Minute).Unix()})),
		"wrong audience": keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, map[string]interface{}{"aud": "https://other"})),
		"unknown user":   keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, map[string]interface{}{"sub": "nobody"})),
		"alg/key clash":  keys.sign(t, "ES256", "k-EdDSA", baClaims(now, nil)),
	}
	tampered := keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, nil))
	cases["tampered"] = tampered[:len(tampered)-4] + "AAAA"
	for name, tok := range cases {
		if _, err := b.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	only := legacyBackend(t, keys, now, func(e *LegacyIssuer) { e.Algorithms = []string{"EdDSA"} })
	if _, err := only.Verify(context.Background(), keys.sign(t, "RS256", "k-RS256", baClaims(now, nil))); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("algorithm allowlist: %v", err)
	}
}

func TestLegacyIssuerWindowAndAtlasTokens(t *testing.T) {
	keys := newLegacyKeys(t)
	now := time.Now()
	atlasKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, atlasKey, "atlas-kid", nil)
	b, err := NewAtlasBackend(AtlasBackendOptions{
		JWKSURL: srv.URL, Issuer: "https://id.atlas.test", HTTPClient: srv.Client(), Now: func() time.Time { return now },
		LegacyIssuers: []LegacyIssuer{{Issuer: baIssuer, JWKS: keys.jwks(), Until: now.Add(-time.Second),
			ResolveSubject: func(context.Context, string, map[string]interface{}) (string, error) { return "user_atlas_1", nil }}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(context.Background(), keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, nil))); err == nil {
		t.Error("a closed window must refuse the legacy token")
	}
	atlasTok := signToken(t, atlasKey, "atlas-kid", map[string]interface{}{"iss": "https://id.atlas.test", "sub": "user_1", "exp": now.Add(time.Minute).Unix()})
	if claims, err := b.Verify(context.Background(), atlasTok); err != nil || claims.Sub != "user_1" {
		t.Errorf("Atlas token alongside a legacy issuer: %+v %v", claims, err)
	}
}

func TestLegacyIssuerDefaultResolverAndJWKSURL(t *testing.T) {
	keys := newLegacyKeys(t)
	now := time.Now()
	lookups := 0
	fail := true
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/jwks":
			_, _ = w.Write(keys.jwks())
		case "/v1/users":
			lookups++
			gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
			if fail {
				fail = false
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"user_atlas_9"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	b, err := NewAtlasBackend(AtlasBackendOptions{
		JWKSURL: srv.URL + "/atlas-jwks", Issuer: "https://id.atlas.test", HTTPClient: srv.Client(), Now: func() time.Time { return now },
		SecretKey: "sk_test_123", APIURL: srv.URL,
		LegacyIssuers: []LegacyIssuer{{Issuer: baIssuer, JWKSURL: srv.URL + "/api/auth/jwks", Until: now.Add(time.Hour)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := keys.sign(t, "EdDSA", "k-EdDSA", baClaims(now, nil))
	if _, err := b.Verify(context.Background(), tok); err == nil {
		t.Fatal("a failed lookup must refuse")
	}
	for i := 0; i < 2; i++ {
		claims, err := b.Verify(context.Background(), tok)
		if err != nil || claims.Sub != "user_atlas_9" {
			t.Fatalf("verify = %+v %v", claims, err)
		}
	}
	if lookups != 2 {
		t.Errorf("lookups = %d (the failure is not cached, the success is)", lookups)
	}
	if gotAuth != "Bearer sk_test_123" || gotQuery != "external_id=ba_user_1&limit=1" {
		t.Errorf("lookup auth=%q query=%q", gotAuth, gotQuery)
	}
}

func TestLegacyIssuerConfigErrors(t *testing.T) {
	keys := newLegacyKeys(t)
	until := time.Now().Add(time.Hour)
	base := AtlasBackendOptions{JWKSURL: "https://id.atlas.test/jwks", Issuer: "https://id.atlas.test", SecretKey: "sk"}
	for name, e := range map[string]LegacyIssuer{
		"no keys":      {Issuer: baIssuer, Until: until},
		"both keys":    {Issuer: baIssuer, Until: until, JWKS: keys.jwks(), JWKSURL: "https://x"},
		"no window":    {Issuer: baIssuer, JWKS: keys.jwks()},
		"atlas issuer": {Issuer: "https://id.atlas.test", Until: until, JWKS: keys.jwks()},
		"bad jwks":     {Issuer: baIssuer, Until: until, JWKS: []byte("nope")},
	} {
		opts := base
		opts.LegacyIssuers = []LegacyIssuer{e}
		if _, err := NewAtlasBackend(opts); err == nil {
			t.Errorf("%s: expected a construction error", name)
		}
	}
	opts := base
	opts.SecretKey = ""
	opts.LegacyIssuers = []LegacyIssuer{{Issuer: baIssuer, Until: until, JWKS: keys.jwks()}}
	if _, err := NewAtlasBackend(opts); err == nil || !strings.Contains(err.Error(), "SecretKey") {
		t.Errorf("no secret key: %v", err)
	}
}
