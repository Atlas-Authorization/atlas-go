package atlas

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 9421 Appendix B.1.4: the Ed25519 test key (also the key the Web Bot Auth drafts use in their examples).
const (
	wbaSeedPKCS8 = "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF"
	wbaX         = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	wbaKeyID     = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
	wbaAgent     = "https://bot.example.com"
	wbaURL       = "https://site.example.net/pricing?a=1"
	wbaNow       = int64(1_735_689_600)
)

func wbaSeed(t *testing.T) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(wbaSeedPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	return der[len(der)-32:]
}

func wbaSign(t *testing.T, mutate func(*SignWebBotAuthInput)) http.Header {
	t.Helper()
	in := SignWebBotAuthInput{Method: "GET", URL: wbaURL, SignatureAgent: wbaAgent, PrivateKey: wbaSeed(t), Created: wbaNow, Expires: wbaNow + 300}
	if mutate != nil {
		mutate(&in)
	}
	headers, err := SignWebBotAuthRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return h
}

func wbaVerify(h http.Header, o WebBotAuthVerifyOptions) WebBotAuthResult {
	if o.GetKeys == nil {
		o.GetKeys = func(context.Context, string, bool) []WebBotAuthJWK {
			return []WebBotAuthJWK{{Kty: "OKP", Crv: "Ed25519", X: wbaX}}
		}
	}
	o.Now = time.Unix(wbaNow, 0)
	return VerifyWebBotAuth(context.Background(), WebBotAuthRequest{Method: "GET", URL: wbaURL, Header: h}, o)
}

func TestWebBotAuthRFCVectors(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(wbaSeed(t)).Public().(ed25519.PublicKey)
	if base64.RawURLEncoding.EncodeToString(pub) != wbaX || Ed25519JWKThumbprint(wbaX) != wbaKeyID {
		t.Fatal("the test key and its thumbprint must be the ones the drafts show")
	}

	// B.2.6 (Ed25519): the signature base and the signature are the RFC values.
	params := `("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	h := http.Header{}
	h.Set("Host", "example.com")
	h.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "18")
	comps := []WebBotAuthComponent{{Name: "date"}, {Name: "@method"}, {Name: "@path"}, {Name: "@authority"}, {Name: "content-type"}, {Name: "content-length"}}
	base, failure := BuildWebBotAuthSignatureBase(WebBotAuthRequest{Method: "POST", URL: "https://example.com/foo?param=Value&Pet=dog", Header: h}, comps, params)
	want := strings.Join([]string{
		`"date": Tue, 20 Apr 2021 02:07:55 GMT`, `"@method": POST`, `"@path": /foo`, `"@authority": example.com`,
		`"content-type": application/json`, `"content-length": 18`, `"@signature-params": ` + params,
	}, "\n")
	if failure != "" || base != want {
		t.Fatalf("signature base:\n%s\nfailure=%q", base, failure)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(wbaSeed(t)), []byte(base))
	if base64.StdEncoding.EncodeToString(sig) != "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==" {
		t.Fatal("the Ed25519 signature must be the RFC value")
	}
}

func TestWebBotAuthDerivedComponents(t *testing.T) {
	r := WebBotAuthRequest{Method: "get", URL: "https://EXAMPLE.com:443/a/b?x=1&y=2", Header: http.Header{}}
	comps := []WebBotAuthComponent{{Name: "@method"}, {Name: "@authority"}, {Name: "@path"}, {Name: "@query"}, {Name: "@scheme"}, {Name: "@target-uri"}, {Name: "@request-target"}}
	base, failure := BuildWebBotAuthSignatureBase(r, comps, "()")
	want := strings.Join([]string{`"@method": GET`, `"@authority": example.com`, `"@path": /a/b`, `"@query": ?x=1&y=2`, `"@scheme": https`,
		`"@target-uri": https://example.com/a/b?x=1&y=2`, `"@request-target": /a/b?x=1&y=2`, `"@signature-params": ()`}, "\n")
	if failure != "" || base != want {
		t.Fatalf("derived components:\n%s", base)
	}
	if b, _ := BuildWebBotAuthSignatureBase(WebBotAuthRequest{Method: "GET", URL: "https://example.com:8443/p"}, []WebBotAuthComponent{{Name: "@authority"}}, "()"); b != "\"@authority\": example.com:8443\n\"@signature-params\": ()" {
		t.Fatalf("a non-default port stays: %q", b)
	}
	if _, f := BuildWebBotAuthSignatureBase(r, []WebBotAuthComponent{{Name: "@method"}, {Name: "@method"}}, "()"); f != WebBotAuthUnsupportedComponent {
		t.Fatalf("duplicates refused: %q", f)
	}
	if _, f := BuildWebBotAuthSignatureBase(r, []WebBotAuthComponent{{Name: "x-missing"}}, "()"); f != WebBotAuthComponentMissing {
		t.Fatalf("a missing header refused: %q", f)
	}
}

func TestVerifyWebBotAuth(t *testing.T) {
	res := wbaVerify(wbaSign(t, nil), WebBotAuthVerifyOptions{})
	if !res.Verified || res.Directory != wbaAgent || res.KeyID != wbaKeyID {
		t.Fatalf("a signed request verifies: %+v", res)
	}
	if res := wbaVerify(http.Header{}, WebBotAuthVerifyOptions{}); res.Signed || res.Reason != WebBotAuthNoSignature {
		t.Fatalf("unsigned: %+v", res)
	}

	cases := []struct {
		name   string
		mutate func(*SignWebBotAuthInput)
		opts   WebBotAuthVerifyOptions
		want   WebBotAuthFailure
	}{
		{"expired", func(in *SignWebBotAuthInput) { in.Created, in.Expires = wbaNow-1000, wbaNow-500 }, WebBotAuthVerifyOptions{}, WebBotAuthExpired},
		{"future", func(in *SignWebBotAuthInput) { in.Created, in.Expires = wbaNow+1000, wbaNow+1300 }, WebBotAuthVerifyOptions{}, WebBotAuthNotYetValid},
		{"too long", func(in *SignWebBotAuthInput) { in.Expires = wbaNow + 7200 }, WebBotAuthVerifyOptions{}, WebBotAuthLifetimeTooLong},
		{"does not cover the host", func(in *SignWebBotAuthInput) { in.Components = []WebBotAuthComponent{{Name: "signature-agent"}} }, WebBotAuthVerifyOptions{}, WebBotAuthComponentsNotCovered},
		{"unknown key", nil, WebBotAuthVerifyOptions{GetKeys: func(context.Context, string, bool) []WebBotAuthJWK { return []WebBotAuthJWK{} }}, WebBotAuthKeyNotFound},
		{"directory down", nil, WebBotAuthVerifyOptions{GetKeys: func(context.Context, string, bool) []WebBotAuthJWK { return nil }}, WebBotAuthDirectoryUnavailable},
	}
	for _, c := range cases {
		if got := wbaVerify(wbaSign(t, c.mutate), c.opts); got.Verified || got.Reason != c.want {
			t.Errorf("%s: want %q, got %+v", c.name, c.want, got)
		}
	}

	// A request the signature does not cover (another host) fails the signature check.
	h := wbaSign(t, nil)
	other := VerifyWebBotAuth(context.Background(), WebBotAuthRequest{Method: "GET", URL: "https://evil.example.org/pricing", Header: h}, WebBotAuthVerifyOptions{
		GetKeys: func(context.Context, string, bool) []WebBotAuthJWK {
			return []WebBotAuthJWK{{Kty: "OKP", Crv: "Ed25519", X: wbaX}}
		}, Now: time.Unix(wbaNow, 0),
	})
	if other.Verified || other.Reason != WebBotAuthBadSignature {
		t.Fatalf("a signature for another host: %+v", other)
	}

	// Replay guard: the same nonce twice.
	seen := map[string]bool{}
	claim := func(_ context.Context, key string, _ int64) bool {
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	signed := wbaSign(t, func(in *SignWebBotAuthInput) { in.Nonce = "n-1" })
	if r := wbaVerify(signed, WebBotAuthVerifyOptions{ClaimNonce: claim}); !r.Verified || r.Nonce != "n-1" {
		t.Fatalf("first use: %+v", r)
	}
	if r := wbaVerify(signed, WebBotAuthVerifyOptions{ClaimNonce: claim}); r.Reason != WebBotAuthReplayed {
		t.Fatalf("second use: %+v", r)
	}
}

func TestParseSignatureAgentAndDirectory(t *testing.T) {
	cases := map[string]string{
		`"https://bot.example.com"`:              "https://bot.example.com",
		`https://bot.example.com/`:               "https://bot.example.com",
		`bot.example.com`:                        "https://bot.example.com",
		`sig1="https://bot.example.com/agents/"`: "https://bot.example.com/agents",
		`http://bot.example.com`:                 "",
		`https://user:pw@bot.example.com`:        "",
		`https://bot.example.com/?q=1`:           "",
		``:                                       "",
	}
	for in, want := range cases {
		if got := ParseSignatureAgent(in, "sig1"); got != want {
			t.Errorf("ParseSignatureAgent(%q) = %q, want %q", in, got, want)
		}
	}
	if got := WebBotAuthDirectoryURL("https://bot.example.com"); got != "https://bot.example.com/.well-known/http-message-signatures-directory" {
		t.Fatalf("directory url: %q", got)
	}
}

func TestWebBotAuthDirectoryCacheAndDecision(t *testing.T) {
	var fetches int32
	now := time.UnixMilli(5_000_000)
	failing := false
	cache := NewWebBotAuthDirectoryCache(WebBotAuthDirectoryCacheOptions{
		Now: func() time.Time { return now },
		FetchJSON: func(context.Context, string) ([]byte, error) {
			atomic.AddInt32(&fetches, 1)
			if failing {
				return nil, errors.New("down")
			}
			return []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + wbaX + `"},{"kty":"RSA","n":"x","e":"AQAB"}]}`), nil
		},
	})
	ctx := context.Background()
	url := WebBotAuthDirectoryURL(wbaAgent)
	if keys := cache.GetKeys(ctx, url, false); len(keys) != 1 {
		t.Fatalf("only Ed25519 keys are kept: %+v", keys)
	}
	cache.GetKeys(ctx, url, false)
	cache.GetKeys(ctx, url, true) // inside the refresh cooldown: still cached
	if atomic.LoadInt32(&fetches) != 1 {
		t.Fatalf("cached, fetches=%d", fetches)
	}
	now = now.Add(11 * time.Minute)
	failing = true
	if keys := cache.GetKeys(ctx, url, false); len(keys) != 1 {
		t.Fatal("a failed refresh keeps serving the last good copy")
	}

	verified := WebBotAuthResult{Signed: true, Verified: true, Directory: wbaAgent, KeyID: wbaKeyID}
	policy := WebBotAuthPolicy{Allow: []WebBotAuthListEntry{{Directory: "bot.example.com", Name: "Example bot"}}}
	if d := DecideWebBotAuth(verified, policy); d.Decision != "allow" || d.Tier != "allowed" || d.Agent.Name != "Example bot" {
		t.Fatalf("allow: %+v", d)
	}
	policy.Block = []WebBotAuthListEntry{{Directory: wbaAgent}}
	if d := DecideWebBotAuth(verified, policy); d.Decision != "block" || d.Tier != "blocked" || d.Agent.Name != "bot.example.com" {
		t.Fatalf("a block entry beats an allow entry: %+v", d)
	}
	if d := DecideWebBotAuth(WebBotAuthResult{Signed: true, Reason: WebBotAuthBadSignature, Directory: wbaAgent}, policy); d.Decision != "unknown" || d.Agent != nil || d.Reason != WebBotAuthBadSignature {
		t.Fatalf("an unverified claim is never attributed: %+v", d)
	}
}

func TestWebBotAuthVerifierMiddleware(t *testing.T) {
	jwk := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + wbaX + `"}]}`
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		_, _ = rec.WriteString(jwk)
		return rec.Result(), nil
	})}
	v := NewWebBotAuthVerifier(WebBotAuthVerifierOptions{
		HTTPClient: hc, Now: func() time.Time { return time.Unix(wbaNow, 0) },
		WebBotAuthPolicy: WebBotAuthPolicy{Block: []WebBotAuthListEntry{{Directory: wbaAgent}}},
		RequestURL:       func(*http.Request) string { return wbaURL },
	})
	var seen WebBotAuthDecision
	handler := v.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = WebBotAuthDecisionFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pricing?a=1", nil)
	req.Header = wbaSign(t, nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a blocked verified bot is refused, got %d (%+v)", rec.Code, seen)
	}
	plain := httptest.NewRecorder()
	handler.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/pricing", nil))
	if plain.Code != http.StatusOK || seen.Decision != "unknown" {
		t.Fatalf("an unsigned request passes with decision unknown: %d %+v", plain.Code, seen)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClassifySpecialAddress(t *testing.T) {
	cases := map[string]SpecialAddressReason{
		"127.0.0.1": SpecialAddressLoopback, "10.1.2.3": SpecialAddressPrivate, "172.20.0.1": SpecialAddressPrivate,
		"192.168.1.1": SpecialAddressPrivate, "100.64.0.1": SpecialAddressPrivate, "169.254.169.254": SpecialAddressLinkLocal,
		"224.0.0.1": SpecialAddressMulticast, "0.0.0.0": SpecialAddressReserved, "240.0.0.1": SpecialAddressReserved,
		"::1": SpecialAddressLoopback, "[::1]": SpecialAddressLoopback, "::ffff:127.0.0.1": SpecialAddressLoopback,
		"::ffff:7f00:1": SpecialAddressLoopback, "fd00::1": SpecialAddressPrivate, "fe80::1": SpecialAddressLinkLocal,
		"ff02::1": SpecialAddressMulticast, "2001:db8::1": SpecialAddressReserved, "64:ff9b::a00:1": SpecialAddressPrivate,
		"8.8.8.8": "", "93.184.216.34": "", "2606:4700:4700::1111": "", "example.com": "",
	}
	for in, want := range cases {
		if got := ClassifySpecialAddress(in); got != want {
			t.Errorf("ClassifySpecialAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
