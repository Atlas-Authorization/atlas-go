package atlas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestGeneratePKCEChallengeMatchesVerifier is the core PKCE invariant: the
// challenge must equal base64url(no padding) of SHA-256(ASCII(verifier)), or the
// server (which recomputes exactly this) will reject every redeem.
func TestGeneratePKCEChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatalf("GeneratePKCE returned empty pair: verifier=%q challenge=%q", verifier, challenge)
	}

	// The verifier is base64url(no padding) — decodable, no '=' padding, and the
	// 32 seed bytes encode to 43 chars.
	if strings.ContainsAny(verifier, "=+/") {
		t.Errorf("verifier %q contains non-base64url or padding characters", verifier)
	}
	seed, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		t.Fatalf("verifier is not valid base64url: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("verifier decodes to %d bytes, want 32", len(seed))
	}

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Errorf("challenge = %q, want base64url(sha256(verifier)) = %q", challenge, want)
	}
}

// TestGeneratePKCEIsRandom is a mutation-check: two calls must not return the
// same verifier (a hardcoded/reused verifier would defeat the binding).
func TestGeneratePKCEIsRandom(t *testing.T) {
	v1, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	v2, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if v1 == v2 {
		t.Errorf("two GeneratePKCE calls returned the same verifier %q, want distinct", v1)
	}
}

// TestRedeemHandshakeSendsCodeVerifier asserts the redeem POST body carries the
// code_verifier alongside user_id and nonce, and that a 2xx decodes into a
// session.
func TestRedeemHandshakeSendsCodeVerifier(t *testing.T) {
	var gotBody redeemHandshakeBody
	var gotPath, gotPK, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPK = r.Header.Get("X-Publishable-Key")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jwt":"jwt-abc","refresh_token":"rt-xyz","session_id":"sess_1","expires_in":60}`))
	}))
	defer srv.Close()

	s, err := RedeemHandshake(context.Background(), RedeemHandshakeParams{
		FapiOrigin:     srv.URL,
		PublishableKey: "pk_live_123",
		UserID:         "user_1",
		Nonce:          "nonce-1",
		CodeVerifier:   "verifier-1",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatalf("RedeemHandshake: %v", err)
	}
	if s == nil {
		t.Fatal("session = nil on a 2xx with tokens, want a session")
	}

	if gotPath != "/v1/client/handshake/redeem" {
		t.Errorf("path = %q, want /v1/client/handshake/redeem", gotPath)
	}
	if gotPK != "pk_live_123" {
		t.Errorf("X-Publishable-Key = %q, want pk_live_123", gotPK)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.CodeVerifier != "verifier-1" {
		t.Errorf("body code_verifier = %q, want verifier-1", gotBody.CodeVerifier)
	}
	if gotBody.UserID != "user_1" || gotBody.Nonce != "nonce-1" {
		t.Errorf("body = %+v, want user_id=user_1 nonce=nonce-1", gotBody)
	}
	if s.JWT != "jwt-abc" || s.RefreshToken != "rt-xyz" || s.SessionID != "sess_1" || s.ExpiresIn != 60 {
		t.Errorf("session = %+v, want jwt-abc/rt-xyz/sess_1/60", s)
	}
}

// TestRedeemHandshakeBodyJSONField pins the wire name to the server contract:
// the field the server verifies is "code_verifier", not any other spelling.
func TestRedeemHandshakeBodyJSONField(t *testing.T) {
	raw, err := json.Marshal(redeemHandshakeBody{UserID: "u", Nonce: "n", CodeVerifier: "v"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["code_verifier"] != "v" {
		t.Errorf(`JSON body = %s, want a "code_verifier":"v" field`, raw)
	}
}

// TestHandshakeRedirectURLIncludesChallenge asserts the outbound URL carries a
// code_challenge that matches the returned verifier, that the verifier itself
// never appears on the URL, and that the redirect_url round-trips.
func TestHandshakeRedirectURLIncludesChallenge(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://satellite.example.com/dashboard?a=1", nil)
	req.Host = "satellite.example.com"

	got, verifier, ok := HandshakeRedirectURL(req, "https://id.atlasauth.net", "pk_live_123")
	if !ok {
		t.Fatal("ok = false on a fresh request, want true")
	}
	if verifier == "" {
		t.Fatal("verifier = empty, want a stashable PKCE verifier")
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redirect URL is not parseable: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://id.atlasauth.net/v1/client/handshake" {
		t.Errorf("redirect base = %q, want https://id.atlasauth.net/v1/client/handshake", u.Scheme+"://"+u.Host+u.Path)
	}

	q := u.Query()
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("code_challenge missing from the handshake URL")
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Errorf("code_challenge = %q, want base64url(sha256(returned verifier)) = %q", challenge, want)
	}
	if q.Get("publishable_key") != "pk_live_123" {
		t.Errorf("publishable_key = %q, want pk_live_123", q.Get("publishable_key"))
	}
	if q.Get("redirect_url") != "https://satellite.example.com/dashboard?a=1" {
		t.Errorf("redirect_url = %q, want the original request URL", q.Get("redirect_url"))
	}

	// The verifier must NOT leak onto the URL — that is the whole point of PKCE.
	if strings.Contains(got, verifier) {
		t.Errorf("redirect URL %q contains the raw verifier %q", got, verifier)
	}
}

// TestHandshakeRedirectURLLoopGuard keeps the pre-PKCE behavior: a request that
// already carries the __atlas_hs marker returns ok=false so the caller falls
// through to the sign-in redirect instead of bouncing forever.
func TestHandshakeRedirectURLLoopGuard(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://satellite.example.com/dashboard?__atlas_hs=ok&__atlas_hn=n", nil)
	got, verifier, ok := HandshakeRedirectURL(req, "https://id.atlasauth.net", "pk_live_123")
	if ok {
		t.Error("ok = true when __atlas_hs is already present, want false (loop guard)")
	}
	if got != "" || verifier != "" {
		t.Errorf("got=%q verifier=%q on the loop-guard path, want both empty", got, verifier)
	}
}
