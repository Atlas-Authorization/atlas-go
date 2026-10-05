package middleware

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	atlas "github.com/Atlas-Authorization/atlas-go"
)

const testIssuer = "https://issuer.atlas.dev"

// newBackend mirrors verify_test.go's helper: it stubs a single-key JWKS,
// mints a real RS256 token, and returns a genuine *atlas.AtlasBackend so the
// middleware exercises the real verification path (no mock verifier).
func newBackend(t *testing.T) (*atlas.AtlasBackend, string, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)

	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{"kty": "RSA", "kid": "kid-1", "n": n, "e": e, "alg": "RS256"}},
		})
	}))
	t.Cleanup(srv.Close)

	b, err := atlas.NewAtlasBackend(atlas.AtlasBackendOptions{
		JWKSURL: srv.URL,
		Issuer:  testIssuer,
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAtlasBackend: %v", err)
	}

	token := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": testIssuer, "sub": "user_1", "sid": "sess_1",
		"exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(),
	})
	return b, token, now
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	enc := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	signingInput := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestRequireAuthValidBearer(t *testing.T) {
	b, token, _ := newBackend(t)

	var sawSub string
	handler := RequireAuth(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := FromContext(r.Context())
		if !ok {
			t.Error("FromContext: no claims in context")
		} else {
			sawSub = claims.Sub
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if sawSub != "user_1" {
		t.Errorf("claims.Sub = %q, want user_1", sawSub)
	}
}

func TestRequireAuthCookie(t *testing.T) {
	b, token, _ := newBackend(t)

	handler := RequireAuth(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			t.Error("FromContext: no claims from cookie path")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "__session", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (cookie path)", rec.Code)
	}
}

func TestRequireAuthMissing(t *testing.T) {
	b, _, _ := newBackend(t)
	handler := RequireAuth(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran for an unauthenticated request")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for missing token", rec.Code)
	}
}

func TestRequireAuthInvalid(t *testing.T) {
	b, _, _ := newBackend(t)
	handler := RequireAuth(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran for an invalid token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for invalid token", rec.Code)
	}
}

func TestOptionalAttachesWhenPresent(t *testing.T) {
	b, token, _ := newBackend(t)

	var hadClaims bool
	handler := Optional(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadClaims = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !hadClaims {
		t.Fatalf("status=%d hadClaims=%v, want 200 + claims", rec.Code, hadClaims)
	}
}

func TestOptionalNeverBlocks(t *testing.T) {
	b, _, _ := newBackend(t)

	var ran bool
	var hadClaims bool
	handler := Optional(b)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		_, hadClaims = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// No token at all.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("ran=%v status=%d, want handler to run with 200", ran, rec.Code)
	}
	if hadClaims {
		t.Error("FromContext returned claims for an anonymous request")
	}

	// Invalid token must also pass through without a 401.
	ran = false
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("ran=%v status=%d for invalid token, want handler to run with 200", ran, rec.Code)
	}
}
