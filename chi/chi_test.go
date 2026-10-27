package chi

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
	"github.com/go-chi/chi/v5"
)

const testIssuer = "https://issuer.atlas.dev"


// newBackend stubs a single-key JWKS, mints a real RS256 token, and returns a
// genuine *atlas.AtlasBackend so the adapter exercises the real verify path.
func newBackend(t *testing.T) (*atlas.AtlasBackend, string) {
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
	return b, token
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


func serve(t *testing.T, b *atlas.AtlasBackend, token string, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(Auth(b))
		r.Get("/me", func(w http.ResponseWriter, req *http.Request) {
			c, ok := FromRequest(req)
			if !ok {
				t.Error("no claims on an authenticated route")
				return
			}
			_, _ = w.Write([]byte(c.Sub))
		})
		r.With(Require(func(c *atlas.SessionClaims) bool { return c.HasRole("admin") })).Get("/admin", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("admin"))
		})
	})
	r.With(Optional(b)).Get("/public", func(w http.ResponseWriter, req *http.Request) {
		if c, ok := FromRequest(req); ok {
			_, _ = w.Write([]byte(c.Sub))
			return
		}
		_, _ = w.Write([]byte("anon"))
	})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAuthPassesAndExposesClaims(t *testing.T) {
	b, token := newBackend(t)
	rec := serve(t, b, token, "/me")
	if rec.Code != 200 || rec.Body.String() != "user_1" {
		t.Fatalf("got %d %q, want 200 user_1", rec.Code, rec.Body.String())
	}
}

func TestAuthRejectsSignedOut(t *testing.T) {
	b, _ := newBackend(t)
	if rec := serve(t, b, "", "/me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if rec := serve(t, b, "garbage", "/me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

func TestRequireForbidsWithoutRole(t *testing.T) {
	b, token := newBackend(t)
	if rec := serve(t, b, token, "/admin"); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestOptionalNeverBlocks(t *testing.T) {
	b, token := newBackend(t)
	if rec := serve(t, b, "", "/public"); rec.Code != 200 || rec.Body.String() != "anon" {
		t.Fatalf("anon: %d %q", rec.Code, rec.Body.String())
	}
	if rec := serve(t, b, token, "/public"); rec.Body.String() != "user_1" {
		t.Fatalf("signed in: %q", rec.Body.String())
	}
}
