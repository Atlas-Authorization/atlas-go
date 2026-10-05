package gin

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
	"github.com/gin-gonic/gin"
)

const testIssuer = "https://issuer.atlas.dev"

func init() { gin.SetMode(gin.TestMode) }

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

func TestAuthValidBearer(t *testing.T) {
	b, token := newBackend(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	Auth(b)(c)
	if c.IsAborted() {
		t.Fatalf("request aborted with status %d, want it to pass", rec.Code)
	}
	claims, ok := FromGin(c)
	if !ok {
		t.Fatal("FromGin: no claims set")
	}
	if claims.Sub != "user_1" {
		t.Errorf("claims.Sub = %q, want user_1", claims.Sub)
	}
}

func TestAuthCookie(t *testing.T) {
	b, token := newBackend(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "__session", Value: token})

	Auth(b)(c)
	if c.IsAborted() {
		t.Fatalf("cookie request aborted with status %d, want it to pass", rec.Code)
	}
	if _, ok := FromGin(c); !ok {
		t.Error("FromGin: no claims from cookie path")
	}
}

func TestAuthMissing(t *testing.T) {
	b, _ := newBackend(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	Auth(b)(c)
	if !c.IsAborted() || rec.Code != http.StatusUnauthorized {
		t.Fatalf("aborted=%v status=%d, want abort with 401", c.IsAborted(), rec.Code)
	}
	if _, ok := FromGin(c); ok {
		t.Error("FromGin returned claims for an unauthenticated request")
	}
}

func TestAuthInvalid(t *testing.T) {
	b, _ := newBackend(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer not-a-jwt")

	Auth(b)(c)
	if !c.IsAborted() || rec.Code != http.StatusUnauthorized {
		t.Fatalf("aborted=%v status=%d, want abort with 401 for invalid token", c.IsAborted(), rec.Code)
	}
}
