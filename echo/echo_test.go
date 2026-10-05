package echo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/labstack/echo/v4"
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

// okHandler asserts claims are present then returns 200.
func okHandler(t *testing.T) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, ok := FromEcho(c); !ok {
			t.Error("FromEcho: no claims in context")
		}
		return c.NoContent(http.StatusOK)
	}
}

// want401 asserts err is an echo 401 HTTPError.
func want401(t *testing.T, err error) {
	t.Helper()
	var he *echo.HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v, want *echo.HTTPError with code 401", err)
	}
}

func TestAuthValidBearer(t *testing.T) {
	b, token := newBackend(t)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := Auth(b)(okHandler(t))(c); err != nil {
		t.Fatalf("middleware returned err = %v, want nil", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAuthCookie(t *testing.T) {
	b, token := newBackend(t)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "__session", Value: token})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := Auth(b)(okHandler(t))(c); err != nil {
		t.Fatalf("cookie path returned err = %v, want nil", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (cookie path)", rec.Code)
	}
}

func TestAuthMissing(t *testing.T) {
	b, _ := newBackend(t)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := e.NewContext(req, httptest.NewRecorder())

	err := Auth(b)(func(c echo.Context) error {
		t.Error("next handler ran for an unauthenticated request")
		return nil
	})(c)
	want401(t, err)
}

func TestAuthInvalid(t *testing.T) {
	b, _ := newBackend(t)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	c := e.NewContext(req, httptest.NewRecorder())

	err := Auth(b)(func(c echo.Context) error {
		t.Error("next handler ran for an invalid token")
		return nil
	})(c)
	want401(t, err)
}
