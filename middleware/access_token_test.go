package middleware

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	atlas "github.com/Atlas-Authorization/atlas-go"
)

func TestRequireAccessToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{"kty": "RSA", "kid": "kid-1", "n": n, "e": e, "alg": "RS256"}},
		})
	}))
	t.Cleanup(srv.Close)
	v, err := atlas.NewAccessTokenVerifier(atlas.AccessTokenVerifierOptions{
		Issuer: testIssuer, Audiences: []string{"https://api.test"}, JWKSURL: srv.URL,
		ResourceMetadataURL: "https://api.test/.well-known/oauth-protected-resource",
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	var seen *atlas.AccessTokenResult
	h := RequireAccessToken(v, "docs:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = AccessTokenFromContext(r.Context())
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/docs", nil))
	if rr.Code != 401 || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `resource_metadata="https://api.test/.well-known/oauth-protected-resource"`) {
		t.Fatalf("no token: %d %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}

	claims := map[string]interface{}{"iss": testIssuer, "sub": "user_1", "aud": "https://api.test",
		"exp": now.Add(time.Minute).Unix(), "token_use": "access_token", "scope": "docs:read"}
	req := httptest.NewRequest("GET", "/docs", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, key, "kid-1", claims))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || seen == nil || seen.Subject != "user_1" {
		t.Fatalf("valid token: %d %+v", rr.Code, seen)
	}

	claims["scope"] = "other"
	req = httptest.NewRequest("GET", "/docs", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, key, "kid-1", claims))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 403 || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("insufficient scope: %d %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireAccessTokenDPoP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{"kty": "RSA", "kid": "kid-1", "n": n, "e": e, "alg": "RS256"}},
		})
	}))
	t.Cleanup(srv.Close)
	nonces, err := atlas.NewHMACDPoPNonceSource([]byte(strings.Repeat("k", 32)), 0)
	if err != nil {
		t.Fatal(err)
	}
	v, err := atlas.NewAccessTokenVerifier(atlas.AccessTokenVerifierOptions{
		Issuer: testIssuer, Audiences: []string{"https://api.test"}, JWKSURL: srv.URL,
		PublicOrigin: "https://api.test", DPoPNonces: nonces,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	var seen *atlas.AccessTokenResult
	h := RequireAccessToken(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = AccessTokenFromContext(r.Context())
	}))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwk := map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	jkt, _ := atlas.JWKThumbprint(jwk)
	tok := signToken(t, key, "kid-1", map[string]interface{}{"iss": testIssuer, "sub": "user_1", "aud": "https://api.test",
		"exp": now.Add(time.Minute).Unix(), "token_use": "access_token", "cnf": map[string]string{"jkt": jkt}})
	proof := func(nonce string) string {
		enc := func(v interface{}) string {
			raw, _ := json.Marshal(v)
			return base64.RawURLEncoding.EncodeToString(raw)
		}
		c := map[string]interface{}{"htm": "PUT", "htu": "https://api.test/docs/1", "iat": now.Unix(), "jti": nonce + "-jti",
			"ath": atlas.DPoPAccessTokenHash(tok)}
		if nonce != "" {
			c["nonce"] = nonce
		}
		in := enc(map[string]interface{}{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk}) + "." + enc(c)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	send := func(p string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/docs/1?draft=1", nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		req.Header.Set("DPoP", p)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	rr := send(proof(""))
	nonce := rr.Header().Get("DPoP-Nonce")
	if rr.Code != 401 || nonce == "" || !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), `DPoP error="use_dpop_nonce"`) {
		t.Fatalf("no nonce: %d %q %q", rr.Code, nonce, rr.Header().Get("WWW-Authenticate"))
	}
	rr = send(proof(nonce))
	if rr.Code != 200 || seen == nil || !seen.DPoPBound || rr.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("with nonce: %d %+v", rr.Code, seen)
	}
	rr = send(proof(nonce))
	if rr.Code != 401 || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`) {
		t.Fatalf("replay: %d %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
}
