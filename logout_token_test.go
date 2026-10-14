package atlas

import (
	"context"
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
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	ltIssuer   = "https://atlasauth.net"
	ltClientID = "cid_shop"
)

type logoutFixture struct {
	key     *rsa.PrivateKey
	other   *rsa.PrivateKey
	jwksURL string
	now     time.Time
}

func newLogoutFixture(t *testing.T) *logoutFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwksBody, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwksBody)
	}))
	t.Cleanup(srv.Close)
	return &logoutFixture{key: key, other: other, jwksURL: srv.URL, now: time.Unix(1_800_000_000, 0)}
}

func (f *logoutFixture) sign(t *testing.T, key *rsa.PrivateKey, header, claims map[string]interface{}) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func (f *logoutFixture) claims() map[string]interface{} {
	return map[string]interface{}{
		"iss": ltIssuer, "aud": ltClientID, "sub": "user_1", "sid": "sess_1", "jti": "jti_1",
		"iat": f.now.Unix(), "exp": f.now.Unix() + 120,
		"events": map[string]interface{}{BackchannelLogoutEvent: map[string]interface{}{}},
	}
}

func (f *logoutFixture) header() map[string]interface{} {
	return map[string]interface{}{"alg": "RS256", "kid": "k1", "typ": "logout+jwt"}
}

func (f *logoutFixture) verifier(t *testing.T, guard LogoutReplayGuard) *LogoutTokenVerifier {
	t.Helper()
	v, err := NewLogoutTokenVerifier(LogoutTokenVerifierOptions{
		JWKSURL: f.jwksURL, Issuer: ltIssuer, ClientID: ltClientID, ReplayGuard: guard,
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLogoutTokenValid(t *testing.T) {
	f := newLogoutFixture(t)
	v := f.verifier(t, nil)
	claims, err := v.Verify(context.Background(), f.sign(t, f.key, f.header(), f.claims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "user_1" || claims.Sid != "sess_1" || claims.Jti != "jti_1" || claims.Iat != f.now.Unix() {
		t.Errorf("claims = %+v", claims)
	}

	// aud as an array containing the client id, no typ header, sid only.
	c := f.claims()
	c["aud"] = []string{"someone_else", ltClientID}
	delete(c, "sub")
	delete(c, "exp")
	h := f.header()
	delete(h, "typ")
	if _, err := v.Verify(context.Background(), f.sign(t, f.key, h, c)); err != nil {
		t.Errorf("array aud / no typ / sid-only: %v", err)
	}
}

func TestLogoutTokenRejections(t *testing.T) {
	f := newLogoutFixture(t)
	v := f.verifier(t, nil)
	cases := map[string]func(h, c map[string]interface{}) *rsa.PrivateKey{
		"wrong typ":      func(h, c map[string]interface{}) *rsa.PrivateKey { h["typ"] = "JWT"; return f.key },
		"has nonce":      func(h, c map[string]interface{}) *rsa.PrivateKey { c["nonce"] = "n"; return f.key },
		"missing events": func(h, c map[string]interface{}) *rsa.PrivateKey { delete(c, "events"); return f.key },
		"wrong event value": func(h, c map[string]interface{}) *rsa.PrivateKey {
			c["events"] = map[string]interface{}{BackchannelLogoutEvent: "yes"}
			return f.key
		},
		"wrong aud":     func(h, c map[string]interface{}) *rsa.PrivateKey { c["aud"] = "cid_other"; return f.key },
		"wrong iss":     func(h, c map[string]interface{}) *rsa.PrivateKey { c["iss"] = "https://evil.test"; return f.key },
		"expired":       func(h, c map[string]interface{}) *rsa.PrivateKey { c["exp"] = f.now.Unix() - 60; return f.key },
		"iat in future": func(h, c map[string]interface{}) *rsa.PrivateKey { c["iat"] = f.now.Unix() + 600; return f.key },
		"iat too old": func(h, c map[string]interface{}) *rsa.PrivateKey {
			c["iat"] = f.now.Unix() - 3600
			delete(c, "exp")
			return f.key
		},
		"missing iat":   func(h, c map[string]interface{}) *rsa.PrivateKey { delete(c, "iat"); return f.key },
		"missing jti":   func(h, c map[string]interface{}) *rsa.PrivateKey { delete(c, "jti"); return f.key },
		"no sid or sub": func(h, c map[string]interface{}) *rsa.PrivateKey { delete(c, "sid"); delete(c, "sub"); return f.key },
		"not RS256":     func(h, c map[string]interface{}) *rsa.PrivateKey { h["alg"] = "HS256"; return f.key },
		"bad signature": func(h, c map[string]interface{}) *rsa.PrivateKey { return f.other },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, c := f.header(), f.claims()
			key := mutate(h, c)
			_, err := v.Verify(context.Background(), f.sign(t, key, h, c))
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
	if _, err := v.Verify(context.Background(), "not-a-jwt"); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed: %v", err)
	}
}

func TestLogoutTokenReplayAndRequest(t *testing.T) {
	f := newLogoutFixture(t)
	guard := &MemoryReplayGuard{Now: func() time.Time { return f.now }}
	v := f.verifier(t, guard)
	token := f.sign(t, f.key, f.header(), f.claims())

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claims, err := v.VerifyRequest(req)
	if err != nil || claims.Sid != "sess_1" {
		t.Fatalf("VerifyRequest = %+v, %v", claims, err)
	}
	if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrLogoutTokenReplayed) {
		t.Errorf("replay: err = %v, want ErrLogoutTokenReplayed", err)
	}
	// After the remembered window, the guard forgets the jti.
	guard.Now = func() time.Time { return f.now.Add(time.Hour) }
	if fresh, _ := guard.Remember(context.Background(), "jti_1", time.Minute); !fresh {
		t.Error("guard should have expired jti_1")
	}

	if _, err := NewLogoutTokenVerifier(LogoutTokenVerifierOptions{JWKSURL: "x", Issuer: ltIssuer}); err == nil {
		t.Error("missing ClientID must be refused")
	}
}
