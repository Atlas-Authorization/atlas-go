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
	"testing"
	"time"
)

// signToken mints a real RS256 JWT for the given claims and kid, so the verifier
// exercises the genuine signature path rather than a stub.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	enc := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serves a single-key JWKS derived from key, counting fetches.
func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string, fetches *int) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetches != nil {
			*fetches++
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{"kty": "RSA", "kid": kid, "n": n, "e": e, "alg": "RS256"}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newVerifier(t *testing.T, jwksURL, issuer string, now time.Time) *AtlasBackend {
	t.Helper()
	b, err := NewAtlasBackend(AtlasBackendOptions{
		JWKSURL: jwksURL,
		Issuer:  issuer,
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAtlasBackend: %v", err)
	}
	return b
}

func TestVerifyValidToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", now)

	token := signToken(t, key, "kid-1", map[string]interface{}{
		"iss":             "https://issuer.atlas.dev",
		"sub":             "user_1",
		"sid":             "sess_1",
		"exp":             now.Add(time.Minute).Unix(),
		"nbf":             now.Add(-time.Minute).Unix(),
		"org_role":        "admin",
		"org_permissions": []string{"billing:read"},
	})

	claims, err := b.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "user_1" || claims.Sid != "sess_1" {
		t.Errorf("claims = %+v, want sub=user_1 sid=sess_1", claims)
	}
	if !claims.HasRole("admin") {
		t.Error("HasRole(admin) = false, want true")
	}
	if !claims.HasPermission("billing:read") {
		t.Error("HasPermission(billing:read) = false, want true")
	}
	if claims.HasPermission("billing:write") {
		t.Error("HasPermission(billing:write) = true, want false")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", now)

	token := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://evil.example.com",
		"sub": "user_1", "sid": "s", "exp": now.Add(time.Minute).Unix(),
	})
	if _, err := b.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", now)

	token := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(-time.Hour).Unix(),
	})
	if _, err := b.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken for expired token", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	// JWKS serves `key`, but the token is signed with `other`.
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", now)

	token := signToken(t, other, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(time.Minute).Unix(),
	})
	if _, err := b.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken for a bad signature", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", time.Now())
	if _, err := b.Verify(context.Background(), "not-a-jwt"); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestVerifyRejectsTokenUseAndAud(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	b := newVerifier(t, srv.URL, "https://issuer.atlas.dev", now)

	// token_use != session must be refused (OP token-confusion guard).
	tok := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(time.Minute).Unix(), "token_use": "access_token",
	})
	if _, err := b.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken for token_use=access_token", err)
	}

	// An aud claim must be refused too.
	tok2 := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(time.Minute).Unix(), "aud": "some-client",
	})
	if _, err := b.Verify(context.Background(), tok2); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken for aud claim", err)
	}
}

func TestVerifyAuthorizedParties(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	b, _ := NewAtlasBackend(AtlasBackendOptions{
		JWKSURL:           srv.URL,
		Issuer:            "https://issuer.atlas.dev",
		AuthorizedParties: []string{"https://app.example.com"},
		Now:               func() time.Time { return now },
	})

	bad := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(time.Minute).Unix(), "azp": "https://evil.example.com",
	})
	if _, err := b.Verify(context.Background(), bad); !errors.Is(err, ErrUnauthorizedParty) {
		t.Errorf("err = %v, want ErrUnauthorizedParty", err)
	}

	good := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s",
		"exp": now.Add(time.Minute).Unix(), "azp": "https://app.example.com",
	})
	if _, err := b.Verify(context.Background(), good); err != nil {
		t.Errorf("Verify(good azp) = %v, want nil", err)
	}
}

func TestJWKSCacheThrottlesKidMiss(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// A mutable clock so we can cross the refetch interval deliberately: a
	// kid-miss at the same instant as the last fetch is throttled by design.
	clock := time.Unix(1_700_000_000, 0)
	fetches := 0
	srv := jwksServer(t, key, "kid-1", &fetches)
	b, err := NewAtlasBackend(AtlasBackendOptions{
		JWKSURL: srv.URL,
		Issuer:  "https://issuer.atlas.dev",
		Now:     func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("NewAtlasBackend: %v", err)
	}

	longExp := clock.Add(time.Hour).Unix()

	// First verify: one fetch (initial population).
	valid := signToken(t, key, "kid-1", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s", "exp": longExp,
	})
	if _, err := b.Verify(context.Background(), valid); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("fetches after first verify = %d, want 1", fetches)
	}

	// Advance past the refetch interval: an unknown kid now triggers one refetch.
	clock = clock.Add(2 * time.Minute)
	unknown := signToken(t, key, "kid-unknown", map[string]interface{}{
		"iss": "https://issuer.atlas.dev", "sub": "u", "sid": "s", "exp": longExp,
	})
	_, _ = b.Verify(context.Background(), unknown)
	if fetches != 2 {
		t.Fatalf("fetches after first kid-miss = %d, want 2 (a refetch)", fetches)
	}

	// A second kid-miss at the same instant is throttled: no new fetch.
	_, _ = b.Verify(context.Background(), unknown)
	if fetches != 2 {
		t.Errorf("fetches after second kid-miss = %d, want 2 (throttled)", fetches)
	}
	if b.JWKS().LastOutcome != OutcomeThrottled {
		t.Errorf("LastOutcome = %q, want throttled", b.JWKS().LastOutcome)
	}
}
