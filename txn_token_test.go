package atlas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type txnFixture struct {
	key  *ecdsa.PrivateKey
	jwks []byte
}

func newTxnFixture(t *testing.T) *txnFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	set, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}}})
	return &txnFixture{key: key, jwks: set}
}

func (f *txnFixture) token(t *testing.T, typ string, claims map[string]interface{}) string {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": typ})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + b64(sig)
}

func txnClaims(now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"iss": "https://id.example.com", "sub": "usr_1", "aud": "trust.example.com", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"txn": "txn_1", "scope": "orders:read orders:write", "req_wl": "wl_1", "tctx": map[string]interface{}{"order": "o1"},
	}
}

func TestVerifyTransactionToken(t *testing.T) {
	f := newTxnFixture(t)
	now := time.Now()
	opts := TxnTokenOptions{Issuer: "https://id.example.com/", TrustDomain: "trust.example.com", JWKSJSON: f.jwks, Now: now}

	res, err := VerifyTransactionToken(context.Background(), f.token(t, "txntoken+jwt", txnClaims(now)), opts)
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if res.Claims.Txn != "txn_1" || len(res.Scopes) != 2 || res.Scopes[1] != "orders:write" || res.Claims.Tctx["order"] != "o1" {
		t.Fatalf("claims: %+v scopes=%v", res.Claims, res.Scopes)
	}

	wrongAud := txnClaims(now)
	wrongAud["aud"] = "other.example.com"
	if _, err := VerifyTransactionToken(context.Background(), f.token(t, "txntoken+jwt", wrongAud), opts); !errors.Is(err, ErrTxnTokenInvalid) {
		t.Fatalf("another trust domain must be refused, got %v", err)
	}
	if _, err := VerifyTransactionToken(context.Background(), f.token(t, "JWT", txnClaims(now)), opts); !errors.Is(err, ErrTxnTokenInvalid) {
		t.Fatalf("a wrong typ must be refused, got %v", err)
	}
	expired := txnClaims(now.Add(-time.Hour))
	if _, err := VerifyTransactionToken(context.Background(), f.token(t, "txntoken+jwt", expired), opts); !errors.Is(err, ErrTxnTokenInvalid) {
		t.Fatalf("an expired token must be refused, got %v", err)
	}
	missing := txnClaims(now)
	delete(missing, "req_wl")
	if _, err := VerifyTransactionToken(context.Background(), f.token(t, "txntoken+jwt", missing), opts); err == nil || errors.Is(err, ErrTxnTokenInvalid) {
		t.Fatalf("a missing required claim is named, got %v", err)
	}
	other := newTxnFixture(t)
	if _, err := VerifyTransactionToken(context.Background(), other.token(t, "txntoken+jwt", txnClaims(now)), opts); !errors.Is(err, ErrTxnTokenInvalid) {
		t.Fatalf("a token signed by another key must be refused, got %v", err)
	}
}
