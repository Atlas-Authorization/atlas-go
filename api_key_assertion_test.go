package atlas

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func pkcs8PEM(t *testing.T, k interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func splitJWT(t *testing.T, jwt string) (hdr, claims map[string]interface{}, input string, sig []byte) {
	t.Helper()
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		t.Fatalf("want 3 segments, got %d", len(p))
	}
	dec := func(s string, v interface{}) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		if v != nil {
			_ = json.Unmarshal(b, v)
		}
	}
	dec(p[0], &hdr)
	dec(p[1], &claims)
	sig, _ = base64.RawURLEncoding.DecodeString(p[2])
	return hdr, claims, p[0] + "." + p[1], sig
}

func TestSignAPIKeyAssertionES256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt, err := SignAPIKeyAssertion(pkcs8PEM(t, k), SignAPIKeyAssertionOptions{KeyID: "key_1", Audience: "ins_1", Scope: "read", JTI: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	h, c, in, sig := splitJWT(t, jwt)
	if h["alg"] != "ES256" || h["kid"] != "key_1" || h["typ"] != "JWT" {
		t.Fatalf("header %v", h)
	}
	if c["iss"] != "key_1" || c["aud"] != "ins_1" || c["scope"] != "read" || c["jti"] != "j1" {
		t.Fatalf("claims %v", c)
	}
	if c["exp"].(float64)-c["iat"].(float64) != 300 {
		t.Fatalf("ttl %v", c)
	}
	if len(sig) != 64 {
		t.Fatalf("sig len %d", len(sig))
	}
	d := sha256.Sum256([]byte(in))
	if !ecdsa.Verify(&k.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
}

func TestSignAPIKeyAssertionEdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwt, err := SignAPIKeyAssertion(pkcs8PEM(t, priv), SignAPIKeyAssertionOptions{KeyID: "key_2", Audience: "ins_1", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	h, c, in, sig := splitJWT(t, jwt)
	if h["alg"] != "EdDSA" || c["jti"] == "" || c["exp"].(float64)-c["iat"].(float64) != 60 {
		t.Fatalf("%v %v", h, c)
	}
	if !ed25519.Verify(pub, []byte(in), sig) {
		t.Fatal("signature does not verify")
	}
}

type keyPairUpstream struct{ rec KeyMirrorKeyRecord }

func (f *keyPairUpstream) CreateKey(_ context.Context, _ CreateAPIKeyParams, _ ...RequestOption) (*KeyMirrorKeyRecord, error) {
	r := f.rec
	return &r, nil
}
func (f *keyPairUpstream) DeleteKey(_ context.Context, _ string) error { return nil }
func (f *keyPairUpstream) ListRevoked(_ context.Context, _ string, _ int) (*KeyMirrorRevokedPage, error) {
	return &KeyMirrorRevokedPage{}, nil
}

func keyPairMirror(t *testing.T, mutate func(*KeyMirrorRecordHelper)) (*KeyMirror, *MemoryKeyMirrorStore, string, *time.Time) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	aud := "ins_1"
	rec := KeyMirrorKeyRecord{ID: "key_1", SubjectType: "machine", SubjectID: "m1", Scopes: []string{"read", "write"}, Credential: "key_pair", PublicKey: &pub, Audience: &aud}
	if mutate != nil {
		h := KeyMirrorRecordHelper{&rec}
		mutate(&h)
	}
	now := time.Now()
	store := NewMemoryKeyMirrorStore()
	m, err := NewKeyMirror(KeyMirrorOptions{Store: store, Upstream: &keyPairUpstream{rec: rec}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Mint(context.Background(), CreateAPIKeyParams{}); err != nil {
		t.Fatal(err)
	}
	return m, store, pkcs8PEM(t, k), &now
}

// KeyMirrorRecordHelper lets a test adjust the key the fake upstream returns.
type KeyMirrorRecordHelper struct{ *KeyMirrorKeyRecord }

func TestKeyMirrorVerifyAssertion(t *testing.T) {
	ctx := context.Background()
	m, store, pem, now := keyPairMirror(t, nil)
	sign := func(o SignAPIKeyAssertionOptions) string {
		o.KeyID = "key_1"
		if o.Audience == "" {
			o.Audience = "ins_1"
		}
		jwt, err := SignAPIKeyAssertion(pem, o)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	code := func(jwt string, o KeyVerifyOptions) string {
		v, err := m.VerifyAssertion(ctx, jwt, o)
		if err != nil || v.Valid {
			t.Fatalf("want a refusal, got %+v %v", v, err)
		}
		return v.Code
	}
	if v, _ := m.VerifyAssertion(ctx, sign(SignAPIKeyAssertionOptions{Scope: "read", JTI: "a"}), KeyVerifyOptions{RequiredScopes: []string{"read"}}); !v.Valid || v.Credential != "key_pair" || v.JTI != "a" || len(v.EffectiveScopes) != 1 {
		t.Fatalf("valid assertion: %+v", v)
	}
	if c := code(sign(SignAPIKeyAssertionOptions{Scope: "admin"}), KeyVerifyOptions{}); c != KeyMirrorCodeScopeNotGranted {
		t.Fatal(c)
	}
	if c := code(sign(SignAPIKeyAssertionOptions{Audience: "other"}), KeyVerifyOptions{}); c != KeyMirrorCodeWrongAudience {
		t.Fatal(c)
	}
	if c := code(sign(SignAPIKeyAssertionOptions{TTLSeconds: -100}), KeyVerifyOptions{}); c != KeyMirrorCodeAssertionExpired {
		t.Fatal(c)
	}
	if c := code(sign(SignAPIKeyAssertionOptions{TTLSeconds: 7200}), KeyVerifyOptions{}); c != KeyMirrorCodeAssertionLifetimeTooLong {
		t.Fatal(c)
	}
	if c := code("a.b.c", KeyVerifyOptions{}); c != KeyMirrorCodeInvalidAssertion {
		t.Fatal(c)
	}
	// A disabled key is refused like an unknown one.
	_ = store.Put(ctx, func() MirroredAPIKey { k, _ := store.Get(ctx, "key_1"); off := false; k.Enabled = &off; return *k }())
	if c := code(sign(SignAPIKeyAssertionOptions{}), KeyVerifyOptions{}); c != KeyMirrorCodeInvalidAssertion {
		t.Fatal(c)
	}
	_ = store.Put(ctx, func() MirroredAPIKey { k, _ := store.Get(ctx, "key_1"); on := true; k.Enabled = &on; return *k }())
	// A refused assertion never burns its jti; the first accepted use does.
	tok := sign(SignAPIKeyAssertionOptions{JTI: "j1"})
	if c := code(tok, KeyVerifyOptions{RequiredScopes: []string{"nope"}}); c != KeyMirrorCodeInsufficientScope {
		t.Fatal(c)
	}
	if v, _ := m.VerifyAssertion(ctx, tok, KeyVerifyOptions{}); !v.Valid {
		t.Fatalf("first use: %+v", v)
	}
	if c := code(tok, KeyVerifyOptions{}); c != KeyMirrorCodeAssertionReplayed {
		t.Fatal(c)
	}
	// An iat in the future (mirror clock behind) is not yet valid.
	*now = now.Add(-10 * time.Minute)
	if c := code(sign(SignAPIKeyAssertionOptions{}), KeyVerifyOptions{}); c != KeyMirrorCodeAssertionNotYetValid {
		t.Fatal(c)
	}
	*now = now.Add(10 * time.Minute)
	_ = store.MarkRevoked(ctx, "key_1", now.UnixMilli(), "")
	if v, _ := m.VerifyAssertion(ctx, sign(SignAPIKeyAssertionOptions{}), KeyVerifyOptions{}); v.Valid || v.Code != "" {
		t.Fatalf("revoked: %+v", v)
	}
}
