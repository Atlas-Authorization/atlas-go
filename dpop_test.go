package atlas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// DPoP (RFC 9449) on the access-token verifier: the same vectors as the
// TypeScript @atlasauth/backend suite, plus every other refusal path.

const dpopAPI = "https://api.example.com/mcp"

type dpopKey struct {
	alg  string
	sign func(input []byte) []byte
	jwk  map[string]interface{}
	jkt  string
}

func newDPoPKey(t *testing.T, alg string) dpopKey {
	t.Helper()
	k := dpopKey{alg: alg}
	switch alg {
	case "ES256":
		ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k.jwk = map[string]interface{}{"kty": "EC", "crv": "P-256",
			"x": b64(ec.PublicKey.X.FillBytes(make([]byte, 32))), "y": b64(ec.PublicKey.Y.FillBytes(make([]byte, 32)))}
		k.sign = func(in []byte) []byte {
			d := sha256.Sum256(in)
			r, s, _ := ecdsa.Sign(rand.Reader, ec, d[:])
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			return sig
		}
	case "RS256", "PS256":
		rs, _ := rsa.GenerateKey(rand.Reader, 2048)
		k.jwk = map[string]interface{}{"kty": "RSA", "n": b64(rs.N.Bytes()), "e": b64(big.NewInt(int64(rs.E)).Bytes())}
		k.sign = func(in []byte) []byte {
			d := sha256.Sum256(in)
			if alg == "PS256" {
				sig, _ := rsa.SignPSS(rand.Reader, rs, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				return sig
			}
			sig, _ := rsa.SignPKCS1v15(rand.Reader, rs, crypto.SHA256, d[:])
			return sig
		}
	case "EdDSA":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k.jwk = map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)}
		k.sign = func(in []byte) []byte { return ed25519.Sign(priv, in) }
	}
	jkt, err := JWKThumbprint(k.jwk)
	if err != nil {
		t.Fatal(err)
	}
	k.jkt = jkt
	return k
}

type proofOpts struct {
	header  map[string]interface{} // replaces the whole header when set
	claims  map[string]interface{} // merged over the defaults; nil value deletes
	tamper  bool
	signAlg string
}

func makeProof(k dpopKey, token string, now time.Time, o proofOpts) string {
	h := map[string]interface{}{"typ": "dpop+jwt", "alg": k.alg, "jwk": k.jwk}
	if o.header != nil {
		h = o.header
	}
	c := map[string]interface{}{"htm": "POST", "htu": dpopAPI, "jti": randomJTI(), "iat": now.Unix(), "ath": DPoPAccessTokenHash(token)}
	for key, v := range o.claims {
		if v == nil {
			delete(c, key)
		} else {
			c[key] = v
		}
	}
	hj, _ := json.Marshal(h)
	cj, _ := json.Marshal(c)
	input := b64(hj) + "." + b64(cj)
	sig := k.sign([]byte(input))
	if o.tamper {
		cj2, _ := json.Marshal(map[string]interface{}{"htm": "POST", "htu": dpopAPI, "jti": "x", "iat": now.Unix(), "ath": "y"})
		input = b64(hj) + "." + b64(cj2)
	}
	return input + "." + b64(sig)
}

func randomJTI() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return b64(b)
}

type dpopFixture struct {
	t    *testing.T
	ec   *ecdsa.PrivateKey
	now  time.Time
	jwks string
}

func newDPoPFixture(t *testing.T) *dpopFixture {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := mixedJWKS(t, ec, rs)
	return &dpopFixture{t: t, ec: ec, now: time.Unix(1_800_000_000, 0), jwks: srv.URL}
}

func (f *dpopFixture) verifier(mod func(*AccessTokenVerifierOptions)) *AccessTokenVerifier {
	o := AccessTokenVerifierOptions{
		Issuer: "https://auth.example.com", Audiences: []string{dpopAPI}, JWKSURL: f.jwks,
		ResourceMetadataURL: "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		Now:                 func() time.Time { return f.now },
	}
	if mod != nil {
		mod(&o)
	}
	v, err := NewAccessTokenVerifier(o)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *dpopFixture) token(jkt string) string {
	c := map[string]interface{}{"iss": "https://auth.example.com", "sub": "user_1", "aud": dpopAPI, "exp": f.now.Unix() + 300,
		"token_use": "access_token", "scope": "tools:read", "client_id": "cli_1"}
	if jkt != "" {
		c["cnf"] = map[string]interface{}{"jkt": jkt}
	}
	return signES256(f.t, f.ec, "ec1", c)
}

func dpopReq(scheme, token, proof string) ResourceRequest {
	return ResourceRequest{Method: "POST", URL: dpopAPI + "?x=1", Authorization: scheme + " " + token, DPoP: proof}
}

func expectRefusal(t *testing.T, name string, r *AccessTokenResult, code AccessTokenErrorCode) {
	t.Helper()
	if r.OK || r.Status != 401 || r.Error != code {
		t.Errorf("%s: want 401 %s, got %+v", name, code, r)
		return
	}
	if !strings.HasPrefix(r.WWWAuthenticate, "DPoP ") || !strings.Contains(r.WWWAuthenticate, `error="`+string(code)+`"`) || !strings.Contains(r.WWWAuthenticate, `algs="ES256`) {
		t.Errorf("%s: challenge %q", name, r.WWWAuthenticate)
	}
}

func TestDPoPAcceptsBoundTokenWithMatchingProof(t *testing.T) {
	f := newDPoPFixture(t)
	v := f.verifier(nil)
	ctx := context.Background()
	for _, alg := range []string{"ES256", "RS256", "PS256", "EdDSA"} {
		k := newDPoPKey(t, alg)
		tok := f.token(k.jkt)
		r := v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{})))
		if !r.OK || !r.DPoPBound || r.Subject != "user_1" {
			t.Errorf("%s proof refused: %+v", alg, r)
		}
	}
	// An unbound token is still a plain Bearer token, and says so.
	if r := v.VerifyResource(ctx, dpopReq("Bearer", f.token(""), "")); !r.OK || r.DPoPBound {
		t.Errorf("bearer = %+v", r)
	}
}

func TestDPoPNeverAcceptsBoundTokenAsBearer(t *testing.T) {
	f := newDPoPFixture(t)
	v := f.verifier(nil)
	k := newDPoPKey(t, "ES256")
	tok := f.token(k.jkt)
	r := v.VerifyResource(context.Background(), dpopReq("Bearer", tok, makeProof(k, tok, f.now, proofOpts{})))
	expectRefusal(t, "bound as bearer", r, AccessTokenInvalidToken)
	// Verify (no proof possible) refuses it too.
	if r := v.Verify(context.Background(), "DPoP "+tok); r.OK || r.Error != AccessTokenInvalidDPoPProof {
		t.Errorf("Verify without proof = %+v", r)
	}
	// An unbound token under the DPoP scheme is refused.
	expectRefusal(t, "unbound as DPoP", v.VerifyResource(context.Background(), dpopReq("DPoP", f.token(""), makeProof(k, f.token(""), f.now, proofOpts{}))), AccessTokenInvalidToken)
}

func TestDPoPRejectsEveryBadProof(t *testing.T) {
	f := newDPoPFixture(t)
	v := f.verifier(func(o *AccessTokenVerifierOptions) { o.DPoPReplayStore = NewMemoryDPoPReplayStore(0) })
	k := newDPoPKey(t, "ES256")
	tok := f.token(k.jkt)
	ctx := context.Background()
	other := newDPoPKey(t, "ES256")
	withPriv := map[string]interface{}{}
	for kk, vv := range k.jwk {
		withPriv[kk] = vv
	}
	withPriv["d"] = "AAAA"
	cases := map[string]string{
		"missing proof":    "",
		"malformed":        "not-a-jwt",
		"garbage header":   "e30.e30.e30",
		"another key":      makeProof(other, tok, f.now, proofOpts{}),
		"wrong htm":        makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"htm": "GET"}}),
		"wrong htu":        makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"htu": "https://api.example.com/other"}}),
		"wrong host":       makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"htu": "https://evil.example.com/mcp"}}),
		"relative htu":     makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"htu": "/mcp"}}),
		"wrong ath":        makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"ath": "nope"}}),
		"no ath":           makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"ath": nil}}),
		"stale":            makeProof(k, tok, f.now.Add(-time.Hour), proofOpts{}),
		"future":           makeProof(k, tok, f.now.Add(time.Minute), proofOpts{}),
		"no iat":           makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"iat": nil}}),
		"expired exp":      makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"exp": f.now.Unix() - 60}}),
		"no jti":           makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"jti": nil}}),
		"typ JWT":          makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "JWT", "alg": "ES256", "jwk": k.jwk}}),
		"alg HS256":        makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "dpop+jwt", "alg": "HS256", "jwk": k.jwk}}),
		"alg none":         makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "dpop+jwt", "alg": "none", "jwk": k.jwk}}),
		"no jwk":           makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256"}}),
		"private jwk":      makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256", "jwk": withPriv}}),
		"alg/key mismatch": makeProof(k, tok, f.now, proofOpts{header: map[string]interface{}{"typ": "dpop+jwt", "alg": "RS256", "jwk": k.jwk}}),
		"bad signature":    makeProof(k, tok, f.now, proofOpts{tamper: true}),
	}
	for name, proof := range cases {
		expectRefusal(t, name, v.VerifyResource(ctx, dpopReq("DPoP", tok, proof)), AccessTokenInvalidDPoPProof)
	}
	// A proof for a different access token (ath mismatch) — the other token is bound to the same key.
	tok2 := f.token(k.jkt)
	f.now = f.now.Add(time.Second)
	tok3 := f.token(k.jkt)
	if tok2 == tok3 {
		t.Fatal("tokens should differ")
	}
	expectRefusal(t, "proof for another token", v.VerifyResource(ctx, dpopReq("DPoP", tok3, makeProof(k, tok2, f.now, proofOpts{}))), AccessTokenInvalidDPoPProof)

	once := makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"jti": "fixed"}})
	if r := v.VerifyResource(ctx, dpopReq("DPoP", tok, once)); !r.OK {
		t.Fatalf("first use refused: %+v", r)
	}
	expectRefusal(t, "replay", v.VerifyResource(ctx, dpopReq("DPoP", tok, once)), AccessTokenInvalidDPoPProof)
	// The same jti from a different key is a different proof.
	tokOther := f.token(other.jkt)
	if r := v.VerifyResource(ctx, dpopReq("DPoP", tokOther, makeProof(other, tokOther, f.now, proofOpts{claims: map[string]interface{}{"jti": "fixed"}}))); !r.OK {
		t.Errorf("same jti, other key refused: %+v", r)
	}
}

func TestDPoPRequireDPoPRefusesUnboundToken(t *testing.T) {
	f := newDPoPFixture(t)
	v := f.verifier(func(o *AccessTokenVerifierOptions) { o.RequireDPoP = true })
	r := v.VerifyResource(context.Background(), dpopReq("Bearer", f.token(""), ""))
	expectRefusal(t, "requireDpop", r, AccessTokenInvalidToken)
	none := v.VerifyResource(context.Background(), ResourceRequest{Method: "GET", URL: dpopAPI})
	if none.Status != 401 || none.Error != "" || !strings.HasPrefix(none.WWWAuthenticate, "DPoP ") || !strings.Contains(none.WWWAuthenticate, `algs="`) {
		t.Errorf("no token under requireDpop = %+v", none)
	}
}

func TestDPoPHTUNormalisationAndPublicOrigin(t *testing.T) {
	f := newDPoPFixture(t)
	k := newDPoPKey(t, "ES256")
	tok := f.token(k.jkt)
	v := f.verifier(nil)
	ctx := context.Background()
	for _, htu := range []string{"HTTPS://API.Example.COM:443/mcp", "https://api.example.com/mcp?other=2#frag"} {
		r := v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"htu": htu}})))
		if !r.OK {
			t.Errorf("htu %q refused: %+v", htu, r)
		}
	}
	// A path-only URL needs PublicOrigin.
	path := ResourceRequest{Method: "post", URL: "/mcp?x=1", Authorization: "DPoP " + tok}
	path.DPoP = makeProof(k, tok, f.now, proofOpts{})
	expectRefusal(t, "path without origin", v.VerifyResource(ctx, path), AccessTokenInvalidDPoPProof)
	vo := f.verifier(func(o *AccessTokenVerifierOptions) { o.PublicOrigin = "https://api.example.com" })
	path.DPoP = makeProof(k, tok, f.now, proofOpts{})
	if r := vo.VerifyResource(ctx, path); !r.OK {
		t.Errorf("path with PublicOrigin refused: %+v", r)
	}
	// VerifyRequest reads method, URL, Authorization and DPoP off *http.Request.
	hr := httptest.NewRequest("POST", "https://api.example.com/mcp?x=1", nil)
	hr.Header.Set("Authorization", "DPoP "+tok)
	hr.Header.Set("DPoP", makeProof(k, tok, f.now, proofOpts{}))
	if r := v.VerifyRequest(ctx, hr); !r.OK {
		t.Errorf("VerifyRequest refused: %+v", r)
	}
	// Two DPoP headers are no proof.
	hr2 := httptest.NewRequest("POST", "https://api.example.com/mcp", nil)
	hr2.Header.Set("Authorization", "DPoP "+tok)
	hr2.Header.Add("DPoP", makeProof(k, tok, f.now, proofOpts{}))
	hr2.Header.Add("DPoP", makeProof(k, tok, f.now, proofOpts{}))
	expectRefusal(t, "two proofs", v.VerifyRequest(ctx, hr2), AccessTokenInvalidDPoPProof)

	for in, want := range map[string]string{
		"https://A.example.com:443":     "https://a.example.com/",
		"http://a.example.com:80/x?y#z": "http://a.example.com/x",
		"https://a.example.com:8443/p/": "https://a.example.com:8443/p/",
		"https://[::1]:443/p":           "https://[::1]/p",
	} {
		if got, ok := NormalizeHTU(in); !ok || got != want {
			t.Errorf("NormalizeHTU(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := NormalizeHTU("ftp://x/y"); ok {
		t.Error("non-http htu normalised")
	}
}

func TestDPoPServerNonce(t *testing.T) {
	f := newDPoPFixture(t)
	nonces, err := NewHMACDPoPNonceSource([]byte(strings.Repeat("s", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	nonces.now = func() time.Time { return f.now }
	v := f.verifier(func(o *AccessTokenVerifierOptions) { o.DPoPNonces = nonces })
	k := newDPoPKey(t, "ES256")
	tok := f.token(k.jkt)
	ctx := context.Background()

	r := v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{})))
	expectRefusal(t, "no nonce", r, AccessTokenUseDPoPNonce)
	if r.DPoPNonce == "" || r.DPoPNonce != nonces.Current() {
		t.Errorf("refusal carries no DPoP-Nonce: %+v", r)
	}
	expectRefusal(t, "wrong nonce", v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"nonce": "made-up"}}))), AccessTokenUseDPoPNonce)
	ok := v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"nonce": r.DPoPNonce}})))
	if !ok.OK || ok.DPoPNonce == "" {
		t.Fatalf("proof with nonce refused: %+v", ok)
	}
	// The nonce from the previous window still works; two windows back does not.
	issued := nonces.Current()
	f.now = f.now.Add(time.Minute)
	if !nonces.Valid(issued) {
		t.Error("previous-window nonce refused")
	}
	f.now = f.now.Add(time.Minute)
	if nonces.Valid(issued) {
		t.Error("stale nonce accepted")
	}
	tok = f.token(k.jkt)
	expectRefusal(t, "stale nonce", v.VerifyResource(ctx, dpopReq("DPoP", tok, makeProof(k, tok, f.now, proofOpts{claims: map[string]interface{}{"nonce": issued}}))), AccessTokenUseDPoPNonce)
	if _, err := NewHMACDPoPNonceSource([]byte("short"), 0); err == nil {
		t.Error("short nonce secret accepted")
	}
}

func TestDPoPHelpers(t *testing.T) {
	// RFC 7638 §3.1 example key and thumbprint.
	got, err := JWKThumbprint(map[string]interface{}{
		"kty": "RSA", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	})
	if err != nil || got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint = %q, %v", got, err)
	}
	if _, err := JWKThumbprint(map[string]interface{}{"kty": "oct", "k": "x"}); err == nil {
		t.Error("oct thumbprint computed")
	}
	store := NewMemoryDPoPReplayStore(2)
	now := time.Unix(1000, 0)
	store.now = func() time.Time { return now }
	if !store.Claim("a", now.Add(time.Minute)) || store.Claim("a", now.Add(time.Minute)) {
		t.Error("replay store let a repeat through")
	}
	now = now.Add(2 * time.Minute)
	if !store.Claim("a", now.Add(time.Minute)) {
		t.Error("expired entry still blocks")
	}
	store.Claim("b", now.Add(time.Minute))
	store.Claim("c", now.Add(time.Minute))
	if len(store.seen) > 2 {
		t.Errorf("store holds %d entries, max 2", len(store.seen))
	}
	doc := ProtectedResourceMetadataRequiringDPoP(dpopAPI, "https://auth.example.com/", nil)
	if doc["dpop_bound_access_tokens_required"] != true || len(doc["dpop_signing_alg_values_supported"].([]string)) != len(DPoPAlgs) {
		t.Errorf("metadata = %v", doc)
	}
	if h := BuildWWWAuthenticate(WWWAuthenticateParams{Scheme: "DPoP", Error: AccessTokenUseDPoPNonce, Description: "n"}); h != `DPoP error="use_dpop_nonce", error_description="n", algs="`+strings.Join(DPoPAlgs, " ")+`"` {
		t.Errorf("challenge = %q", h)
	}
}
