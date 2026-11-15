package atlas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"testing"
)

func jwsB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwsPad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// jwsTestKey makes a key for alg at runtime and returns its public JWK and a signer.
func jwsTestKey(t *testing.T, alg string) (jwk, func(input string) []byte) {
	t.Helper()
	switch alg {
	case "RS256", "PS256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub := jwk{Kid: "k", Kty: "RSA", N: jwsB64(k.N.Bytes()), E: jwsB64(big.NewInt(int64(k.E)).Bytes())}
		return pub, func(in string) []byte {
			d := sha256.Sum256([]byte(in))
			var sig []byte
			var err error
			if alg == "RS256" {
				sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
			} else {
				sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			}
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
	case "ES256", "ES384":
		curve, crv, size := elliptic.P256(), "P-256", 32
		if alg == "ES384" {
			curve, crv, size = elliptic.P384(), "P-384", 48
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := jwk{Kid: "k", Kty: "EC", Crv: crv, X: jwsB64(jwsPad(k.X.Bytes(), size)), Y: jwsB64(jwsPad(k.Y.Bytes(), size))}
		return pub, func(in string) []byte {
			var digest []byte
			if alg == "ES384" {
				d := sha512.Sum384([]byte(in))
				digest = d[:]
			} else {
				d := sha256.Sum256([]byte(in))
				digest = d[:]
			}
			r, s, err := ecdsa.Sign(rand.Reader, k, digest)
			if err != nil {
				t.Fatal(err)
			}
			return append(jwsPad(r.Bytes(), size), jwsPad(s.Bytes(), size)...)
		}
	default: // EdDSA
		pubK, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return jwk{Kid: "k", Kty: "OKP", Crv: "Ed25519", X: jwsB64(pubK)}, func(in string) []byte {
			return ed25519.Sign(priv, []byte(in))
		}
	}
}

func TestVerifyJWSSignatureAllAlgs(t *testing.T) {
	const input = "header.payload"
	for _, alg := range SigningAlgs {
		pub, sign := jwsTestKey(t, alg)
		set := &jwks{Keys: []jwk{pub}}
		sig := sign(input)
		if !verifyJWSSignature(set, alg, "k", input, sig) {
			t.Errorf("%s: a valid signature was refused", alg)
		}
		if verifyJWSSignature(set, alg, "k", input+"x", sig) {
			t.Errorf("%s: a signature over other input verified", alg)
		}
		if verifyJWSSignature(set, alg, "other", input, sig) {
			t.Errorf("%s: a missing kid verified", alg)
		}
		// a key that pins its own alg is not usable for another
		pinned := pub
		pinned.Alg = "RS256"
		if alg != "RS256" && verifyJWSSignature(&jwks{Keys: []jwk{pinned}}, alg, "k", input, sig) {
			t.Errorf("%s: a key pinned to RS256 verified", alg)
		}
	}
}

func TestVerifyJWSSignatureNoAlgConfusion(t *testing.T) {
	const input = "header.payload"
	keys := map[string]jwk{}
	sigs := map[string][]byte{}
	for _, alg := range SigningAlgs {
		pub, sign := jwsTestKey(t, alg)
		keys[alg], sigs[alg] = pub, sign(input)
	}
	for keyAlg, pub := range keys {
		set := &jwks{Keys: []jwk{pub}}
		for tokAlg := range keys {
			// RS256 and PS256 share an RSA key type, but a signature of one never verifies as the other
			if keyAlg == tokAlg {
				continue
			}
			if verifyJWSSignature(set, tokAlg, "k", input, sigs[keyAlg]) {
				t.Errorf("a %s key and signature verified as %s", keyAlg, tokAlg)
			}
		}
	}
	for _, bad := range []string{"none", "HS256", "HS384", "HS512", "", "rs256"} {
		for _, pub := range keys {
			if verifyJWSSignature(&jwks{Keys: []jwk{pub}}, bad, "k", input, []byte("sig")) {
				t.Errorf("alg %q verified", bad)
			}
		}
		if contains(SigningAlgs, bad) {
			t.Errorf("alg %q is allowed", bad)
		}
	}
}

func TestSelectJWSKeyChecksKeyTypeAndCurve(t *testing.T) {
	p256, _ := jwsTestKey(t, "ES256")
	p384, _ := jwsTestKey(t, "ES384")
	ed, _ := jwsTestKey(t, "EdDSA")
	set := &jwks{Keys: []jwk{p256, p384, ed}}
	if _, ok := selectJWSKey(set, "ES384", "").(*ecdsa.PublicKey); !ok {
		t.Error("ES384 should find the P-384 key")
	}
	if hasJWSKey(&jwks{Keys: []jwk{p256}}, "ES384", "") || hasJWSKey(&jwks{Keys: []jwk{p384}}, "ES256", "") {
		t.Error("an EC key of the wrong curve was selected")
	}
	if hasJWSKey(&jwks{Keys: []jwk{ed}}, "ES256", "") || hasJWSKey(&jwks{Keys: []jwk{p256}}, "EdDSA", "") || hasJWSKey(&jwks{Keys: []jwk{p256}}, "RS256", "") {
		t.Error("a key of the wrong type was selected")
	}
}
