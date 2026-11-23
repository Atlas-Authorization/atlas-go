package atlas

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"
)

// SignAPIKeyAssertionOptions are the claims of a key-pair assertion. TTLSeconds
// defaults to 300; JTI defaults to a random value.
type SignAPIKeyAssertionOptions struct {
	KeyID      string
	Audience   string
	TTLSeconds int
	Scope      string
	JTI        string
}

// SignAPIKeyAssertion signs a short-lived JWT with the PKCS#8 PEM private key
// of a key-pair API key (ES256 for P-256, EdDSA for Ed25519). Present it to
// APIKeysService.VerifyWithParams (Token) or the token exchange (Assertion).
func SignAPIKeyAssertion(privateKeyPEM string, o SignAPIKeyAssertionOptions) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("atlas: private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	if o.TTLSeconds == 0 {
		o.TTLSeconds = 300
	}
	if o.JTI == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		o.JTI = base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now().Unix()
	claims := map[string]interface{}{"iss": o.KeyID, "aud": o.Audience, "iat": now, "exp": now + int64(o.TTLSeconds), "jti": o.JTI}
	if o.Scope != "" {
		claims["scope"] = o.Scope
	}
	var alg string
	switch parsed.(type) {
	case *ecdsa.PrivateKey:
		alg = "ES256"
	case ed25519.PrivateKey:
		alg = "EdDSA"
	default:
		return "", errors.New("atlas: key must be P-256 or Ed25519")
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": o.KeyID, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	var sig []byte
	switch k := parsed.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize != 256 {
			return "", errors.New("atlas: key must be P-256 or Ed25519")
		}
		digest := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return "", err
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type parsedAPIKeyAssertion struct {
	alg, kid string
	claims   map[string]interface{}
	input    string
	sig      []byte
}

// parseAPIKeyAssertion splits a compact JWS; nil when it is not three base64url segments of JSON.
func parseAPIKeyAssertion(token string) *parsedAPIKeyAssertion {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil
	}
	var seg [3][]byte
	for i := range p {
		b, err := base64.RawURLEncoding.DecodeString(p[i])
		if err != nil {
			return nil
		}
		seg[i] = b
	}
	var header map[string]interface{}
	var claims map[string]interface{}
	if json.Unmarshal(seg[0], &header) != nil || json.Unmarshal(seg[1], &claims) != nil || header == nil || claims == nil {
		return nil
	}
	a := &parsedAPIKeyAssertion{claims: claims, input: p[0] + "." + p[1], sig: seg[2]}
	a.alg, _ = header["alg"].(string)
	a.kid, _ = header["kid"].(string)
	return a
}

func (a *parsedAPIKeyAssertion) claimString(name string) string {
	s, _ := a.claims[name].(string)
	return s
}

func (a *parsedAPIKeyAssertion) claimInt(name string) (int64, bool) {
	f, ok := a.claims[name].(float64)
	return int64(f), ok
}

// verifySignature checks the signature with an SPKI PEM public key; alg must fit the key's type.
func (a *parsedAPIKeyAssertion) verifySignature(publicKeyPEM string) bool {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if a.alg != "ES256" || k.Curve.Params().BitSize != 256 || len(a.sig) != 64 {
			return false
		}
		digest := sha256.Sum256([]byte(a.input))
		return ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(a.sig[:32]), new(big.Int).SetBytes(a.sig[32:]))
	case ed25519.PublicKey:
		return a.alg == "EdDSA" && ed25519.Verify(k, []byte(a.input), a.sig)
	}
	return false
}
