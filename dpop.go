package atlas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoP proof verification (RFC 9449) for AccessTokenVerifier.
//
// A DPoP-bound access token carries cnf.jkt, the RFC 7638 thumbprint of the
// client's key. Each request must then arrive with the DPoP scheme and a DPoP
// header: a short-lived JWT (typ dpop+jwt) signed by that key, carrying the
// public key itself, the request method (htm) and URL (htu), the hash of the
// access token (ath), a unique jti, and the server's nonce when the API asks
// for one.

// DPoPProofMaxAgeSeconds is how old a DPoP proof may be.
const DPoPProofMaxAgeSeconds = 300

// DPoPAlgs are the JWS algorithms accepted on a DPoP proof, and advertised in
// the DPoP challenge (algs) and in the protected-resource metadata.
var DPoPAlgs = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}

// DPoPReplayStore guards against a DPoP proof being used twice. Claim records
// key until expiresAt and returns false when it was already recorded (and has
// not expired). Share one store across processes (Redis SET NX PX, a database
// unique key, ...) when the API runs on more than one.
type DPoPReplayStore interface {
	Claim(key string, expiresAt time.Time) bool
}

// MemoryDPoPReplayStore is the in-process DPoPReplayStore: entries live until
// they expire, and the store never holds more than max of them.
type MemoryDPoPReplayStore struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryDPoPReplayStore builds an in-memory replay store holding at most
// max live entries (10000 when max <= 0).
func NewMemoryDPoPReplayStore(max int) *MemoryDPoPReplayStore {
	if max <= 0 {
		max = 10000
	}
	return &MemoryDPoPReplayStore{max: max, seen: map[string]time.Time{}, now: time.Now}
}

// Claim implements DPoPReplayStore.
func (s *MemoryDPoPReplayStore) Claim(key string, expiresAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if exp, ok := s.seen[key]; ok && exp.After(now) {
		return false
	}
	s.seen[key] = expiresAt
	if len(s.seen) > s.max {
		for k, exp := range s.seen {
			if !exp.After(now) {
				delete(s.seen, k)
			}
		}
		// Still full of live entries: drop the ones closest to expiry.
		for len(s.seen) > s.max {
			var oldest string
			var oldestAt time.Time
			for k, exp := range s.seen {
				if k != key && (oldest == "" || exp.Before(oldestAt)) {
					oldest, oldestAt = k, exp
				}
			}
			if oldest == "" {
				break
			}
			delete(s.seen, oldest)
		}
	}
	return true
}

// DPoPNonceSource hands out the server nonce a DPoP proof must carry (RFC 9449
// §8) and checks one. Current is sent to the client in the DPoP-Nonce header;
// Valid accepts the nonces still in force.
type DPoPNonceSource interface {
	Current() string
	Valid(nonce string) bool
}

// HMACDPoPNonceSource derives nonces from a secret and the clock: a nonce is
// good for the window it was issued in and the one after, so every process
// sharing the secret agrees without shared state.
type HMACDPoPNonceSource struct {
	secret []byte
	window time.Duration
	now    func() time.Time
}

// NewHMACDPoPNonceSource builds a nonce source. secret must be at least 32
// bytes; window defaults to 5 minutes.
func NewHMACDPoPNonceSource(secret []byte, window time.Duration) (*HMACDPoPNonceSource, error) {
	if len(secret) < 32 {
		return nil, errors.New("atlas: the DPoP nonce secret must be at least 32 bytes")
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &HMACDPoPNonceSource{secret: append([]byte{}, secret...), window: window, now: time.Now}, nil
}

func (s *HMACDPoPNonceSource) at(epoch int64) string {
	m := hmac.New(sha256.New, s.secret)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	m.Write([]byte("atlas-dpop-nonce:"))
	m.Write(b[:])
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *HMACDPoPNonceSource) epoch() int64 { return s.now().UnixNano() / int64(s.window) }

// Current implements DPoPNonceSource.
func (s *HMACDPoPNonceSource) Current() string { return s.at(s.epoch()) }

// Valid implements DPoPNonceSource.
func (s *HMACDPoPNonceSource) Valid(nonce string) bool {
	e := s.epoch()
	for _, c := range []string{s.at(e), s.at(e - 1)} {
		if hmac.Equal([]byte(c), []byte(nonce)) {
			return true
		}
	}
	return false
}

// dpopRefusal is a proof refusal: code is invalid_dpop_proof or use_dpop_nonce.
type dpopRefusal struct {
	code AccessTokenErrorCode
	desc string
}

func proofErr(desc string) *dpopRefusal { return &dpopRefusal{AccessTokenInvalidDPoPProof, desc} }

type dpopCheck struct {
	token, jkt, method, url, publicOrigin string
	now                                   time.Time
	replay                                DPoPReplayStore
	nonces                                DPoPNonceSource
}

func checkDPoPProof(proof string, c dpopCheck) *dpopRefusal {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return proofErr("The DPoP proof is malformed.")
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return proofErr("The DPoP proof is malformed.")
	}
	var h struct {
		Typ string                 `json:"typ"`
		Alg string                 `json:"alg"`
		JWK map[string]interface{} `json:"jwk"`
	}
	if json.Unmarshal(headerRaw, &h) != nil {
		return proofErr("The DPoP proof is malformed.")
	}
	if h.Typ != "dpop+jwt" {
		return proofErr("The DPoP proof must have typ dpop+jwt.")
	}
	if !contains(DPoPAlgs, h.Alg) {
		return proofErr("The DPoP proof uses an unsupported algorithm.")
	}
	if h.JWK == nil {
		return proofErr("The DPoP proof must carry its public key.")
	}
	for _, private := range []string{"d", "k", "p", "q", "dp", "dq", "qi"} {
		if _, ok := h.JWK[private]; ok {
			return proofErr("The DPoP proof key must be a public key.")
		}
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil || !verifyDPoPSignature(h.JWK, h.Alg, parts[0]+"."+parts[1], sig) {
		return proofErr("The DPoP proof signature is invalid.")
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return proofErr("The DPoP proof is malformed.")
	}
	var p map[string]interface{}
	if json.Unmarshal(payloadRaw, &p) != nil {
		return proofErr("The DPoP proof is malformed.")
	}
	thumb, err := JWKThumbprint(h.JWK)
	if err != nil || !hmac.Equal([]byte(thumb), []byte(c.jkt)) {
		return proofErr("The DPoP proof key does not match the token binding.")
	}
	if htm, _ := p["htm"].(string); htm != c.method {
		return proofErr("The DPoP proof htm does not match the request method.")
	}
	target := c.url
	if !hasHTTPScheme(target) {
		if c.publicOrigin == "" {
			target = ""
		} else if base, err := url.Parse(c.publicOrigin); err == nil {
			if ref, err := url.Parse(target); err == nil {
				target = base.ResolveReference(ref).String()
			} else {
				target = ""
			}
		} else {
			target = ""
		}
	}
	expected, ok1 := NormalizeHTU(target)
	htu, _ := p["htu"].(string)
	got, ok2 := NormalizeHTU(htu)
	if !ok1 || !ok2 || got != expected {
		return proofErr("The DPoP proof htu does not match the request URL.")
	}
	iat, ok := p["iat"].(float64)
	nowSec := float64(c.now.UnixNano()) / 1e9
	if !ok || iat > nowSec+ClockSkewSeconds || nowSec-iat > DPoPProofMaxAgeSeconds {
		return proofErr("The DPoP proof is too old or from the future.")
	}
	if exp, ok := p["exp"].(float64); ok && nowSec >= exp+ClockSkewSeconds {
		return proofErr("The DPoP proof is too old or from the future.")
	}
	if ath, _ := p["ath"].(string); ath != DPoPAccessTokenHash(c.token) {
		return proofErr("The DPoP proof ath does not match the access token.")
	}
	jti, _ := p["jti"].(string)
	if jti == "" {
		return proofErr("The DPoP proof needs a jti.")
	}
	if c.nonces != nil {
		nonce, _ := p["nonce"].(string)
		if nonce == "" || !c.nonces.Valid(nonce) {
			return &dpopRefusal{AccessTokenUseDPoPNonce, "The DPoP proof must carry the nonce from the DPoP-Nonce header."}
		}
	}
	expiresAt := time.Unix(0, int64(iat*1e9)).Add(DPoPProofMaxAgeSeconds * time.Second)
	if !c.replay.Claim(c.jkt+":"+jti, expiresAt) {
		return proofErr("The DPoP proof has already been used.")
	}
	return nil
}

func hasHTTPScheme(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// NormalizeHTU reduces a URL to the form RFC 9449 §4.3 compares htu in: scheme
// and host lower-cased, the default port dropped, an empty path as "/", and no
// query or fragment. ok is false for anything but an absolute http(s) URL.
func NormalizeHTU(raw string) (string, bool) {
	if !hasHTTPScheme(raw) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}

// DPoPAccessTokenHash is the ath a DPoP proof carries for token:
// base64url(SHA-256(token)).
func DPoPAccessTokenHash(token string) string {
	d := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// JWKThumbprint is the RFC 7638 SHA-256 thumbprint (base64url) of a public
// EC, RSA or OKP JWK: the cnf.jkt a DPoP-bound token carries.
func JWKThumbprint(jwk map[string]interface{}) (string, error) {
	str := func(k string) (string, error) {
		v, ok := jwk[k].(string)
		if !ok || v == "" {
			return "", errors.New("atlas: JWK member " + k + " is missing")
		}
		return v, nil
	}
	kty, err := str("kty")
	if err != nil {
		return "", err
	}
	var members []string
	switch kty {
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return "", errors.New("atlas: unsupported JWK kty " + kty)
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range members {
		v, err := str(m)
		if err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		kj, _ := json.Marshal(m)
		vj, _ := json.Marshal(v)
		b.Write(kj)
		b.WriteByte(':')
		b.Write(vj)
	}
	b.WriteByte('}')
	d := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(d[:]), nil
}

func verifyDPoPSignature(jwk map[string]interface{}, alg, signingInput string, sig []byte) bool {
	str := func(k string) string { v, _ := jwk[k].(string); return v }
	b := func(k string) []byte {
		v, err := base64urlDecode(str(k))
		if err != nil {
			return nil
		}
		return v
	}
	if kjwk, ok := jwk["alg"].(string); ok && kjwk != "" && kjwk != alg {
		return false
	}
	switch alg {
	case "ES256", "ES384", "ES512":
		var curve elliptic.Curve
		var crv string
		var size int
		var hash crypto.Hash
		switch alg {
		case "ES256":
			curve, crv, size, hash = elliptic.P256(), "P-256", 32, crypto.SHA256
		case "ES384":
			curve, crv, size, hash = elliptic.P384(), "P-384", 48, crypto.SHA384
		default:
			curve, crv, size, hash = elliptic.P521(), "P-521", 66, crypto.SHA512
		}
		if str("kty") != "EC" || str("crv") != crv || len(sig) != 2*size {
			return false
		}
		xb, yb := b("x"), b("y")
		if len(xb) != size || len(yb) != size {
			return false
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(x, y) {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return ecdsa.Verify(pub, digestOf(hash, signingInput), new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:]))
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if str("kty") != "RSA" {
			return false
		}
		nb, eb := b("n"), b("e")
		if len(nb) == 0 || len(eb) == 0 || len(eb) > 4 {
			return false
		}
		n := new(big.Int).SetBytes(nb)
		e := new(big.Int).SetBytes(eb)
		if n.BitLen() < 2048 || e.Int64() < 3 {
			return false
		}
		pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
		hash := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
		digest := digestOf(hash, signingInput)
		if alg[0] == 'P' {
			return rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, sig) == nil
	case "EdDSA":
		if str("kty") != "OKP" || str("crv") != "Ed25519" {
			return false
		}
		x := b("x")
		if len(x) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), []byte(signingInput), sig)
	}
	return false
}

func digestOf(h crypto.Hash, input string) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384([]byte(input))
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512([]byte(input))
		return d[:]
	}
	d := sha256.Sum256([]byte(input))
	return d[:]
}
