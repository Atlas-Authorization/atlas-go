package atlas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// §7.3 verification by customer backends.
//
// The design constraint that matters is what this does NOT do: it never calls
// Atlas on the hot path. A customer's API handling thousands of requests a second
// cannot make an outbound call to verify each one — and a verifier that did would
// make Atlas's availability the customer's availability. So the default path is
// local, against cached JWKS, and the revocation window is bounded instead by the
// short token lifetime. TokensService.Verify is the documented slow path when a
// 60-second window is too long.

// ClockSkewSeconds is §7.3's five seconds either side, matching the server's
// minting tolerance.
const ClockSkewSeconds = 5

// RefetchIntervalMS is §7.3's at-most-one JWKS refetch per minute, however many
// kid-misses arrive. The rate limit is a security property, not politeness: it
// stops an attacker sending random kids from turning this process into a traffic
// amplifier aimed at the JWKS endpoint.
const RefetchIntervalMS = 60_000

// DefaultTTLMS is the JWKS cache TTL (§7.3 serves Cache-Control: max-age=3600).
const DefaultTTLMS = 3_600_000

// SessionClaims is the decoded payload of a verified Atlas session JWT. Known
// claims are typed; everything else is available in Raw.
type SessionClaims struct {
	Iss            string   `json:"iss"`
	Sub            string   `json:"sub"`
	Sid            string   `json:"sid"`
	Exp            int64    `json:"exp"`
	Nbf            int64    `json:"nbf"`
	Iat            int64    `json:"iat"`
	Azp            string   `json:"azp"`
	Sv             int64    `json:"sv"`
	MFA            bool     `json:"mfa"`
	OrgID          string   `json:"org_id"`
	OrgSlug        string   `json:"org_slug"`
	OrgRole        string   `json:"org_role"`
	OrgPermissions []string `json:"org_permissions"`
	// SSOConnectionID is the enterprise SSO connection the session was made through.
	SSOConnectionID string `json:"sso_connection_id"`
	// SSOOrganizationID is the Atlas organization that owns that connection ("" for
	// an instance-wide one), independent of OrgID.
	SSOOrganizationID string `json:"sso_organization_id"`
	// SSOConnectionType is saml or oidc.
	SSOConnectionType string `json:"sso_connection_type"`

	// Raw is the full claim set, including any not modelled above.
	Raw map[string]interface{} `json:"-"`
}

// HasRole reports whether the session's org_role equals role.
func (c *SessionClaims) HasRole(role string) bool { return c.OrgRole == role }

// HasAppRole reports whether the app_roles claim (the user's instance-wide
// app roles) contains role. It needs no active organization.
func (c *SessionClaims) HasAppRole(role string) bool {
	return claimListContains(c.Raw, "app_roles", role)
}

// HasAppPermission reports whether the app_permissions claim (the union of
// the user's app roles' permissions) contains permission. It needs no active
// organization.
func (c *SessionClaims) HasAppPermission(permission string) bool {
	return claimListContains(c.Raw, "app_permissions", permission)
}

func claimListContains(raw map[string]interface{}, claim, want string) bool {
	list, _ := raw[claim].([]interface{})
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}

// HasPermission reports whether org_permissions contains permission. Reading the
// claim rather than calling Atlas is the whole point of putting permissions in
// the token: a permission change takes effect within one token lifetime, the same
// bound as revocation.
func (c *SessionClaims) HasPermission(permission string) bool {
	for _, p := range c.OrgPermissions {
		if p == permission {
			return true
		}
	}
	return false
}

// VerificationError is returned when a token fails verification. Reason is coarse
// by design — telling a caller whether the signature, issuer, or expiry was wrong
// helps someone refining a forged token more than a developer debugging a real
// one. Its values are "malformed", "invalid", "no_keys", and "unauthorized_party".
type VerificationError struct {
	Reason string
}

func (e *VerificationError) Error() string { return "atlas: token verification failed: " + e.Reason }

// Sentinel reasons, recoverable with errors.Is.
var (
	ErrMalformed         = &VerificationError{Reason: "malformed"}
	ErrInvalidToken      = &VerificationError{Reason: "invalid"}
	ErrNoKeys            = &VerificationError{Reason: "no_keys"}
	ErrUnauthorizedParty = &VerificationError{Reason: "unauthorized_party"}
)

// Retryable reports whether the failure is temporary and on the verifier's
// side: "no_keys", the issuer's keys could not be fetched (a network error or
// a JWKS outage). A back-channel logout endpoint should answer 503 with
// Retry-After then, so Atlas retries the delivery, and 400 for every other
// reason, which Atlas never retries.
func (e *VerificationError) Retryable() bool { return e != nil && e.Reason == "no_keys" }

// IsRetryable reports whether err is a *VerificationError that is Retryable.
func IsRetryable(err error) bool {
	var ve *VerificationError
	return errors.As(err, &ve) && ve.Retryable()
}

// Is lets errors.Is match VerificationErrors by Reason.
func (e *VerificationError) Is(target error) bool {
	t, ok := target.(*VerificationError)
	return ok && t.Reason == e.Reason
}

// jwk is one key in a JWKS document.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// FetchOutcome records the last JWKS cache action, exposed so a caller can assert
// the rate limit actually bit.
type FetchOutcome string

const (
	OutcomeFresh     FetchOutcome = "fresh"
	OutcomeCached    FetchOutcome = "cached"
	OutcomeRefetched FetchOutcome = "refetched"
	OutcomeThrottled FetchOutcome = "throttled"
	OutcomeFailed    FetchOutcome = "failed"
)

// JWKSCache caches an instance's JWKS in-process, refetching on a kid-miss at
// most once a minute. A stale JWKS still verifies every token signed by a key it
// contains, so it degrades to "new keys do not work yet", never "nobody can
// authenticate".
type JWKSCache struct {
	url               string
	httpClient        *http.Client
	now               func() time.Time
	ttlMS             int64
	refetchIntervalMS int64

	mu            sync.Mutex
	cached        *jwks
	fetchedAt     int64
	lastAttemptAt int64
	LastOutcome   FetchOutcome
}

// JWKSCacheOptions configure a JWKSCache.
type JWKSCacheOptions struct {
	URL               string
	HTTPClient        *http.Client
	Now               func() time.Time
	TTLMS             int64
	RefetchIntervalMS int64
}

// NewJWKSCache builds a JWKSCache. Only URL is required.
func NewJWKSCache(opts JWKSCacheOptions) *JWKSCache {
	c := &JWKSCache{
		url:               opts.URL,
		httpClient:        opts.HTTPClient,
		now:               opts.Now,
		ttlMS:             opts.TTLMS,
		refetchIntervalMS: opts.RefetchIntervalMS,
		LastOutcome:       OutcomeFresh,
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.ttlMS == 0 {
		c.ttlMS = DefaultTTLMS
	}
	if c.refetchIntervalMS == 0 {
		c.refetchIntervalMS = RefetchIntervalMS
	}
	return c
}

func (c *JWKSCache) nowMS() int64 { return c.now().UnixMilli() }

func (c *JWKSCache) has(kid string) bool {
	if c.cached == nil {
		return false
	}
	if kid == "" {
		return len(c.cached.Keys) > 0
	}
	for _, k := range c.cached.Keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// get returns the JWKS to verify against, refetching if this kid is unknown. It
// returns whatever is cached when a refetch is throttled or fails.
func (c *JWKSCache) get(ctx context.Context, kid string) *jwks {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowMS()
	expired := c.cached == nil || now-c.fetchedAt >= c.ttlMS
	kidMiss := c.cached != nil && !c.has(kid)

	if !expired && !kidMiss {
		c.LastOutcome = OutcomeCached
		return c.cached
	}

	// The throttle: a kid-miss inside the window is answered from cache, and the
	// token simply fails to verify.
	if kidMiss && !expired && now-c.lastAttemptAt < c.refetchIntervalMS {
		c.LastOutcome = OutcomeThrottled
		return c.cached
	}

	c.lastAttemptAt = now
	fetched, err := c.fetch(ctx)
	if err != nil || fetched == nil {
		c.LastOutcome = OutcomeFailed
		return c.cached
	}
	c.cached = fetched
	c.fetchedAt = now
	if kidMiss {
		c.LastOutcome = OutcomeRefetched
	} else {
		c.LastOutcome = OutcomeFresh
	}
	return c.cached
}

func (c *JWKSCache) fetch(ctx context.Context) (*jwks, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("atlas: JWKS fetch failed (%d)", resp.StatusCode)
	}
	var body jwks
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Keys == nil {
		return nil, errors.New("atlas: JWKS is malformed")
	}
	return &body, nil
}

// Snapshot is a test/diagnostic surface — never used for a security decision.
func (c *JWKSCache) Snapshot() (keys int, fetchedAtMS int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil {
		keys = len(c.cached.Keys)
	}
	return keys, c.fetchedAt
}

// AtlasBackendOptions configure an AtlasBackend verifier.
type AtlasBackendOptions struct {
	// JWKSURL is the instance's JWKS URL. Required.
	JWKSURL string
	// Issuer is the expected iss. Required — an unchecked issuer accepts any
	// Atlas instance's tokens.
	Issuer string
	// AuthorizedParties, when set, refuses a token minted for a different origin
	// (§7.3 azp allowlist).
	AuthorizedParties []string
	HTTPClient        *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
	// TTLMS / RefetchIntervalMS override the JWKS cache tuning.
	TTLMS             int64
	RefetchIntervalMS int64
	// LegacyIssuers: cutover from another auth provider (Better Auth). Tokens
	// from these issuers are ALSO accepted until each one's Until, verified
	// against that issuer's own key set, with sub mapped to the Atlas user id
	// (the old id is the user's external_id). The claims then carry Sub = the
	// Atlas id and Raw["external_id"] / Raw["legacy"] ({kind, issuer, sub}).
	// Atlas tokens are unaffected.
	LegacyIssuers []LegacyIssuer
	// SecretKey and APIURL (default DefaultAPIURL) drive the default
	// LegacyIssuers subject lookup (GET /v1/users?external_id=).
	SecretKey string
	APIURL    string
}

// AtlasBackend verifies Atlas session JWTs locally against the instance JWKS,
// with caching. Construct it with NewAtlasBackend.
type AtlasBackend struct {
	opts   AtlasBackendOptions
	jwks   *JWKSCache
	legacy *legacyVerifier
}

// NewAtlasBackend builds a verifier. JWKSURL and Issuer are required.
func NewAtlasBackend(opts AtlasBackendOptions) (*AtlasBackend, error) {
	if opts.JWKSURL == "" {
		return nil, errors.New("atlas: NewAtlasBackend requires JWKSURL")
	}
	if opts.Issuer == "" {
		return nil, errors.New("atlas: NewAtlasBackend requires Issuer")
	}
	b := &AtlasBackend{
		opts: opts,
		jwks: NewJWKSCache(JWKSCacheOptions{
			URL:               opts.JWKSURL,
			HTTPClient:        opts.HTTPClient,
			Now:               opts.Now,
			TTLMS:             opts.TTLMS,
			RefetchIntervalMS: opts.RefetchIntervalMS,
		}),
	}
	if len(opts.LegacyIssuers) > 0 {
		legacy, err := newLegacyVerifier(opts, b.now)
		if err != nil {
			return nil, err
		}
		b.legacy = legacy
	}
	return b, nil
}

// JWKS exposes the underlying cache (for LastOutcome / Snapshot assertions).
func (b *AtlasBackend) JWKS() *JWKSCache { return b.jwks }

func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// readKID reads the kid from a JWT header without verifying anything.
func readKID(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return ""
	}
	raw, err := base64urlDecode(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Kid
}

// Verify verifies a token locally. No network call unless the kid is unknown, and
// at most one of those a minute. On success it returns the decoded claims; on
// failure a *VerificationError.
func (b *AtlasBackend) Verify(ctx context.Context, token string) (*SessionClaims, error) {
	parts := strings.Split(token, ".")
	if token == "" || len(parts) != 3 {
		return nil, ErrMalformed
	}

	// A token from a configured legacy issuer (inside its window) is verified
	// against THAT issuer's keys only, never the Atlas keys: the iss routes, the
	// signature decides.
	if b.legacy != nil {
		if entry := b.legacy.match(peekIssuer(token)); entry != nil {
			claims, err := b.legacy.verify(ctx, token, entry)
			if err != nil {
				return nil, err
			}
			if len(b.opts.AuthorizedParties) > 0 && claims.Azp != "" && !contains(b.opts.AuthorizedParties, claims.Azp) {
				return nil, ErrUnauthorizedParty
			}
			return claims, nil
		}
	}

	set := b.jwks.get(ctx, readKID(token))
	if set == nil || len(set.Keys) == 0 {
		return nil, ErrNoKeys
	}

	// Header: pin RS256 / ES256 (SigningAlgs). Without this, a token whose
	// header says alg:none — or any algorithm the key material can be coerced
	// into — could verify.
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || !contains(SigningAlgs, header.Alg) {
		return nil, ErrInvalidToken
	}

	sig, err := base64urlDecode(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !verifyJWSSignature(set, header.Alg, header.Kid, parts[0]+"."+parts[1], sig) {
		return nil, ErrInvalidToken
	}

	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims := &SessionClaims{}
	if json.Unmarshal(payloadRaw, claims) != nil {
		return nil, ErrInvalidToken
	}
	_ = json.Unmarshal(payloadRaw, &claims.Raw)

	nowSec := b.now().Unix()
	if claims.Iss != b.opts.Issuer {
		return nil, ErrInvalidToken
	}
	if claims.Exp != 0 && nowSec > claims.Exp+ClockSkewSeconds {
		return nil, ErrInvalidToken
	}
	if claims.Nbf != 0 && nowSec+ClockSkewSeconds < claims.Nbf {
		return nil, ErrInvalidToken
	}

	// §13.1 token-confusion guard. Reject any token carrying an OP marker
	// (token_use != "session", or an aud claim) so a "Sign in with Atlas" RP
	// cannot replay one as a customer session. An absent token_use/aud is a valid
	// session (backward-compat), so this never mass-invalidates a live fleet.
	if tu, ok := claims.Raw["token_use"]; ok {
		if s, _ := tu.(string); s != "session" {
			return nil, ErrInvalidToken
		}
	}
	if _, hasAud := claims.Raw["aud"]; hasAud {
		return nil, ErrInvalidToken
	}

	if len(b.opts.AuthorizedParties) > 0 {
		if claims.Azp == "" || !contains(b.opts.AuthorizedParties, claims.Azp) {
			return nil, ErrUnauthorizedParty
		}
	}
	return claims, nil
}

// AuthenticateRequest verifies whatever a request carries: an Authorization
// bearer token wins over a __session cookie (a deliberately-set header should not
// be overridden by a stale cookie).
func (b *AtlasBackend) AuthenticateRequest(ctx context.Context, r *http.Request) (*SessionClaims, error) {
	token := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
	} else if ck, err := r.Cookie("__session"); err == nil {
		token = ck.Value
	}
	if token == "" {
		return nil, ErrMalformed
	}
	return b.Verify(ctx, token)
}

func (b *AtlasBackend) now() time.Time {
	if b.opts.Now != nil {
		return b.opts.Now()
	}
	return time.Now()
}

// SigningAlgs are the JWS algorithms Atlas signs tokens with: an instance key
// is RS256 (the default) or ES256, and an API may use either. Every verifier
// in this package is pinned to exactly this list — "none" and HMAC never
// verify — and the token's kid selects one published key whose type fixes
// which of the two applies.
var SigningAlgs = []string{"RS256", "ES256"}

// verifyJWSSignature checks sig over signingInput with the key kid selects,
// for alg RS256 (an RSA key) or ES256 (a P-256 EC key, raw r||s signature).
// A key whose own alg names the other algorithm never verifies.
func verifyJWSSignature(set *jwks, alg, kid, signingInput string, sig []byte) bool {
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "RS256":
		pub := selectRSAKey(set, kid)
		return pub != nil && rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
	case "ES256":
		pub := selectECKey(set, kid)
		if pub == nil || len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		sv := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, digest[:], r, sv)
	}
	return false
}

// selectECKey picks the P-256 key matching kid (any when kid is empty).
func selectECKey(set *jwks, kid string) *ecdsa.PublicKey {
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") {
			continue
		}
		if kid != "" && k.Kid != kid {
			continue
		}
		xb, err1 := base64urlDecode(k.X)
		yb, err2 := base64urlDecode(k.Y)
		if err1 != nil || err2 != nil {
			continue
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !elliptic.P256().IsOnCurve(x, y) {
			continue
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}
	return nil
}

// selectRSAKey picks the RSA key matching kid (any RSA key when kid is empty).
func selectRSAKey(set *jwks, kid string) *rsa.PublicKey {
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if kid != "" && k.Kid != kid {
			continue
		}
		if pub, err := jwkToPublicKey(k); err == nil {
			return pub
		}
	}
	return nil
}

func jwkToPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64urlDecode(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64urlDecode(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, errors.New("atlas: invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
