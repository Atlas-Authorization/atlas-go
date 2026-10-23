package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Accepting your OLD auth provider's JWTs during a cutover — today, Better
// Auth's jwt plugin tokens.
//
// When you move to Atlas, API clients may still hold short-lived JWTs your
// Better Auth app minted. With AtlasBackendOptions.LegacyIssuers, a token whose
// iss is one of these issuers is verified against THAT issuer's key set (the
// JWKS you imported into Atlas, or the old app's /api/auth/jwks) for a bounded
// window, and its sub (the Better Auth user id) is mapped to the Atlas user id:
// Atlas keeps the Better Auth id as the user's external_id. After Until, those
// tokens are refused like any other foreign token.

// BetterAuthJWTAlgs are the Better Auth jwt plugin's key algorithms.
var BetterAuthJWTAlgs = []string{"EdDSA", "ES256", "ES512", "RS256", "PS256"}

// legacySubjectTTL is how long a resolved sub → Atlas id mapping is reused, and
// legacySubjectMax caps the cache so distinct tokens cannot grow it unbounded.
const (
	legacySubjectTTL = 5 * time.Minute
	legacySubjectMax = 10_000
)

// DefaultAPIURL is the Backend API origin the default legacy subject lookup uses.
const DefaultAPIURL = "https://api.atlasauth.net"

// LegacyIssuer is one old issuer accepted during the cutover.
type LegacyIssuer struct {
	// Kind of the old provider; "better_auth" (the default) today.
	Kind string
	// Issuer is the iss the old tokens carry (Better Auth: its baseURL, unless
	// jwt.issuer was set). Required.
	Issuer string
	// JWKS is the imported key set as JSON ({"keys":[...]}). Exactly one of
	// JWKS / JWKSURL.
	JWKS []byte
	// JWKSURL is where to fetch the old key set
	// (e.g. https://app.example.com/api/auth/jwks).
	JWKSURL string
	// Audience, when set, must contain the token's aud (Better Auth: its baseURL,
	// unless jwt.audience was set).
	Audience []string
	// Until ends the acceptance window. Required: a legacy issuer is never
	// accepted forever.
	Until time.Time
	// Algorithms accepted (default BetterAuthJWTAlgs).
	Algorithms []string
	// ResolveSubject maps the old sub to the Atlas user id. Default: look the user
	// up by external_id through the Backend API (needs SecretKey), cached for 5
	// minutes. Return "" to refuse the token.
	ResolveSubject func(ctx context.Context, legacySub string, claims map[string]interface{}) (string, error)
}

type legacySubject struct {
	id string
	at time.Time
}

type legacyVerifier struct {
	issuers   []LegacyIssuer
	caches    map[string]*JWKSCache
	static    map[string]*jwks
	secretKey string
	apiURL    string
	http      *http.Client
	now       func() time.Time

	mu       sync.Mutex
	subjects map[string]legacySubject
}

func newLegacyVerifier(opts AtlasBackendOptions, now func() time.Time) (*legacyVerifier, error) {
	v := &legacyVerifier{
		issuers:   opts.LegacyIssuers,
		caches:    map[string]*JWKSCache{},
		static:    map[string]*jwks{},
		secretKey: opts.SecretKey,
		apiURL:    strings.TrimRight(opts.APIURL, "/"),
		http:      opts.HTTPClient,
		now:       now,
		subjects:  map[string]legacySubject{},
	}
	if v.apiURL == "" {
		v.apiURL = DefaultAPIURL
	}
	for _, e := range opts.LegacyIssuers {
		if e.Issuer == "" {
			return nil, errors.New("atlas: LegacyIssuers: every entry needs Issuer")
		}
		if e.Issuer == opts.Issuer {
			return nil, errors.New("atlas: a legacy issuer cannot be the Atlas Issuer itself")
		}
		if (len(e.JWKS) > 0) == (e.JWKSURL != "") {
			return nil, fmt.Errorf("atlas: LegacyIssuers: %q needs exactly one of JWKS or JWKSURL", e.Issuer)
		}
		if e.Until.IsZero() {
			return nil, fmt.Errorf("atlas: LegacyIssuers: %q needs Until (the end of the window)", e.Issuer)
		}
		if e.ResolveSubject == nil && opts.SecretKey == "" {
			return nil, fmt.Errorf("atlas: LegacyIssuers: %q maps its sub to an Atlas user through the Backend API, which needs SecretKey on AtlasBackendOptions, or give the issuer a ResolveSubject", e.Issuer)
		}
		if e.JWKSURL != "" {
			v.caches[e.Issuer] = NewJWKSCache(JWKSCacheOptions{URL: e.JWKSURL, HTTPClient: opts.HTTPClient, Now: opts.Now})
		} else {
			set := &jwks{}
			if err := json.Unmarshal(e.JWKS, set); err != nil {
				return nil, fmt.Errorf("atlas: LegacyIssuers: %q JWKS is not a JSON key set: %w", e.Issuer, err)
			}
			v.static[e.Issuer] = set
		}
	}
	return v, nil
}

// match returns the entry for iss when its window is still open.
func (v *legacyVerifier) match(iss string) *LegacyIssuer {
	if iss == "" {
		return nil
	}
	for i := range v.issuers {
		if v.issuers[i].Issuer == iss {
			if v.now().Before(v.issuers[i].Until) {
				return &v.issuers[i]
			}
			return nil
		}
	}
	return nil
}

// peekIssuer reads the UNVERIFIED iss of a compact JWT, for routing only.
func peekIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64urlDecode(parts[1])
	if err != nil {
		return ""
	}
	var p struct {
		Iss interface{} `json:"iss"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return ""
	}
	s, _ := p.Iss.(string)
	return s
}

func jwkMap(k jwk) map[string]interface{} {
	m := map[string]interface{}{"kty": k.Kty}
	for name, val := range map[string]string{"kid": k.Kid, "n": k.N, "e": k.E, "crv": k.Crv, "x": k.X, "y": k.Y, "alg": k.Alg} {
		if val != "" {
			m[name] = val
		}
	}
	return m
}

// verify checks a legacy token: signature against the issuer's own keys, iss,
// exp (required), nbf, aud; then maps sub to the Atlas id.
func (v *legacyVerifier) verify(ctx context.Context, token string, e *LegacyIssuer) (*SessionClaims, error) {
	parts := strings.Split(token, ".")
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	algs := e.Algorithms
	if len(algs) == 0 {
		algs = BetterAuthJWTAlgs
	}
	if json.Unmarshal(headerRaw, &header) != nil || !contains(algs, header.Alg) {
		return nil, ErrInvalidToken
	}
	set := v.static[e.Issuer]
	if cache := v.caches[e.Issuer]; cache != nil {
		set = cache.get(ctx, header.Kid)
	}
	if set == nil || len(set.Keys) == 0 {
		return nil, ErrNoKeys
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	verified := false
	for _, k := range set.Keys {
		if header.Kid != "" && k.Kid != header.Kid {
			continue
		}
		if verifyDPoPSignature(jwkMap(k), header.Alg, parts[0]+"."+parts[1], sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrInvalidToken
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	raw := map[string]interface{}{}
	if json.Unmarshal(payloadRaw, &raw) != nil {
		return nil, ErrInvalidToken
	}
	nowSec := v.now().Unix()
	if iss, _ := raw["iss"].(string); iss != e.Issuer {
		return nil, ErrInvalidToken
	}
	// A legacy token without an expiry would outlive the window it is accepted in.
	exp, ok := raw["exp"].(float64)
	if !ok || float64(nowSec) > exp+ClockSkewSeconds {
		return nil, ErrInvalidToken
	}
	if nbf, ok := raw["nbf"].(float64); ok && float64(nowSec+ClockSkewSeconds) < nbf {
		return nil, ErrInvalidToken
	}
	if len(e.Audience) > 0 && !audienceMatches(raw["aud"], e.Audience) {
		return nil, ErrInvalidToken
	}
	legacySub, _ := raw["sub"].(string)
	if legacySub == "" {
		legacySub, _ = raw["id"].(string)
	}
	if legacySub == "" {
		return nil, ErrInvalidToken
	}
	atlasID := v.resolve(ctx, legacySub, raw, e)
	if atlasID == "" {
		return nil, ErrInvalidToken
	}
	kind := e.Kind
	if kind == "" {
		kind = "better_auth"
	}
	raw["sub"] = atlasID
	if _, ok := raw["sid"].(string); !ok {
		raw["sid"] = ""
	}
	raw["external_id"] = legacySub
	raw["legacy"] = map[string]interface{}{"kind": kind, "issuer": e.Issuer, "sub": legacySub}

	encoded, _ := json.Marshal(raw)
	claims := &SessionClaims{}
	// Typed fields best-effort (a foreign token may type aud etc. differently).
	_ = json.Unmarshal(encoded, claims)
	claims.Sub = atlasID
	claims.Iss = e.Issuer
	claims.Raw = raw
	return claims, nil
}

func (v *legacyVerifier) resolve(ctx context.Context, legacySub string, claims map[string]interface{}, e *LegacyIssuer) string {
	if e.ResolveSubject != nil {
		id, err := e.ResolveSubject(ctx, legacySub, claims)
		if err != nil {
			return ""
		}
		return id
	}
	key := e.Issuer + "\x00" + legacySub
	now := v.now()
	v.mu.Lock()
	if hit, ok := v.subjects[key]; ok && now.Sub(hit.at) < legacySubjectTTL {
		v.mu.Unlock()
		return hit.id
	}
	v.mu.Unlock()

	q := url.Values{"external_id": {legacySub}, "limit": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.apiURL+"/v1/users?"+q.Encode(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+v.secretKey)
	req.Header.Set("Accept", "application/json")
	hc := v.http
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "" // not cached: a transient failure should not stick
	}
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return ""
	}
	id := ""
	if len(body.Data) > 0 {
		id = body.Data[0].ID
	}
	v.mu.Lock()
	if len(v.subjects) >= legacySubjectMax {
		v.subjects = map[string]legacySubject{}
	}
	v.subjects[key] = legacySubject{id: id, at: now}
	v.mu.Unlock()
	return id
}
