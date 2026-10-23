package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BackchannelLogoutEvent is the events member that marks an OIDC Back-Channel
// Logout token.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// DefaultLogoutTokenMaxAge is how old (by iat) a logout token may be before it
// is refused. Atlas mints them with a two-minute life and sends them at once.
const DefaultLogoutTokenMaxAge = 5 * time.Minute

// LogoutTokenClaims are the verified claims of a back-channel logout token.
// End the local session(s) matching Sid (preferred) or, when Sid is empty,
// every session of Sub.
type LogoutTokenClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub,omitempty"`
	Sid string `json:"sid,omitempty"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp,omitempty"`

	// Raw is the full claim set.
	Raw map[string]interface{} `json:"-"`
}

// LogoutTokenVerifierOptions configure a LogoutTokenVerifier.
type LogoutTokenVerifierOptions struct {
	// JWKSURL is the issuer's JWKS URL. Required.
	JWKSURL string
	// Issuer is the expected iss (the same value your id_tokens carry; for Sign
	// in with Atlas apps, https://atlasauth.net). Required.
	Issuer string
	// ClientID is your client id; aud must contain it. Required.
	ClientID string
	// MaxAge bounds how old (by iat) a token may be. Default
	// DefaultLogoutTokenMaxAge.
	MaxAge time.Duration
	// ReplayGuard, when set, refuses a jti it has already seen.
	ReplayGuard LogoutReplayGuard
	HTTPClient  *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
	// JWKS shares an existing cache (e.g. AtlasBackend.JWKS()) instead of
	// building one from JWKSURL.
	JWKS *JWKSCache
}

// LogoutTokenVerifier verifies OIDC Back-Channel Logout 1.0 logout tokens
// (§2.6) against the issuer's JWKS: RS256 only, iss, aud, iat, exp, jti, the
// back-channel-logout event, sid and/or sub, no nonce, and typ "logout+jwt"
// when a typ header is present.
type LogoutTokenVerifier struct {
	opts LogoutTokenVerifierOptions
	jwks *JWKSCache
}

// ErrLogoutTokenReplayed is returned when the ReplayGuard has already seen the
// token's jti.
var ErrLogoutTokenReplayed = &VerificationError{Reason: "replayed"}

// NewLogoutTokenVerifier builds a verifier. JWKSURL (or JWKS), Issuer and
// ClientID are required.
func NewLogoutTokenVerifier(opts LogoutTokenVerifierOptions) (*LogoutTokenVerifier, error) {
	if opts.JWKS == nil && opts.JWKSURL == "" {
		return nil, errors.New("atlas: NewLogoutTokenVerifier requires JWKSURL")
	}
	if opts.Issuer == "" {
		return nil, errors.New("atlas: NewLogoutTokenVerifier requires Issuer")
	}
	if opts.ClientID == "" {
		return nil, errors.New("atlas: NewLogoutTokenVerifier requires ClientID")
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultLogoutTokenMaxAge
	}
	cache := opts.JWKS
	if cache == nil {
		cache = NewJWKSCache(JWKSCacheOptions{URL: opts.JWKSURL, HTTPClient: opts.HTTPClient, Now: opts.Now})
	}
	return &LogoutTokenVerifier{opts: opts, jwks: cache}, nil
}

func (v *LogoutTokenVerifier) now() time.Time {
	if v.opts.Now != nil {
		return v.opts.Now()
	}
	return time.Now()
}

// Verify checks a logout_token and returns its claims, or a
// *VerificationError (ErrMalformed, ErrNoKeys, ErrInvalidToken,
// ErrLogoutTokenReplayed). IsRetryable(err) is true for ErrNoKeys: answer 503
// with Retry-After so Atlas retries; answer 400 otherwise.
func (v *LogoutTokenVerifier) Verify(ctx context.Context, token string) (*LogoutTokenClaims, error) {
	parts := strings.Split(token, ".")
	if token == "" || len(parts) != 3 {
		return nil, ErrMalformed
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var header struct {
		Alg string  `json:"alg"`
		Kid string  `json:"kid"`
		Typ *string `json:"typ"`
	}
	if json.Unmarshal(headerRaw, &header) != nil {
		return nil, ErrMalformed
	}
	if !contains(SigningAlgs, header.Alg) {
		return nil, ErrInvalidToken
	}
	if header.Typ != nil && !strings.EqualFold(*header.Typ, "logout+jwt") && !strings.EqualFold(*header.Typ, "application/logout+jwt") {
		return nil, ErrInvalidToken
	}

	set := v.jwks.get(ctx, header.Kid)
	if set == nil || len(set.Keys) == 0 {
		return nil, ErrNoKeys
	}
	var keyFound bool
	if header.Alg == "ES256" {
		keyFound = selectECKey(set, header.Kid) != nil
	} else {
		keyFound = selectRSAKey(set, header.Kid) != nil
	}
	if !keyFound {
		// A key Atlas just rotated to, whose refetch failed: temporary.
		v.jwks.mu.Lock()
		failed := v.jwks.LastOutcome == OutcomeFailed
		v.jwks.mu.Unlock()
		if failed {
			return nil, ErrNoKeys
		}
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
	claims := &LogoutTokenClaims{}
	if json.Unmarshal(payloadRaw, claims) != nil || json.Unmarshal(payloadRaw, &claims.Raw) != nil {
		return nil, ErrInvalidToken
	}
	raw := claims.Raw

	if claims.Iss != v.opts.Issuer {
		return nil, ErrInvalidToken
	}
	if !audienceContains(raw["aud"], v.opts.ClientID) {
		return nil, ErrInvalidToken
	}
	now := v.now().Unix()
	if _, ok := raw["iat"].(float64); !ok {
		return nil, ErrInvalidToken
	}
	if claims.Iat > now+ClockSkewSeconds || now-claims.Iat > int64(v.opts.MaxAge/time.Second)+ClockSkewSeconds {
		return nil, ErrInvalidToken
	}
	if _, has := raw["exp"]; has && now > claims.Exp+ClockSkewSeconds {
		return nil, ErrInvalidToken
	}
	if claims.Jti == "" {
		return nil, ErrInvalidToken
	}
	events, ok := raw["events"].(map[string]interface{})
	if !ok {
		return nil, ErrInvalidToken
	}
	if _, ok := events[BackchannelLogoutEvent].(map[string]interface{}); !ok {
		return nil, ErrInvalidToken
	}
	if claims.Sid == "" && claims.Sub == "" {
		return nil, ErrInvalidToken
	}
	if _, has := raw["nonce"]; has {
		return nil, ErrInvalidToken
	}
	if v.opts.ReplayGuard != nil {
		ttl := v.opts.MaxAge + 2*ClockSkewSeconds*time.Second
		if fresh, err := v.opts.ReplayGuard.Remember(ctx, claims.Jti, ttl); err != nil {
			return nil, err
		} else if !fresh {
			return nil, ErrLogoutTokenReplayed
		}
	}
	return claims, nil
}

// VerifyRequest reads the `logout_token` form field from a back-channel
// logout POST and verifies it.
func (v *LogoutTokenVerifier) VerifyRequest(r *http.Request) (*LogoutTokenClaims, error) {
	if err := r.ParseForm(); err != nil {
		return nil, ErrMalformed
	}
	return v.Verify(r.Context(), r.PostForm.Get("logout_token"))
}

func audienceContains(aud interface{}, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []interface{}:
		for _, x := range a {
			if s, _ := x.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

// LogoutReplayGuard remembers logout-token ids so a replayed token is refused.
// Remember records jti for ttl and reports whether it was new. Back it with a
// shared store (Redis SET NX EX, a database unique key) when you run more than
// one process.
type LogoutReplayGuard interface {
	Remember(ctx context.Context, jti string, ttl time.Duration) (fresh bool, err error)
}

// MemoryReplayGuard is an in-process LogoutReplayGuard, fine for a single
// server. Its zero value is ready to use.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Remember implements LogoutReplayGuard.
func (g *MemoryReplayGuard) Remember(_ context.Context, jti string, ttl time.Duration) (bool, error) {
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
	if _, dup := g.seen[jti]; dup {
		return false, nil
	}
	g.seen[jti] = now.Add(ttl)
	return true, nil
}
