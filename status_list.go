package atlas

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The signed session status list (GET /v1/sessions/revocations/status-list): a JWT
// signed with the instance session key that carries the first HashBytes bytes of
// the SHA-256 of every session id revoked in its window, sorted, as one base64url
// string. VerifyStatusListToken checks it; EdgeRevocationChecker keeps one fresh.

// Reasons of a StatusListError.
const (
	StatusListMalformed    = "malformed"
	StatusListUnsupported  = "unsupported"
	StatusListNoKey        = "no_key"
	StatusListBadSignature = "bad_signature"
	StatusListBadClaims    = "bad_claims"
	StatusListExpired      = "expired"
)

// StatusListError is returned for any problem with a status list; a list that does
// not verify is never used.
type StatusListError struct{ Reason string }

func (e *StatusListError) Error() string { return "atlas: invalid session status list: " + e.Reason }

// VerifyStatusListOptions configures VerifyStatusListToken.
type VerifyStatusListOptions struct {
	// JWKS is the instance key cache the signature is checked against (required).
	JWKS *JWKSCache
	// Issuer the list must carry. Strongly recommended: without it any key in the JWKS may vouch for any issuer.
	Issuer string
	// Now overrides the clock (tests).
	Now func() time.Time
	// Skew is the allowed clock skew (default 30s).
	Skew time.Duration
}

// VerifiedStatusList is a verified list and its lookup.
type VerifiedStatusList struct {
	// Count is the number of sessions in the list.
	Count int
	// Truncated means more sessions were revoked than fit: a miss proves nothing, use the feed.
	Truncated bool
	// IssuedAt, ExpiresAt are when the list was issued and stops being valid.
	IssuedAt, ExpiresAt time.Time
	// Since is the epoch ms the list reaches back to.
	Since int64

	list      []byte
	hashBytes int
}

// Has reports whether the session id's hash is in the list.
func (v *VerifiedStatusList) Has(sid string) bool {
	sum := sha256.Sum256([]byte(sid))
	needle := sum[:v.hashBytes]
	lo, hi := 0, v.Count-1
	for lo <= hi {
		mid := (lo + hi) / 2
		c := compareBytes(v.list[mid*v.hashBytes:(mid+1)*v.hashBytes], needle)
		switch {
		case c == 0:
			return true
		case c < 0:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return false
}

func compareBytes(a, b []byte) int {
	for i := range b {
		if d := int(a[i]) - int(b[i]); d != 0 {
			return d
		}
	}
	return 0
}

func statusListJSON(raw string) (map[string]interface{}, error) {
	b, err := base64urlDecodeStrict(raw)
	if err != nil {
		return nil, &StatusListError{StatusListMalformed}
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil || m == nil {
		return nil, &StatusListError{StatusListMalformed}
	}
	return m, nil
}

// base64urlDecodeStrict rejects anything outside the base64url alphabet (padding included).
func base64urlDecodeStrict(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, fmt.Errorf("not base64url")
	}
	return base64urlDecode(s)
}

// VerifyStatusListToken verifies the signed list (any of SigningAlgs with the instance
// key) and returns a lookup. It returns a *StatusListError on any problem.
func VerifyStatusListToken(ctx context.Context, token string, opts VerifyStatusListOptions) (*VerifiedStatusList, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 4_000_000 || opts.JWKS == nil {
		return nil, &StatusListError{StatusListMalformed}
	}
	header, err := statusListJSON(parts[0])
	if err != nil {
		return nil, err
	}
	if header["typ"] != "statuslist+jwt" {
		return nil, &StatusListError{StatusListUnsupported}
	}
	alg, _ := header["alg"].(string)
	if !contains(SigningAlgs, alg) {
		return nil, &StatusListError{StatusListUnsupported}
	}
	kid, _ := header["kid"].(string)
	set := opts.JWKS.get(ctx, kid)
	if set == nil || len(set.Keys) == 0 {
		return nil, &StatusListError{StatusListNoKey}
	}
	sig, err := base64urlDecodeStrict(parts[2])
	if err != nil {
		return nil, &StatusListError{StatusListMalformed}
	}
	if !verifyJWSSignature(set, alg, kid, parts[0]+"."+parts[1], sig) {
		return nil, &StatusListError{StatusListBadSignature}
	}

	claims, err := statusListJSON(parts[1])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	nowSec := float64(now.UnixMilli()) / 1000
	skew := opts.Skew.Seconds()
	if opts.Skew <= 0 {
		skew = 30
	}
	num := func(k string) (float64, error) {
		v, ok := claims[k].(float64)
		if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, &StatusListError{StatusListBadClaims}
		}
		return v, nil
	}
	if claims["aud"] != "atlas:session-status-list" || claims["token_use"] != "session_status_list" {
		return nil, &StatusListError{StatusListBadClaims}
	}
	if opts.Issuer != "" && claims["iss"] != opts.Issuer {
		return nil, &StatusListError{StatusListBadClaims}
	}
	exp, err := num("exp")
	if err != nil {
		return nil, err
	}
	iat, err := num("iat")
	if err != nil {
		return nil, err
	}
	if exp+skew < nowSec {
		return nil, &StatusListError{StatusListExpired}
	}
	if iat-skew > nowSec {
		return nil, &StatusListError{StatusListBadClaims}
	}
	hb, err := num("hash_bytes")
	if err != nil || hb != math.Trunc(hb) || hb < 4 || hb > 32 {
		return nil, &StatusListError{StatusListBadClaims}
	}
	cnt, err := num("count")
	if err != nil || cnt != math.Trunc(cnt) || cnt < 0 {
		return nil, &StatusListError{StatusListBadClaims}
	}
	since, err := num("since")
	if err != nil {
		return nil, err
	}
	h, ok := claims["h"].(string)
	if !ok {
		return nil, &StatusListError{StatusListBadClaims}
	}
	list, derr := base64urlDecodeStrict(h)
	if derr != nil {
		return nil, &StatusListError{StatusListMalformed}
	}
	if float64(len(list)) != cnt*hb {
		return nil, &StatusListError{StatusListBadClaims}
	}
	truncated, _ := claims["truncated"].(bool)
	return &VerifiedStatusList{
		Count: int(cnt), Truncated: truncated, Since: int64(since), list: list, hashBytes: int(hb),
		IssuedAt: time.UnixMilli(int64(iat * 1000)), ExpiresAt: time.UnixMilli(int64(exp * 1000)),
	}, nil
}

// EdgeRevocationVerdict is the answer of EdgeRevocationChecker.Check.
type EdgeRevocationVerdict string

// Verdicts.
const (
	EdgeRevocationOK          EdgeRevocationVerdict = "ok"
	EdgeRevocationRevoked     EdgeRevocationVerdict = "revoked"
	EdgeRevocationUnavailable EdgeRevocationVerdict = "unavailable"
)

// EdgeRevocationOptions configures an EdgeRevocationChecker.
type EdgeRevocationOptions struct {
	// SecretKey needs the sessions:read scope; keep it server-side.
	SecretKey string
	// BaseURL is the API origin (default https://api.atlasauth.net).
	BaseURL string
	// JWKSURL is the instance JWKS URL (required).
	JWKSURL string
	// Issuer is the iss of your session tokens; the list must carry it.
	Issuer string
	// WindowSeconds is how far back the list reaches; at least your longest token lifetime. 0 = the server default.
	WindowSeconds int
	// Refresh refetches the list when older than this (default 30s).
	Refresh time.Duration
	// StaleAfter is how long without a successful refresh counts as stale (default 2m).
	StaleAfter time.Duration
	// ServeStaleFor keeps answering from the last list this much longer past StaleAfter before failing closed.
	ServeStaleFor time.Duration
	// AllowStale keeps using the last list however old it is (default: reject, answer unavailable).
	AllowStale bool
	// HTTPClient performs the requests (nil = http.DefaultClient).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
	// OnError is called when a refresh fails; the last list stays in force.
	OnError func(err error)
	// OnServeStale fires for each check answered from a stale list inside ServeStaleFor.
	OnServeStale func(lastSuccessAt time.Time, staleFor time.Duration)
}

// EdgeRevocationChecker keeps the last verified status list in memory, refreshes it
// when older than Refresh and answers ok, revoked or unavailable (the list is too
// old, or was truncated). Concurrent checks share one refresh. A list that does
// not verify is never used. It is safe for concurrent use.
type EdgeRevocationChecker struct {
	opts EdgeRevocationOptions
	jwks *JWKSCache

	refreshMu   sync.Mutex
	mu          sync.Mutex
	current     *VerifiedStatusList
	lastSuccess *int64
}

// NewEdgeRevocationChecker builds a checker; it does no I/O until the first Check.
func NewEdgeRevocationChecker(opts EdgeRevocationOptions) (*EdgeRevocationChecker, error) {
	if opts.SecretKey == "" || opts.JWKSURL == "" {
		return nil, fmt.Errorf("atlas: EdgeRevocationChecker needs a SecretKey and a JWKSURL")
	}
	return &EdgeRevocationChecker{
		opts: opts,
		jwks: NewJWKSCache(JWKSCacheOptions{URL: opts.JWKSURL, HTTPClient: opts.HTTPClient, Now: opts.Now}),
	}, nil
}

func (c *EdgeRevocationChecker) nowMS() int64 {
	if c.opts.Now != nil {
		return c.opts.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// LastSuccessAt is the epoch ms of the last list that verified (false before the first).
func (c *EdgeRevocationChecker) LastSuccessAt() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastSuccess == nil {
		return 0, false
	}
	return *c.lastSuccess, true
}

func (c *EdgeRevocationChecker) needsRefresh() bool {
	refresh := c.opts.Refresh
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current == nil || c.lastSuccess == nil || c.nowMS()-*c.lastSuccess >= refresh.Milliseconds()
}

func (c *EdgeRevocationChecker) fail(err error) {
	if c.opts.OnError != nil {
		c.opts.OnError(err)
	}
}

func (c *EdgeRevocationChecker) refresh(ctx context.Context) {
	base := strings.TrimRight(c.opts.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	target := base + "/v1/sessions/revocations/status-list"
	if c.opts.WindowSeconds > 0 {
		target += "?" + url.Values{"window_seconds": {strconv.Itoa(c.opts.WindowSeconds)}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		c.fail(err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.opts.SecretKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	hc := c.opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		c.fail(err)
		return
	}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if rerr != nil {
		c.fail(rerr)
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.fail(fmt.Errorf("status list answered %d", resp.StatusCode))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Token == "" {
		c.fail(fmt.Errorf("status list answer had no token"))
		return
	}
	list, err := VerifyStatusListToken(ctx, body.Token, VerifyStatusListOptions{JWKS: c.jwks, Issuer: c.opts.Issuer, Now: c.opts.Now})
	if err != nil {
		c.fail(err)
		return
	}
	at := c.nowMS()
	c.mu.Lock()
	c.current = list
	c.lastSuccess = &at
	c.mu.Unlock()
}

// Check is the verdict for a session id (the sid of a verified session token).
func (c *EdgeRevocationChecker) Check(ctx context.Context, sid string) EdgeRevocationVerdict {
	if c.needsRefresh() {
		c.refreshMu.Lock()
		if c.needsRefresh() {
			c.refresh(ctx)
		}
		c.refreshMu.Unlock()
	}
	c.mu.Lock()
	cur, last := c.current, c.lastSuccess
	c.mu.Unlock()
	if cur == nil || last == nil {
		if c.opts.AllowStale {
			return EdgeRevocationOK
		}
		return EdgeRevocationUnavailable
	}
	if cur.Has(sid) {
		return EdgeRevocationRevoked
	}
	if cur.Truncated {
		return EdgeRevocationUnavailable
	}
	staleAfter := c.opts.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 2 * time.Minute
	}
	stale := c.nowMS() - *last - staleAfter.Milliseconds()
	if stale > 0 && !c.opts.AllowStale {
		if stale <= c.opts.ServeStaleFor.Milliseconds() {
			if c.opts.OnServeStale != nil {
				c.opts.OnServeStale(time.UnixMilli(*last), time.Duration(stale)*time.Millisecond)
			}
			return EdgeRevocationOK
		}
		return EdgeRevocationUnavailable
	}
	return EdgeRevocationOK
}
