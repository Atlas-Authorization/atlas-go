package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session revocation for a local verifier. Verifying a session token locally (no
// network call) cannot see a session Atlas revoked a moment ago. SidRevocationList
// polls GET /v1/sessions/revoked (needs a secret key with sessions:read) and
// remembers each revoked session id until a token for it can no longer be live, so
// a request whose token names a listed sid can be refused.

// Errors returned by SidRevocationList.Check.
var (
	// ErrSessionRevoked means Atlas revoked the token's session.
	ErrSessionRevoked = errors.New("atlas: the session was revoked")
	// ErrRevocationUnavailable means the list could not be refreshed for too long and StaleReject is set (fail closed).
	ErrRevocationUnavailable = errors.New("atlas: the session revocation list is unavailable")
)

// SidRevocationOptions configures a SidRevocationList. Only SecretKey is required.
type SidRevocationOptions struct {
	// SecretKey needs the sessions:read scope.
	SecretKey string
	// BaseURL is the Backend API origin (default https://api.atlasauth.net).
	BaseURL string
	// HTTPClient performs the polls (nil = http.DefaultClient).
	HTTPClient *http.Client
	// Interval is how often to poll. Default 15s. This plus the token lifetime is the worst-case window.
	Interval time.Duration
	// MaxTokenLifetime is your longest-lived session token (Atlas's default is 60s). A listed sid is remembered this long. Default 1h.
	MaxTokenLifetime time.Duration
	// StaleReject fails closed: when the list could not be refreshed for longer than
	// StaleAfter (plus ServeStaleFor), Check answers ErrRevocationUnavailable. Default
	// false: keep trusting the last list through an Atlas incident.
	StaleReject bool
	// StaleAfter is how long without a successful poll counts as stale. Default 2 minutes.
	StaleAfter time.Duration
	// ServeStaleFor keeps answering from the last list for this long after StaleAfter
	// before failing closed (StaleReject only). OnServeStale fires for each check inside it.
	ServeStaleFor time.Duration
	// OnServeStale is called when a check is answered from a stale list still inside ServeStaleFor.
	OnServeStale func(lastSuccessAt time.Time, staleFor time.Duration)
	// Source is where the list comes from: "feed" (default) pages GET /v1/sessions/revoked;
	// "status_list" fetches the signed list at GET /v1/sessions/revocations/status-list and
	// verifies it against the instance JWKS (JWKSURL), a smaller answer for a busy verifier.
	// Both need sessions:read.
	Source string
	// JWKSURL is the instance JWKS URL the signed list is checked against (Source "status_list").
	JWKSURL string
	// Issuer is the issuer the signed list must carry (Source "status_list").
	Issuer string
	// OnError is called when a poll fails; the last list stays in force.
	OnError func(err error)
	// Now overrides the clock (tests).
	Now func() time.Time
}

// SidRevocationList is an in-memory set of revoked session ids kept fresh by polling
// on demand. It is safe for concurrent use.
type SidRevocationList struct {
	opts       SidRevocationOptions
	interval   time.Duration
	lifetimeMS int64
	createdAt  int64

	pollMu sync.Mutex // serialises polls

	statusChecker *EdgeRevocationChecker // Source "status_list"

	mu          sync.Mutex
	revoked     map[string]int64 // sid -> expiry (epoch ms)
	since       *int64
	nextPollAt  int64
	lastSuccess *int64
}

type sidRevokedPage struct {
	Data []struct {
		Sid       string `json:"sid"`
		RevokedAt int64  `json:"revoked_at"`
	} `json:"data"`
	HasMore    bool    `json:"has_more"`
	NextCursor *string `json:"next_cursor"`
	ServerTime int64   `json:"server_time"`
}

// NewSidRevocationList builds a list. It does no I/O until the first check.
func NewSidRevocationList(opts SidRevocationOptions) (*SidRevocationList, error) {
	if opts.SecretKey == "" {
		return nil, errors.New("atlas: SidRevocationList needs a SecretKey")
	}
	if opts.Source != "" && opts.Source != "feed" && opts.Source != "status_list" {
		return nil, errors.New(`atlas: SidRevocationList Source must be "feed" or "status_list"`)
	}
	if opts.Source == "status_list" && opts.JWKSURL == "" {
		return nil, errors.New("atlas: revocation source status_list needs JWKSURL")
	}
	l := &SidRevocationList{opts: opts, revoked: map[string]int64{}}
	l.interval = opts.Interval
	if l.interval <= 0 {
		l.interval = 15 * time.Second
	}
	life := opts.MaxTokenLifetime
	if life <= 0 {
		life = time.Hour
	}
	l.lifetimeMS = life.Milliseconds()
	l.createdAt = l.nowMS()
	return l, nil
}

func (l *SidRevocationList) nowMS() int64 {
	if l.opts.Now != nil {
		return l.opts.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// Unavailable reports whether the list could not be refreshed for StaleAfter and
// the caller asked to fail closed (StaleReject). Call it after IsRevoked.
func (l *SidRevocationList) Unavailable() bool {
	if !l.opts.StaleReject {
		return false
	}
	staleAfter := l.opts.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 2 * time.Minute
	}
	l.mu.Lock()
	last := l.lastSuccess
	l.mu.Unlock()
	base := l.createdAt
	if last != nil {
		base = *last
	}
	stale := l.nowMS() - base - staleAfter.Milliseconds()
	if stale <= 0 {
		return false
	}
	// A list that was fetched at least once may be served a little longer; one never fetched may not.
	if last != nil && stale <= l.opts.ServeStaleFor.Milliseconds() {
		if l.opts.OnServeStale != nil {
			l.opts.OnServeStale(time.UnixMilli(*last), time.Duration(stale)*time.Millisecond)
		}
		return false
	}
	return true
}

// IsRevoked reports whether sid is on the list, refreshing it first when the
// interval has passed.
func (l *SidRevocationList) IsRevoked(ctx context.Context, sid string) bool {
	if l.opts.Source == "status_list" {
		if verdict := l.statusListVerdict(ctx, sid); verdict != EdgeRevocationUnavailable {
			return verdict == EdgeRevocationRevoked
		}
	}
	now := l.nowMS()
	l.mu.Lock()
	due := now >= l.nextPollAt
	l.mu.Unlock()
	if due {
		l.pollMu.Lock()
		l.mu.Lock()
		stillDue := l.nowMS() >= l.nextPollAt
		l.mu.Unlock()
		if stillDue {
			l.poll(ctx)
		}
		l.pollMu.Unlock()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	expiry, ok := l.revoked[sid]
	return ok && expiry > now
}

// Check refuses a token whose session is revoked (ErrSessionRevoked) and, with
// StaleReject, fails closed when the list is too stale (ErrRevocationUnavailable).
// A token without a sid passes.
func (l *SidRevocationList) Check(ctx context.Context, claims *SessionClaims) error {
	if claims == nil || claims.Sid == "" {
		return nil
	}
	if l.IsRevoked(ctx, claims.Sid) {
		return ErrSessionRevoked
	}
	if l.Unavailable() {
		return ErrRevocationUnavailable
	}
	return nil
}

// statusListVerdict asks the signed list. A list that was cut short, or never
// fetched, cannot clear a session, so the caller falls back to the feed.
func (l *SidRevocationList) statusListVerdict(ctx context.Context, sid string) EdgeRevocationVerdict {
	l.mu.Lock()
	if l.statusChecker == nil {
		window := int((l.lifetimeMS + 999) / 1000)
		if window < 60 {
			window = 60
		}
		if window > 86400 {
			window = 86400
		}
		// NewSidRevocationList validated the options, so this cannot fail.
		l.statusChecker, _ = NewEdgeRevocationChecker(EdgeRevocationOptions{
			SecretKey: l.opts.SecretKey, BaseURL: l.opts.BaseURL, JWKSURL: l.opts.JWKSURL, Issuer: l.opts.Issuer,
			WindowSeconds: window, Refresh: l.interval, StaleAfter: l.opts.StaleAfter, AllowStale: true,
			HTTPClient: l.opts.HTTPClient, Now: l.opts.Now, OnError: l.opts.OnError,
		})
	}
	checker := l.statusChecker
	l.mu.Unlock()
	verdict := checker.Check(ctx, sid)
	if at, ok := checker.LastSuccessAt(); ok {
		l.mu.Lock()
		l.lastSuccess = &at
		l.mu.Unlock()
	}
	return verdict
}

func (l *SidRevocationList) fail(err error) {
	if l.opts.OnError != nil {
		l.opts.OnError(err)
	}
}

func (l *SidRevocationList) poll(ctx context.Context) {
	started := l.nowMS()
	l.mu.Lock()
	l.nextPollAt = started + l.interval.Milliseconds()
	since := started - l.lifetimeMS
	if l.since != nil {
		since = *l.since
	}
	l.mu.Unlock()

	base := strings.TrimRight(l.opts.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	hc := l.opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	cursor := ""
	serverTime := started
	for {
		q := url.Values{}
		q.Set("since", strconv.FormatInt(since, 10))
		q.Set("limit", "5000")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/sessions/revoked?"+q.Encode(), nil)
		if err != nil {
			l.fail(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+l.opts.SecretKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := hc.Do(req)
		if err != nil {
			l.fail(err)
			return
		}
		var page sidRevokedPage
		derr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			l.fail(fmt.Errorf("GET /v1/sessions/revoked answered %d", resp.StatusCode))
			return
		}
		if derr != nil {
			l.fail(derr)
			return
		}
		l.mu.Lock()
		for _, r := range page.Data {
			l.revoked[r.Sid] = r.RevokedAt + l.lifetimeMS
		}
		l.mu.Unlock()
		serverTime = page.ServerTime
		if page.HasMore && page.NextCursor != nil && *page.NextCursor != "" {
			cursor = *page.NextCursor
			continue
		}
		break
	}
	// Re-ask from a little before the answer's own clock, so a row committed late is not missed.
	next := serverTime - 10_000
	l.mu.Lock()
	l.since = &next
	l.lastSuccess = &started
	for sid, expiry := range l.revoked {
		if expiry <= started {
			delete(l.revoked, sid)
		}
	}
	l.mu.Unlock()
}
