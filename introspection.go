package atlas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IntrospectionOptions configure RFC 7662 token introspection at Atlas, used
// by AccessTokenVerifier for opaque (reference) access tokens.
//
// An API, client or instance set to the "opaque" access-token format gets
// oat_… tokens that only Atlas can read. The client below authenticates to
// the introspection endpoint with client_secret_basic; it must be a
// confidential client listed in the API's introspection_client_ids (or the
// client the tokens are issued to).
type IntrospectionOptions struct {
	ClientID     string
	ClientSecret string
	// Endpoint defaults to Issuer + "/oauth2/introspect".
	Endpoint string
	// CacheTTL is how long an active answer is reused (default 60s; never past
	// the token's exp).
	CacheTTL time.Duration
	// NegativeCacheTTL is how long an inactive answer is reused (default 10s).
	// Set DisableNegativeCache to turn it off.
	NegativeCacheTTL     time.Duration
	DisableNegativeCache bool
	// CacheMax is the most answers kept (default 10 000).
	CacheMax int
	// IntrospectJWTs also introspects JWT access tokens, so a revoked grant or
	// a banned user is refused before the token expires (one cached call per
	// token). Off by default: JWTs are verified locally.
	IntrospectJWTs bool
}

type introspectionEntry struct {
	claims map[string]interface{}
	until  time.Time
}

// Introspector calls Atlas's introspection endpoint with a small TTL cache
// keyed by the SHA-256 of the token (the token itself is never kept).
type Introspector struct {
	endpoint    string
	opts        IntrospectionOptions
	httpClient  *http.Client
	now         func() time.Time
	ttl         time.Duration
	negativeTTL time.Duration
	max         int

	mu    sync.Mutex
	cache map[string]introspectionEntry
	order []string
}

// NewIntrospector builds an Introspector for an issuer.
func NewIntrospector(issuer string, opts IntrospectionOptions, httpClient *http.Client, now func() time.Time) (*Introspector, error) {
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, errors.New("atlas: Introspection needs ClientID and ClientSecret")
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = strings.TrimRight(issuer, "/") + "/oauth2/introspect"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	negative := opts.NegativeCacheTTL
	if negative <= 0 {
		negative = 10 * time.Second
	}
	if opts.DisableNegativeCache {
		negative = 0
	}
	max := opts.CacheMax
	if max <= 0 {
		max = 10000
	}
	return &Introspector{
		endpoint: endpoint, opts: opts, httpClient: httpClient, now: now,
		ttl: ttl, negativeTTL: negative, max: max, cache: map[string]introspectionEntry{},
	}, nil
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Introspect returns the claims of an active access token, or nil for an
// inactive one (also for a refresh token). It returns an error when Atlas
// could not be reached or answered with a non-2xx status.
func (i *Introspector) Introspect(ctx context.Context, token string) (map[string]interface{}, error) {
	key := tokenCacheKey(token)
	now := i.now()
	i.mu.Lock()
	if hit, ok := i.cache[key]; ok {
		if hit.until.After(now) {
			i.mu.Unlock()
			return hit.claims, nil
		}
		delete(i.cache, key)
	}
	i.mu.Unlock()

	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(i.opts.ClientID), url.QueryEscape(i.opts.ClientSecret))
	res, err := i.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("atlas: introspection failed with HTTP %d", res.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if active, _ := body["active"].(bool); active && body["token_use"] != "refresh_token" {
		claims = body
	}
	now = i.now()
	until := now.Add(i.negativeTTL)
	if claims != nil {
		until = now.Add(i.ttl)
		if exp, ok := claims["exp"].(float64); ok {
			if expAt := time.Unix(int64(exp), 0); expAt.Before(until) {
				until = expAt
			}
		}
	}
	if until.After(now) {
		i.mu.Lock()
		if _, exists := i.cache[key]; !exists {
			i.order = append(i.order, key)
		}
		i.cache[key] = introspectionEntry{claims: claims, until: until}
		if len(i.cache) > i.max {
			for k, v := range i.cache {
				if !v.until.After(now) {
					delete(i.cache, k)
				}
			}
			for len(i.cache) > i.max && len(i.order) > 0 {
				delete(i.cache, i.order[0])
				i.order = i.order[1:]
			}
		}
		// Keep the insertion order list from growing past what is cached.
		if len(i.order) > 2*i.max {
			kept := i.order[:0]
			for _, k := range i.order {
				if _, ok := i.cache[k]; ok {
					kept = append(kept, k)
				}
			}
			i.order = kept
		}
		i.mu.Unlock()
	}
	return claims, nil
}
