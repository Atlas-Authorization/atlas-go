package atlas

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SpecialAddressReason says why an address is not a public internet address.
type SpecialAddressReason string

// Reasons returned by ClassifySpecialAddress.
const (
	SpecialAddressLoopback  SpecialAddressReason = "loopback"
	SpecialAddressPrivate   SpecialAddressReason = "private_address"
	SpecialAddressLinkLocal SpecialAddressReason = "link_local"
	SpecialAddressMulticast SpecialAddressReason = "multicast"
	SpecialAddressReserved  SpecialAddressReason = "reserved"
)

// ClassifySpecialAddress classifies one IP literal against the special-purpose
// registries (v4 and v6): loopback, RFC 1918, CGNAT, link-local (including the cloud
// metadata address), unique-local, multicast, documentation and benchmark ranges, the
// unspecified address, and v6 forms that embed a v4 address (v4-mapped, NAT64, 6to4,
// Teredo), which are judged by the embedded address or refused. It returns "" for a
// public address and for a string that is not an IP literal (a hostname, which the
// caller must resolve and classify).
func ClassifySpecialAddress(value string) SpecialAddressReason {
	lit := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	if i := strings.IndexByte(lit, '%'); i >= 0 {
		lit = lit[:i]
	}
	addr, err := netip.ParseAddr(lit)
	if err != nil {
		return ""
	}
	if addr.Is4() {
		b := addr.As4()
		return classifyV4Bytes(b[:])
	}
	b := addr.As16()
	return classifyV6Bytes(b[:])
}

func classifyV4Bytes(b []byte) SpecialAddressReason {
	a, c := b[0], b[1]
	switch {
	case a == 0:
		return SpecialAddressReserved // "this network" 0.0.0.0/8
	case a == 10:
		return SpecialAddressPrivate
	case a == 100 && c >= 64 && c <= 127:
		return SpecialAddressPrivate // CGNAT 100.64/10
	case a == 127:
		return SpecialAddressLoopback
	case a == 169 && c == 254:
		return SpecialAddressLinkLocal // incl. 169.254.169.254 metadata
	case a == 172 && c >= 16 && c <= 31:
		return SpecialAddressPrivate
	case a == 192 && c == 0 && b[2] == 0, a == 192 && c == 0 && b[2] == 2, a == 192 && c == 88 && b[2] == 99:
		return SpecialAddressReserved // IETF assignments, TEST-NET-1, 6to4 relay anycast
	case a == 192 && c == 168:
		return SpecialAddressPrivate
	case a == 198 && (c == 18 || c == 19), a == 198 && c == 51 && b[2] == 100, a == 203 && c == 0 && b[2] == 113:
		return SpecialAddressReserved // benchmarking, TEST-NET-2, TEST-NET-3
	case a >= 224 && a <= 239:
		return SpecialAddressMulticast
	case a >= 240:
		return SpecialAddressReserved // 240/4 + broadcast
	}
	return ""
}

func classifyV6Bytes(b []byte) SpecialAddressReason {
	zeroUpTo := func(n int) bool {
		for _, x := range b[:n] {
			if x != 0 {
				return false
			}
		}
		return true
	}
	// ::/128 unspecified, ::1/128 loopback.
	if zeroUpTo(15) {
		if b[15] == 1 {
			return SpecialAddressLoopback
		}
		return SpecialAddressReserved
	}
	// ::ffff:0:0/96 v4-mapped: judge the embedded v4 address.
	if zeroUpTo(10) && b[10] == 0xff && b[11] == 0xff {
		return classifyV4Bytes(b[12:])
	}
	// ::/96 deprecated v4-compatible: never a legitimate destination.
	if zeroUpTo(12) {
		return SpecialAddressReserved
	}
	// 64:ff9b::/96 NAT64 (and 64:ff9b:1::/48 local-use): judge the embedded v4, but the local-use prefix is never public.
	if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b {
		if b[4] == 0 && b[5] == 1 {
			return SpecialAddressPrivate
		}
		return classifyV4Bytes(b[12:])
	}
	// 100::/64 discard-only.
	if b[0] == 0x01 && b[1] == 0x00 {
		allZero := true
		for _, x := range b[2:8] {
			if x != 0 {
				allZero = false
			}
		}
		if allZero {
			return SpecialAddressReserved
		}
	}
	if b[0] == 0x20 && b[1] == 0x01 {
		// 2001:db8::/32 documentation.
		if b[2] == 0x0d && b[3] == 0xb8 {
			return SpecialAddressReserved
		}
		// 2001::/23 IETF protocol assignments (Teredo, ORCHID, ...): refuse rather than decode.
		if b[2] < 0x02 {
			return SpecialAddressReserved
		}
	}
	// 2002::/16 6to4: the next 4 bytes are the embedded v4 address.
	if b[0] == 0x20 && b[1] == 0x02 {
		return classifyV4Bytes(b[2:6])
	}
	switch {
	case b[0]&0xfe == 0xfc:
		return SpecialAddressPrivate // fc00::/7 unique local
	case b[0] == 0xfe && b[1]&0xc0 == 0x80:
		return SpecialAddressLinkLocal // fe80::/10
	case b[0] == 0xfe && b[1]&0xc0 == 0xc0:
		return SpecialAddressPrivate // fec0::/10 deprecated site-local
	case b[0] == 0xff:
		return SpecialAddressMulticast
	}
	return ""
}

// PinnedFetchError is a directory fetch refused by the SSRF guard.
type PinnedFetchError struct{ Reason string }

func (e *PinnedFetchError) Error() string { return "atlas: outbound request refused: " + e.Reason }

// PinnedHTTPClientOptions tunes NewPinnedHTTPClient.
type PinnedHTTPClientOptions struct {
	// Timeout bounds the whole request. Default 5s.
	Timeout time.Duration
	// Resolve resolves a hostname to its addresses (tests); nil asks the OS.
	Resolve func(ctx context.Context, host string) ([]string, error)
}

// NewPinnedHTTPClient returns an http.Client for fetching a URL a third party chose
// (a bot's key directory): it resolves the host once, refuses the request when ANY
// address is special-purpose, connects to the vetted address only (so a second DNS
// answer cannot redirect it), keeps checking the certificate against the original
// hostname, never follows a redirect, and allows port 443 only. Use WebBotAuthFetchJSON
// to also require https and cap the size.
func NewPinnedHTTPClient(opts PinnedHTTPClientOptions) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	resolve := opts.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]string, error) {
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			return addrs, err
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, &PinnedFetchError{Reason: "malformed_url"}
			}
			if port != "443" {
				return nil, &PinnedFetchError{Reason: "disallowed_port"}
			}
			lower := strings.ToLower(host)
			if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
				return nil, &PinnedFetchError{Reason: string(SpecialAddressLoopback)}
			}
			var addresses []string
			if _, perr := netip.ParseAddr(host); perr == nil {
				addresses = []string{host}
			} else {
				addresses, err = resolve(ctx, host)
				if err != nil || len(addresses) == 0 {
					return nil, &PinnedFetchError{Reason: "dns_failure"}
				}
			}
			// EVERY address must be public: one public and one private record would be a coin flip an attacker can win.
			for _, a := range addresses {
				if reason := ClassifySpecialAddress(a); reason != "" {
					return nil, &PinnedFetchError{Reason: string(reason)}
				}
				if _, perr := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(a, "["), "]")); perr != nil {
					return nil, &PinnedFetchError{Reason: "dns_failure"}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0], port))
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
		Proxy:               nil, // never through a proxy: the pinning must hold
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// WebBotAuthDirectoryMaxBytes caps a fetched directory document.
const WebBotAuthDirectoryMaxBytes = 64 * 1024

func webBotPrivateHostLiteral(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.Contains(h, ":") || !strings.Contains(h, ".") {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}

// WebBotAuthFetchJSON returns a FetchJSON for NewWebBotAuthDirectoryCache that uses
// hc (https only, no literal or single-label hosts, 200 only, 64 KB cap). hc must
// refuse private addresses itself; NewPinnedHTTPClient does.
func WebBotAuthFetchJSON(hc *http.Client) func(ctx context.Context, target string) ([]byte, error) {
	return func(ctx context.Context, target string) ([]byte, error) {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "https" || webBotPrivateHostLiteral(u.Hostname()) {
			return nil, errors.New("atlas: directory URL refused")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", WebBotAuthDirectoryMediaType)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("atlas: directory fetch failed")
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, WebBotAuthDirectoryMaxBytes+1))
		if err != nil {
			return nil, err
		}
		if len(body) > WebBotAuthDirectoryMaxBytes {
			return nil, errors.New("atlas: directory too large")
		}
		return body, nil
	}
}

// WebBotAuthVerifierOptions configures a WebBotAuthVerifier.
type WebBotAuthVerifierOptions struct {
	WebBotAuthPolicy
	// HTTPClient fetches directories. Default: NewPinnedHTTPClient. One you pass is used
	// as given (behind the literal-host refusal), so it must refuse private addresses itself.
	HTTPClient *http.Client
	// TTL, RefreshCooldown, Skew and MaxLifetime tune the cache and the time window.
	TTL             time.Duration
	RefreshCooldown time.Duration
	Skew            time.Duration
	MaxLifetime     time.Duration
	// RejectReplays refuses a signature whose nonce was seen before (in memory, per
	// process). Off by default: some bots reuse one signed request until it expires.
	RejectReplays bool
	// RequestURL builds the absolute URL the signature covers from a request. Default:
	// https://<Host><RequestURI>.
	RequestURL func(r *http.Request) string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// WebBotAuthVerifier verifies Web Bot Auth signatures inside your own server: no
// call to Atlas, directories cached in memory.
type WebBotAuthVerifier struct {
	opts  WebBotAuthVerifierOptions
	cache *WebBotAuthDirectoryCache
	mu    sync.Mutex
	seen  map[string]int64
}

// NewWebBotAuthVerifier builds a verifier.
func NewWebBotAuthVerifier(opts WebBotAuthVerifierOptions) *WebBotAuthVerifier {
	hc := opts.HTTPClient
	if hc == nil {
		hc = NewPinnedHTTPClient(PinnedHTTPClientOptions{})
	}
	return &WebBotAuthVerifier{
		opts: opts,
		cache: NewWebBotAuthDirectoryCache(WebBotAuthDirectoryCacheOptions{
			FetchJSON: WebBotAuthFetchJSON(hc), TTL: opts.TTL, RefreshCooldown: opts.RefreshCooldown, Now: opts.Now,
		}),
		seen: map[string]int64{},
	}
}

func (v *WebBotAuthVerifier) now() time.Time {
	if v.opts.Now != nil {
		return v.opts.Now()
	}
	return time.Now()
}

func (v *WebBotAuthVerifier) claimNonce(_ context.Context, key string, expiresAtMS int64) bool {
	t := v.now().UnixMilli()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.seen) > 5000 {
		for k, exp := range v.seen {
			if exp <= t {
				delete(v.seen, k)
			}
		}
	}
	if len(v.seen) > 20000 {
		return false // fail closed rather than grow without bound
	}
	if prior, ok := v.seen[key]; ok && prior > t {
		return false
	}
	v.seen[key] = expiresAtMS
	return true
}

// Verify verifies and decides.
func (v *WebBotAuthVerifier) Verify(ctx context.Context, req WebBotAuthRequest) WebBotAuthDecision {
	vo := WebBotAuthVerifyOptions{GetKeys: v.cache.GetKeys, Now: v.now(), Skew: v.opts.Skew, MaxLifetime: v.opts.MaxLifetime}
	if v.opts.RejectReplays {
		vo.ClaimNonce = v.claimNonce
	}
	return DecideWebBotAuth(VerifyWebBotAuth(ctx, req, vo), v.opts.WebBotAuthPolicy)
}

// ClearCache drops every cached directory.
func (v *WebBotAuthVerifier) ClearCache() { v.cache.Clear() }

type webBotDecisionKey struct{}

// WebBotAuthDecisionFromContext returns the decision WebBotAuthVerifier.Middleware stored.
func WebBotAuthDecisionFromContext(ctx context.Context) (WebBotAuthDecision, bool) {
	d, ok := ctx.Value(webBotDecisionKey{}).(WebBotAuthDecision)
	return d, ok
}

// Middleware verifies each request's web-bot-auth signature and stores the decision in
// the request context (WebBotAuthDecisionFromContext). It works with net/http and with
// chi, gin and echo through their http.Handler adapters. It never blocks by itself: a
// request whose decision is "block" is answered 403 only when blockBlocked is true.
func (v *WebBotAuthVerifier) Middleware(blockBlocked bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			if v.opts.RequestURL != nil {
				target = v.opts.RequestURL(r)
			}
			d := v.Verify(r.Context(), WebBotAuthRequest{Method: r.Method, URL: target, Header: r.Header})
			if blockBlocked && d.Decision == "block" {
				http.Error(w, "automated access blocked", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), webBotDecisionKey{}, d)))
		})
	}
}
