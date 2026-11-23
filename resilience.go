package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RetryPolicy makes the client retry transient failures. The zero value never
// retries, so behaviour is unchanged until you opt in with WithRetries or
// WithRetryPolicy.
//
// What is retried: HTTP 429 on any method (the request was not processed);
// 502, 503, 504 and transport errors on idempotent methods (GET, HEAD, PUT,
// DELETE) and on writes that carry an Idempotency-Key (WithIdempotencyKey), so
// a retry can never apply a write twice. A Retry-After header (seconds or an
// HTTP date) is honoured; without one the wait grows exponentially with jitter.
type RetryPolicy struct {
	// MaxRetries is the number of retries after the first attempt (0 = none).
	MaxRetries int
	// BaseDelay is the first backoff step (default 250ms).
	BaseDelay time.Duration
	// MaxDelay caps one computed backoff (default 30s).
	MaxDelay time.Duration
	// MaxRetryAfter is the longest Retry-After the client will sit through; a
	// longer hint returns the error at once (default 60s).
	MaxRetryAfter time.Duration
	// RetryStatuses replaces the default retried statuses (429, 502, 503, 504).
	RetryStatuses []int
	// StatusAware reads the public status endpoint (GET /v1/status) after a 503
	// without Retry-After and stretches the wait during a degraded service or a
	// major outage, instead of hammering a service that reports itself down.
	StatusAware bool
	// OnRetry is called before each wait (logging, metrics).
	OnRetry func(RetryEvent)

	// sleep and jitter are replaced in tests.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func() float64
}

// RetryEvent describes one retry about to happen.
type RetryEvent struct {
	Method string
	Path   string
	// Attempt is the attempt that just failed (1 for the first).
	Attempt int
	// Status is the HTTP status that triggered the retry (0 for a transport error).
	Status int
	// Delay is how long the client will wait before the next attempt.
	Delay time.Duration
	Err   error
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.BaseDelay <= 0 {
		p.BaseDelay = 250 * time.Millisecond
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = 30 * time.Second
	}
	if p.MaxRetryAfter <= 0 {
		p.MaxRetryAfter = 60 * time.Second
	}
	if len(p.RetryStatuses) == 0 {
		p.RetryStatuses = []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	}
	return p
}

func (p RetryPolicy) retriesStatus(status int) bool {
	for _, s := range p.RetryStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// next decides after a finished attempt (attempt counts from 1) whether to try
// again and how long to wait first.
func (p RetryPolicy) next(attempt int, method string, hasIdempotencyKey bool, status int, header http.Header, err error) (time.Duration, bool) {
	if attempt > p.MaxRetries {
		return 0, false
	}
	safe := hasIdempotencyKey || method == http.MethodGet || method == http.MethodHead || method == http.MethodPut || method == http.MethodDelete
	switch {
	case err != nil:
		// A transport failure may or may not have reached the server.
		if !safe || status != 0 {
			return 0, false
		}
	case status == http.StatusTooManyRequests:
		// Rejected before processing: safe for every method.
	case p.retriesStatus(status):
		if !safe {
			return 0, false
		}
	default:
		return 0, false
	}
	if hint := parseRetryAfter(header, time.Now()); hint > 0 {
		if hint > p.MaxRetryAfter {
			return 0, false
		}
		return hint, true
	}
	d := p.BaseDelay
	for i := 1; i < attempt && d < p.MaxDelay; i++ {
		d *= 2
	}
	if d > p.MaxDelay {
		d = p.MaxDelay
	}
	j := rand.Float64
	if p.jitter != nil {
		j = p.jitter
	}
	// Equal jitter: half fixed, half random, so synchronised clients spread out.
	return d/2 + time.Duration(j()*float64(d/2)), true
}

// stretch lengthens a backoff according to the reported service status.
func (p RetryPolicy) stretch(wait time.Duration, status string) time.Duration {
	switch status {
	case "major_outage":
		wait *= 4
	case "degraded", "partial_outage":
		wait *= 2
	}
	if wait > p.MaxDelay {
		wait = p.MaxDelay
	}
	return wait
}

func (p RetryPolicy) pause(ctx context.Context, d time.Duration) error {
	if p.sleep != nil {
		return p.sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// parseRetryAfter reads a Retry-After header (delta seconds or an HTTP date).
// It returns 0 when the header is absent, malformed or already in the past.
func parseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseFloat(v, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs * float64(time.Second))
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// probeStatus reads the overall status from GET /v1/status ("operational",
// "degraded", "major_outage") or "" when it cannot be read. It never retries.
func (c *Client) probeStatus(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/status", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	hc := c.httpClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	var body struct {
		Status     string `json:"status"`
		Components []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	// The backend API component being down is an outage even when the overall
	// status reads lower.
	for _, comp := range body.Components {
		if comp.ID == StatusComponentBackendAPI && comp.Status == "major_outage" {
			return "major_outage"
		}
	}
	return body.Status
}

// WithRetries turns on retries with the default backoff: n retries after the
// first attempt. See RetryPolicy for what is retried.
func WithRetries(n int) Option {
	return func(c *Client) { c.retry.MaxRetries = n }
}

// WithRetryPolicy sets the full retry policy.
func WithRetryPolicy(p RetryPolicy) Option {
	return func(c *Client) { c.retry = p }
}

// WithMaxRetries overrides the client's retry count for one call; WithMaxRetries(0)
// turns retries off for it.
func WithMaxRetries(n int) RequestOption {
	return func(rc *requestConfig) { rc.retries = &n }
}

// ---- observability hook -------------------------------------------------------

// RequestInfo identifies a call to an Observer.
type RequestInfo struct {
	Method string
	// Path is the API path without the query string, e.g. /v1/users/user_1.
	Path string
}

// RequestResult is what a finished call reports to an Observer.
type RequestResult struct {
	// Status is the last HTTP status (0 when the request never got a response).
	Status int
	// Attempts is how many HTTP requests were made (1 when nothing was retried).
	Attempts int
	// Err is the error the call returned, nil on success.
	Err error
}

// Observer watches every API call; the opt-in OpenTelemetry module
// (github.com/Atlas-Authorization/atlas-go/otel) implements it. StartRequest is
// called once per call, before the first attempt; the returned context is used
// for the HTTP requests and the returned function is called when the call is
// done.
type Observer interface {
	StartRequest(ctx context.Context, info RequestInfo) (context.Context, func(RequestResult))
}

// HeaderInjector is an optional Observer extension: it can add headers (for
// example W3C trace context) to each HTTP attempt.
type HeaderInjector interface {
	InjectHeaders(ctx context.Context, h http.Header)
}

// WithObserver registers an Observer for tracing and metrics.
func WithObserver(o Observer) Option {
	return func(c *Client) { c.observer = o }
}

// resetRetryable reports a connection-level failure before any response (a reset,
// a broken pipe, a refused connect, the server closing a reused idle socket) on a
// request that is safe to replay: GET, HEAD, OPTIONS, PUT, DELETE or any request
// carrying an Idempotency-Key. Timeouts and cancellations never qualify.
func resetRetryable(err error, req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
	default:
		if req.Header.Get("Idempotency-Key") == "" {
			return false
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "server closed idle connection")
}

// cloneForRetry returns a fresh copy of req with a re-readable body.
func cloneForRetry(ctx context.Context, req *http.Request) (*http.Request, error) {
	c := req.Clone(ctx)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		c.Body = body
	}
	return c, nil
}

// resetDelay is the short jittered wait (25-125ms) before the single reset retry.
func resetDelay() time.Duration {
	return 25*time.Millisecond + time.Duration(rand.Float64()*float64(100*time.Millisecond))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
