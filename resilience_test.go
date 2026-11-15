package atlas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// retryServer answers failStatus (with extra headers) for the first fails
// calls, then 200 {}.
func retryServer(fails int32, failStatus int, hdr map[string]string, calls *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n <= fails {
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			w.WriteHeader(failStatus)
			_, _ = w.Write([]byte(`{"errors":[{"code":"UNAVAILABLE","message":"try later"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
}

func noSleep(slept *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return nil
	}
}

func TestRetryHonoursRetryAfter(t *testing.T) {
	var calls int32
	srv := retryServer(2, http.StatusTooManyRequests, map[string]string{"Retry-After": "3"}, &calls)
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{MaxRetries: 3, sleep: noSleep(&slept)}))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if calls != 3 || len(slept) != 2 || slept[0] != 3*time.Second || slept[1] != 3*time.Second {
		t.Fatalf("calls=%d slept=%v", calls, slept)
	}
}

func TestRetryBacksOffOn503ForIdempotentMethods(t *testing.T) {
	var calls int32
	srv := retryServer(2, http.StatusServiceUnavailable, nil, &calls)
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{
		MaxRetries: 3, BaseDelay: 100 * time.Millisecond, sleep: noSleep(&slept), jitter: func() float64 { return 1 },
	}))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("expected success: %v", err)
	}
	// jitter 1 => the full step: 100ms, then 200ms
	if len(slept) != 2 || slept[0] != 100*time.Millisecond || slept[1] != 200*time.Millisecond {
		t.Fatalf("slept=%v", slept)
	}
}

func TestNoRetryOfUnkeyedWriteOn503ButRetryOn429(t *testing.T) {
	var calls int32
	srv := retryServer(1, http.StatusServiceUnavailable, nil, &calls)
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{MaxRetries: 3, sleep: noSleep(&slept)}))
	err := c.do(context.Background(), "POST", "/v1/anything", nil, map[string]string{"a": "b"}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 503 || calls != 1 {
		t.Fatalf("an unkeyed POST must not be retried on 503: err=%v calls=%d", err, calls)
	}
	// with an idempotency key the same write is retried
	calls = 0
	if err := c.do(context.Background(), "POST", "/v1/anything", nil, map[string]string{"a": "b"}, nil, WithIdempotencyKey("k1")); err != nil || calls != 2 {
		t.Fatalf("keyed POST should retry: err=%v calls=%d", err, calls)
	}
	// 429 is retried for any method
	var calls2 int32
	srv2 := retryServer(1, http.StatusTooManyRequests, nil, &calls2)
	defer srv2.Close()
	c2 := New("sk_test", WithBaseURL(srv2.URL), WithRetryPolicy(RetryPolicy{MaxRetries: 2, sleep: noSleep(&slept)}))
	if err := c2.do(context.Background(), "POST", "/v1/anything", nil, nil, nil); err != nil || calls2 != 2 {
		t.Fatalf("429 should retry any method: err=%v calls=%d", err, calls2)
	}
}

func TestRetryGivesUpAndReportsRetryAfter(t *testing.T) {
	var calls int32
	srv := retryServer(10, http.StatusTooManyRequests, map[string]string{"Retry-After": "7"}, &calls)
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{MaxRetries: 1, sleep: noSleep(&slept)}))
	_, err := c.Instance.Get(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 7*time.Second || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestRetryAfterBeyondCapReturnsAtOnce(t *testing.T) {
	var calls int32
	srv := retryServer(10, http.StatusTooManyRequests, map[string]string{"Retry-After": "3600"}, &calls)
	defer srv.Close()
	c := New("sk_test", WithBaseURL(srv.URL), WithRetries(5))
	if _, err := c.Instance.Get(context.Background()); err == nil || calls != 1 {
		t.Fatalf("a long Retry-After must not be waited out: err=%v calls=%d", err, calls)
	}
}

func TestPerCallMaxRetriesOverride(t *testing.T) {
	var calls int32
	srv := retryServer(10, http.StatusServiceUnavailable, nil, &calls)
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{MaxRetries: 5, sleep: noSleep(&slept)}))
	if err := c.do(context.Background(), "GET", "/v1/anything", nil, nil, nil, WithMaxRetries(0)); err == nil || calls != 1 {
		t.Fatalf("WithMaxRetries(0) must switch retries off: err=%v calls=%d", err, calls)
	}
}

func TestStatusAwareStretchesWaitDuringOutage(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/status" {
			_, _ = w.Write([]byte(`{"object":"status","status":"major_outage"}`))
			return
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{
		MaxRetries: 2, BaseDelay: time.Second, StatusAware: true, sleep: noSleep(&slept), jitter: func() float64 { return 1 },
	}))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if len(slept) != 1 || slept[0] != 4*time.Second {
		t.Fatalf("a major outage should stretch 1s to 4s, got %v", slept)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := http.Header{}
	if parseRetryAfter(h, now) != 0 {
		t.Fatal("absent header should be 0")
	}
	h.Set("Retry-After", "2")
	if parseRetryAfter(h, now) != 2*time.Second {
		t.Fatal("delta seconds")
	}
	h.Set("Retry-After", now.Add(90*time.Second).UTC().Format(http.TimeFormat))
	if d := parseRetryAfter(h, now); d != 90*time.Second {
		t.Fatalf("http date: %v", d)
	}
	h.Set("Retry-After", "soon")
	if parseRetryAfter(h, now) != 0 {
		t.Fatal("garbage should be 0")
	}
}

type recordingObserver struct {
	started  []RequestInfo
	finished []RequestResult
}

func (o *recordingObserver) StartRequest(ctx context.Context, info RequestInfo) (context.Context, func(RequestResult)) {
	o.started = append(o.started, info)
	return ctx, func(r RequestResult) { o.finished = append(o.finished, r) }
}

func (o *recordingObserver) InjectHeaders(_ context.Context, h http.Header) {
	h.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
}

func TestObserverSeesCallAttemptsAndInjectsHeaders(t *testing.T) {
	var calls int32
	var gotTP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTP = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	obs := &recordingObserver{}
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithObserver(obs), WithRetryPolicy(RetryPolicy{MaxRetries: 2, sleep: noSleep(&slept)}))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if len(obs.started) != 1 || obs.started[0].Method != "GET" || obs.started[0].Path != "/v1/instance" {
		t.Fatalf("started=%v", obs.started)
	}
	if len(obs.finished) != 1 || obs.finished[0].Attempts != 2 || obs.finished[0].Status != 200 || obs.finished[0].Err != nil {
		t.Fatalf("finished=%v", obs.finished)
	}
	if gotTP == "" {
		t.Fatal("the observer's headers were not injected")
	}
}

func TestStatusAwareTreatsBackendComponentOutageAsOutage(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/status" {
			_, _ = w.Write([]byte(`{"object":"status","status":"degraded","components":[{"id":"backend_api","status":"major_outage"}]}`))
			return
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	var slept []time.Duration
	c := New("sk_test", WithBaseURL(srv.URL), WithRetryPolicy(RetryPolicy{
		MaxRetries: 2, BaseDelay: time.Second, StatusAware: true, sleep: noSleep(&slept), jitter: func() float64 { return 1 },
	}))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if len(slept) != 1 || slept[0] != 4*time.Second {
		t.Fatalf("got %v", slept)
	}
}
