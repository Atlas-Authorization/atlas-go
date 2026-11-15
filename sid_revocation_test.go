package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSidRevocationListPollsAndRemembers(t *testing.T) {
	var polls int32
	var failing atomic.Bool
	const base = int64(1_000_000)
	now := time.UnixMilli(base)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&polls, 1)
		if r.Header.Get("Authorization") != "Bearer sk_test" || r.URL.Path != "/v1/sessions/revoked" {
			t.Errorf("unexpected request %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":        []map[string]interface{}{{"sid": "sess_revoked", "revoked_at": base}},
			"has_more":    false,
			"next_cursor": nil,
			"server_time": base,
		})
	}))
	defer srv.Close()

	var errs int32
	list, err := NewSidRevocationList(SidRevocationOptions{
		SecretKey: "sk_test", BaseURL: srv.URL, Interval: time.Minute, StaleReject: true, StaleAfter: time.Minute,
		OnError: func(error) { atomic.AddInt32(&errs, 1) }, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if !list.IsRevoked(ctx, "sess_revoked") || list.IsRevoked(ctx, "sess_ok") {
		t.Fatal("the listed sid is revoked, another is not")
	}
	if err := list.Check(ctx, &SessionClaims{Sid: "sess_revoked"}); err != ErrSessionRevoked {
		t.Fatalf("want ErrSessionRevoked, got %v", err)
	}
	if err := list.Check(ctx, &SessionClaims{Sid: "sess_ok"}); err != nil {
		t.Fatalf("an unlisted sid passes: %v", err)
	}
	if atomic.LoadInt32(&polls) != 1 {
		t.Fatalf("the interval throttles polling, polls=%d", polls)
	}

	// The list cannot refresh: it stays in force, then fails closed once stale.
	failing.Store(true)
	now = now.Add(2 * time.Minute)
	if !list.IsRevoked(ctx, "sess_revoked") {
		t.Fatal("a failed poll keeps the last list")
	}
	if atomic.LoadInt32(&errs) == 0 {
		t.Fatal("OnError must fire for a failed poll")
	}
	if err := list.Check(ctx, &SessionClaims{Sid: "sess_ok"}); err != ErrRevocationUnavailable {
		t.Fatalf("a stale list with StaleReject fails closed, got %v", err)
	}
}
