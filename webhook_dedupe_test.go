package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func dedupeSignedRequest(secret, id string, now time.Time, body string) http.Header {
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + ts + "." + body))
	h := http.Header{}
	h.Set("Atlas-Id", id)
	h.Set("Atlas-Timestamp", ts)
	h.Set("Atlas-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return h
}

const dedupeBody = `{"id":"evt_1","type":"user.created","timestamp":1,"instance_id":"ins_1","data":{}}`

func TestVerifyAndDedupeDropsRetries(t *testing.T) {
	now := time.Now()
	store := NewMemoryWebhookStore()
	opts := VerifyAndDedupeOptions{Secret: "whsec_test", Store: store, Verify: &WebhookVerifyOptions{Now: now}}
	h := dedupeSignedRequest("whsec_test", "dlv_1", now, dedupeBody)

	first, err := VerifyAndDedupe(context.Background(), []byte(dedupeBody), h, opts)
	if err != nil || first.Duplicate || first.DeliveryID != "dlv_1" || first.Event.Type != "user.created" {
		t.Fatalf("first delivery: %+v %v", first, err)
	}
	again, err := VerifyAndDedupe(context.Background(), []byte(dedupeBody), h, opts)
	if err != nil || !again.Duplicate {
		t.Fatalf("retry must be a duplicate: %+v %v", again, err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	third, err := VerifyAndDedupe(context.Background(), []byte(dedupeBody), h, opts)
	if err != nil || third.Duplicate {
		t.Fatalf("a released id is processed again: %+v %v", third, err)
	}
}

func TestVerifyAndDedupeRejectsUnverifiedWithoutTouchingStore(t *testing.T) {
	now := time.Now()
	store := NewMemoryWebhookStore()
	opts := VerifyAndDedupeOptions{Secret: "whsec_test", Store: store, Verify: &WebhookVerifyOptions{Now: now}}
	h := dedupeSignedRequest("whsec_other", "dlv_2", now, dedupeBody)
	_, err := VerifyAndDedupe(context.Background(), []byte(dedupeBody), h, opts)
	var verr *WebhookVerificationError
	if !errors.As(err, &verr) || verr.Reason != "signature_mismatch" || !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Fatalf("want signature_mismatch, got %v", err)
	}
	fresh, _ := store.SetIfAbsent(context.Background(), "atlas-webhook:dlv_2", time.Minute)
	if !fresh {
		t.Fatal("an unverified delivery must not be remembered")
	}
}

func TestMemoryWebhookStoreExpires(t *testing.T) {
	clock := time.Unix(1000, 0)
	s := NewMemoryWebhookStore()
	s.Now = func() time.Time { return clock }
	ctx := context.Background()
	if ok, _ := s.SetIfAbsent(ctx, "k", time.Second); !ok {
		t.Fatal("first claim")
	}
	if ok, _ := s.SetIfAbsent(ctx, "k", time.Second); ok {
		t.Fatal("second claim inside ttl")
	}
	clock = clock.Add(2 * time.Second)
	if ok, _ := s.SetIfAbsent(ctx, "k", time.Second); !ok {
		t.Fatal("claim after expiry")
	}
}

func TestWebhookDedupeHandler(t *testing.T) {
	now := time.Now()
	calls := 0
	failNext := false
	opts := VerifyAndDedupeOptions{Secret: "whsec_test", Store: NewMemoryWebhookStore(), Verify: &WebhookVerifyOptions{Now: now}}
	handler := WebhookDedupeHandler(opts, func(_ context.Context, _ *WebhookEvent) error {
		calls++
		if failNext {
			return errors.New("boom")
		}
		return nil
	})
	post := func(id string) int {
		req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(dedupeBody))
		req.Header = dedupeSignedRequest("whsec_test", id, now, dedupeBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if post("dlv_a") != 200 || post("dlv_a") != 200 || calls != 1 {
		t.Fatalf("a retried delivery runs the handler once, calls=%d", calls)
	}
	failNext = true
	if post("dlv_b") != 500 {
		t.Fatal("a failing handler answers 500")
	}
	failNext = false
	if post("dlv_b") != 200 || calls != 3 {
		t.Fatalf("a failed delivery is released so the retry runs again, calls=%d", calls)
	}
	bad := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(dedupeBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bad)
	if rec.Code != 400 {
		t.Fatalf("an unsigned delivery answers 400, got %d", rec.Code)
	}
}
