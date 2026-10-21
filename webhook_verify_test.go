package atlas

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const testWebhookSecret = "whsec_test_secret"

func signWebhook(id string, ts int64, body, secret string) http.Header {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + body))
	h := http.Header{}
	h.Set("atlas-id", id)
	h.Set("atlas-timestamp", strconv.FormatInt(ts, 10))
	h.Set("atlas-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return h
}

func TestVerifyWebhookReturnsDeliveryIDAndTimestamp(t *testing.T) {
	now := time.UnixMilli(1_757_937_600_000)
	body := `{"id":"evt_1","type":"user.updated","data":{"id":"user_1"}}`
	ts := now.UnixMilli() - 1000
	hook, err := VerifyWebhook([]byte(body), signWebhook("evt_1", ts, body, testWebhookSecret), testWebhookSecret, &WebhookVerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if hook.DeliveryID != "evt_1" || hook.Timestamp != ts {
		t.Fatalf("got %q %d", hook.DeliveryID, hook.Timestamp)
	}
	if hook.Event == nil || hook.Event.Type != "user.updated" {
		t.Fatalf("event %+v", hook.Event)
	}
}

func TestVerifyWebhookRejects(t *testing.T) {
	now := time.UnixMilli(1_757_937_600_000)
	body := `{"id":"evt_1"}`
	opts := &WebhookVerifyOptions{Now: now}
	cases := []struct {
		name   string
		body   string
		header http.Header
		want   error
	}{
		{"tampered", `{"id":"evt_2"}`, signWebhook("evt_1", now.UnixMilli(), body, testWebhookSecret), ErrWebhookSignatureMismatch},
		{"wrong secret", body, signWebhook("evt_1", now.UnixMilli(), body, "whsec_other"), ErrWebhookSignatureMismatch},
		{"stale", body, signWebhook("evt_1", now.UnixMilli()-6*60_000, body, testWebhookSecret), ErrWebhookStaleTimestamp},
		{"future", body, signWebhook("evt_1", now.UnixMilli()+6*60_000, body, testWebhookSecret), ErrWebhookStaleTimestamp},
		{"missing", body, http.Header{}, ErrWebhookMissingHeaders},
	}
	for _, c := range cases {
		if _, err := VerifyWebhook([]byte(c.body), c.header, testWebhookSecret, opts); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	bad := signWebhook("evt_1", now.UnixMilli(), body, testWebhookSecret)
	bad.Set("atlas-signature", "v2,abc")
	if _, err := VerifyWebhook([]byte(body), bad, testWebhookSecret, opts); !errors.Is(err, ErrWebhookMalformedSignature) {
		t.Errorf("malformed: %v", err)
	}
}

func TestVerifyWebhookSeveralSignatures(t *testing.T) {
	now := time.UnixMilli(1_757_937_600_000)
	body := `{"id":"evt_1","type":"user.updated"}`
	opts := &WebhookVerifyOptions{Now: now}
	h := signWebhook("evt_1", now.UnixMilli(), body, testWebhookSecret)
	fresh := h.Get("atlas-signature")
	stale := signWebhook("evt_1", now.UnixMilli(), body, "whsec_old_secret").Get("atlas-signature")
	for _, value := range []string{stale + " " + fresh, fresh + " " + stale, "v2,abc " + fresh} {
		h.Set("atlas-signature", value)
		if _, err := VerifyWebhook([]byte(body), h, testWebhookSecret, opts); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	h.Set("atlas-signature", stale+" "+stale)
	if _, err := VerifyWebhook([]byte(body), h, testWebhookSecret, opts); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("only stale: %v", err)
	}
	h.Set("atlas-signature", "v2,abc v0,def")
	if _, err := VerifyWebhook([]byte(body), h, testWebhookSecret, opts); !errors.Is(err, ErrWebhookMalformedSignature) {
		t.Errorf("no v1: %v", err)
	}
}
