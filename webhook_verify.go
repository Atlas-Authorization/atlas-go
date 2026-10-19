package atlas

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verifying inbound webhooks, for the customer consuming events.
//
// Atlas signs every delivery: the atlas-signature header is "v1,<base64>", an
// HMAC-SHA256 over "<id>.<timestamp>.<raw body>" keyed with the endpoint
// secret (whsec_...), sent with atlas-id and atlas-timestamp (epoch ms). A
// delivery more than five minutes from now, in either direction, is refused.
// Verify the RAW body, before any JSON decode. Matches verifyWebhook in
// @atlasauth/backend.

// Webhook header names (matched case-insensitively).
const (
	WebhookHeaderID        = "Atlas-Id"
	WebhookHeaderTimestamp = "Atlas-Timestamp"
	WebhookHeaderSignature = "Atlas-Signature"
)

// WebhookReplayTolerance is the default accepted clock distance of a delivery.
const WebhookReplayTolerance = 5 * time.Minute

// Errors returned by VerifyWebhook.
var (
	ErrWebhookMissingHeaders     = errors.New("atlas webhook: missing one of the atlas-id/atlas-timestamp/atlas-signature headers")
	ErrWebhookMalformedSignature = errors.New("atlas webhook: malformed signature header")
	ErrWebhookStaleTimestamp     = errors.New("atlas webhook: stale or invalid timestamp")
	ErrWebhookSignatureMismatch  = errors.New("atlas webhook: signature mismatch")
)

// WebhookEvent is the envelope of every delivery.
type WebhookEvent struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Timestamp  int64           `json:"timestamp"`
	InstanceID string          `json:"instance_id"`
	Data       json.RawMessage `json:"data"`
}

// VerifiedWebhook is a delivery whose signature and timestamp checked out.
type VerifiedWebhook struct {
	// Event is the parsed envelope (nil if the body was not a JSON object).
	Event *WebhookEvent
	// DeliveryID is the signed atlas-id header. It is the same on every retry of
	// one event, so it is the key to deduplicate deliveries on.
	DeliveryID string
	// Timestamp is the signed atlas-timestamp header (epoch ms) of this attempt.
	Timestamp int64
}

// WebhookVerifyOptions tunes VerifyWebhook. The zero value uses the defaults.
type WebhookVerifyOptions struct {
	// Now overrides the current time (tests).
	Now time.Time
	// Tolerance overrides WebhookReplayTolerance.
	Tolerance time.Duration
}

// VerifyWebhook verifies and parses an Atlas webhook delivery.
//
//	body, _ := io.ReadAll(r.Body)
//	hook, err := atlas.VerifyWebhook(body, r.Header, secret, nil)
//	if err != nil { w.WriteHeader(400); return }
//	if seen(hook.DeliveryID) { w.WriteHeader(200); return } // a retry already handled
func VerifyWebhook(body []byte, header http.Header, secret string, opts *WebhookVerifyOptions) (*VerifiedWebhook, error) {
	id := header.Get(WebhookHeaderID)
	tsRaw := header.Get(WebhookHeaderTimestamp)
	sig := header.Get(WebhookHeaderSignature)
	if id == "" || tsRaw == "" || sig == "" {
		return nil, ErrWebhookMissingHeaders
	}
	version, provided, ok := strings.Cut(sig, ",")
	if !ok || version != "v1" || provided == "" {
		return nil, ErrWebhookMalformedSignature
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tsRaw), 10, 64)
	if err != nil {
		return nil, ErrWebhookStaleTimestamp
	}
	now := time.Now()
	tolerance := WebhookReplayTolerance
	if opts != nil {
		if !opts.Now.IsZero() {
			now = opts.Now
		}
		if opts.Tolerance > 0 {
			tolerance = opts.Tolerance
		}
	}
	diff := now.UnixMilli() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance.Milliseconds() {
		return nil, ErrWebhookStaleTimestamp
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return nil, ErrWebhookSignatureMismatch
	}

	out := &VerifiedWebhook{DeliveryID: id, Timestamp: ts}
	var event WebhookEvent
	if json.Unmarshal(body, &event) == nil {
		out.Event = &event
	}
	return out, nil
}
