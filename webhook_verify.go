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
// The header may carry several space-separated "v1,<base64>" entries (one per
// secret while a secret rotates with an overlap); the delivery verifies when
// any one matches. Verify the RAW body, before any JSON decode. Matches verifyWebhook in
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
	provided := webhookSignatures(sig)
	if len(provided) == 0 {
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
	// Compare every entry (no early exit), each in constant time.
	matched := false
	for _, candidate := range provided {
		if hmac.Equal([]byte(expected), []byte(candidate)) {
			matched = true
		}
	}
	if !matched {
		return nil, ErrWebhookSignatureMismatch
	}

	out := &VerifiedWebhook{DeliveryID: id, Timestamp: ts}
	var event WebhookEvent
	if json.Unmarshal(body, &event) == nil {
		out.Event = &event
	}
	return out, nil
}

// Standard Webhooks header names, for application webhooks (matched
// case-insensitively).
const (
	StandardWebhookHeaderID        = "Webhook-Id"
	StandardWebhookHeaderTimestamp = "Webhook-Timestamp"
	StandardWebhookHeaderSignature = "Webhook-Signature"
)

// ErrWebhookInvalidSecret is returned by VerifyStandardWebhook when the
// secret is not whsec_<base64>.
var ErrWebhookInvalidSecret = errors.New("atlas webhook: secret is not whsec_<base64>")

// VerifyStandardWebhook verifies an APPLICATION webhook (the events an app
// publishes to its customers' endpoints through AppEvents): Standard Webhooks.
// webhook-id, webhook-timestamp (decimal epoch SECONDS) and webhook-signature
// ("v1,<base64>", several space-separated during a secret rotation), an
// HMAC-SHA256 over "<id>.<timestamp>.<raw body>" keyed with the
// base64-decoded part of the whsec_ secret. Returns the same VerifiedWebhook
// as VerifyWebhook, with Timestamp in seconds. Matches verifyStandardWebhook
// in @atlasauth/backend.
func VerifyStandardWebhook(body []byte, header http.Header, secret string, opts *WebhookVerifyOptions) (*VerifiedWebhook, error) {
	id := header.Get(StandardWebhookHeaderID)
	tsRaw := strings.TrimSpace(header.Get(StandardWebhookHeaderTimestamp))
	sig := header.Get(StandardWebhookHeaderSignature)
	if id == "" || tsRaw == "" || sig == "" {
		return nil, ErrWebhookMissingHeaders
	}
	provided := webhookSignatures(sig)
	if len(provided) == 0 {
		return nil, ErrWebhookMalformedSignature
	}
	for _, r := range tsRaw {
		if r < '0' || r > '9' {
			return nil, ErrWebhookStaleTimestamp
		}
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
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
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(tolerance/time.Second) {
		return nil, ErrWebhookStaleTimestamp
	}
	// Padding optional, as in the Node verifier.
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(secret, "whsec_"), "="))
	if err != nil || len(key) == 0 {
		return nil, ErrWebhookInvalidSecret
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	// Compare every entry (no early exit), each in constant time.
	matched := false
	for _, candidate := range provided {
		if hmac.Equal([]byte(expected), []byte(candidate)) {
			matched = true
		}
	}
	if !matched {
		return nil, ErrWebhookSignatureMismatch
	}

	out := &VerifiedWebhook{DeliveryID: id, Timestamp: ts}
	var event WebhookEvent
	if json.Unmarshal(body, &event) == nil {
		out.Event = &event
	}
	return out, nil
}

// webhookSignatures returns the v1 signatures in an atlas-signature header: one
// "v1,<base64>" entry, or several separated by spaces (while an endpoint secret
// rotates, Atlas signs with the old and the new secret). Entries of another
// version are skipped.
func webhookSignatures(header string) []string {
	var out []string
	for _, entry := range strings.Fields(header) {
		version, value, ok := strings.Cut(entry, ",")
		if ok && version == "v1" && value != "" {
			out = append(out, value)
		}
	}
	return out
}
