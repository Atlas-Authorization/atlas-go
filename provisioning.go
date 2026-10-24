package atlas

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ProvisioningFields are the provisioning fields every tagged resource
// (platform apps, instances, secret keys, OAuth clients, webhook endpoints,
// Sign in with Atlas apps, integrations) carries in a response. Embed it in a
// response struct; the JSON fields flatten.
type ProvisioningFields struct {
	// Metadata is the provisioning tag bag (strings, numbers and booleans).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// ExternalRef is your idempotent-create key. A repeat create with the same
	// ref returns the existing object (200, no secret).
	ExternalRef *string `json:"external_ref,omitempty"`
	// IdempotentReplay is true on a create that sent a ref and got the
	// existing object back.
	IdempotentReplay bool `json:"idempotent_replay,omitempty"`
}

// ProvisioningInput are the create-body fields any provisioning create
// accepts. Embed it in a params struct; the JSON fields flatten.
type ProvisioningInput struct {
	// Metadata tags the resource. Values are strings, numbers or booleans.
	// On a PATCH it replaces the tags.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// ExternalRef is a stable key of your own: a repeat create with it returns
	// the existing object instead of creating another one.
	ExternalRef string `json:"external_ref,omitempty"`
}

// MetadataQuery turns a metadata filter into the `metadata[key]=value` query
// parameters the provisioning lists accept. Keys are sorted for stable URLs.
func MetadataQuery(filter map[string]interface{}) url.Values {
	v := url.Values{}
	keys := make([]string, 0, len(filter))
	for k := range filter {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v.Set("metadata["+k+"]", fmt.Sprint(filter[k]))
	}
	return v
}

// DryRunChange is one change a write would make (config-changelog shape).
type DryRunChange struct {
	Section string      `json:"section"`
	Before  interface{} `json:"before"`
	After   interface{} `json:"after"`
}

// DryRunResult is what a write answers with `?dry_run=true`: the changes it
// would make, nothing changed.
type DryRunResult struct {
	Object string `json:"object"`
	DryRun bool   `json:"dry_run"`
	// Mode is "native" (the endpoint validated in full) or "plan" (the body
	// diffed over the current object, unvalidated).
	Mode        string         `json:"mode"`
	Validated   bool           `json:"validated"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	Changes     []DryRunChange `json:"changes"`
	WouldReturn interface{}    `json:"would_return,omitempty"`
	Note        string         `json:"note"`
}

// WithDryRun marks one write (POST, PUT, PATCH, DELETE) as a dry run: it is
// sent with `?dry_run=true`, Atlas validates it and answers with the changes
// it would make without changing anything. The typed result of a method called
// with this option is mostly empty; use Client.DryRun to get a DryRunResult.
// The Idempotency-Key is not sent on a dry run.
func WithDryRun() RequestOption {
	return func(rc *requestConfig) { rc.dryRun = true }
}

// DryRun sends one write as a dry run and returns the plan. method is POST,
// PUT, PATCH or DELETE; body may be nil.
//
//	plan, err := c.DryRun(ctx, "PATCH", "/v1/platform/apps/ins_1", map[string]any{"name": "New"})
func (c *Client) DryRun(ctx context.Context, method, path string, body interface{}, opts ...RequestOption) (*DryRunResult, error) {
	out := &DryRunResult{}
	all := append([]RequestOption{WithDryRun()}, opts...)
	return out, c.do(ctx, strings.ToUpper(method), path, nil, body, out, all...)
}

// ---- trace context -----------------------------------------------------------

var traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

// WithTraceparent sends a W3C `traceparent` header on one call, so Atlas
// stores the trace id on webhook deliveries, back-channel deliveries,
// referral calls and the executor requests it triggers. Use NewTraceparent to
// mint one.
func WithTraceparent(traceparent string) RequestOption {
	return func(rc *requestConfig) { rc.traceparent = traceparent }
}

// NewTraceparent mints a fresh sampled W3C traceparent
// (`00-<32 hex>-<16 hex>-01`).
func NewTraceparent() string {
	var buf [24]byte
	_, _ = rand.Read(buf[:])
	// All-zero ids are invalid; nudge the last byte of each.
	if allZero(buf[:16]) {
		buf[15] = 1
	}
	if allZero(buf[16:]) {
		buf[23] = 1
	}
	return "00-" + hex.EncodeToString(buf[:16]) + "-" + hex.EncodeToString(buf[16:]) + "-01"
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ParseTraceparent returns the trace id, span id and flags of a W3C
// traceparent, or ok=false when it is malformed.
func ParseTraceparent(traceparent string) (traceID, spanID, flags string, ok bool) {
	m := traceparentPattern.FindStringSubmatch(strings.TrimSpace(strings.ToLower(traceparent)))
	if m == nil || m[1] == strings.Repeat("0", 32) || m[2] == strings.Repeat("0", 16) {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// TraceparentFromHeader reads the traceparent Atlas sent (an executor or
// orchestrator receiver), returning "" when absent or malformed.
func TraceparentFromHeader(h http.Header) string {
	v := strings.TrimSpace(h.Get("traceparent"))
	if _, _, _, ok := ParseTraceparent(v); ok {
		return v
	}
	return ""
}

// WithSecretRecipient seals every shown-once secret in a response to the given
// recipient (`x25519:<base64 public key>`, see GenerateSealKeyPair): responses
// then carry `sealed_secret` fields instead of plaintext. Open them with
// OpenSealedSecret.
func WithSecretRecipient(recipient string) Option {
	return func(c *Client) { c.secretRecipient = recipient }
}

// jsonUnmarshal is encoding/json.Unmarshal, for files that need one decode.
func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
