package atlas

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Vectors computed with verifyPolicyFeedRequest / signPolicySourceEvent from
// @atlasauth/backend.
const (
	polSecret   = "whsec_policy_source_test_secret"
	polNowMS    = int64(1_800_000_000_000)
	polSigKey   = "veZ8K1cchaPsRfu/JPTU6fBWAsbUn/e/iaGPyP9nFoU="
	polSigAll   = "yJ3sPsHcT6fbi40UVNPScqsB9/5UomhRMTD/VcpNlWA="
	polSigEvent = "m2QmhSM8RGmN8j3QS0wyVr1kqaHmykmswSug5wyHaVU="
)

func polHeaders(sig, id, ts string) http.Header {
	h := http.Header{}
	h.Set("Atlas-Id", id)
	h.Set("Atlas-Timestamp", ts)
	h.Set("Atlas-Signature", sig)
	h.Set("Atlas-Policies-Version", PolicySourceProtocolVersion)
	return h
}

func TestPoliciesSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"policy","id":"pol_1","key":"tos","data":[],"has_more":false,"deleted":true,"retired":false}`)

	if _, err := c.Policies.List(ctx, true); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/policies")
	if rec.Query != "include_retired=true" {
		t.Errorf("query = %q", rec.Query)
	}
	required := true
	days := 14
	_, _ = c.Policies.Create(ctx, CreatePolicyParams{Key: "tos", Title: "Terms", Required: &required, Reaccept: PolicyReacceptGrace, GraceDays: &days})
	rec.expect(t, "POST", "/v1/policies")
	if rec.Body["key"] != "tos" || rec.Body["reaccept"] != "grace" || rec.Body["grace_days"] != 14.0 || rec.Body["required"] != true {
		t.Errorf("Create body = %v", rec.Body)
	}
	_, _ = c.Policies.Get(ctx, "tos")
	rec.expect(t, "GET", "/v1/policies/tos")
	_, _ = c.Policies.Update(ctx, "tos", UpdatePolicyParams{Status: "retired", ClearGraceDays: true})
	rec.expect(t, "PATCH", "/v1/policies/tos")
	if v, ok := rec.Body["grace_days"]; !ok || v != nil || rec.Body["status"] != "retired" {
		t.Errorf("Update body = %s", rec.RawBody)
	}
	del, err := c.Policies.Delete(ctx, "tos")
	rec.expect(t, "DELETE", "/v1/policies/tos")
	if err != nil || !del.Deleted {
		t.Errorf("Delete = %+v, %v", del, err)
	}
	_, _ = c.Policies.ListAcceptances(ctx, "tos", ListPolicyAcceptancesParams{Version: "v2", Status: "all", Limit: 5})
	rec.expect(t, "GET", "/v1/policies/tos/acceptances")
	for _, want := range []string{"version=v2", "status=all", "limit=5"} {
		if !strings.Contains(rec.Query, want) {
			t.Errorf("acceptances query %q lacks %s", rec.Query, want)
		}
	}
	_, _ = c.Policies.ForUser(ctx, "user_1")
	rec.expect(t, "GET", "/v1/users/user_1/policies")
}

func TestPolicyVersionsAndSettingsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"policy_version","id":"polv_1","data":[],"session_claim":true}`)

	_, _ = c.Policies.Versions.List(ctx, "tos")
	rec.expect(t, "GET", "/v1/policies/tos/versions")
	_, _ = c.Policies.Versions.Create(ctx, "tos", CreatePolicyVersionParams{Version: "v2", ContentMarkdown: "# Terms", Publish: true, EffectiveAt: int64(1800000000000)})
	rec.expect(t, "POST", "/v1/policies/tos/versions")
	if rec.Body["version"] != "v2" || rec.Body["publish"] != true || rec.Body["effective_at"] != 1.8e12 {
		t.Errorf("Create version body = %v", rec.Body)
	}
	_, _ = c.Policies.Versions.Get(ctx, "tos", "v2")
	rec.expect(t, "GET", "/v1/policies/tos/versions/v2")
	_, _ = c.Policies.Versions.Update(ctx, "tos", "v2", UpdatePolicyVersionParams{ContentHTML: "<p>x</p>", ClearSummaryOfChanges: true})
	rec.expect(t, "PATCH", "/v1/policies/tos/versions/v2")
	if v, ok := rec.Body["summary_of_changes"]; !ok || v != nil || rec.Body["content_html"] != "<p>x</p>" {
		t.Errorf("Update version body = %s", rec.RawBody)
	}
	_, _ = c.Policies.Versions.Delete(ctx, "tos", "v2")
	rec.expect(t, "DELETE", "/v1/policies/tos/versions/v2")
	_, _ = c.Policies.Versions.Publish(ctx, "tos", "v2", PublishPolicyVersionParams{EffectiveAt: "2026-11-01T00:00:00Z"})
	rec.expect(t, "POST", "/v1/policies/tos/versions/v2/publish")
	if rec.Body["effective_at"] != "2026-11-01T00:00:00Z" {
		t.Errorf("publish body = %v", rec.Body)
	}
	_, _ = c.Policies.Versions.Publish(ctx, "tos", "v 2/x", PublishPolicyVersionParams{})
	if rec.RawBody != "{}" {
		t.Errorf("empty publish body = %q", rec.RawBody)
	}
	_, _ = c.Policies.Versions.Retire(ctx, "tos", "v2")
	rec.expect(t, "POST", "/v1/policies/tos/versions/v2/retire")

	set, _ := c.Policies.Settings.Get(ctx)
	rec.expect(t, "GET", "/v1/instance/policy_settings")
	if !set.SessionClaim {
		t.Errorf("settings = %+v", set)
	}
	on := true
	_, _ = c.Policies.Settings.Update(ctx, UpdatePolicySettingsParams{SessionClaim: &on})
	rec.expect(t, "PATCH", "/v1/instance/policy_settings")
	if rec.Body["session_claim"] != true {
		t.Errorf("settings body = %v", rec.Body)
	}
}

func TestExportAcceptancesCSV(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies/tos/acceptances" || r.URL.Query().Get("format") != "csv" || r.URL.Query().Get("limit") != "" {
			t.Errorf("request = %s", r.URL.String())
		}
		_, _ = w.Write([]byte("user_id,policy\nu_1,tos\n"))
	})
	out, err := c.Policies.ExportAcceptancesCSV(context.Background(), "tos", ListPolicyAcceptancesParams{Limit: 9, Status: "accepted"})
	if err != nil || string(out) != "user_id,policy\nu_1,tos\n" {
		t.Fatalf("csv = %q, %v", out, err)
	}
}

func TestPolicySourceSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"policy_source","enabled":true,"endpoint_url":"https://cms.test","signing_secret_set":true,"sync":"webhook","poll_interval_minutes":60,"webhook_url":"https://api/hook","protocol_version":"2026-10-24","last_synced_at":null,"last_sync_ok":null,"last_sync_error":null,"next_poll_at":null,"ok":true,"data":[]}`)

	src, err := c.PolicySource.Get(ctx)
	rec.expect(t, "GET", "/v1/instance/policy_source")
	if err != nil || !src.SigningSecretSet || src.WebhookURL == nil || *src.WebhookURL != "https://api/hook" {
		t.Fatalf("Get = %+v, %v", src, err)
	}
	on := true
	_, _ = c.PolicySource.Update(ctx, UpdatePolicySourceParams{Enabled: &on, EndpointURL: "https://cms.test", SigningSecret: strings.Repeat("s", 20), Clear: []string{"unused"}})
	rec.expect(t, "PUT", "/v1/instance/policy_source")
	if rec.Body["enabled"] != true || rec.Body["signing_secret"] == nil {
		t.Errorf("Update body = %v", rec.Body)
	}
	if v, ok := rec.Body["unused"]; !ok || v != nil {
		t.Errorf("Clear should send null: %s", rec.RawBody)
	}
	_, _ = c.PolicySource.Delete(ctx)
	rec.expect(t, "DELETE", "/v1/instance/policy_source")
	if r, _ := c.PolicySource.Test(ctx); r == nil || !r.OK {
		t.Errorf("Test = %+v", r)
	}
	rec.expect(t, "POST", "/v1/instance/policy_source/test")
	_, _ = c.PolicySource.Sync(ctx)
	rec.expect(t, "POST", "/v1/instance/policy_source/sync")
	_, _ = c.PolicySource.ListDeliveries(ctx, ListPolicySourceDeliveriesParams{Kind: "fetch", Status: "failed", Limit: 2})
	rec.expect(t, "GET", "/v1/instance/policy_source/deliveries")
	for _, want := range []string{"kind=fetch", "status=failed", "limit=2"} {
		if !strings.Contains(rec.Query, want) {
			t.Errorf("deliveries query %q lacks %s", rec.Query, want)
		}
	}
}

func TestConsentEvidenceFields(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"consent","id":"con_1","policy":"tos","version":"v2","status":"accepted","source":null,"created_at":1,"policy_version_id":"polv_1","content_sha256":"ab","display":"scroll","scrolled_to_end":true,"view_ms":1200,"locale":"en"}`)
	yes := true
	ms := int64(1200)
	got, err := c.Users.RecordConsent(context.Background(), "user_1", RecordConsentParams{Policy: "tos", Version: "v2", PolicyVersionID: "polv_1", ContentSHA256: "ab", Display: "scroll", ScrolledToEnd: &yes, ViewMS: &ms, Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Body["policy_version_id"] != "polv_1" || rec.Body["scrolled_to_end"] != true || rec.Body["view_ms"] != 1200.0 || rec.Body["display"] != "scroll" {
		t.Errorf("body = %v", rec.Body)
	}
	if got.PolicyVersionID == nil || *got.PolicyVersionID != "polv_1" || got.ViewMS == nil || *got.ViewMS != 1200 || got.ScrolledToEnd == nil || !*got.ScrolledToEnd {
		t.Errorf("consent = %+v", got)
	}
}

func TestPolicyEventConstantsAndPolClaim(t *testing.T) {
	if WebhookEventUserPolicyAccepted != "user.policy_accepted" || WebhookEventPolicyVersionPublished != "policy.version_published" {
		t.Error("event constants")
	}
	claims := &SessionClaims{Raw: map[string]interface{}{"pol": map[string]interface{}{"tos": "2026-10-24", "privacy": 3.0, "bad": true}}}
	got := claims.Policies()
	if len(got) != 2 || got["tos"] != "2026-10-24" || got["privacy"] != "3" {
		t.Errorf("Policies = %v", got)
	}
	if v, ok := claims.AcceptedPolicyVersion("tos"); !ok || v != "2026-10-24" {
		t.Error("AcceptedPolicyVersion")
	}
	if _, ok := claims.AcceptedPolicyVersion("nope"); ok {
		t.Error("unknown policy")
	}
	if len((&SessionClaims{}).Policies()) != 0 {
		t.Error("no claim")
	}
}

func TestVerifyPolicyFeedRequestMatchesTypeScriptVectors(t *testing.T) {
	now := time.UnixMilli(polNowMS + 1000)
	opts := &PolicyFeedVerifyOptions{Now: now}
	req, err := VerifyPolicyFeedRequest("GET", "/atlas/policies?key=tos", polHeaders("v1,"+polSigKey, "evt_feed_1", "1800000000000"), polSecret, opts)
	if err != nil || req.Key != "tos" || req.DeliveryID != "evt_feed_1" || req.Timestamp != polNowMS || req.ProtocolVersion != PolicySourceProtocolVersion {
		t.Fatalf("keyed = %+v, %v", req, err)
	}
	req, err = VerifyPolicyFeedRequest("", "/atlas/policies", polHeaders("v1,"+polSigAll, "evt_feed_2", "1800000000000"), polSecret, opts)
	if err != nil || req.Key != "" {
		t.Fatalf("full = %+v, %v", req, err)
	}
	// several v1 values, one of them right; other versions skipped
	_, err = VerifyPolicyFeedRequest("get", "/atlas/policies?key=tos", polHeaders("v1,AAAA v2,zzzz v1,"+polSigKey, "evt_feed_1", "1800000000000"), polSecret, opts)
	if err != nil {
		t.Errorf("multiple signatures: %v", err)
	}
}

func TestVerifyPolicyFeedRequestRefusals(t *testing.T) {
	at := func(d int64) *PolicyFeedVerifyOptions {
		return &PolicyFeedVerifyOptions{Now: time.UnixMilli(polNowMS + d)}
	}
	good := polHeaders("v1,"+polSigKey, "evt_feed_1", "1800000000000")
	cases := []struct {
		name   string
		method string
		path   string
		h      http.Header
		opts   *PolicyFeedVerifyOptions
		secret string
		want   error
	}{
		{"missing headers", "GET", "/atlas/policies?key=tos", http.Header{}, at(0), polSecret, ErrPolicyFeedMissingHeaders},
		{"not v1", "GET", "/atlas/policies?key=tos", polHeaders("v2,abc", "evt_feed_1", "1800000000000"), at(0), polSecret, ErrPolicyFeedMalformedSig},
		{"stale future", "GET", "/atlas/policies?key=tos", good, at(300_001), polSecret, ErrPolicyFeedStaleTimestamp},
		{"stale past", "GET", "/atlas/policies?key=tos", good, at(-300_001), polSecret, ErrPolicyFeedStaleTimestamp},
		{"bad timestamp", "GET", "/atlas/policies?key=tos", polHeaders("v1,"+polSigKey, "evt_feed_1", "nope"), at(0), polSecret, ErrPolicyFeedStaleTimestamp},
		{"other path", "GET", "/atlas/policies?key=privacy", good, at(0), polSecret, ErrPolicyFeedSignatureMismatch},
		{"other secret", "GET", "/atlas/policies?key=tos", good, at(0), "other", ErrPolicyFeedSignatureMismatch},
		{"not base64", "GET", "/atlas/policies?key=tos", polHeaders("v1,!!!!", "evt_feed_1", "1800000000000"), at(0), polSecret, ErrPolicyFeedSignatureMismatch},
		{"wrong method", "POST", "/atlas/policies?key=tos", good, at(0), polSecret, ErrPolicyFeedWrongMethod},
	}
	for _, tc := range cases {
		if _, err := VerifyPolicyFeedRequest(tc.method, tc.path, tc.h, tc.secret, tc.opts); err != tc.want {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// the tolerance edge is inclusive
	if _, err := VerifyPolicyFeedRequest("GET", "/atlas/policies?key=tos", good, polSecret, at(300_000)); err != nil {
		t.Errorf("edge: %v", err)
	}
}

func TestSignPolicySourceEventMatchesTypeScriptVector(t *testing.T) {
	e, err := SignPolicySourceEvent(PolicySourceEvent{Type: PolicySourceEventPublished, Key: "tos", Version: "2026-10-24", OccurredAt: "2026-10-24T00:00:00.000Z"},
		polSecret, &PolicySourceEventOptions{ID: "evt_out_1", Now: time.UnixMilli(polNowMS + 123)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"occurred_at":"2026-10-24T00:00:00.000Z","type":"policy.published","key":"tos","version":"2026-10-24"}`
	if string(e.Body) != want {
		t.Errorf("body = %s", e.Body)
	}
	if e.Header.Get("Atlas-Id") != "evt_out_1" || e.Header.Get("Atlas-Timestamp") != "1800000000123" || e.Header.Get("Atlas-Signature") != "v1,"+polSigEvent {
		t.Errorf("headers = %v", e.Header)
	}
	req, err := e.Request(context.Background(), "https://api.example.test/v1/webhooks/policies/ins_1")
	if err != nil || req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request = %+v, %v", req, err)
	}
}

func TestSignPolicySourceEventDefaultsAndValidation(t *testing.T) {
	e, err := SignPolicySourceEvent(PolicySourceEvent{Type: PolicySourceEventRetired, Key: "tos"}, polSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if json.Unmarshal(e.Body, &body) != nil || body["type"] != "policy.retired" || body["key"] != "tos" || !strings.HasSuffix(body["occurred_at"].(string), "Z") {
		t.Errorf("body = %s", e.Body)
	}
	if _, has := body["version"]; has || !strings.HasPrefix(e.Header.Get("Atlas-Id"), "evt_") {
		t.Errorf("retired event = %s %v", e.Body, e.Header)
	}
	if _, err := SignPolicySourceEvent(PolicySourceEvent{Type: PolicySourceEventPublished, Key: "tos"}, polSecret, nil); err == nil {
		t.Error("published without a version should fail")
	}
	if _, err := SignPolicySourceEvent(PolicySourceEvent{Type: "policy.deleted", Key: "tos"}, polSecret, nil); err == nil {
		t.Error("unknown type should fail")
	}
}

func TestPolicyFeedHandler(t *testing.T) {
	var gotKey string
	h := PolicyFeedHandler(polSecret, func(_ context.Context, key string) (PolicyFeed, error) {
		gotKey = key
		return NewPolicyFeed(PolicyFeedPolicy{Key: "tos", Title: "Terms", Versions: []PolicyFeedVersion{{Version: "v1", ContentMarkdown: "# T"}}}), nil
	})
	// a live request signed now, the way Atlas does it
	ts := time.Now().UnixMilli()
	tsStr := strconvItoa(ts)
	path := "/atlas/policies?key=tos"
	sig := "v1," + base64.StdEncoding.EncodeToString(policyMAC(polSecret, "evt_h", tsStr, "GET\n"+path))
	req := httptest.NewRequest("GET", path, nil)
	req.Header = polHeaders(sig, "evt_h", tsStr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || gotKey != "tos" || !strings.Contains(rr.Body.String(), `"object":"policy_list"`) {
		t.Fatalf("handler = %d %s (key %q)", rr.Code, rr.Body.String(), gotKey)
	}
	bad := httptest.NewRequest("GET", path, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, bad)
	if rr.Code != 401 {
		t.Errorf("unsigned = %d", rr.Code)
	}
}

func strconvItoa(n int64) string { return strconv.FormatInt(n, 10) }
