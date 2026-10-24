package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const referralSettingsJSON = `{"object":"referral_settings","enabled":true,"provider":"webhook","endpoint_url":"https://referrals.example.com/atlas","program_id":null,"connection_id":null,"signing_secret_set":true,"api_key_set":false,"url_params":["ref","via","aff"],"context_cookie":null,"consent_category":"referrals","consent_fallback_category":"marketing","auto_enroll_users":true,"link_template":"https://app.example.com/join?ref={code}","timeout_ms":3000,"security":{"challenge_referred_signups":"always","on_high_risk":"flag","hold_until_email_verified":false,"max_referred_signups_per_ip_hour":5},"missing":[],"connection":{"last_test":{"ok":true,"at":1,"http_status":404,"error":null},"failed_calls_7d":0,"retrying_calls":0,"last_success_at":1},"providers":[{"id":"webhook","name":"Atlas referral protocol (any platform)","capabilities":{"signup":true,"erase":true,"export":true,"partner":true,"auto_enroll":true,"signal":true},"needs":["endpoint_url","signing_secret"],"default_context_cookie":null,"docs_url":null}],"updated_at":1}`

// TestReferralSettings covers get / update (with clears and nested security) / test.
func TestReferralSettings(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, referralSettingsJSON)

	view, err := c.Referrals.Get(ctx)
	if err != nil || !view.Enabled || view.Security.OnHighRisk != "flag" || !view.Providers[0].Capabilities.Signal || view.Connection.LastTest == nil || *view.Connection.LastTest.HTTPStatus != 404 {
		t.Fatalf("get = %+v, %v", view, err)
	}
	rec.expect(t, "GET", "/v1/instance/referrals")

	on := true
	hold := "hold"
	_, err = c.Referrals.Update(ctx, UpdateReferralSettingsParams{
		Enabled:       &on,
		SigningSecret: strings.Repeat("x", 32),
		Security:      &UpdateReferralSecurityParams{OnHighRisk: &hold},
		Clear:         []string{"link_template"},
	}, WithIdempotencyKey("idem-1"))
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PATCH", "/v1/instance/referrals")
	want := `{"enabled":true,"link_template":null,"security":{"on_high_risk":"hold"},"signing_secret":"` + strings.Repeat("x", 32) + `"}`
	if rec.RawBody != want {
		t.Errorf("update body = %s", rec.RawBody)
	}

	c, rec = recordingClient(t, `{"ok":false,"http_status":401,"latency_ms":12,"error":{"code":"signature_rejected","message":"m"}}`)
	res, err := c.Referrals.Test(ctx)
	if err != nil || res.OK || res.Error == nil || res.Error.Code != "signature_rejected" {
		t.Fatalf("test = %+v, %v", res, err)
	}
	rec.expect(t, "POST", "/v1/instance/referrals/test")
}

// TestReferralCalls covers the call log filters and a retry.
func TestReferralCalls(t *testing.T) {
	ctx := context.Background()
	call := `{"object":"referral_call","id":"rfc_1","kind":"signup","status":"succeeded","outcome":"referred","customer_ref":"user_1","user_id":"user_1","http_status":200,"last_error":null,"attempts":2,"next_attempt_at":null,"risk":{"level":"low","score":5,"signals":[],"captcha":"passed","emailVerified":true},"payload":{"customerRef":"user_1"},"created_at":1,"updated_at":2}`
	c, rec := recordingClient(t, `{"object":"list","data":[`+call+`],"has_more":false}`)
	page, err := c.Referrals.ListCalls(ctx, ListReferralCallsParams{Limit: 10, Status: "failed", Kind: "signup", UserID: "user_1"})
	if err != nil || len(page.Data) != 1 || page.Data[0].Risk == nil || !page.Data[0].Risk.EmailVerified {
		t.Fatalf("list = %+v, %v", page, err)
	}
	rec.expect(t, "GET", "/v1/instance/referrals/calls")
	q, _ := url.ParseQuery(rec.Query)
	if q.Get("limit") != "10" || q.Get("status") != "failed" || q.Get("kind") != "signup" || q.Get("user_id") != "user_1" {
		t.Errorf("query = %s", rec.Query)
	}
	_, _ = c.Referrals.ListCalls(ctx, ListReferralCallsParams{})
	if rec.Query != "" {
		t.Errorf("empty query = %s", rec.Query)
	}

	c, rec = recordingClient(t, call)
	out, err := c.Referrals.RetryCall(ctx, "rfc_1")
	if err != nil || out.Outcome == nil || *out.Outcome != "referred" {
		t.Fatalf("retry = %+v, %v", out, err)
	}
	rec.expect(t, "POST", "/v1/instance/referrals/calls/rfc_1/retry")
}

// TestUserReferralFields covers the user fields, create/update params and the flag.
func TestUserReferralFields(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"user","id":"user_1","referral":{"partner_id":"pn_1","referrer_external_id":"cust_9","referrer_user_id":"user_9","matched_via":"code","status":"lead","risk_level":"low","flagged":false},"referral_code":"ada-1","referral_link":"https://app.example.com/join?ref=ada-1"}`)

	u, err := c.Users.Create(ctx, CreateUserParams{EmailAddress: "a@example.com", Referral: &CreateUserReferral{Code: "ACME10", ClickID: "clk_123"}, ReferralCode: "ada-1"})
	if err != nil || u.Referral == nil || *u.Referral.ReferrerUserID != "user_9" || *u.ReferralLink != "https://app.example.com/join?ref=ada-1" {
		t.Fatalf("create = %+v, %v", u, err)
	}
	if rec.RawBody != `{"email_address":"a@example.com","referral":{"code":"ACME10","click_id":"clk_123"},"referral_code":"ada-1"}` {
		t.Errorf("create body = %s", rec.RawBody)
	}

	_, _ = c.Users.Update(ctx, "user_1", UpdateUserParams{ClearReferralCode: true})
	if rec.RawBody != `{"referral_code":null}` {
		t.Errorf("clear body = %s", rec.RawBody)
	}
	_, _ = c.Users.Update(ctx, "user_1", UpdateUserParams{FirstName: "Ada"})
	if rec.RawBody != `{"first_name":"Ada"}` {
		t.Errorf("plain update body = %s", rec.RawBody)
	}

	c, rec = recordingClient(t, `{"object":"user_referral","user_id":"user_1","status":"flagged","flagged":true,"flag_reason":"ring","flagged_at":5,"risk_level":"high"}`)
	f, err := c.Users.FlagReferral(ctx, "user_1", FlagReferralParams{Reason: "ring"})
	if err != nil || !f.Flagged || *f.FlaggedAt != 5 {
		t.Fatalf("flag = %+v, %v", f, err)
	}
	rec.expect(t, "POST", "/v1/users/user_1/referral/flag")
	if rec.RawBody != `{"reason":"ring"}` {
		t.Errorf("flag body = %s", rec.RawBody)
	}
}

// TestReferralCodeTaken surfaces the 409 code.
func TestReferralCodeTaken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"errors":[{"code":"REFERRAL_CODE_TAKEN","message":"taken","param":"referral_code"}]}`))
	})
	_, err := c.Users.Update(context.Background(), "user_1", UpdateUserParams{ReferralCode: "ada-1"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code() != ErrCodeReferralCodeTaken || ErrCodeReferralsNotConfigured != "REFERRALS_NOT_CONFIGURED" {
		t.Fatalf("err = %v", err)
	}
}

const referralSecret = "referral_signing_secret_0123456789"

var referralNow = time.UnixMilli(1792584000000)

func referralHeaders(id, body, secret string, ts int64) http.Header {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + body))
	h := http.Header{}
	h.Set("Atlas-Id", id)
	h.Set("Atlas-Timestamp", strconv.FormatInt(ts, 10))
	h.Set("Atlas-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	h.Set("Idempotency-Key", "signup:user_1")
	return h
}

func verifyRef(t *testing.T, body string, opts ReferralVerifyOptions) (*ReferralRequest, error) {
	t.Helper()
	opts.WebhookVerifyOptions = WebhookVerifyOptions{Now: referralNow}
	return VerifyReferralRequest([]byte(body), referralHeaders("rfc_1", body, referralSecret, referralNow.UnixMilli()), referralSecret, &opts)
}

// TestVerifyReferralRequest covers every protocol operation, the op/endpoint
// match and the refusals.
func TestVerifyReferralRequest(t *testing.T) {
	signup := `{"op":"signup","customerRef":"user_1","emailHash":null,"ip":"203.0.113.7","ua":"Mozilla/5.0","signedUpAt":"2026-10-21T11:59:00.000Z","programId":null,"autoEnroll":true,"referral":{"code":"ACME10","clickId":null,"anonId":null,"capturedAt":"2026-10-21T11:58:00.000Z","consent":"not_required"},"risk":{"level":"low","score":0,"signals":[],"captcha":"passed","emailVerified":false},"rejected":null}`
	req, err := verifyRef(t, signup, ReferralVerifyOptions{Path: "/atlas/signups"})
	if err != nil || req.Op != ReferralOpSignup || req.Signup == nil || *req.Signup.Referral.Code != "ACME10" || req.Signup.Risk.Captcha != "passed" || req.CustomerRef != "user_1" || req.DeliveryID != "rfc_1" || req.IdempotencyKey != "signup:user_1" {
		t.Fatalf("signup = %+v, %v", req, err)
	}

	exportTest := `{"op":"export","customerRef":"` + ReferralConnectionTestRef + `","test":true}`
	req, err = verifyRef(t, exportTest, ReferralVerifyOptions{Path: "https://referrals.example.com/atlas/export"})
	if err != nil || req.Op != ReferralOpExport || !req.Test || req.Export == nil || !req.Export.Test || req.CustomerRef != ReferralConnectionTestRef {
		t.Fatalf("test export = %+v, %v", req, err)
	}
	exportUser := `{"op":"export","customerRef":"user_1","test":false}`
	req, err = verifyRef(t, exportUser, ReferralVerifyOptions{Path: "/export"})
	if err != nil || req.Test || req.CustomerRef != "user_1" {
		t.Fatalf("export = %+v, %v", req, err)
	}

	erase := `{"op":"erase","customerRef":"user_1"}`
	req, err = verifyRef(t, erase, ReferralVerifyOptions{Path: "/erase"})
	if err != nil || req.Op != ReferralOpErase || req.Erase.CustomerRef != "user_1" {
		t.Fatalf("erase = %+v, %v", req, err)
	}
	partner := `{"op":"partner","customerRef":"user_1","code":"ada-1","emailHash":null}`
	req, err = verifyRef(t, partner, ReferralVerifyOptions{Path: "/atlas/partners/"})
	if err != nil || req.Op != ReferralOpPartner || req.CustomerRef != "user_1" || req.Partner.Code != "ada-1" {
		t.Fatalf("partner = %+v, %v", req, err)
	}
	signal := `{"op":"signal","customerRef":"user_1","type":"fraud_confirmed","occurredAt":"2026-10-21T12:00:00.000Z","data":{"reason":"ring"}}`
	req, err = verifyRef(t, signal, ReferralVerifyOptions{ExpectedOp: ReferralOpSignal})
	if err != nil || req.Op != ReferralOpSignal || req.Signal.Type != ReferralSignalFraudConfirmed {
		t.Fatalf("signal = %+v, %v", req, err)
	}
	// Neither path nor expected operation: the signed op decides.
	if req, err = VerifyReferralRequest([]byte(partner), referralHeaders("rfc_2", partner, referralSecret, referralNow.UnixMilli()), referralSecret, &ReferralVerifyOptions{WebhookVerifyOptions: WebhookVerifyOptions{Now: referralNow}}); err != nil || req.Op != ReferralOpPartner {
		t.Fatalf("no path = %+v, %v", req, err)
	}

	refusals := []struct {
		name string
		body string
		opts ReferralVerifyOptions
		want error
	}{
		{"export replayed on erase", exportUser, ReferralVerifyOptions{Path: "/atlas/erase"}, ErrReferralOpMismatch},
		{"signup replayed on partners", signup, ReferralVerifyOptions{Path: "/atlas/partners"}, ErrReferralOpMismatch},
		{"erase where export expected", erase, ReferralVerifyOptions{ExpectedOp: ReferralOpExport}, ErrReferralOpMismatch},
		{"path ok, expected op not", erase, ReferralVerifyOptions{Path: "/erase", ExpectedOp: ReferralOpSignal}, ErrReferralOpMismatch},
		{"old partners path", erase, ReferralVerifyOptions{Path: "/atlas/partners/user_1"}, ErrReferralUnknownEndpoint},
		{"foreign path", erase, ReferralVerifyOptions{Path: "/atlas/webhooks"}, ErrReferralUnknownEndpoint},
		{"no op", `{"customerRef":"user_1"}`, ReferralVerifyOptions{Path: "/erase"}, ErrReferralMissingOp},
		{"unknown op", `{"op":"delete"}`, ReferralVerifyOptions{Path: "/erase"}, ErrReferralUnknownOp},
		{"non-string op", `{"op":7}`, ReferralVerifyOptions{Path: "/erase"}, ErrReferralUnknownOp},
		{"empty body", ``, ReferralVerifyOptions{Path: "/export"}, ErrReferralMalformedBody},
		{"array body", `[1]`, ReferralVerifyOptions{Path: "/export"}, ErrReferralMalformedBody},
		{"wrong field type", `{"op":"erase","customerRef":7}`, ReferralVerifyOptions{Path: "/erase"}, ErrReferralMalformedBody},
	}
	for _, tc := range refusals {
		if _, err := verifyRef(t, tc.body, tc.opts); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	ts := referralNow.UnixMilli()
	opts := &ReferralVerifyOptions{WebhookVerifyOptions: WebhookVerifyOptions{Now: referralNow}}
	if _, err := VerifyReferralRequest([]byte(signup), referralHeaders("rfc_7", signup, "another_secret_0123456789", ts), referralSecret, opts); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("wrong secret = %v", err)
	}
	if _, err := VerifyReferralRequest([]byte(signup), referralHeaders("rfc_7", signup, referralSecret, ts-600000), referralSecret, opts); !errors.Is(err, ErrWebhookStaleTimestamp) {
		t.Errorf("stale = %v", err)
	}
	if _, err := VerifyReferralRequest([]byte(signup+" "), referralHeaders("rfc_7", signup, referralSecret, ts), referralSecret, opts); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("tampered = %v", err)
	}
}

// TestReferralOpForPath maps endpoint paths to operations.
func TestReferralOpForPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a/signups":                           ReferralOpSignup,
		"https://x.example.com/b/partners?x=1": ReferralOpPartner,
		"/signals/":                            ReferralOpSignal,
		"/nope":                                "",
	} {
		if got := ReferralOpForPath(in); got != want {
			t.Errorf("ReferralOpForPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReferralsV2 covers the v2 settings fields, the ping test, call-log
// paging, retry_failed, simulate, backfill and the per-user result.
func TestReferralsV2(t *testing.T) {
	ctx := context.Background()
	settings := `{"object":"referral_settings","enabled":true,"provider":"referalli","signing_secret_set":true,"api_key_set":false,"url_params":["ref"],"tracking_token":"tt_public_1","code_lookup_url":"https://referrals.example.com/lookup/{code}","signup_code_field":true,"forward_lifecycle":true,"mirror_to_public_metadata":false,"include_referral_claims":true,"connection":{"last_test":null,"last_ping":{"ok":true,"at":7,"http_status":200,"org_name":"Acme","server_time":"2026-10-21T12:00:00.000Z","clock_skew_ms":90000,"clock_skew_warning":true},"alert":{"code":"signature_rejected","message":"401","at":9,"call_id":"rfc_9"},"failed_calls_7d":1,"retrying_calls":0,"last_success_at":null},"providers":[{"id":"referalli","name":"Referalli","capabilities":{"signup":true,"erase":true,"export":true,"partner":true,"auto_enroll":true,"signal":true,"alias":true,"user":true,"ping":true},"needs":["endpoint_url","connection_id","signing_secret"],"default_context_cookie":"referalli_ctx","docs_url":null}]}`
	c, rec := recordingClient(t, settings)
	view, err := c.Referrals.Get(ctx)
	if err != nil || *view.TrackingToken != "tt_public_1" || !view.SignupCodeField || !view.IncludeReferralClaims || view.Connection.Alert == nil || view.Connection.Alert.Code != "signature_rejected" || !view.Connection.LastPing.ClockSkewWarning || *view.Connection.LastPing.ClockSkewMS != 90000 || !view.Providers[0].Capabilities.Ping {
		t.Fatalf("get = %+v, %v", view, err)
	}
	off, on := false, true
	_, _ = c.Referrals.Update(ctx, UpdateReferralSettingsParams{Provider: "referalli", TrackingToken: "tt_public_1", ForwardLifecycle: &off, IncludeReferralClaims: &on, Clear: []string{"code_lookup_url"}})
	if rec.RawBody != `{"code_lookup_url":null,"forward_lifecycle":false,"include_referral_claims":true,"provider":"referalli","tracking_token":"tt_public_1"}` {
		t.Errorf("update body = %s", rec.RawBody)
	}

	c, rec = recordingClient(t, `{"ok":true,"http_status":200,"latency_ms":31,"method":"ping","ping":{"ok":true,"org_name":"Acme","program_name":"Acme partners"},"warnings":["clock skew"]}`)
	tested, err := c.Referrals.Test(ctx)
	if err != nil || tested.Method != "ping" || *tested.Ping.OrgName != "Acme" || len(tested.Warnings) != 1 {
		t.Fatalf("test = %+v, %v", tested, err)
	}

	call := `{"object":"referral_call","id":"rfc_2","kind":"alias","status":"failed","customer_ref":"cust_1","attempts":1,"error_code":"signature_rejected","latency_ms":44,"request_id":"req_1","response":{"ok":false},"highlights":{"matched_via":"code","partner_external_ref":"cust_9","notes":["n"]},"batch_id":"rbf_1","created_at":1,"updated_at":2}`
	c, rec = recordingClient(t, `{"object":"list","data":[`+call+`],"has_more":true}`)
	page, err := c.Referrals.ListCalls(ctx, ListReferralCallsParams{Limit: 1000, ErrorCode: "signature_rejected", StartingAfter: "rfc_0"})
	if err != nil || !page.HasMore || *page.Data[0].ErrorCode != "signature_rejected" || *page.Data[0].BatchID != "rbf_1" || page.Data[0].Highlights.Notes[0] != "n" || *page.Data[0].LatencyMS != 44 {
		t.Fatalf("list = %+v, %v", page, err)
	}
	q, _ := url.ParseQuery(rec.Query)
	if q.Get("limit") != "1000" || q.Get("error_code") != "signature_rejected" || q.Get("starting_after") != "rfc_0" {
		t.Errorf("query = %s", rec.Query)
	}

	c, rec = recordingClient(t, `{"object":"referral_retry","requeued":4}`)
	retried, err := c.Referrals.RetryFailed(ctx, RetryFailedReferralCallsParams{ErrorCode: "signature_rejected"}, WithIdempotencyKey("k1"))
	if err != nil || retried.Requeued != 4 || rec.RawBody != `{"error_code":"signature_rejected"}` {
		t.Fatalf("retry_failed = %+v, %v, %s", retried, err, rec.RawBody)
	}
	rec.expect(t, "POST", "/v1/instance/referrals/calls/retry_failed")

	c, rec = recordingClient(t, `{"object":"referral_simulation","ok":true,"call_id":"rfc_5","customer_ref":"atlas_test_abc","http_status":200,"latency_ms":20,"result":{"referral":{"partner_id":"pn_1","partner_external_ref":"cust_9","matched_via":"code","status":"active"},"partner":null,"notes":["matched code"]},"response":{"referral":{}},"error":null}`)
	sim, err := c.Referrals.Simulate(ctx, ReferralSimulateParams{Code: "ACME10"})
	if err != nil || !sim.OK || sim.CustomerRef != "atlas_test_abc" || *sim.Result.Referral.PartnerExternalRef != "cust_9" || sim.Result.Notes[0] != "matched code" || rec.RawBody != `{"code":"ACME10"}` {
		t.Fatalf("simulate = %+v, %v, %s", sim, err, rec.RawBody)
	}
	rec.expect(t, "POST", "/v1/instance/referrals/simulate")
	_, _ = c.Referrals.Simulate(ctx, ReferralSimulateParams{})
	if rec.RawBody != `{}` {
		t.Errorf("empty simulate body = %s", rec.RawBody)
	}

	job := `{"object":"referral_backfill","id":"rbf_1","status":"running","since":1790000000000,"code_metadata_path":null,"codes_given":1,"users_scanned":12,"users_skipped":2,"calls_queued":10,"truncated":false,"next_since":null,"calls":{"pending":10,"succeeded":0,"failed":0,"skipped":0,"held":0},"created_at":1,"finished_at":null}`
	c, rec = recordingClient(t, job)
	bf, err := c.Referrals.Backfill(ctx, ReferralBackfillParams{Since: "2026-01-01", Codes: map[string]string{"cust_1": "ACME10"}}, WithIdempotencyKey("k2"))
	if err != nil || bf.ID != "rbf_1" || bf.Calls.Pending != 10 || rec.RawBody != `{"since":"2026-01-01","codes":{"cust_1":"ACME10"}}` {
		t.Fatalf("backfill = %+v, %v, %s", bf, err, rec.RawBody)
	}
	rec.expect(t, "POST", "/v1/instance/referrals/backfill")
	if _, err := c.Referrals.GetBackfill(ctx, "rbf_1"); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/instance/referrals/backfill/rbf_1")

	c, rec = recordingClient(t, `{"object":"user_referral","user_id":"user_1","status":"attributed","customer_ref":"cust_1","partner_id":"pn_1","partner_external_ref":"cust_9","referrer_user_id":"user_9","matched_via":"code","referral_status":"active","notes":["matched code"],"referral_code":"ada-1","referral_link":null,"context":{"code":"ACME10"},"risk_level":"low","flagged":false,"hold_reason":null,"signed_up_at":1,"updated_at":2}`)
	res, err := c.Referrals.GetForUser(ctx, "user_1")
	if err != nil || res.Status != "attributed" || *res.ReferralStatus != "active" || res.CustomerRef != "cust_1" || res.Context["code"] != "ACME10" {
		t.Fatalf("get_for_user = %+v, %v", res, err)
	}
	rec.expect(t, "GET", "/v1/users/user_1/referral")
}

// TestUserReferralV2 covers SetExternalID, ClearExternalID and the v2 user referral fields.
func TestUserReferralV2(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"user","id":"user_1","external_id":"cust_1","referral":{"status":"pending","partner_id":null,"partner_external_ref":"cust_9","referrer_external_id":"cust_9","referrer_user_id":null,"matched_via":null,"referral_status":"active","notes":["n"],"risk_level":null,"flagged":false}}`)
	u, err := c.Users.SetExternalID(ctx, "user_1", "cust_1")
	if err != nil || *u.ExternalID != "cust_1" || *u.Referral.Status != "pending" || *u.Referral.ReferralStatus != "active" || *u.Referral.PartnerExternalRef != "cust_9" || u.Referral.Notes[0] != "n" {
		t.Fatalf("set external id = %+v, %v", u, err)
	}
	rec.expect(t, "PATCH", "/v1/users/user_1")
	if rec.RawBody != `{"external_id":"cust_1"}` {
		t.Errorf("body = %s", rec.RawBody)
	}
	_, _ = c.Users.SetExternalID(ctx, "user_1", "")
	if rec.RawBody != `{"external_id":null}` {
		t.Errorf("clear body = %s", rec.RawBody)
	}
	_, _ = c.Users.Update(ctx, "user_1", UpdateUserParams{ClearExternalID: true, ClearReferralCode: true})
	if rec.RawBody != `{"external_id":null,"referral_code":null}` {
		t.Errorf("update clear body = %s", rec.RawBody)
	}
	_, _ = c.Users.Update(ctx, "user_1", UpdateUserParams{ExternalID: "cust_2"})
	if rec.RawBody != `{"external_id":"cust_2"}` {
		t.Errorf("update body = %s", rec.RawBody)
	}
	var resolved UserReferralResolvedEvent = *u
	if resolved.ID != "user_1" {
		t.Errorf("resolved event = %+v", resolved)
	}
}

// TestBeforeUserCreateHook covers get / update / test of the hook.
func TestBeforeUserCreateHook(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"before_user_create_hook","enabled":true,"url":"https://app.example.com/hooks/before-create","signing_secret_set":true,"timeout_ms":3000,"last_call":{"at":3,"status":"ok","error":null},"updated_at":3}`)
	hook, err := c.UserHooks.GetBeforeUserCreate(ctx)
	if err != nil || !hook.Enabled || !hook.SigningSecretSet || *hook.LastCall.Status != "ok" {
		t.Fatalf("get = %+v, %v", hook, err)
	}
	rec.expect(t, "GET", "/v1/instance/hooks/before_user_create")
	on := true
	_, _ = c.UserHooks.UpdateBeforeUserCreate(ctx, UpdateBeforeUserCreateHookParams{Enabled: &on, URL: "https://app.example.com/hooks/before-create", SigningSecret: strings.Repeat("s", 32), TimeoutMS: 2000})
	rec.expect(t, "PATCH", "/v1/instance/hooks/before_user_create")
	if rec.RawBody != `{"enabled":true,"url":"https://app.example.com/hooks/before-create","signing_secret":"`+strings.Repeat("s", 32)+`","timeout_ms":2000}` {
		t.Errorf("update body = %s", rec.RawBody)
	}
	_, _ = c.UserHooks.UpdateBeforeUserCreate(ctx, UpdateBeforeUserCreateHookParams{Clear: []string{"url"}})
	if rec.RawBody != `{"url":null}` {
		t.Errorf("clear body = %s", rec.RawBody)
	}

	c, rec = recordingClient(t, `{"ok":true,"latency_ms":12,"answer":{"external_id":"cust_1","public_metadata":null,"private_metadata_set":true,"unsafe_metadata":null}}`)
	tested, err := c.UserHooks.TestBeforeUserCreate(ctx)
	if err != nil || !tested.OK || *tested.Answer.ExternalID != "cust_1" || !tested.Answer.PrivateMetadataSet {
		t.Fatalf("test = %+v, %v", tested, err)
	}
	rec.expect(t, "POST", "/v1/instance/hooks/before_user_create/test")
}

// TestVerifyReferralRequestV2 covers the alias, user and ping operations and
// the protocol version header.
func TestVerifyReferralRequestV2(t *testing.T) {
	alias := `{"op":"alias","customerRef":"cust_1","fromCustomerRef":"user_1","toCustomerRef":"cust_1"}`
	req, err := verifyRef(t, alias, ReferralVerifyOptions{Path: "/atlas/aliases"})
	if err != nil || req.Op != ReferralOpAlias || req.Alias == nil || req.Alias.FromCustomerRef != "user_1" || req.CustomerRef != "cust_1" {
		t.Fatalf("alias = %+v, %v", req, err)
	}
	user := `{"op":"user","customerRef":"cust_1","email":"a@example.com","status":"suspended"}`
	req, err = verifyRef(t, user, ReferralVerifyOptions{Path: "/atlas/users"})
	if err != nil || req.Op != ReferralOpUser || req.User == nil || req.User.Status != "suspended" || *req.User.Email != "a@example.com" || req.User.Name != nil {
		t.Fatalf("user = %+v, %v", req, err)
	}
	ping := `{"op":"ping","customerRef":"` + ReferralConnectionTestRef + `"}`
	req, err = verifyRef(t, ping, ReferralVerifyOptions{Path: "/atlas/ping"})
	if err != nil || req.Op != ReferralOpPing || req.Ping == nil || req.Test || req.CustomerRef != ReferralConnectionTestRef || req.ProtocolVersion != "" {
		t.Fatalf("ping = %+v, %v", req, err)
	}
	if req, err = verifyRef(t, ping, ReferralVerifyOptions{ExpectedOp: ReferralOpPing}); err != nil || req.Op != ReferralOpPing {
		t.Fatalf("ping expected op = %+v, %v", req, err)
	}
	for _, tc := range []struct {
		body string
		opts ReferralVerifyOptions
	}{
		{alias, ReferralVerifyOptions{Path: "/atlas/users"}},
		{ping, ReferralVerifyOptions{Path: "/atlas/export"}},
		{user, ReferralVerifyOptions{ExpectedOp: ReferralOpAlias}},
	} {
		if _, err := verifyRef(t, tc.body, tc.opts); !errors.Is(err, ErrReferralOpMismatch) {
			t.Errorf("%s with %+v: err = %v", tc.body, tc.opts, err)
		}
	}

	h := referralHeaders("rfc_3", ping, referralSecret, referralNow.UnixMilli())
	h.Set(ReferralProtocolVersionHeader, ReferralProtocolVersion)
	req, err = VerifyReferralRequest([]byte(ping), h, referralSecret, &ReferralVerifyOptions{WebhookVerifyOptions: WebhookVerifyOptions{Now: referralNow}, Path: "/ping"})
	if err != nil || req.ProtocolVersion != "2026-10-21" {
		t.Fatalf("version = %+v, %v", req, err)
	}
	for in, want := range map[string]string{"/a/aliases": ReferralOpAlias, "/a/users/": ReferralOpUser, "/a/ping?x=1": ReferralOpPing} {
		if got := ReferralOpForPath(in); got != want {
			t.Errorf("ReferralOpForPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReferralsBrowserCapture covers browser_sources and consent_provider.
func TestReferralsBrowserCapture(t *testing.T) {
	ctx := context.Background()
	settings := `{"object":"referral_settings","enabled":true,"provider":"dub","signing_secret_set":false,"api_key_set":true,"url_params":["ref"],"browser_sources":["dub"],"browser_sources_default":true,"consent_provider":"onetrust","providers":[]}`
	c, rec := recordingClient(t, settings)
	view, err := c.Referrals.Get(ctx)
	if err != nil || len(view.BrowserSources) != 1 || view.BrowserSources[0] != "dub" || !view.BrowserSourcesDefault || view.ConsentProvider != "onetrust" {
		t.Fatalf("get = %+v, %v", view, err)
	}
	_, _ = c.Referrals.Update(ctx, UpdateReferralSettingsParams{BrowserSources: []string{"rewardful", "dub"}, ConsentProvider: "app"})
	if rec.RawBody != `{"browser_sources":["rewardful","dub"],"consent_provider":"app"}` {
		t.Errorf("update body = %s", rec.RawBody)
	}
	_, _ = c.Referrals.Update(ctx, UpdateReferralSettingsParams{Clear: []string{"browser_sources"}})
	if rec.RawBody != `{"browser_sources":null}` {
		t.Errorf("clear body = %s", rec.RawBody)
	}
}

// TestReferralsInbound covers the two-way sync fields and the referral.updated signer.
func TestReferralsInbound(t *testing.T) {
	ctx := context.Background()
	settings := `{"object":"referral_settings","enabled":true,"provider":"webhook","signing_secret_set":true,"api_key_set":false,"url_params":["ref"],"inbound":{"url":"https://api.example.test/v1/webhooks/referrals/ins_1","secret_set":true,"endpoint_id":"we_1","last_event":{"at":1700000000000,"type":"referral.updated","outcome":"applied"}},"providers":[{"id":"webhook","name":"Atlas referral protocol","capabilities":{"signup":true,"erase":true,"export":true,"partner":true,"auto_enroll":true,"signal":true,"inbound":true},"needs":["endpoint_url","signing_secret"],"default_context_cookie":null,"docs_url":null}]}`
	c, rec := recordingClient(t, settings)
	view, err := c.Referrals.Get(ctx)
	if err != nil || view.Inbound == nil || *view.Inbound.URL != "https://api.example.test/v1/webhooks/referrals/ins_1" || !view.Inbound.SecretSet || *view.Inbound.EndpointID != "we_1" || view.Inbound.LastEvent.Outcome != "applied" || view.Inbound.LastEvent.At != 1700000000000 || !view.Providers[0].Capabilities.Inbound {
		t.Fatalf("get = %+v, %v", view, err)
	}
	_, _ = c.Referrals.Update(ctx, UpdateReferralSettingsParams{InboundSecret: "whsec_" + strings.Repeat("y", 32), InboundEndpointID: "we_1"})
	if rec.RawBody != `{"inbound_secret":"whsec_`+strings.Repeat("y", 32)+`","inbound_endpoint_id":"we_1"}` {
		t.Errorf("update body = %s", rec.RawBody)
	}
	_, _ = c.Referrals.Update(ctx, UpdateReferralSettingsParams{Clear: []string{"inbound_secret", "inbound_endpoint_id"}})
	if rec.RawBody != `{"inbound_endpoint_id":null,"inbound_secret":null}` {
		t.Errorf("clear body = %s", rec.RawBody)
	}

	inbound := "https://api.example.test/v1/webhooks/referrals/ins_1"
	e, err := SignReferralUpdatedEvent(inbound, referralSecret, ReferralUpdatedEvent{CustomerRef: "user_1", ReferralID: "ref_1", Status: "qualified", PartnerID: "pn_2"}, &ReferralEventOptions{EventID: "rfe_1", Now: referralNow})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"referral.updated","occurredAt":"` + referralNow.UTC().Format("2006-01-02T15:04:05.000Z07:00") + `","customerRef":"user_1","referralId":"ref_1","status":"qualified","partnerId":"pn_2"}`
	if e.URL != inbound || string(e.Body) != want || e.Header.Get("Atlas-Id") != "rfe_1" || e.Header.Get("Atlas-Timestamp") != strconv.FormatInt(referralNow.UnixMilli(), 10) {
		t.Fatalf("event = %s %s %v", e.URL, e.Body, e.Header)
	}
	if e.Header.Get("Atlas-Signature") != referralHeaders("rfe_1", want, referralSecret, referralNow.UnixMilli()).Get("Atlas-Signature") {
		t.Errorf("signature = %s", e.Header.Get("Atlas-Signature"))
	}
	hook, err := VerifyWebhook(e.Body, e.Header, referralSecret, &WebhookVerifyOptions{Now: referralNow})
	if err != nil || hook.DeliveryID != "rfe_1" {
		t.Fatalf("verify = %+v, %v", hook, err)
	}
	if _, err := VerifyWebhook(e.Body, e.Header, "wrong_secret_wrong_secret", &WebhookVerifyOptions{Now: referralNow}); err == nil {
		t.Error("wrong secret verified")
	}
	req, err := e.Request(ctx)
	if err != nil || req.Method != http.MethodPost || req.URL.String() != inbound || req.Header.Get("Atlas-Id") != "rfe_1" {
		t.Fatalf("request = %+v, %v", req, err)
	}

	e, err = SignReferralUpdatedEvent(inbound, referralSecret, ReferralUpdatedEvent{ReferralID: "ref_1", OccurredAt: "2026-10-20T00:00:00Z"}, nil)
	if err != nil || !strings.Contains(string(e.Body), `"occurredAt":"2026-10-20T00:00:00Z"`) || !strings.HasPrefix(e.Header.Get("Atlas-Id"), "rfe_") {
		t.Fatalf("defaults = %s %v, %v", e.Body, e.Header, err)
	}
	if _, err := SignReferralUpdatedEvent(inbound, referralSecret, ReferralUpdatedEvent{Status: "qualified"}, nil); !errors.Is(err, ErrReferralEventNoReference) {
		t.Errorf("no reference err = %v", err)
	}
}
