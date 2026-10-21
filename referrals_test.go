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
