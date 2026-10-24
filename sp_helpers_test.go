package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Sealed boxes made by libsodium (PHP's sodium_crypto_box_seal) open with the key pair they were
// sealed to: the Go implementation interoperates with the reference one.
func TestOpenSealedBoxFromLibsodium(t *testing.T) {
	var pub, sec [32]byte
	pb, _ := hex.DecodeString("1b1b58dd50ea14b60da17b790cd02754d970c9bab864ebb3c0f3016fe51d3f57")
	sb, _ := hex.DecodeString("5ce86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef3ee")
	copy(pub[:], pb)
	copy(sec[:], sb)
	pair := &SealKeyPair{PublicKey: pub, SecretKey: sec}
	got, err := OpenSealedSecret("odKhh8e5o1em9TtirH5UV+E1tNR5E8xy8dkxOrgZ+jrsbcxVgYe59ah5+bWPLj2dPN1DVCmkBY1bqn6/tAAAAng78qc=", pair)
	if err != nil || got != "atlas_live_sk_vector" {
		t.Fatalf("libsodium box: got %q, %v", got, err)
	}
	empty, err := OpenSealedSecret("cnCnIagPkiQi9REa9TXqWvdgumPdfnuLcLf2BVisdVA3VcRF4z3ekOv71ndRaGt1", pair)
	if err != nil || empty != "" {
		t.Fatalf("libsodium empty box: got %q, %v", empty, err)
	}
}

func TestSealedBoxRoundTrip(t *testing.T) {
	pair, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pair.Recipient, "x25519:") {
		t.Errorf("recipient = %q", pair.Recipient)
	}
	for _, msg := range []string{"", "atlas_live_sk_x", strings.Repeat("secret-", 40)} {
		sealed, err := SealBox([]byte(msg), pair.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenSealedSecret(base64.StdEncoding.EncodeToString(sealed), pair)
		if err != nil || got != msg {
			t.Errorf("round trip %q: got %q, %v", msg, got, err)
		}
	}
	// Another key pair cannot open it; a flipped bit fails the tag.
	other, _ := GenerateSealKeyPair()
	sealed, _ := SealBox([]byte("secret"), pair.PublicKey)
	if _, err := OpenSealedBox(sealed, other.PublicKey, other.SecretKey); !errors.Is(err, ErrSealedBoxInvalid) {
		t.Errorf("opened with the wrong key: %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenSealedBox(sealed, pair.PublicKey, pair.SecretKey); !errors.Is(err, ErrSealedBoxInvalid) {
		t.Errorf("opened a tampered box: %v", err)
	}
	if _, err := OpenSealedBox(make([]byte, 10), pair.PublicKey, pair.SecretKey); !errors.Is(err, ErrSealedBoxInvalid) {
		t.Error("opened a short box")
	}
}

func signWebhookV2(id string, ts int64, body, endpoint, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + endpoint + "." + body))
	return "v2," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookURLV2(t *testing.T) {
	now := time.UnixMilli(1_757_937_600_000)
	body := `{"id":"evt_1","type":"user.updated","data":{}}`
	ts := now.UnixMilli()
	endpoint := "https://app.example.com/hooks/atlas"
	opts := &WebhookVerifyOptions{Now: now}

	v1 := signWebhook("evt_1", ts, body, testWebhookSecret)
	both := v1.Get("atlas-signature") + " " + signWebhookV2("evt_1", ts, body, endpoint, testWebhookSecret) + " v9,ignored"
	v1.Set("atlas-signature", both)

	hook, err := VerifyWebhookURL([]byte(body), v1, testWebhookSecret, endpoint, true, opts)
	if err != nil || hook.DeliveryID != "evt_1" || hook.Event == nil || hook.Event.Type != "user.updated" {
		t.Fatalf("v2 verify = %+v, %v", hook, err)
	}
	// Replayed to another URL: v2 fails, and requireV2 forbids falling back to v1.
	if _, err := VerifyWebhookURL([]byte(body), v1, testWebhookSecret, "https://evil.example.com/hook", true, opts); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("other url with requireV2: %v", err)
	}
	// Without requireV2 the v1 entry still verifies.
	if _, err := VerifyWebhookURL([]byte(body), v1, testWebhookSecret, "https://evil.example.com/hook", false, opts); err != nil {
		t.Errorf("v1 fallback: %v", err)
	}
	// Plain VerifyWebhook ignores the v2 and unknown entries.
	if _, err := VerifyWebhook([]byte(body), v1, testWebhookSecret, opts); err != nil {
		t.Errorf("VerifyWebhook with a v2 entry: %v", err)
	}
	// Only unknown versions: malformed.
	h := http.Header{}
	h.Set("atlas-id", "evt_1")
	h.Set("atlas-timestamp", strconv.FormatInt(ts, 10))
	h.Set("atlas-signature", "v9,abc")
	if _, err := VerifyWebhookURL([]byte(body), h, testWebhookSecret, endpoint, false, opts); !errors.Is(err, ErrWebhookMalformedSignature) {
		t.Errorf("unknown version: %v", err)
	}
	// Stale.
	if _, err := VerifyWebhookURL([]byte(body), v1, testWebhookSecret, endpoint, true, &WebhookVerifyOptions{Now: now.Add(10 * time.Minute)}); !errors.Is(err, ErrWebhookStaleTimestamp) {
		t.Errorf("stale: %v", err)
	}
}

func TestVerifyPrivacyCall(t *testing.T) {
	now := time.UnixMilli(1_757_937_600_000)
	body := `{"id":"evt_9","type":"privacy_request.completed","data":{"object":"privacy_request","id":"pr_1","status":"completed","canonicalType":"deletion","steps":[{"name":"user","status":"done"}],"retention":[]}}`
	h := signWebhook("evt_9", now.UnixMilli(), body, testWebhookSecret)
	h.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	call, err := VerifyPrivacyCall([]byte(body), h, testWebhookSecret, &WebhookVerifyOptions{Now: now})
	if err != nil || call.Event == nil || call.Event.Type != WebhookEventPrivacyRequestCompleted || call.Traceparent == "" || call.DeliveryID != "evt_9" {
		t.Fatalf("call = %+v, %v", call, err)
	}
	pr, err := PrivacyRequestFromEvent(call.Event)
	if err != nil || pr.ID != "pr_1" || pr.Status != PrivacyStatusCompleted || pr.CanonicalType != PrivacyTypeDeletion || len(pr.Steps) != 1 {
		t.Errorf("request = %+v, %v", pr, err)
	}
	// A case call has no webhook envelope: Event stays nil.
	caseBody := `{"caseRef":"dsr_1","subject":{"sub":"u1"}}`
	h2 := signWebhook("dsr_1", now.UnixMilli(), caseBody, testWebhookSecret)
	c2, err := VerifyPrivacyCall([]byte(caseBody), h2, testWebhookSecret, &WebhookVerifyOptions{Now: now})
	if err != nil || c2.Event != nil || string(c2.Body) != caseBody {
		t.Errorf("case call = %+v, %v", c2, err)
	}
	if _, err := VerifyPrivacyCall([]byte(caseBody), h2, "whsec_wrong", &WebhookVerifyOptions{Now: now}); err == nil {
		t.Error("accepted a wrong secret")
	}
}

func TestBackchannelLogoutHandler(t *testing.T) {
	f := newLogoutFixture(t)
	var got []string
	var failOnLogout bool
	guard := &MemoryReplayGuard{Now: func() time.Time { return f.now }}
	h, err := BackchannelLogoutHandler(BackchannelLogoutHandlerOptions{
		Verify: LogoutTokenVerifierOptions{JWKSURL: f.jwksURL, Issuer: ltIssuer, ClientID: ltClientID, ReplayGuard: guard, Now: func() time.Time { return f.now }},
		OnLogout: func(ctx context.Context, c *LogoutTokenClaims) error {
			if failOnLogout {
				return errors.New("db down")
			}
			got = append(got, c.Sid+"|"+c.Sub)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"logout_token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	good := f.sign(t, f.key, f.header(), f.claims())
	w := post(good)
	if w.Code != 200 || len(got) != 1 || got[0] != "sess_1|user_1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("good: %d %v %v", w.Code, got, w.Header())
	}
	// The same token again: a replay is answered 200 and not handled twice.
	if w := post(good); w.Code != 200 || len(got) != 1 {
		t.Errorf("replay: %d %v", w.Code, got)
	}
	// A bad token is 400, no logout.
	c := f.claims()
	c["aud"] = "cid_other"
	c["jti"] = "jti_2"
	if w := post(f.sign(t, f.key, f.header(), c)); w.Code != 400 || len(got) != 1 {
		t.Errorf("bad aud: %d", w.Code)
	}
	// OnLogout failing is 503 with Retry-After.
	failOnLogout = true
	c2 := f.claims()
	c2["jti"] = "jti_3"
	if w := post(f.sign(t, f.key, f.header(), c2)); w.Code != 503 || w.Header().Get("Retry-After") != "30" {
		t.Errorf("onLogout error: %d %v", w.Code, w.Header())
	}
	// Missing token and wrong method.
	r := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != 400 {
		t.Errorf("missing token: %d", w2.Code)
	}
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if w3.Code != 405 {
		t.Errorf("GET: %d", w3.Code)
	}
	if _, err := BackchannelLogoutHandler(BackchannelLogoutHandlerOptions{}); err == nil {
		t.Error("built a handler without OnLogout")
	}
}

func TestOperatorDeviceFlowAndExchange(t *testing.T) {
	ctx := context.Background()
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/v1/operator":
			_, _ = w.Write([]byte(`{"issuer":"https://atlasauth.net","device_authorization_endpoint":"` + srv.URL + `/device","token_endpoint":"` + srv.URL + `/token","client_id":"atlas-cli","scope":"openid","token_exchange_endpoint":"` + srv.URL + `/v1/oauth/token","token_exchange_audience":"atlas","root_action_max_mfa_age_seconds":300}`))
		case "/device":
			if r.PostForm.Get("client_id") != "atlas-cli" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://atlasauth.net/device","verification_uri_complete":"https://atlasauth.net/device?c=ABCD-EFGH","expires_in":600,"interval":5}`))
		case "/token":
			polls++
			switch polls {
			case 1:
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			case 2:
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
			default:
				_, _ = w.Write([]byte(`{"access_token":"op_tok","token_type":"Bearer","expires_in":3600}`))
			}
		case "/v1/oauth/token":
			switch r.PostForm.Get("grant_type") {
			case "urn:ietf:params:oauth:grant-type:token-exchange":
				if r.PostForm.Get("subject_token") != "op_tok" || r.PostForm.Get("resource") != "ins_1" || r.PostForm.Get("scope") != "users:read users:write" || r.PostForm.Get("audience") != "atlas" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"errors":[{"code":"STEP_UP_REQUIRED","message":"mfa"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"atlas_live_at_x","token_type":"Bearer","expires_in":3600,"resource":"ins_1"}`))
			case "client_credentials":
				_, _ = w.Write([]byte(`{"access_token":"pl_tok","token_type":"Bearer","expires_in":300}`))
			}
		case "/v1/keys/revoke_leaked":
			_, _ = w.Write([]byte(`{"results":[{"index":0,"kind":"secret_key","outcome":"revoked"}]}`))
		}
	}))
	defer srv.Close()

	var slept []time.Duration
	opts := &OperatorOptions{APIURL: srv.URL, Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }}
	start, err := StartOperatorLogin(ctx, nil, opts)
	if err != nil || start.UserCode != "ABCD-EFGH" || start.Config.ClientID != "atlas-cli" {
		t.Fatalf("start = %+v, %v", start, err)
	}
	tok, err := PollOperatorLogin(ctx, start, opts)
	if err != nil || tok.AccessToken != "op_tok" {
		t.Fatalf("poll = %+v, %v", tok, err)
	}
	if len(slept) != 3 || slept[0] != 5*time.Second || slept[1] != 5*time.Second || slept[2] != 10*time.Second {
		t.Errorf("sleeps = %v (slow_down must add 5s)", slept)
	}
	at, err := ExchangeOperatorToken(ctx, "op_tok", "ins_1", []string{"users:read", "users:write"}, opts)
	if err != nil || at.AccessToken != "atlas_live_at_x" || at.Resource != "ins_1" || !IsAccessToken(at.AccessToken) {
		t.Fatalf("exchange = %+v, %v", at, err)
	}
	_, err = ExchangeOperatorToken(ctx, "bad", "ins_1", nil, opts)
	var fe *OAuthFlowError
	if !errors.As(err, &fe) || fe.Err != "STEP_UP_REQUIRED" || fe.Status != 400 {
		t.Errorf("exchange error = %v", err)
	}
	pl, err := PartnerLinkToken(ctx, "cid", "secret", "privacy:execute", opts)
	if err != nil || pl.AccessToken != "pl_tok" {
		t.Errorf("partner token = %+v, %v", pl, err)
	}
	res, err := RevokeLeakedKeys(ctx, []string{"atlas_live_sk_x"}, "https://gist.example.com/1", opts)
	if err != nil || len(res) != 1 || res[0].Outcome != "revoked" {
		t.Errorf("revoke leaked = %+v, %v", res, err)
	}
	cl, err := NewClientFromAccessToken("atlas_live_at_x")
	if err != nil || cl.Users == nil || cl.Platform == nil {
		t.Errorf("client = %+v, %v", cl, err)
	}
	if _, err := NewClientFromAccessToken(""); err == nil {
		t.Error("accepted an empty token")
	}
}

func TestPollOperatorLoginExpires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"denied"}`))
	}))
	defer srv.Close()
	start := &OperatorDeviceAuthorization{DeviceCode: "dc", ExpiresIn: 600, Interval: 1, Config: OperatorConfiguration{TokenEndpoint: srv.URL, ClientID: "atlas-cli"}}
	opts := &OperatorOptions{Sleep: func(context.Context, time.Duration) error { return nil }}
	_, err := PollOperatorLogin(context.Background(), start, opts)
	var fe *OAuthFlowError
	if !errors.As(err, &fe) || fe.Err != "access_denied" {
		t.Errorf("denied = %v", err)
	}
	// A clock past the deadline ends in expired_token without polling.
	now := time.Unix(1000, 0)
	calls := 0
	opts2 := &OperatorOptions{Now: func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(time.Hour)
		}
		return now
	}, Sleep: func(context.Context, time.Duration) error { return nil }}
	_, err = PollOperatorLogin(context.Background(), start, opts2)
	if !errors.As(err, &fe) || fe.Err != "expired_token" {
		t.Errorf("expiry = %v", err)
	}
}

func TestSecretKeyDecodeAndSealedFields(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"secret_key","id":"key_1","kind":"secret_key","format":"atlas","prefix":"atlas_live_sk_4fGq","name":"ci","owner":null,"scopes":["read_only"],"environment":"live","resource":{"type":"instance","id":"ins_1"},"expires_at":null,"expires_in_days":null,"status":"active","ip_allowlist":[],"origin_allowlist":[],"last_used_at":null,"last_used_ip":null,"created_at":1,"revoked_at":null,"allowed_ips":["10.0.0.0/8"],"rotated_from":"key_0","sealed_secret":"AAAA","note":"n","replaces":"key_0","previous_key_expires_at":99}`)
	k, err := c.SecretKeys.Rotate(ctx, "key_1", RotateSecretKeyParams{})
	if err != nil || k.ID != "key_1" || k.Format != "atlas" || k.Resource.Type != "instance" || k.SealedSecret != "AAAA" || k.Replaces != "key_0" || *k.PreviousKeyExpiresAt != 99 || k.AllowedIPs[0] != "10.0.0.0/8" || *k.Name != "ci" {
		t.Fatalf("key = %+v, %v", k, err)
	}
}

func TestPlatformProvisioningDecode(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"platform_app","id":"ins_1","name":"A","environment":"production","publishable_key":"pk","allowed_origins":[],"tags":[],"archived":false,"archived_at":null,"disabled":false,"created_at":1,"updated_at":1,"metadata":{"product":"x"},"external_ref":"r-1","idempotent_replay":true}`, WithPlatformKey("psk_test"))
	app, err := c.Platform.Apps.Get(ctx, "ins_1")
	if err != nil || app.ExternalRef == nil || *app.ExternalRef != "r-1" || !app.IdempotentReplay || app.Metadata["product"] != "x" {
		t.Fatalf("app = %+v, %v", app, err)
	}
}
