package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestRound20261030Operations walks every route added in the 2026-10-30 round.
func TestRound20261030Operations(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"app_event","id":"evt_1","idempotent_replay":false,"deliveries_queued":2,"endpoint_ids":["we_1","we_2"],"ticket":"tkt","expires_at":"2026-10-30T00:00:00Z"}`)
	no := false

	ev, err := c.AppEvents.Publish(ctx, PublishAppEventParams{OrganizationID: "org_1", Type: "call.completed", Data: map[string]interface{}{"call_id": "c1"}, IdempotencyKey: "c1"})
	if err != nil || ev.DeliveriesQueued == nil || *ev.DeliveriesQueued != 2 || len(ev.EndpointIDs) != 2 || ev.IdempotentReplay {
		t.Fatalf("Publish = %+v, %v", ev, err)
	}
	rec.expect(t, "POST", "/v1/app_events")
	if rec.Body["organization_id"] != "org_1" || rec.Body["idempotency_key"] != "c1" || rec.Body["type"] != "call.completed" {
		t.Errorf("Publish body = %v", rec.Body)
	}

	rows := []struct {
		method, path, query string
		call                func() error
	}{
		{"GET", "/v1/app_events", "organization_id=org_1&type=call.completed", func() error {
			_, err := c.AppEvents.List(ctx, ListAppEventsParams{OrganizationID: "org_1", Type: "call.completed"})
			return err
		}},
		{"GET", "/v1/app_events/evt_1", "", func() error { _, err := c.AppEvents.Get(ctx, "evt_1"); return err }},
		{"GET", "/v1/app_event_types", "", func() error { _, err := c.AppEvents.Types.List(ctx); return err }},
		{"POST", "/v1/app_event_types", "", func() error {
			_, err := c.AppEvents.Types.Create(ctx, CreateAppEventTypeParams{Type: "call.completed"})
			return err
		}},
		{"GET", "/v1/app_event_types/call.completed", "", func() error { _, err := c.AppEvents.Types.Get(ctx, "call.completed"); return err }},
		{"PATCH", "/v1/app_event_types/aet_1", "", func() error {
			_, err := c.AppEvents.Types.Update(ctx, "aet_1", UpdateAppEventTypeParams{Deprecated: &no})
			return err
		}},
		{"DELETE", "/v1/app_event_types/aet_1", "", func() error { _, err := c.AppEvents.Types.Delete(ctx, "aet_1"); return err }},
		{"GET", "/v1/organizations/org_1/app_webhook_endpoints", "", func() error { _, err := c.AppEvents.Endpoints.List(ctx, "org_1"); return err }},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints", "", func() error {
			_, err := c.AppEvents.Endpoints.Create(ctx, "org_1", AppWebhookEndpointParams{URL: "https://acme.example.com/hooks"})
			return err
		}},
		{"GET", "/v1/organizations/org_1/app_webhook_endpoints/we_1", "", func() error { _, err := c.AppEvents.Endpoints.Get(ctx, "org_1", "we_1"); return err }},
		{"PATCH", "/v1/organizations/org_1/app_webhook_endpoints/we_1", "", func() error {
			_, err := c.AppEvents.Endpoints.Update(ctx, "org_1", "we_1", AppWebhookEndpointParams{Active: &no})
			return err
		}},
		{"DELETE", "/v1/organizations/org_1/app_webhook_endpoints/we_1", "", func() error { _, err := c.AppEvents.Endpoints.Delete(ctx, "org_1", "we_1"); return err }},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints/we_1/rotate_secret", "", func() error {
			_, err := c.AppEvents.Endpoints.RotateSecret(ctx, "org_1", "we_1")
			return err
		}},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints/we_1/reveal_secret", "", func() error {
			_, err := c.AppEvents.Endpoints.RevealSecret(ctx, "org_1", "we_1")
			return err
		}},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints/we_1/test", "wait=10s", func() error {
			_, err := c.AppEvents.Endpoints.Test(ctx, "org_1", "we_1", "10s")
			return err
		}},
		{"GET", "/v1/organizations/org_1/app_webhook_endpoints/we_1/deliveries", "limit=5", func() error {
			_, err := c.AppEvents.Endpoints.Deliveries(ctx, "org_1", "we_1", ListWebhookDeliveriesParams{Limit: 5})
			return err
		}},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints/we_1/deliveries/del_1/redeliver", "", func() error {
			_, err := c.AppEvents.Endpoints.Redeliver(ctx, "org_1", "we_1", "del_1")
			return err
		}},
		{"POST", "/v1/organizations/org_1/app_webhook_endpoints/we_1/replay", "", func() error {
			_, err := c.AppEvents.Endpoints.Replay(ctx, "org_1", "we_1", ReplayWebhookParams{SinceKeyword: SinceFailingSince})
			return err
		}},
		{"GET", "/v1/organizations/org_1/app_event_types", "", func() error { _, err := c.AppEvents.Endpoints.AppEventTypes(ctx, "org_1"); return err }},
		{"GET", "/v1/instance/sign_in_with_atlas", "", func() error { _, err := c.Instance.GetSignInWithAtlas(ctx); return err }},
		{"PATCH", "/v1/instance/sign_in_with_atlas", "", func() error {
			_, err := c.Instance.UpdateSignInWithAtlas(ctx, UpdateSignInWithAtlasParams{Enabled: true})
			return err
		}},
		{"GET", "/v1/instance/hosted_pages", "", func() error { _, err := c.Instance.GetHostedPages(ctx); return err }},
		{"PATCH", "/v1/instance/hosted_pages", "", func() error {
			_, err := c.Instance.UpdateHostedPages(ctx, UpdateHostedPagesParams{SignInURL: "https://app.example.com/login", Clear: []string{"user_url"}})
			return err
		}},
		{"GET", "/v1/instance/privacy_integrations", "", func() error { _, err := c.Privacy.GetIntegration(ctx); return err }},
		{"POST", "/v1/instance/privacy_integrations/connect", "", func() error {
			_, err := c.Privacy.ConnectIntegration(ctx, ConnectPrivacyIntegrationParams{Preset: "custom", CookieConsent: false})
			return err
		}},
		{"POST", "/v1/testing/sign_in_url", "", func() error {
			_, err := c.Testing.CreateSignInURL(ctx, CreateSignInURLParams{UserID: "user_1", RedirectURL: "http://localhost:3000/"})
			return err
		}},
	}
	for _, r := range rows {
		if err := r.call(); err != nil {
			t.Errorf("%s %s: %v", r.method, r.path, err)
			continue
		}
		rec.expect(t, r.method, r.path)
		if rec.Query != r.query {
			t.Errorf("%s %s query = %q, want %q", r.method, r.path, rec.Query, r.query)
		}
	}

	// The last PATCH /v1/instance/hosted_pages body: Clear keys go out as null.
	_, _ = c.Instance.UpdateHostedPages(ctx, UpdateHostedPagesParams{SignInURL: "https://app.example.com/login", Clear: []string{"user_url"}})
	if v, ok := rec.Body["user_url"]; !ok || v != nil || rec.Body["sign_in_url"] != "https://app.example.com/login" {
		t.Errorf("UpdateHostedPages body = %v", rec.Body)
	}
	_, _ = c.Privacy.ConnectIntegration(ctx, ConnectPrivacyIntegrationParams{Preset: "custom", CookieConsent: false})
	if rec.Body["cookie_consent"] != false {
		t.Errorf("ConnectIntegration body = %v", rec.Body)
	}

	tk, err := c.Sessions.CreateBrowserTicket(ctx, CreateBrowserTicketParams{UserID: "user_1", RedirectURL: "https://app.example.com/", ExpiresInSeconds: 120})
	if err != nil || tk.Ticket != "tkt" || tk.ExpiresAt == "" {
		t.Fatalf("CreateBrowserTicket = %+v, %v", tk, err)
	}
	rec.expect(t, "POST", "/v1/sessions")
	if rec.Body["mode"] != "browser_ticket" || rec.Body["redirect_url"] != "https://app.example.com/" || rec.Body["expires_in_seconds"] != float64(120) || rec.Body["user_id"] != "user_1" {
		t.Errorf("CreateBrowserTicket body = %v", rec.Body)
	}
	_, _ = c.Sessions.Create(ctx, CreateSessionParams{UserID: "user_1"})
	if _, ok := rec.Body["mode"]; ok {
		t.Errorf("Create sent mode: %v", rec.Body)
	}
}

func signStandardWebhook(id string, ts int64, body, secret string) string {
	key, _ := base64.StdEncoding.DecodeString(secret[len("whsec_"):])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + body))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func standardHeaders(id string, ts int64, sig string) http.Header {
	h := http.Header{}
	h.Set("webhook-id", id)
	h.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	h.Set("webhook-signature", sig)
	return h
}

func TestVerifyStandardWebhook(t *testing.T) {
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("app-webhook-test-key-32-bytes!!!"))
	oldSecret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("previous-key"))
	now := time.Unix(1_790_000_000, 0)
	ts := now.Unix() - 10
	body := `{"id":"evt_1","type":"call.completed","data":{"call_id":"c1"}}`
	opts := &WebhookVerifyOptions{Now: now}

	hook, err := VerifyStandardWebhook([]byte(body), standardHeaders("msg_1", ts, signStandardWebhook("msg_1", ts, body, secret)), secret, opts)
	if err != nil || hook.DeliveryID != "msg_1" || hook.Timestamp != ts || hook.Event == nil || hook.Event.Type != "call.completed" {
		t.Fatalf("good = %+v, %v", hook, err)
	}

	rotated := signStandardWebhook("msg_1", ts, body, oldSecret) + " " + signStandardWebhook("msg_1", ts, body, secret)
	if _, err := VerifyStandardWebhook([]byte(body), standardHeaders("msg_1", ts, rotated), secret, opts); err != nil {
		t.Errorf("rotated: %v", err)
	}

	cases := []struct {
		name   string
		body   string
		header http.Header
		want   error
	}{
		{"bad sig", body, standardHeaders("msg_1", ts, signStandardWebhook("msg_1", ts, body, oldSecret)), ErrWebhookSignatureMismatch},
		{"tampered", `{"id":"evt_2"}`, standardHeaders("msg_1", ts, signStandardWebhook("msg_1", ts, body, secret)), ErrWebhookSignatureMismatch},
		{"stale", body, standardHeaders("msg_1", ts-600, signStandardWebhook("msg_1", ts-600, body, secret)), ErrWebhookStaleTimestamp},
		{"ms timestamp", body, standardHeaders("msg_1", ts*1000, signStandardWebhook("msg_1", ts*1000, body, secret)), ErrWebhookStaleTimestamp},
		{"missing", body, http.Header{}, ErrWebhookMissingHeaders},
		{"malformed", body, standardHeaders("msg_1", ts, "v2,abc"), ErrWebhookMalformedSignature},
	}
	for _, c := range cases {
		if _, err := VerifyStandardWebhook([]byte(c.body), c.header, secret, opts); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	if _, err := VerifyStandardWebhook([]byte(body), standardHeaders("msg_1", ts, signStandardWebhook("msg_1", ts, body, secret)), "whsec_!!!", opts); !errors.Is(err, ErrWebhookInvalidSecret) {
		t.Errorf("invalid secret: %v", err)
	}
}

func TestRound20261030Models(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"id":"user_1","external_accounts":[{"object":"external_account","id":"idn_1","provider":"google","provider_user_id":"g1","provider_email":"a@example.com","email_verified":true,"connected_at":5}]}`)
	u, err := c.Users.Get(ctx, "user_1")
	if err != nil || len(u.ExternalAccounts) != 1 || u.ExternalAccounts[0].Provider != "google" || !u.ExternalAccounts[0].EmailVerified {
		t.Fatalf("external_accounts = %+v, %v", u, err)
	}
	raw, _ := UpdateUserParams{ClearImageURL: true}.MarshalJSON()
	if string(raw) != `{"image_url":null}` {
		t.Errorf("ClearImageURL = %s", raw)
	}
}
