package atlas

import (
	"context"
	"encoding/json"
	"testing"
)

// TestIntegratorRoundSurface walks the 0.23.0 additions after the logout
// round: preflight acknowledgements, the OAuth client secret reveal, chosen
// client_secret and require_verified_email, invitation expiry, the platform app
// lookups and the before_user_create fail_closed switch: method, path, query and
// body for each.
func TestIntegratorRoundSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x"}`, WithPlatformKey("psk_test"))
	yes, no := true, false

	cases := []struct {
		method, path, query, body string
		call                      func() error
	}{
		{"GET", "/v1/instance/preflight/acks", "", "", func() error { _, err := c.Instance.PreflightAcks(ctx); return err }},
		{"PUT", "/v1/instance/preflight/acks/pkce_not_required", "", `{"reason":"legacy client","expires_at":1900000000000}`, func() error {
			_, err := c.Instance.AcknowledgePreflight(ctx, "pkce_not_required", AcknowledgePreflightParams{Reason: "legacy client", ExpiresAt: int64(1900000000000)})
			return err
		}},
		{"PUT", "/v1/instance/preflight/acks/pkce_not_required", "", `{"reason":"accepted"}`, func() error {
			_, err := c.Instance.AcknowledgePreflight(ctx, "pkce_not_required", AcknowledgePreflightParams{Reason: "accepted"})
			return err
		}},
		{"DELETE", "/v1/instance/preflight/acks/pkce_not_required", "", "", func() error { _, err := c.Instance.DeletePreflightAck(ctx, "pkce_not_required"); return err }},
		{"POST", "/v1/oauth_clients/oac_1/secret/reveal", "", "", func() error { _, err := c.OAuthClients.RevealSecret(ctx, "oac_1"); return err }},
		{"POST", "/v1/oauth_clients", "", `{"name":"App","redirect_uris":["https://app.example.com/cb"],"client_secret":"s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t","require_verified_email":true}`, func() error {
			_, err := c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, ClientSecret: "s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t", RequireVerifiedEmail: &yes})
			return err
		}},
		{"PATCH", "/v1/oauth_clients/oac_1", "", `{"require_verified_email":false}`, func() error {
			_, err := c.OAuthClients.Update(ctx, "oac_1", UpdateOAuthClientParams{RequireVerifiedEmail: &no})
			return err
		}},
		{"POST", "/v1/invitations", "", `{"email_address":"a@example.com","expires_in_days":30}`, func() error {
			_, err := c.Invitations.Create(ctx, CreateInvitationParams{EmailAddress: "a@example.com", ExpiresInDays: 30})
			return err
		}},
		{"POST", "/v1/invitations", "", `{"email_address":"a@example.com","expires_at":"2027-01-01T00:00:00Z"}`, func() error {
			_, err := c.Invitations.Create(ctx, CreateInvitationParams{EmailAddress: "a@example.com", ExpiresAt: "2027-01-01T00:00:00Z"})
			return err
		}},
		{"GET", "/v1/platform/apps", "external_ref=acme%2Fprod&limit=50&name=Acme&name_prefix=Ac&starting_after=ins_9", "", func() error {
			_, err := c.Platform.Apps.List(ctx, ListPlatformAppsParams{Name: "Acme", NamePrefix: "Ac", ExternalRef: "acme/prod", ListParams: ListParams{Limit: 50, StartingAfter: "ins_9"}})
			return err
		}},
		{"PATCH", "/v1/instance/hooks/before_user_create", "", `{"fail_closed":true}`, func() error {
			_, err := c.UserHooks.UpdateBeforeUserCreate(ctx, UpdateBeforeUserCreateHookParams{FailClosed: &yes})
			return err
		}},
	}
	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.path, err)
			continue
		}
		rec.expect(t, tc.method, tc.path)
		if rec.Query != tc.query {
			t.Errorf("%s %s query = %q, want %q", tc.method, tc.path, rec.Query, tc.query)
		}
		if tc.body == "" {
			continue
		}
		var want map[string]interface{}
		_ = json.Unmarshal([]byte(tc.body), &want)
		got, _ := json.Marshal(rec.Body)
		exp, _ := json.Marshal(want)
		if string(got) != string(exp) {
			t.Errorf("%s %s body = %s, want %s", tc.method, tc.path, got, exp)
		}
	}
}

// TestIntegratorRoundDecode checks the new response fields decode.
func TestIntegratorRoundDecode(t *testing.T) {
	ctx := context.Background()

	c, _ := recordingClient(t, `{"object":"preflight","ok":true,"findings":[{"severity":"warning","code":"pkce_not_required","message":"m","fix":"f","acknowledged":{"reason":"legacy","by":"ak_1","at":1,"expires_at":null}}]}`)
	p, err := c.Instance.Preflight(ctx)
	if err != nil || len(p.Findings) != 1 || p.Findings[0].Acknowledged == nil || p.Findings[0].Acknowledged.Reason != "legacy" || p.Findings[0].Acknowledged.ExpiresAt != nil {
		t.Errorf("preflight = %+v, %v", p, err)
	}

	c, _ = recordingClient(t, `{"object":"list","data":[{"object":"preflight_ack","code":"pkce_not_required","reason":"r","by":null,"at":5,"expires_at":9,"active":false}],"has_more":false}`)
	acks, err := c.Instance.PreflightAcks(ctx)
	if err != nil || len(acks.Data) != 1 || acks.Data[0].Code != "pkce_not_required" || acks.Data[0].Active || acks.Data[0].At != 5 || *acks.Data[0].ExpiresAt != 9 {
		t.Errorf("acks = %+v, %v", acks, err)
	}

	c, _ = recordingClient(t, `{"object":"oauth_client","id":"oac_1","client_secret":"s","require_verified_email":true,"client_secret_reveal":{"path":"/v1/oauth_clients/oac_1/secret/reveal","expires_at":7},"note":"n"}`)
	cl, err := c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "App"})
	if err != nil || !cl.RequireVerifiedEmail || cl.ClientSecretReveal == nil || cl.ClientSecretReveal.Path != "/v1/oauth_clients/oac_1/secret/reveal" || cl.ClientSecretReveal.ExpiresAt != 7 {
		t.Errorf("client = %+v, %v", cl, err)
	}

	c, _ = recordingClient(t, `{"object":"oauth_client_secret","id":"oac_1","client_id":"atlas_client_1","client_secret":"s","secret_prefix":"sk","client_secret_expires_at":null,"note":"n"}`)
	rv, err := c.OAuthClients.RevealSecret(ctx, "oac_1")
	if err != nil || rv.ClientSecret != "s" || rv.ClientID != "atlas_client_1" || rv.ClientSecretExpiresAt != nil {
		t.Errorf("reveal = %+v, %v", rv, err)
	}

	c, _ = recordingClient(t, `{"object":"messaging_test","channel":"email","sent_to":"a@example.com","ok":true,"accepted":true,"provider":"smtp","provider_message_id":"q1","provider_response":"250 queued as q1"}`)
	mt, err := c.Messaging.Test(ctx, "email", "a@example.com")
	if err != nil || !mt.Accepted || mt.Provider != "smtp" || mt.ProviderMessageID == nil || *mt.ProviderMessageID != "q1" || mt.ProviderResponse != "250 queued as q1" {
		t.Errorf("messaging test = %+v, %v", mt, err)
	}

	c, _ = recordingClient(t, `{"object":"webhook_test_result","delivery_id":"d","event_id":"e","url":"https://hooks.example.com/atlas","status":"success"}`)
	wt, err := c.Webhooks.Endpoints.TestNow(ctx, "we_1", "")
	if err != nil || wt.URL != "https://hooks.example.com/atlas" {
		t.Errorf("webhook test = %+v, %v", wt, err)
	}

	c, _ = recordingClient(t, `{"id":"user_1","status":"suspended"}`)
	u, err := c.Users.Get(ctx, "user_1")
	if err != nil || u.Status != UserStatusSuspended {
		t.Errorf("user = %+v, %v", u, err)
	}

	c, _ = recordingClient(t, `{"object":"before_user_create_hook","enabled":true,"fail_closed":true,"timeout_ms":3000}`)
	h, err := c.UserHooks.GetBeforeUserCreate(ctx)
	if err != nil || !h.FailClosed {
		t.Errorf("hook = %+v, %v", h, err)
	}

	if WebhookEventSessionExpired != "session.expired" || WebhookEventInvitationAccepted != "invitation.accepted" {
		t.Error("event constants")
	}
}
