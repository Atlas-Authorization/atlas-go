package atlas

import (
	"context"
	"encoding/json"
	"testing"
)

// TestAddedOperations walks the origin move, instance connections and
// integrations, logout fan-out, managed email, back-channel delivery logs and
// tests, the Sign in with Atlas app lookups, the publisher and the platform
// config changelog: method, path, query and body for each.
func TestAddedOperations(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","data":[],"changes":[],"problems":[]}`, WithPlatformKey("psk_test"))
	move := OriginMoveParams{From: "https://old.example.com", To: "https://new.example.com", DryRun: true}
	moveBody := `{"dry_run":true,"from":"https://old.example.com","to":"https://new.example.com"}`

	cases := []struct {
		method, path, query, body string
		call                      func() error
	}{
		{"POST", "/v1/instance/move_origin", "", moveBody, func() error { _, err := c.Instance.MoveOrigin(ctx, move); return err }},
		{"GET", "/v1/instance/connections", "", "", func() error { _, err := c.Instance.Connections(ctx); return err }},
		{"GET", "/v1/instance/integrations/chatly", "", "", func() error { _, err := c.Instance.ChatlyIntegration(ctx); return err }},
		{"PUT", "/v1/instance/integrations/chatly", "", `{"channel":"support"}`, func() error {
			_, err := c.Instance.SetChatlyIntegration(ctx, SetChatlyIntegrationParams{Channel: "support"})
			return err
		}},
		{"DELETE", "/v1/instance/integrations/chatly", "", "", func() error { _, err := c.Instance.DeleteChatlyIntegration(ctx); return err }},
		{"GET", "/v1/instance/integrations/forumulate", "", "", func() error { _, err := c.Instance.ForumulateIntegration(ctx); return err }},
		{"PUT", "/v1/instance/integrations/forumulate", "", `{"org_id":"org_1","spaces":[{"id":"sp_1"}]}`, func() error {
			_, err := c.Instance.SetForumulateIntegration(ctx, SetForumulateIntegrationParams{OrgID: "org_1", Spaces: []ForumulateSpace{{ID: "sp_1"}}})
			return err
		}},
		{"DELETE", "/v1/instance/integrations/forumulate", "", "", func() error { _, err := c.Instance.DeleteForumulateIntegration(ctx); return err }},
		{"GET", "/v1/logout_notify_endpoints", "", "", func() error { _, err := c.LogoutNotifyEndpoints.List(ctx); return err }},
		{"POST", "/v1/logout_notify_endpoints", "", `{"url":"https://hooks.example.com/logout"}`, func() error {
			_, err := c.LogoutNotifyEndpoints.Create(ctx, CreateLogoutNotifyEndpointParams{URL: "https://hooks.example.com/logout"})
			return err
		}},
		{"GET", "/v1/logout_notify_endpoints/lne_1", "", "", func() error { _, err := c.LogoutNotifyEndpoints.Get(ctx, "lne_1"); return err }},
		{"PATCH", "/v1/logout_notify_endpoints/lne_1", "", `{"description":"x"}`, func() error {
			_, err := c.LogoutNotifyEndpoints.Update(ctx, "lne_1", UpdateLogoutNotifyEndpointParams{Description: "x"})
			return err
		}},
		{"DELETE", "/v1/logout_notify_endpoints/lne_1", "", "", func() error { _, err := c.LogoutNotifyEndpoints.Delete(ctx, "lne_1"); return err }},
		{"GET", "/v1/logout_notify_endpoints/lne_1/deliveries", "limit=5", "", func() error { _, err := c.LogoutNotifyEndpoints.Deliveries(ctx, "lne_1", 5); return err }},
		{"GET", "/v1/messaging_providers/email/managed", "", "", func() error { _, err := c.Messaging.ManagedEmail(ctx); return err }},
		{"POST", "/v1/messaging_providers/email/managed", "", `{"dns":{"api_token":"t","provider":"cloudflare"},"from_address":"no-reply@example.com"}`, func() error {
			_, err := c.Messaging.CreateManagedEmail(ctx, CreateManagedEmailParams{FromAddress: "no-reply@example.com", DNS: &CustomDomainDNSParams{Provider: "cloudflare", APIToken: "t"}})
			return err
		}},
		{"POST", "/v1/messaging_providers/email/managed/verify", "", "", func() error { _, err := c.Messaging.VerifyManagedEmail(ctx); return err }},
		{"DELETE", "/v1/messaging_providers/email/managed", "force=true", "", func() error {
			_, err := c.Messaging.DeleteManagedEmail(ctx, DeleteMessagingProviderParams{Force: true})
			return err
		}},
		{"GET", "/v1/oauth_clients/oac_1/backchannel_deliveries", "limit=10", "", func() error {
			_, err := c.OAuthClients.ListBackchannelDeliveries(ctx, "oac_1", ListParams{Limit: 10})
			return err
		}},
		{"POST", "/v1/oauth_clients/oac_1/backchannel_logout/test", "", "", func() error { _, err := c.OAuthClients.TestBackchannelLogout(ctx, "oac_1"); return err }},
		{"POST", "/v1/users/u_1/sessions/revoke", "", `{"revoke_grants":true}`, func() error {
			_, err := c.Users.RevokeSessionsWithParams(ctx, "u_1", RevokeSessionsParams{RevokeGrants: true})
			return err
		}},
		{"GET", "/v1/platform/atlas_id_apps/app_1/backchannel_deliveries", "starting_after=d_1", "", func() error {
			_, err := c.Platform.AtlasIDApps.ListBackchannelDeliveries(ctx, "app_1", ListParams{StartingAfter: "d_1"})
			return err
		}},
		{"POST", "/v1/platform/atlas_id_apps/app_1/backchannel_logout/test", "", "", func() error { _, err := c.Platform.AtlasIDApps.TestBackchannelLogout(ctx, "app_1"); return err }},
		{"GET", "/v1/platform/atlas_id_apps/app_1/preflight", "", "", func() error { _, err := c.Platform.AtlasIDApps.Preflight(ctx, "app_1"); return err }},
		{"GET", "/v1/platform/atlas_id_apps/app_1/users", "email=a%40example.com", "", func() error {
			_, err := c.Platform.AtlasIDApps.FindUsers(ctx, "app_1", "a@example.com")
			return err
		}},
		{"DELETE", "/v1/platform/atlas_id_apps/app_1/grants/gr_1", "", "", func() error { _, err := c.Platform.AtlasIDApps.RevokeGrant(ctx, "app_1", "gr_1"); return err }},
		{"POST", "/v1/platform/atlas_id_apps/app_1/move_origin", "", moveBody, func() error { _, err := c.Platform.AtlasIDApps.MoveOrigin(ctx, "app_1", move); return err }},
		{"POST", "/v1/platform/atlas_id_apps/app_1/webhook/rotate_secret", "", "", func() error { _, err := c.Platform.AtlasIDApps.RotateWebhookSecret(ctx, "app_1"); return err }},
		{"GET", "/v1/platform/atlas_id_publisher", "", "", func() error { _, err := c.Platform.AtlasIDPublisher.Get(ctx); return err }},
		{"PUT", "/v1/platform/atlas_id_publisher", "", `{"domain":"example.com","name":"Acme"}`, func() error {
			_, err := c.Platform.AtlasIDPublisher.Set(ctx, SetAtlasIDPublisherParams{Name: "Acme", Domain: "example.com"})
			return err
		}},
		{"PATCH", "/v1/platform/atlas_id_publisher", "", `{"skip_consent":true}`, func() error { _, err := c.Platform.AtlasIDPublisher.SetSkipConsent(ctx, true); return err }},
		{"DELETE", "/v1/platform/atlas_id_publisher", "", "", func() error { _, err := c.Platform.AtlasIDPublisher.Delete(ctx); return err }},
		{"POST", "/v1/platform/atlas_id_publisher/verify", "", "", func() error { _, err := c.Platform.AtlasIDPublisher.Verify(ctx); return err }},
		{"GET", "/v1/platform/config_changelog", "action=atlas_id_app.updated&limit=5", "", func() error {
			_, err := c.Platform.ConfigChangelog(ctx, ConfigChangelogParams{ListParams: ListParams{Limit: 5}, Action: "atlas_id_app.updated"})
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
			if rec.RawBody != "" {
				t.Errorf("%s %s unexpected body %s", tc.method, tc.path, rec.RawBody)
			}
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

// TestAddedFieldsDecode checks the new response fields decode.
func TestAddedFieldsDecode(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"cookie_consent","enabled":true,"culture":"page","declared_cookies":[{"name":"__session","pattern":null,"store":"cookie","domain":".example.com","lifetime_seconds":null,"lifetime":"session","http_only":true,"category":"necessary","purpose":"p","written_when":"w","set_by":"atlas_frontend_api"}]}`)
	cc, err := c.Instance.CookieConsent(ctx)
	if err != nil || cc.Culture != "page" || len(cc.DeclaredCookies) != 1 || cc.DeclaredCookies[0].Store != "cookie" || !cc.DeclaredCookies[0].HTTPOnly {
		t.Errorf("cookie consent = %+v, %v", cc, err)
	}
	c2, _ := recordingClient(t, `{"object":"origin_move","from":"https://old.example.com","to":"https://new.example.com","dry_run":false,"applied":true,"changes":[{"object":"oauth_client","id":"oac_1","field":"redirect_uris","before":["https://old.example.com/cb"],"after":["https://new.example.com/cb"]}],"problems":[]}`)
	mv, err := c2.Instance.MoveOrigin(ctx, OriginMoveParams{From: "https://old.example.com", To: "https://new.example.com"})
	if err != nil || !mv.Applied || mv.Changes[0].Field != "redirect_uris" {
		t.Errorf("move = %+v, %v", mv, err)
	}
}
