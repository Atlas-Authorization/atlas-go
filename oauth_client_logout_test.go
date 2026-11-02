package atlas

import (
	"context"
	"encoding/json"
	"testing"
)

// TestOAuthClientLogoutSurface walks the 0.23.0 additions: OAuthClients.Logout,
// refresh_touches_session / add_redirect_origins on client writes and site_key
// on the captcha secret: method, path and body for each.
func TestOAuthClientLogoutSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x"}`)
	yes, no := true, false

	cases := []struct {
		method, path, body string
		call               func() error
	}{
		{"POST", "/v1/oauth_clients/oac_1/logout", `{"sid":"sess_1"}`, func() error { _, err := c.OAuthClients.Logout(ctx, "oac_1", "sess_1"); return err }},
		{"POST", "/v1/oauth_clients", `{"name":"App","redirect_uris":["https://app.example.com/cb"],"first_party":true,"refresh_touches_session":true,"add_redirect_origins":true}`, func() error {
			_, err := c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, FirstParty: &yes, RefreshTouchesSession: &yes, AddRedirectOrigins: true})
			return err
		}},
		{"PATCH", "/v1/oauth_clients/oac_1", `{"refresh_touches_session":false,"add_redirect_origins":true}`, func() error {
			_, err := c.OAuthClients.Update(ctx, "oac_1", UpdateOAuthClientParams{RefreshTouchesSession: &no, AddRedirectOrigins: true})
			return err
		}},
		{"PUT", "/v1/instance/captcha_secret", `{"secret":"0x4AAA","provider":"turnstile","site_key":"0x4BBB"}`, func() error {
			_, err := c.InstanceSecurity.SetCaptchaSecretWithParams(ctx, SetCaptchaSecretParams{Secret: "0x4AAA", Provider: "turnstile", SiteKey: "0x4BBB"})
			return err
		}},
	}
	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.path, err)
			continue
		}
		rec.expect(t, tc.method, tc.path)
		var want map[string]interface{}
		_ = json.Unmarshal([]byte(tc.body), &want)
		got, _ := json.Marshal(rec.Body)
		exp, _ := json.Marshal(want)
		if string(got) != string(exp) {
			t.Errorf("%s %s body = %s, want %s", tc.method, tc.path, got, exp)
		}
	}
}

// TestOAuthClientLogoutDecode checks the new response fields decode.
func TestOAuthClientLogoutDecode(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"oauth_client_logout","client_id":"atlas_client_1","sid":"sess_1","session":"revoked","grants_revoked":2,"backchannel_logouts":3}`)
	out, err := c.OAuthClients.Logout(ctx, "oac_1", "sess_1")
	if err != nil || out.Session != "revoked" || out.GrantsRevoked != 2 || out.BackchannelLogouts != 3 || out.SID != "sess_1" {
		t.Errorf("logout = %+v, %v", out, err)
	}
	c2, _ := recordingClient(t, `{"object":"oauth_client","id":"oac_1","refresh_touches_session":true,"added_origins":["https://app.example.com"]}`)
	cl, err := c2.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}})
	if err != nil || !cl.RefreshTouchesSession || len(cl.AddedOrigins) != 1 || cl.AddedOrigins[0] != "https://app.example.com" {
		t.Errorf("client = %+v, %v", cl, err)
	}
	c3, _ := recordingClient(t, `{"object":"captcha_secret","provider":"turnstile","set":true,"switched":true,"captcha":{"provider":"turnstile","siteKey":"0x4BBB"}}`)
	cs, err := c3.InstanceSecurity.SetCaptchaSecretWithParams(ctx, SetCaptchaSecretParams{Secret: "0x4AAA", SiteKey: "0x4BBB"})
	if err != nil || !cs.Switched || cs.Captcha["siteKey"] != "0x4BBB" {
		t.Errorf("captcha = %+v, %v", cs, err)
	}
}
