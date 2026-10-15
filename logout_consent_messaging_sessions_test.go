package atlas

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestOAuthClientSkipLogoutConfirmation(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"oauth_client","id":"oc_1","client_id":"cid","name":"App","logo_url":null,"redirect_uris":[],"allowed_scopes":[],"grant_types":[],"token_endpoint_auth_method":"client_secret_basic","secret_prefix":null,"is_public":false,"first_party":true,"skip_logout_confirmation":true,"created_at":1,"updated_at":2}`)
	ctx := context.Background()
	tr, f := true, false

	created, err := c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "App", RedirectURIs: []string{"https://app.test/cb"}, FirstParty: &tr, SkipLogoutConfirmation: &tr})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/oauth_clients")
	if rec.Body["skip_logout_confirmation"] != true {
		t.Errorf("create body = %s", rec.RawBody)
	}
	if !created.SkipLogoutConfirmation || !created.FirstParty {
		t.Errorf("decoded create = %+v", created)
	}

	if _, err := c.OAuthClients.Update(ctx, "oc_1", UpdateOAuthClientParams{SkipLogoutConfirmation: &f}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PATCH", "/v1/oauth_clients/oc_1")
	if v, ok := rec.Body["skip_logout_confirmation"]; !ok || v != false {
		t.Errorf("update body = %s", rec.RawBody)
	}

	if _, err := c.OAuthClients.Update(ctx, "oc_1", UpdateOAuthClientParams{Name: "Renamed"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Body["skip_logout_confirmation"]; ok {
		t.Errorf("skip_logout_confirmation sent when unset: %s", rec.RawBody)
	}

	got, err := c.OAuthClients.Get(ctx, "oc_1")
	if err != nil || !got.SkipLogoutConfirmation {
		t.Fatalf("get = %+v %v", got, err)
	}
}

func TestCookieConsentSettingsLink(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		return `{"object":"cookie_consent","enabled":true,"script_url":"https://cmp.test/s.js","settings_link":{"label":"Cookie settings","preset":"cookiebot","attributes":{"class":"cs"},"rendered_attributes":{"class":"cs","data-cc":"settings"}}}`
	})
	ctx := context.Background()

	cc, err := c.Instance.SetCookieConsent(ctx, SetCookieConsentParams{
		ScriptURL: "https://cmp.test/s.js",
		SettingsLink: &CookieSettingsLinkInput{
			Label:      "Cookie settings",
			Preset:     CookieSettingsLinkPresetCookiebot,
			Attributes: map[string]string{"class": "cs"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got[0].Body) != `{"script_url":"https://cmp.test/s.js","settings_link":{"label":"Cookie settings","preset":"cookiebot","attributes":{"class":"cs"}}}` {
		t.Errorf("cookie consent body = %s", got[0].Body)
	}
	l := cc.SettingsLink
	if l == nil || l.Label != "Cookie settings" || l.Preset == nil || *l.Preset != CookieSettingsLinkPresetCookiebot ||
		l.Attributes["class"] != "cs" || l.RenderedAttributes["data-cc"] != "settings" {
		t.Fatalf("settings link = %+v", l)
	}

	if _, err := c.Instance.SetCookieConsent(ctx, SetCookieConsentParams{ScriptURL: "https://cmp.test/s.js"}); err != nil {
		t.Fatal(err)
	}
	if string(got[1].Body) != `{"script_url":"https://cmp.test/s.js"}` {
		t.Errorf("no-link body = %s", got[1].Body)
	}

	for _, p := range []string{CookieSettingsLinkPresetCookiemunch, CookieSettingsLinkPresetCookiebot, CookieSettingsLinkPresetOneTrust, CookieSettingsLinkPresetCustom} {
		if p == "" {
			t.Errorf("empty preset constant")
		}
	}
}

func TestCookieConsentSettingsLinkUnknownPreset(t *testing.T) {
	c, _ := recordingClient(t, `{"object":"cookie_consent","enabled":true,"settings_link":{"label":"Prefs","preset":"future_cmp","attributes":{},"rendered_attributes":{}}}`)
	cc, err := c.Instance.CookieConsent(context.Background())
	if err != nil || cc.SettingsLink == nil || *cc.SettingsLink.Preset != "future_cmp" {
		t.Fatalf("cookie consent = %+v %v", cc, err)
	}
}

func TestMessagingDeleteChannelForce(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"messaging_provider","channel":"email","deleted":true}`)
	ctx := context.Background()

	out, err := c.Messaging.DeleteChannel(ctx, "email")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "DELETE", "/v1/messaging_providers/email")
	if rec.Query != "" {
		t.Errorf("query = %q, want none", rec.Query)
	}
	if !out.Deleted || out.Channel != "email" || out.Object != "messaging_provider" {
		t.Errorf("decoded = %+v", out)
	}

	if _, err := c.Messaging.DeleteChannelWithParams(ctx, "email", DeleteMessagingProviderParams{}); err != nil {
		t.Fatal(err)
	}
	if rec.Query != "" {
		t.Errorf("query = %q, want none", rec.Query)
	}

	if _, err := c.Messaging.DeleteChannelWithParams(ctx, "email", DeleteMessagingProviderParams{Force: true}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "DELETE", "/v1/messaging_providers/email")
	if rec.Query != "force=true" {
		t.Errorf("query = %q, want force=true", rec.Query)
	}
}

func TestMessagingDeleteChannelEmailProviderInUse(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"code":"EMAIL_PROVIDER_IN_USE","message":"in use","meta":{"features":["emailCode","passwordReset"]}}]}`))
	})
	_, err := c.Messaging.DeleteChannel(context.Background(), "email")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || !apiErr.HasCode(ErrCodeEmailProviderInUse) {
		t.Fatalf("err = %v", err)
	}
	if features, ok := apiErr.Errors[0].Meta["features"].([]interface{}); !ok || len(features) != 2 || features[0] != "emailCode" {
		t.Errorf("meta = %+v", apiErr.Errors[0].Meta)
	}
	if ErrCodeEmailProviderInUse != "EMAIL_PROVIDER_IN_USE" || ErrCodeEmailProviderRequired != "EMAIL_PROVIDER_REQUIRED" {
		t.Errorf("code constants = %q %q", ErrCodeEmailProviderInUse, ErrCodeEmailProviderRequired)
	}
}

func TestUserListSessionsDecodesIdleAndActor(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"list","data":[{"object":"session","id":"sess_1","user_id":"user_1","status":"active","last_active_organization_id":"org_1","impersonated_by":"user_admin","last_active_at":1,"expire_at":9,"abandon_at":5,"idle_expires_at":5,"created_at":0},{"object":"session","id":"sess_2","user_id":"user_1","status":"active","last_active_organization_id":null,"impersonated_by":null,"last_active_at":1,"expire_at":9,"abandon_at":5,"created_at":0}],"has_more":false}`)
	page, err := c.Users.ListSessions(context.Background(), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/users/user_1/sessions")
	if len(page.Data) != 2 {
		t.Fatalf("decoded = %+v", page)
	}
	s := page.Data[0]
	if s.IdleExpiresAt != 5 || s.IdleExpiresAt != s.AbandonAt || s.LastActiveOrganizationID == nil || *s.LastActiveOrganizationID != "org_1" ||
		s.ImpersonatedBy == nil || *s.ImpersonatedBy != "user_admin" {
		t.Errorf("session = %+v", s)
	}
	if s2 := page.Data[1]; s2.IdleExpiresAt != 0 || s2.LastActiveOrganizationID != nil || s2.ImpersonatedBy != nil {
		t.Errorf("legacy session = %+v", s2)
	}
}

func TestSessionGetAndListDecodeIdleExpiresAt(t *testing.T) {
	c, _ := recordingClient(t, `{"object":"list","data":[{"object":"session","id":"sess_1","abandon_at":5,"idle_expires_at":5}],"id":"sess_1","abandon_at":5,"idle_expires_at":5,"has_more":false}`)
	ctx := context.Background()
	s, err := c.Sessions.Get(ctx, "sess_1")
	if err != nil || s.IdleExpiresAt != 5 {
		t.Fatalf("get = %+v %v", s, err)
	}
	page, err := c.Sessions.List(ctx, "user_1")
	if err != nil || len(page.Data) != 1 || page.Data[0].IdleExpiresAt != 5 {
		t.Fatalf("list = %+v %v", page, err)
	}
}

func TestCaptchaSecretBYOK(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"captcha_secret","provider":"hcaptcha","deleted":true,"flows_turned_off":["signUp"]}`)
	ctx := context.Background()

	if _, err := c.InstanceSecurity.SetCaptchaSecretWithParams(ctx, SetCaptchaSecretParams{Secret: "s3cret", Provider: "turnstile"}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PUT", "/v1/instance/captcha_secret")
	if rec.Body["provider"] != "turnstile" || rec.Body["secret"] != "s3cret" {
		t.Errorf("body = %v", rec.Body)
	}

	out, err := c.InstanceSecurity.DeleteCaptchaSecretWithParams(ctx, DeleteCaptchaSecretParams{Provider: "hcaptcha", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "DELETE", "/v1/instance/captcha_secret")
	if rec.Query != "force=true&provider=hcaptcha" {
		t.Errorf("query = %q", rec.Query)
	}
	if len(out.FlowsTurnedOff) != 1 || out.FlowsTurnedOff[0] != "signUp" {
		t.Errorf("decoded = %+v", out)
	}

	if _, err := c.InstanceSecurity.DeleteCaptchaSecret(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.Query != "" {
		t.Errorf("query = %q, want none", rec.Query)
	}
	if ErrCodeCaptchaKeysRequired != "CAPTCHA_KEYS_REQUIRED" || ErrCodeCaptchaInUse != "CAPTCHA_IN_USE" {
		t.Error("captcha error codes")
	}
}
