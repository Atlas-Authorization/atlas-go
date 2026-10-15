package atlas

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const designSettingsJSON = `{"object":"design","design":{"version":1,"preset":"midnight","palette":{"primary":"#112233"},"background":{"gradient":{"type":"linear","angle":90,"stops":[{"color":"#000000","at":0},{"color":"#ffffff","at":1}]}}},
"resolved":{"version":1,"preset":"midnight","colorScheme":"dark","palette":{"primary":"#112233"},"paletteDark":{"primary":"#445566"},"typography":{},"shape":{"radius":8},"elevation":{},"spacing":{},"card":{},"layout":{},"buttons":{},"inputs":{},"background":{},"backgroundDark":{},"logo":{}},
"warnings":[],"legacy":false,"legacy_design":null}`

func TestDesignInstanceAndOrganization(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/design/catalog":
			return `{"object":"design_catalog","version":1,"presets":[{"id":"glass","label":"Glass","description":"d","resolved":{"preset":"glass"}}],"fonts":[{"id":"inter","label":"Inter","family":"Inter","category":"sans","web_font":true,"stylesheet":"/v1/design/fonts/inter.css"}],"css_variables":[{"name":"--atlas-color-primary","type":"color","perMode":true,"description":"d"}]}`
		case "/v1/instance/design/preview":
			return `{"object":"design_preview","scope":".atlas-root","css":"x","data_attributes":{},"font_stylesheets":["https://f.test/a.css"],"resolved":{},"warnings":[],"html":"<p/>"}`
		}
		if strings.HasPrefix(r.URL.Path, "/v1/organizations/") {
			return `{"object":"organization_design","organization_id":"org_1","design":{},"resolved":{},"warnings":[],"legacy":false}`
		}
		return designSettingsJSON
	})
	ctx := context.Background()

	s, err := c.Design.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Design.Preset != "midnight" || s.Design.Palette.Primary != "#112233" || *s.Design.Background.Gradient.Angle != 90 ||
		s.Design.Background.Gradient.Stops[1].At != 1 || s.Resolved.PaletteDark["primary"] != "#445566" || s.Resolved.Shape["radius"] != float64(8) {
		t.Errorf("decoded design = %+v", s)
	}
	if _, err := c.Design.Replace(ctx, Design{Preset: "atlas", Layout: &DesignLayout{Position: "split", SplitImageSide: "left"}}); err != nil {
		t.Fatal(err)
	}
	if string(got[1].Body) != `{"design":{"preset":"atlas","layout":{"position":"split","splitImageSide":"left"}}}` {
		t.Errorf("replace body = %s", got[1].Body)
	}
	if _, err := c.Design.Update(ctx, DesignPatch{"palette": map[string]interface{}{"primary": "#000000"}, "logo": nil}); err != nil {
		t.Fatal(err)
	}
	if string(got[2].Body) != `{"design":{"logo":null,"palette":{"primary":"#000000"}}}` {
		t.Errorf("patch body = %s", got[2].Body)
	}
	p, err := c.Design.Preview(ctx, Design{Preset: "glass"})
	if err != nil || p.HTML != "<p/>" || p.FontStylesheets[0] != "https://f.test/a.css" {
		t.Fatalf("preview = %+v %v", p, err)
	}
	o, err := c.Design.GetOrganization(ctx, "org_1")
	if err != nil || o.OrganizationID != "org_1" {
		t.Fatalf("org get = %+v %v", o, err)
	}
	if _, err := c.Design.ReplaceOrganization(ctx, "org_1", Design{}); err != nil {
		t.Fatal(err)
	}
	if string(got[5].Body) != `{"design":{}}` {
		t.Errorf("org replace (remove) body = %s", got[5].Body)
	}
	if _, err := c.Design.UpdateOrganization(ctx, "org_1", DesignPatch{"preset": nil}); err != nil {
		t.Fatal(err)
	}
	cat, err := c.Design.Catalog(ctx)
	if err != nil || cat.Fonts[0].WebFont != true || !cat.CSSVariables[0].PerMode || cat.Presets[0].Resolved.Preset != "glass" {
		t.Fatalf("catalog = %+v %v", cat, err)
	}
	want := []string{"GET /v1/instance/design", "PUT /v1/instance/design", "PATCH /v1/instance/design", "POST /v1/instance/design/preview",
		"GET /v1/organizations/org_1/design", "PUT /v1/organizations/org_1/design", "PATCH /v1/organizations/org_1/design", "GET /v1/design/catalog"}
	for i, w := range want {
		if g := got[i].Method + " " + got[i].Path; g != w {
			t.Errorf("request %d = %s, want %s", i, g, w)
		}
	}
}

func TestPreflightAndCookieConsent(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		if r.URL.Path == "/v1/instance/preflight" {
			return `{"object":"preflight","ok":false,"checked_at":5,"findings":[{"severity":"error","code":"oauth_provider_missing_credentials","message":"m","fix":"f","subject":{"provider":"google"}},{"severity":"info","code":"x","message":"m","fix":"f"}]}`
		}
		if r.Method == http.MethodDelete {
			return `{"object":"cookie_consent","enabled":false}`
		}
		return `{"object":"cookie_consent","enabled":true,"script_url":"https://cmp.test/s.js","script_id":null,"site_id":"cb_1","blocking_mode":"auto","extra_origins":["https://api.cmp.test"]}`
	})
	ctx := context.Background()
	pf, err := c.Instance.Preflight(ctx)
	if err != nil || pf.OK || len(pf.Findings) != 2 || pf.Findings[0].Subject["provider"] != "google" || len(pf.Errors()) != 1 {
		t.Fatalf("preflight = %+v %v", pf, err)
	}
	cc, err := c.Instance.SetCookieConsent(ctx, SetCookieConsentParams{ScriptURL: "https://cmp.test/s.js", SiteID: "cb_1", BlockingMode: "auto", ExtraOrigins: []string{"https://api.cmp.test"}})
	if err != nil || !cc.Enabled || *cc.SiteID != "cb_1" || cc.ScriptID != nil {
		t.Fatalf("cookie consent = %+v %v", cc, err)
	}
	if string(got[1].Body) != `{"script_url":"https://cmp.test/s.js","site_id":"cb_1","blocking_mode":"auto","extra_origins":["https://api.cmp.test"]}` {
		t.Errorf("cookie consent body = %s", got[1].Body)
	}
	if _, err := c.Instance.CookieConsent(ctx); err != nil {
		t.Fatal(err)
	}
	off, err := c.Instance.DeleteCookieConsent(ctx)
	if err != nil || off.Enabled {
		t.Fatalf("delete = %+v %v", off, err)
	}
	want := []string{"GET /v1/instance/preflight", "PUT /v1/instance/cookie_consent", "GET /v1/instance/cookie_consent", "DELETE /v1/instance/cookie_consent"}
	for i, w := range want {
		if g := got[i].Method + " " + got[i].Path; g != w {
			t.Errorf("request %d = %s, want %s", i, g, w)
		}
	}
}

func TestOAuthProvidersFiltersAndUpsert(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		if r.Method == http.MethodPut {
			return `{"object":"oauth_provider","provider":"siwe","configured":true,"enabled":false,"setting_values":{"domain":"shop.test","chain_ids":"1,10"},"updated_fields":["settings","display_name"],"warning":"w"}`
		}
		return `{"object":"list","data":[{"object":"oauth_provider","provider":"google","display_name":"Google","configured":true,"enabled":true,"allow_sign_in":true,"allow_sign_up":true,"mode":"redirect","icon_url":"https://i.test/g.png","setting_values":{},"javascript_origins":["https://shop.test"]}]}`
	})
	ctx := context.Background()
	yes := true
	l, err := c.OAuthProviders.ListFiltered(ctx, ListOAuthProvidersParams{Providers: []string{"google", "github"}, Configured: &yes})
	if err != nil || l.Data[0].Mode != "redirect" || *l.Data[0].IconURL != "https://i.test/g.png" || l.Data[0].JavaScriptOrigins[0] != "https://shop.test" {
		t.Fatalf("list = %+v %v", l, err)
	}
	if got[0].Query != "configured=true&provider=google%2Cgithub" {
		t.Errorf("list query = %q", got[0].Query)
	}

	name, mode := "Discord", ""
	res, err := c.OAuthProviders.Upsert(ctx, "siwe", UpsertOAuthProviderParams{
		DisplayName:  &name,
		Mode:         &mode,
		Settings:     map[string]string{"statement": "Sign in"},
		SettingsJSON: WalletSettings{Domain: "shop.test", ChainIDs: []int{1, 10}, Clear: []string{"rpc_url"}}.Map(),
	})
	if err != nil || res.SettingValues["chain_ids"] != "1,10" || res.UpdatedFields[1] != "display_name" || res.Warning != "w" {
		t.Fatalf("upsert = %+v %v", res, err)
	}
	b := bodyMap(t, got[1].Body)
	st := b["settings"].(map[string]interface{})
	if b["display_name"] != "Discord" || b["mode"] != "" || st["domain"] != "shop.test" || st["statement"] != "Sign in" ||
		len(st["chain_ids"].([]interface{})) != 2 {
		t.Errorf("upsert body = %s", got[1].Body)
	}
	if v, ok := st["rpc_url"]; !ok || v != nil {
		t.Errorf("rpc_url must be null: %s", got[1].Body)
	}
	if _, ok := b["client_id"]; ok {
		t.Errorf("unset client_id must be omitted: %s", got[1].Body)
	}
	if got[1].Method != http.MethodPut || got[1].Path != "/v1/oauth_providers/siwe" {
		t.Errorf("upsert request = %s %s", got[1].Method, got[1].Path)
	}
	// Plain credentials still encode exactly as before.
	if _, err := c.OAuthProviders.Upsert(ctx, "google", UpsertOAuthProviderParams{ClientID: "id", ClientSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	if string(got[2].Body) != `{"client_id":"id","client_secret":"s"}` {
		t.Errorf("credential body = %s", got[2].Body)
	}
}

func TestWebhookEndpointsComplete(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/reveal_secret"):
			return `{"object":"webhook_secret","secret":"whsec_old"}`
		case strings.HasSuffix(p, "/rotate_secret"):
			return `{"object":"webhook_secret","secret":"whsec_new","warning":"old rejected"}`
		case strings.HasSuffix(p, "/test"), strings.HasSuffix(p, "/redeliver"):
			return `{"object":"webhook_delivery","id":"del_2","event_id":"evt_1","status":"pending","note":"n"}`
		case strings.HasSuffix(p, "/deliveries"):
			return `{"object":"list","data":[{"object":"webhook_delivery","id":"del_1","event_id":"evt_1","event_type":"user.created","attempt_number":1,"max_attempts":8,"payload":{"a":1},"status":"success","http_status":200,"response_snippet":"ok","next_retry_at":null,"delivered_at":5,"created_at":4}]}`
		case r.Method == http.MethodGet:
			return `{"object":"list","data":[{"object":"webhook_endpoint","id":"we_1","url":"https://h.test","enabled_events":["*"],"active":true,"failing_since":7,"disabled_at":null,"created_at":1}],"has_more":false,"available_events":["user.created"],"retry_schedule_ms":[1000,5000],"max_attempts":8}`
		}
		return `{"object":"webhook_endpoint","id":"we_1","url":"https://h2.test","enabled_events":["user.created"],"active":false,"failing_since":null,"disabled_at":null,"created_at":1}`
	}, WithStrict(true))
	ctx := context.Background()
	no := false
	ep, err := c.Webhooks.Endpoints.Update(ctx, "we_1", UpdateWebhookEndpointParams{URL: "https://h2.test", Active: &no})
	if err != nil || ep.URL != "https://h2.test" || ep.Active {
		t.Fatalf("update = %+v %v", ep, err)
	}
	if string(got[0].Body) != `{"url":"https://h2.test","active":false}` || got[0].Method != http.MethodPatch || got[0].Strict != "true" {
		t.Errorf("update request = %+v body=%s", got[0], got[0].Body)
	}
	l, err := c.Webhooks.Endpoints.ListDetailed(ctx)
	if err != nil || *l.Data[0].FailingSince != 7 || l.MaxAttempts != 8 || l.RetryScheduleMS[1] != 5000 || l.AvailableEvents[0] != "user.created" {
		t.Fatalf("list = %+v %v", l, err)
	}
	d, err := c.Webhooks.Endpoints.Deliveries(ctx, "we_1", 10)
	if err != nil || *d.Data[0].EventType != "user.created" || d.Data[0].MaxAttempts != 8 || got[2].Query != "limit=10" {
		t.Fatalf("deliveries = %+v %v (query %q)", d, err, got[2].Query)
	}
	rv, err := c.Webhooks.Endpoints.RevealSecret(ctx, "we_1")
	if err != nil || rv.Secret != "whsec_old" {
		t.Fatalf("reveal = %+v %v", rv, err)
	}
	rt, err := c.Webhooks.Endpoints.RotateSecret(ctx, "we_1")
	if err != nil || rt.Secret != "whsec_new" || rt.Warning == "" {
		t.Fatalf("rotate = %+v %v", rt, err)
	}
	ts, err := c.Webhooks.Endpoints.Test(ctx, "we_1")
	if err != nil || ts.EventID != "evt_1" {
		t.Fatalf("test = %+v %v", ts, err)
	}
	if _, err := c.Webhooks.Endpoints.Redeliver(ctx, "we_1", "del_1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"PATCH /v1/webhook_endpoints/we_1", "GET /v1/webhook_endpoints", "GET /v1/webhook_endpoints/we_1/deliveries",
		"POST /v1/webhook_endpoints/we_1/reveal_secret", "POST /v1/webhook_endpoints/we_1/rotate_secret",
		"POST /v1/webhook_endpoints/we_1/test", "POST /v1/webhook_endpoints/we_1/deliveries/del_1/redeliver"}
	for i, w := range want {
		if g := got[i].Method + " " + got[i].Path; g != w {
			t.Errorf("request %d = %s, want %s", i, g, w)
		}
	}
}

func TestEntitlementOverridesAndOrgEntitlements(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch {
		case strings.HasSuffix(r.URL.Path, "/entitlements"):
			return `{"object":"organization_entitlements","organization_id":"org_1","plan":"pro","features":["sso"],"limits":{"seats":50}}`
		case r.Method == http.MethodGet:
			return `{"object":"list","data":[{"object":"entitlement_override","id":"eo_1","subject_type":"org","subject_id":"org_1","plan":null,"features":null,"limits":{"max_devices":50},"expires_at":null,"created_by":null,"created_at":1}],"has_more":false}`
		case r.Method == http.MethodDelete:
			return `{"object":"entitlement_override","id":"eo_1","deleted":true}`
		}
		return `{"object":"entitlement_override","id":"eo_1","subject_type":"org","subject_id":"org_1","plan":"enterprise","features":["sso","scim"],"limits":{},"expires_at":99,"created_by":"user_1","created_at":1}`
	})
	ctx := context.Background()
	exp := int64(99)
	o, err := c.EntitlementOverrides.Create(ctx, CreateEntitlementOverrideParams{SubjectType: "org", SubjectID: "org_1", Plan: "enterprise", Features: []string{"sso", "scim"}, ExpiresAt: &exp})
	if err != nil || *o.Plan != "enterprise" || *o.ExpiresAt != 99 {
		t.Fatalf("create = %+v %v", o, err)
	}
	if string(got[0].Body) != `{"subject_type":"org","subject_id":"org_1","plan":"enterprise","features":["sso","scim"],"expires_at":99}` {
		t.Errorf("create body = %s", got[0].Body)
	}
	l, err := c.EntitlementOverrides.List(ctx, ListEntitlementOverridesParams{SubjectType: "org", SubjectID: "org_1"})
	if err != nil || l.Data[0].Plan != nil || l.Data[0].Limits["max_devices"] != float64(50) || got[1].Query != "subject_id=org_1&subject_type=org" {
		t.Fatalf("list = %+v %v (%q)", l, err, got[1].Query)
	}
	if d, err := c.EntitlementOverrides.Delete(ctx, "eo_1"); err != nil || !d.Deleted || got[2].Path != "/v1/entitlement_overrides/eo_1" {
		t.Fatalf("delete = %+v %v", d, err)
	}
	e, err := c.Organizations.Entitlements(ctx, "org_1")
	if err != nil || *e.Plan != "pro" || e.Features[0] != "sso" || e.Limits["seats"] != float64(50) {
		t.Fatalf("org entitlements = %+v %v", e, err)
	}
}

func TestOrgPolicyTypedPatch(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		return `{"object":"organization_policy","organization_id":"org_1","policy":{"requireMfa":true,"ipAllowlist":["10.0.0.0/8"],"maxSessionAgeSeconds":3600,"endUserPool":{"enabled":true,"requireApproval":true},"futureKey":"x"}}`
	})
	yes := true
	age := int64(3600)
	res, err := c.Organizations.SetPolicy(context.Background(), "org_1", OrgPolicyPatch{
		RequireMFA:           &yes,
		MaxSessionAgeSeconds: &age,
		EndUserPool:          &OrgEndUserPoolPolicy{Enabled: true, RequireApproval: &yes},
		Clear:                []string{"allowedSignInMethods"},
		Extra:                map[string]interface{}{"futureKey": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !*res.Policy.RequireMFA || res.Policy.IPAllowlist[0] != "10.0.0.0/8" || *res.Policy.MaxSessionAgeSeconds != 3600 ||
		!*res.Policy.EndUserPool.RequireApproval || res.Policy.Extra["futureKey"] != "x" || res.Policy.SSORequired != nil {
		t.Errorf("decoded policy = %+v", res.Policy)
	}
	if string(got[0].Body) != `{"allowedSignInMethods":null,"endUserPool":{"enabled":true,"requireApproval":true},"futureKey":"x","maxSessionAgeSeconds":3600,"requireMfa":true}` {
		t.Errorf("patch body = %s", got[0].Body)
	}
	if got[0].Method != http.MethodPatch || got[0].Path != "/v1/organizations/org_1/policy" {
		t.Errorf("request = %s %s", got[0].Method, got[0].Path)
	}
}

func TestErrorCodeConstants(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string { return "" })
	_ = c
	err := parseError(422, []byte(`{"errors":[{"code":"UNKNOWN_FIELD","message":"m","param":"nmae"}]}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.HasCode(ErrCodeUnknownField) || apiErr.Errors[0].Param != "nmae" {
		t.Errorf("err = %v", err)
	}
	for _, code := range []string{ErrCodeEmailDeliveryNotConfigured, ErrCodeEmailProviderRequired, ErrCodeEmailProviderInUse, ErrCodePlanInUse, ErrCodeWrongKeySurface, ErrCodeInvalidKey} {
		if code == "" || strings.ToUpper(code) != code {
			t.Errorf("bad code constant %q", code)
		}
	}
}
