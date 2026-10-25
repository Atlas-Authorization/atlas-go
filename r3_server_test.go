package atlas

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestR3PartnerPlatforms(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"partner_platform","partner":"acme","token_set":true,"token_prefix":"tok_ab","registration":{"status":"registered","registered_at":5},"data":[],"presets":[{"id":"acme"}],"deleted":true,"signature":{"header":"x-sig"},"outcome":"recorded"}`)

	if _, err := c.PartnerPlatforms.List(ctx); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/partner_platforms")
	pp, err := c.PartnerPlatforms.Get(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/partner_platforms/acme")
	if !pp.TokenSet || pp.Registration.Status != "registered" {
		t.Errorf("decode: %+v", pp)
	}
	on := true
	if _, err := c.PartnerPlatforms.Set(ctx, "acme", SetPartnerPlatformParams{Enabled: &on, AllowedSources: []string{"a"}, Clear: []string{"name"}}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PUT", "/v1/partner_platforms/acme")
	if rec.Body["enabled"] != true || rec.Body["name"] != nil {
		t.Errorf("set body: %s", rec.RawBody)
	}
	if _, err := c.PartnerPlatforms.Remove(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "DELETE", "/v1/partner_platforms/acme")
	if _, err := c.PartnerPlatforms.Registration(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/partner_platforms/acme/registration")
	if _, err := c.PartnerPlatforms.Deliveries(ctx, "acme", 5); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/partner_platforms/acme/deliveries")
	if rec.Query != "limit=5" {
		t.Errorf("query %q", rec.Query)
	}
	params := StorePartnerPlatformTokenParams{Token: "SECRET-TOKEN-VALUE", Rotate: true, APIBaseURL: "https://api.example.com"}
	if _, err := c.PartnerPlatforms.StoreToken(ctx, "acme", params); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/partner_platforms/acme/token")
	if rec.Body["token"] != "SECRET-TOKEN-VALUE" || rec.Body["rotate"] != true || rec.Body["api_base_url"] != "https://api.example.com" {
		t.Errorf("token body: %s", rec.RawBody)
	}
}

// The partner token is write-only: no response model carries it and the params
// redact it when printed.
func TestR3PartnerPlatformTokenNeverEchoed(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"partner_platform","partner":"acme","token_set":true,"token_prefix":"tok_ab"}`)
	params := StorePartnerPlatformTokenParams{Token: "SECRET-TOKEN-VALUE"}
	pp, err := c.PartnerPlatforms.StoreToken(ctx, "acme", params)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%v", pp), fmt.Sprintf("%+v", pp), fmt.Sprintf("%#v", pp), fmt.Sprintf("%v", params), fmt.Sprintf("%+v", params), fmt.Sprintf("%#v", params), params.String()} {
		if strings.Contains(s, "SECRET-TOKEN-VALUE") {
			t.Errorf("token leaked: %s", s)
		}
	}
}

func TestR3ErrorCodeAndUsersAndOperator(t *testing.T) {
	if ErrCodeManagedWAFNotConfigured != "MANAGED_WAF_NOT_CONFIGURED" {
		t.Error("code")
	}
	v := UserListParams{IncludeDeleted: true}.values()
	if v.Get("include_deleted") != "true" {
		t.Errorf("include_deleted: %v", v)
	}
	if (UserListParams{}).values().Has("include_deleted") {
		t.Error("include_deleted must be off by default")
	}
}

func TestR3IntegrationAndPrivacy(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"integration","id":"acme","per_call_audience":{"param":"tenant","template":"acme:{tenant}","allowed":["a"],"any_matching":false,"default":false},"jwt":"x","partner_link_id":"pl_1","site_id":"s1","cancel_deletion_on_sign_in":true}`)
	it, err := c.Instance.GetIntegration(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if it.PerCallAudience == nil || it.PerCallAudience.Param != "tenant" || it.PerCallAudience.Allowed[0] != "a" {
		t.Errorf("per_call_audience: %+v", it.PerCallAudience)
	}
	if _, err := c.Instance.SetIntegration(ctx, "acme", SetIntegrationParams{PerCallAudience: &PerCallAudienceParams{Param: "tenant", Template: "acme:{tenant}", Allowed: []string{"a"}}}); err != nil {
		t.Fatal(err)
	}
	pc, _ := rec.Body["per_call_audience"].(map[string]interface{})
	if pc["param"] != "tenant" || pc["template"] != "acme:{tenant}" {
		t.Errorf("set body: %s", rec.RawBody)
	}
	if _, err := c.Instance.SetIntegration(ctx, "acme", SetIntegrationParams{Clear: []string{"per_call_audience"}}); err != nil {
		t.Fatal(err)
	}
	if v, ok := rec.Body["per_call_audience"]; !ok || v != nil {
		t.Errorf("null body: %s", rec.RawBody)
	}
	if _, err := c.Sessions.GetIntegrationTokenFor(ctx, "sess_1", "acme", IntegrationTokenParams{CBID: "dv-1", Audience: "acme:x", AudienceParams: map[string]string{"tenant": "t1"}}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/sessions/sess_1/integration_tokens/acme")
	if rec.Query != "audience=acme%3Ax&cbid=dv-1&tenant=t1" {
		t.Errorf("query %q", rec.Query)
	}
	if _, err := c.Sessions.GetIntegrationToken(ctx, "sess_1", "acme"); err != nil {
		t.Fatal(err)
	}
	if rec.Query != "" {
		t.Errorf("plain mint has query %q", rec.Query)
	}

	po, err := c.Privacy.Orchestrator.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if po.PartnerLinkID == nil || *po.PartnerLinkID != "pl_1" || *po.SiteID != "s1" || !po.CancelDeletionOnSignIn {
		t.Errorf("orchestrator: %+v", po)
	}
	on := true
	if _, err := c.Privacy.Orchestrator.Set(ctx, SetPrivacyOrchestratorParams{PartnerLinkID: "pl_1", SiteID: "s1", CancelDeletionOnSignIn: &on}); err != nil {
		t.Fatal(err)
	}
	if rec.Body["partner_link_id"] != "pl_1" || rec.Body["site_id"] != "s1" || rec.Body["cancel_deletion_on_sign_in"] != true {
		t.Errorf("orchestrator body: %s", rec.RawBody)
	}
}
