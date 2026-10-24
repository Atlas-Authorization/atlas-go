package atlas

import (
	"context"
	"encoding/json"
	"testing"
)

func TestR2AdoptionAndPreflight(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"atlas_id_app","id":"app_1","managed_via":"adopted","changed":true,"button_rendered_origins":[{"origin":"https://a.example","last_seen_at":1,"requests":2}],"authorize_requests_7d":{"button":1,"js":0,"fedcm":0,"fallback":2,"unmarked":0},"fallback_origins":[{"origin":"https://b.example","last_seen_at":1,"requests":1}],"homepage_includes_script":false,"sealed_client_secret":"AAAA","secrets_sealed":{"algorithm":"x25519-sealed-box","recipient":"x25519:k","fields":["client_secret"]}}`, WithPlatformKey("psk_test"))

	ins := "ins_1"
	res, err := c.Platform.AtlasIDApps.SetManagedBy(ctx, "app_1", &ins)
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PUT", "/v1/platform/atlas_id_apps/app_1/managed_by")
	if rec.RawBody != `{"instance_id":"ins_1"}` || !res.Changed || res.ManagedVia == nil || *res.ManagedVia != "adopted" {
		t.Errorf("body %s res %+v", rec.RawBody, res)
	}
	if res.SealedClientSecret != "AAAA" || res.SecretsSealed == nil || res.SecretsSealed.Fields[0] != "client_secret" {
		t.Errorf("sealed fields not decoded: %+v", res.SealedFields)
	}
	if _, err = c.Platform.AtlasIDApps.SetManagedBy(ctx, "app_1", nil); err != nil {
		t.Fatal(err)
	}
	if rec.RawBody != `{"instance_id":null}` {
		t.Errorf("release body %s", rec.RawBody)
	}

	pf, err := c.AtlasIDGrants.Preflight(ctx, "app_1")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/atlas_id_apps/app_1/preflight")
	if len(pf.ButtonRenderedOrigins) != 1 || pf.AuthorizeRequests7d.Fallback != 2 || len(pf.FallbackOrigins) != 1 || pf.HomepageIncludesScript == nil || *pf.HomepageIncludesScript {
		t.Errorf("preflight %+v", pf)
	}
}

func TestR2DryRunResultFields(t *testing.T) {
	var r DryRunResult
	raw := `{"object":"dry_run","dry_run":true,"mode":"rollback","validated":true,"method":"POST","path":"/v1/users","changes":[],"warnings":[{"code":"origin_still_referenced"}],"would_return_status":201,"would_return":{"id":"x"},"suppressed":["email"],"validation_skipped":{"reason":"external_call","detail":"d"},"note":""}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	if r.Mode != "rollback" || r.WouldReturnStatus != 201 || r.Suppressed[0] != "email" || r.Warnings[0].Code != "origin_still_referenced" || r.ValidationSkipped.Reason != "external_call" {
		t.Errorf("%+v", r)
	}
}

func TestR2SSOClaims(t *testing.T) {
	sso := OIDCSSOOf(map[string]interface{}{"sso_connection_id": "sso_1", "sso_organization_id": "org_1", "sso_connection_type": "saml"})
	if sso == nil || sso.OrganizationID != "org_1" || sso.Type != "saml" {
		t.Errorf("%+v", sso)
	}
	if s := OIDCSSOOf(map[string]interface{}{"sso_connection_id": "s", "sso_connection_type": "ldap"}); s.Type != "" || s.OrganizationID != "" {
		t.Errorf("%+v", s)
	}
	var c SessionClaims
	if err := json.Unmarshal([]byte(`{"sub":"u","sso_connection_id":"sso_1","sso_organization_id":"org_1","sso_connection_type":"oidc"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.SSOOrganizationID != "org_1" || c.SSOConnectionType != "oidc" || c.SSOConnectionID != "sso_1" {
		t.Errorf("%+v", c)
	}
}
