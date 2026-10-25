package atlas

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestAtlasIDProvisionedAccountsAndDomains(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"atlas_id_provisioned_account","id":"pa_1","email":"r@acme.example","label":"reviewer","kind":"provisioned","password":"hunter2-hunter2","sealed_password":"c2VhbGVk","data":[{"id":"d_1"}],"limit":25,"total":1,"deleted":true,"sessions_ended":2,"verified_domains":["acme.example"],"test_mode":true,"provisioned_verified_domains_only":true}`)
	pa := c.Platform.AtlasIDApps.ProvisionedAccounts

	list, err := pa.List(ctx, "app_1")
	rec.expect(t, "GET", "/v1/platform/atlas_id_apps/app_1/provisioned_accounts")
	if err != nil || list.Limit != 25 || list.Total != 1 || len(list.Data) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	ev := true
	acct, err := pa.Create(ctx, "app_1", CreateAtlasIDProvisionedAccountParams{Email: "r@acme.example", Label: "reviewer", EmailVerified: &ev, TwoFactorExempt: true})
	rec.expect(t, "POST", "/v1/platform/atlas_id_apps/app_1/provisioned_accounts")
	if err != nil || rec.Body["label"] != "reviewer" || rec.Body["two_factor_exempt"] != true || acct.Password == "" || acct.SealedPassword != "c2VhbGVk" {
		t.Fatalf("create body=%v out=%+v err=%v", rec.Body, acct, err)
	}
	for _, s := range []string{fmt.Sprint(acct), fmt.Sprintf("%v", *acct), fmt.Sprintf("%#v", *acct), fmt.Sprintf("%+v", acct)} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "c2VhbGVk") {
			t.Errorf("password leaked in %q", s)
		}
	}
	p := CreateAtlasIDProvisionedAccountParams{Email: "x@y.z", Label: "l", Password: "hunter2-hunter2"}
	if strings.Contains(fmt.Sprintf("%v %#v %+v", p, p, p), "hunter2") {
		t.Error("params password leaked")
	}
	_, _ = pa.Get(ctx, "app_1", "pa_1")
	rec.expect(t, "GET", "/v1/platform/atlas_id_apps/app_1/provisioned_accounts/pa_1")
	del, _ := pa.Remove(ctx, "app_1", "pa_1")
	rec.expect(t, "DELETE", "/v1/platform/atlas_id_apps/app_1/provisioned_accounts/pa_1")
	if !del.Deleted || del.SessionsEnded != 2 {
		t.Errorf("remove = %+v", del)
	}
	_, _ = pa.RotatePassword(ctx, "app_1", "pa_1", RotateAtlasIDProvisionedPasswordParams{})
	rec.expect(t, "POST", "/v1/platform/atlas_id_apps/app_1/provisioned_accounts/pa_1/password")

	dl, _ := c.Platform.Domains.List(ctx)
	rec.expect(t, "GET", "/v1/platform/domains")
	if len(dl.VerifiedDomains) != 1 {
		t.Errorf("domains = %+v", dl)
	}
	_, _ = c.Platform.Domains.Claim(ctx, "acme.example")
	rec.expect(t, "POST", "/v1/platform/domains")
	if rec.Body["domain"] != "acme.example" {
		t.Errorf("claim body=%v", rec.Body)
	}
	_, _ = c.Platform.Domains.Check(ctx, "dom_1")
	rec.expect(t, "POST", "/v1/platform/domains/dom_1/verify")
	_, _ = c.Platform.Domains.Verify(ctx, "dom_1")
	rec.expect(t, "POST", "/v1/platform/domains/dom_1/verify")
	_, _ = c.Platform.Domains.Remove(ctx, "dom_1")
	rec.expect(t, "DELETE", "/v1/platform/domains/dom_1")

	tm := true
	app, _ := c.Platform.AtlasIDApps.Update(ctx, "app_1", UpdateAtlasIDAppParams{TestMode: &tm, ProvisionedVerifiedDomainsOnly: &tm})
	if rec.Body["test_mode"] != true || rec.Body["provisioned_verified_domains_only"] != true || !app.TestMode || !app.ProvisionedVerifiedDomainsOnly {
		t.Errorf("update body=%v app=%+v", rec.Body, app)
	}
}
