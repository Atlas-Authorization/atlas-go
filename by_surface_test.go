package atlas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── Billing: several subscriptions, settings, checks, providers ─────────────

func TestBillingMultiSubscriptionSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"billing_subscription","id":"bsub_1","kind":"addon","seat_feature_id":"seats","limits":{"projects":-1},"entitlements":{"features":["sso"],"limits":{"projects":10}},"default_limit_merge":"sum","limit_merge":{"projects":"max"},"feature":"api_calls","allowed":true,"source":"provider","remaining":5,"unlimited":false}`)

	sub, err := c.Billing.GetSubscription(ctx, "bsub_1")
	rec.expect(t, "GET", "/v1/billing/subscriptions/bsub_1")
	if err != nil || sub.Entitlements == nil || sub.Entitlements.Features[0] != "sso" || sub.Entitlements.Limits["projects"] != 10 {
		t.Fatalf("GetSubscription = %+v, %v", sub, err)
	}
	plan, _ := c.Billing.SyncPlanEntitlements(ctx, "bp_1")
	rec.expect(t, "POST", "/v1/billing/plans/bp_1/sync_entitlements")
	if plan.Kind != "addon" || plan.SeatFeatureID == nil || *plan.SeatFeatureID != "seats" || plan.Limits["projects"] != float64(-1) {
		t.Errorf("plan = %+v", plan)
	}
	set, _ := c.Billing.GetSettings(ctx)
	rec.expect(t, "GET", "/v1/billing/settings")
	if set.DefaultLimitMerge != "sum" || set.LimitMerge["projects"] != "max" {
		t.Errorf("settings = %+v", set)
	}
	_, _ = c.Billing.UpdateSettings(ctx, UpdateBillingSettingsParams{DefaultLimitMerge: "max", LimitMerge: map[string]string{"seats": "sum"}})
	rec.expect(t, "PUT", "/v1/billing/settings")
	if rec.Body["default_limit_merge"] != "max" || rec.Body["limit_merge"].(map[string]interface{})["seats"] != "sum" {
		t.Errorf("UpdateSettings body = %v", rec.Body)
	}
	two := 2.0
	chk, _ := c.Billing.CheckFeature(ctx, CheckBillingFeatureParams{SubjectType: "org", SubjectID: "org_1", Feature: "api_calls", Required: &two})
	rec.expect(t, "POST", "/v1/billing/check")
	if rec.Body["required"] != 2.0 || rec.Body["feature"] != "api_calls" || !chk.Allowed || chk.Source != "provider" || *chk.Remaining != 5 {
		t.Errorf("CheckFeature body=%v out=%+v", rec.Body, chk)
	}
	_, _ = c.Billing.ReportUsage(ctx, ReportUsageParams{SubjectType: "user", SubjectID: "u_1", Quantity: 3, IdempotencyKey: "k", Feature: "api_calls", SubscriptionID: "bsub_2"})
	rec.expect(t, "POST", "/v1/billing/usage")
	if rec.Body["feature"] != "api_calls" || rec.Body["subscription_id"] != "bsub_2" {
		t.Errorf("usage body = %v", rec.Body)
	}
	_, _ = c.Billing.CreatePlan(ctx, CreateBillingPlanParams{Name: "Extra", Slug: "extra", Provider: BillingProviderAutumn, ProviderPriceID: "extra", Kind: BillingPlanKindAddon, SeatFeatureID: "seats", Limits: map[string]interface{}{"projects": 5}})
	rec.expect(t, "POST", "/v1/billing/plans")
	if rec.Body["kind"] != "addon" || rec.Body["seat_feature_id"] != "seats" || rec.Body["provider"] != "autumn" {
		t.Errorf("CreatePlan body = %v", rec.Body)
	}
	_, _ = c.Billing.UpdatePlan(ctx, "bp_1", UpdateBillingPlanParams{ClearSeatFeatureID: true})
	if v, ok := rec.Body["seat_feature_id"]; !ok || v != nil {
		t.Errorf("clear seat feature body = %s", rec.RawBody)
	}
	_, _ = c.Billing.SetProvider(ctx, BillingProviderChargebee, SetBillingProviderParams{Config: map[string]string{"api_key": "k", "site": "acme", "webhook_username": "u", "webhook_password": "p"}})
	rec.expect(t, "PUT", "/v1/billing/providers/chargebee")
	if BillingProviderCommet != "commet" {
		t.Error("commet constant")
	}
}

// ── Custom OAuth providers + SSO RP settings ────────────────────────────────

func TestCustomOAuthProvidersSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"custom_oauth_provider","id":"coap_1","provider_key":"custom_acme","display_name":"Acme","client_jwks_uri":"https://fapi/jwks","redirect_uri":"https://fapi/cb","has_secret":true,"profile_mapping":{"fields":{"email":"mail"},"update_on_sign_in":false},"logout":{"rp_initiated":true},"signing_keys":[{"kid":"k1","alg":"ES256","status":"active"}],"kid":"k2","alg":"PS256","status":"retired","issuer":"https://idp.test","profile":{"email":"a@b.c","email_verified":false,"public_metadata":{}},"trace":{"email":{"value":"a@b.c","source":"userinfo.mail"}},"warnings":["w"],"data":[{"id":"coap_1"}]}`)

	list, err := c.CustomOAuthProviders.List(ctx)
	rec.expect(t, "GET", "/v1/custom_oauth_providers")
	if err != nil || len(list.Data) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	tr := true
	p, _ := c.CustomOAuthProviders.Create(ctx, CustomOAuthProviderParams{
		ProviderKey: "custom_acme", DisplayName: "Acme", Issuer: "https://idp.test", ClientID: "cid",
		TokenEndpointAuthMethod: TokenEndpointAuthPrivateKeyJWT,
		ProfileMapping: &ProfileMapping{Fields: map[string]ProfileMappingExpr{
			"email": "mail", "first_name": ProfileMappingRule{From: []string{"given_name", "name"}, Transforms: []interface{}{"trim", map[string]string{"split": " "}, "first"}},
		}},
		Logout:            &UpstreamLogoutSettings{RPInitiated: &tr, Backchannel: &tr},
		IdpInitiatedLogin: &IdpInitiatedLoginSettings{Enabled: &tr, AllowedTargets: []string{"https://app.test"}},
	})
	rec.expect(t, "POST", "/v1/custom_oauth_providers")
	fields := rec.Body["profile_mapping"].(map[string]interface{})["fields"].(map[string]interface{})
	if fields["email"] != "mail" || fields["first_name"].(map[string]interface{})["from"].([]interface{})[1] != "name" || rec.Body["token_endpoint_auth_method"] != "private_key_jwt" {
		t.Errorf("Create body = %s", rec.RawBody)
	}
	if p.ClientJWKSURI != "https://fapi/jwks" || !p.HasSecret || len(p.SigningKeys) != 1 || p.ProfileMapping.Fields["email"] != "mail" {
		t.Errorf("provider = %+v", p)
	}
	_, _ = c.CustomOAuthProviders.Get(ctx, "coap_1")
	rec.expect(t, "GET", "/v1/custom_oauth_providers/coap_1")
	_, _ = c.CustomOAuthProviders.Update(ctx, "coap_1", CustomOAuthProviderParams{DisplayName: "Acme 2", Clear: []string{"icon_url"}})
	rec.expect(t, "PATCH", "/v1/custom_oauth_providers/coap_1")
	if v, ok := rec.Body["icon_url"]; !ok || v != nil || rec.Body["display_name"] != "Acme 2" {
		t.Errorf("Update body = %s", rec.RawBody)
	}
	_, _ = c.CustomOAuthProviders.Delete(ctx, "coap_1")
	rec.expect(t, "DELETE", "/v1/custom_oauth_providers/coap_1")
	d, _ := c.CustomOAuthProviders.Discover(ctx, "https://idp.test", "")
	rec.expect(t, "POST", "/v1/custom_oauth_providers/discover")
	if _, has := rec.Body["discovery_url"]; has || d.Issuer != "https://idp.test" {
		t.Errorf("Discover body = %v", rec.Body)
	}
	pv, _ := c.CustomOAuthProviders.PreviewProfileMapping(ctx, "", ProfileMappingPreviewParams{Userinfo: map[string]interface{}{"mail": "a@b.c"}})
	rec.expect(t, "POST", "/v1/custom_oauth_providers/profile_mapping/preview")
	if pv.Profile.Email == nil || *pv.Profile.Email != "a@b.c" || *pv.Trace["email"].Source != "userinfo.mail" || pv.Warnings[0] != "w" {
		t.Errorf("preview = %+v", pv)
	}
	_, _ = c.CustomOAuthProviders.PreviewProfileMapping(ctx, "coap_1", ProfileMappingPreviewParams{IDToken: "a.b.c"})
	rec.expect(t, "POST", "/v1/custom_oauth_providers/coap_1/profile_mapping/preview")
	keys := c.CustomOAuthProviders.SigningKeys("coap_1")
	_, _ = keys.List(ctx)
	rec.expect(t, "GET", "/v1/custom_oauth_providers/coap_1/signing_keys")
	k, _ := keys.Rotate(ctx, "PS256")
	rec.expect(t, "POST", "/v1/custom_oauth_providers/coap_1/signing_keys")
	if rec.Body["alg"] != "PS256" || k.Alg != "PS256" {
		t.Errorf("Rotate body=%v out=%+v", rec.Body, k)
	}
	_, _ = keys.Retire(ctx, "k1")
	rec.expect(t, "POST", "/v1/custom_oauth_providers/coap_1/signing_keys/k1/retire")

	// SSO connections: preview, keys, the RP and SAML SLO fields.
	_, _ = c.SSOConnections.PreviewProfileMapping(ctx, "sso_1", ProfileMappingPreviewParams{IDTokenClaims: map[string]interface{}{"sub": "x"}})
	rec.expect(t, "POST", "/v1/sso_connections/sso_1/profile_mapping/preview")
	_, _ = c.SSOConnections.SigningKeys("sso_1").Rotate(ctx, "")
	rec.expect(t, "POST", "/v1/sso_connections/sso_1/signing_keys")
	_, _ = c.SSOConnections.SigningKeys("sso_1").List(ctx)
	rec.expect(t, "GET", "/v1/sso_connections/sso_1/signing_keys")
	_, _ = c.SSOConnections.SigningKeys("sso_1").Retire(ctx, "k9")
	rec.expect(t, "POST", "/v1/sso_connections/sso_1/signing_keys/k9/retire")
	_, _ = c.SSOConnections.Update(ctx, "sso_1", UpdateSsoConnectionParams{
		SAMLSingleLogout: &tr, SAMLIDPSLOURL: "https://idp.test/slo", SAMLIDPSLOBinding: "post",
		SAMLIDPSLOSOAPURL: "https://idp.test/soap", SAMLRequireEncryptedAssertions: &tr,
		TokenEndpointAuthMethod: "private_key_jwt", Clear: []string{"saml_idp_slo_response_url"},
	})
	rec.expect(t, "PATCH", "/v1/sso_connections/sso_1")
	if rec.Body["saml_idp_slo_soap_url"] != "https://idp.test/soap" || rec.Body["saml_single_logout"] != true || rec.Body["saml_require_encrypted_assertions"] != true {
		t.Errorf("SSO update body = %s", rec.RawBody)
	}
	if v, ok := rec.Body["saml_idp_slo_response_url"]; !ok || v != nil {
		t.Errorf("SSO clear = %s", rec.RawBody)
	}
}

func TestSAMLEncryptionKeys(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"sso_saml_encryption_key","connection_id":"sso_1","certificate":"-----BEGIN CERTIFICATE-----","previous_certificate":null,"rotated_at":1,"require_encrypted_assertions":true}`)
	k, err := c.SSOConnections.GetSAMLEncryptionKey(ctx, "sso_1")
	rec.expect(t, "GET", "/v1/sso_connections/sso_1/saml_encryption_key")
	if err != nil || k.Certificate == nil || !k.RequireEncryptedAssertions || k.PreviousCertificate != nil {
		t.Fatalf("Get = %+v, %v", k, err)
	}
	_, _ = c.SSOConnections.CreateSAMLEncryptionKey(ctx, "sso_1")
	rec.expect(t, "POST", "/v1/sso_connections/sso_1/saml_encryption_key")
	_, _ = c.SSOConnections.RetirePreviousSAMLEncryptionKey(ctx, "sso_1")
	rec.expect(t, "DELETE", "/v1/sso_connections/sso_1/saml_encryption_key/previous")
	_, _ = c.SSOConnections.DeleteSAMLEncryptionKey(ctx, "sso_1")
	rec.expect(t, "DELETE", "/v1/sso_connections/sso_1/saml_encryption_key")

	c2, rec2 := recordingClient(t, `{"object":"sso_saml_metadata","slo_url":"https://fapi/v1/sso/saml/sso_1/slo","metadata_xml":"<x/>"}`)
	md, _ := c2.SSOConnections.SAMLMetadata(ctx, "sso_1")
	rec2.expect(t, "GET", "/v1/sso_connections/sso_1/saml_metadata")
	if md.SLOURL == nil || !strings.HasSuffix(*md.SLOURL, "/slo") {
		t.Errorf("metadata = %+v", md)
	}
}

// ── Actions gallery ─────────────────────────────────────────────────────────

func TestActionGallerySurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"action_gallery_install","action":{"id":"act_1","enabled":false},"template":{"slug":"geo-fence","source":"builtin","version":"1.0.0"},"install_id":"agi_1","missing_secrets":["SLACK_URL"],"updated":true,"version":"1.1.0","id":"atpl_1","slug":"mine","status":"draft","versions":[{"version":"1.0.0","status":"draft"}],"data":[{"slug":"geo-fence","uses_http":true,"author":{"name":"Atlas","first_party":true}}]}`)
	list, err := c.ActionGallery.List(ctx, ActionGalleryFilter{Q: "geo", Trigger: "post_login"})
	rec.expect(t, "GET", "/v1/action_gallery")
	if err != nil || !strings.Contains(rec.Query, "q=geo") || !strings.Contains(rec.Query, "trigger=post_login") || !list.Data[0].UsesHTTP || !list.Data[0].Author.FirstParty {
		t.Fatalf("List = %+v %q, %v", list, rec.Query, err)
	}
	_, _ = c.ActionGallery.Get(ctx, "geo-fence")
	rec.expect(t, "GET", "/v1/action_gallery/geo-fence")
	inst, _ := c.ActionGallery.Install(ctx, "geo-fence", InstallTemplateParams{Secrets: map[string]string{"SLACK_URL": "x"}})
	rec.expect(t, "POST", "/v1/action_gallery/geo-fence/install")
	if inst.Action.ID != "act_1" || inst.MissingSecrets[0] != "SLACK_URL" || rec.Body["secrets"] == nil {
		t.Errorf("Install = %+v body %v", inst, rec.Body)
	}
	_, _ = c.ActionGallery.Installs(ctx)
	rec.expect(t, "GET", "/v1/action_gallery_installs")
	up, _ := c.ActionGallery.Update(ctx, "act_1", nil)
	rec.expect(t, "POST", "/v1/actions/act_1/gallery_update")
	if !up.Updated || up.Version != "1.1.0" {
		t.Errorf("Update = %+v", up)
	}

	_, _ = c.ActionTemplates.List(ctx)
	rec.expect(t, "GET", "/v1/action_templates")
	tpl, _ := c.ActionTemplates.Create(ctx, ActionTemplateParams{Slug: "mine", Name: "Mine", AuthorName: "Me", Trigger: "post_login", Version: "1.0.0", Code: "exports.onExecutePostLogin=async()=>{}", Submit: true})
	rec.expect(t, "POST", "/v1/action_templates")
	if rec.Body["submit"] != true || tpl.Versions[0].Version != "1.0.0" {
		t.Errorf("Create = %+v %v", tpl, rec.Body)
	}
	_, _ = c.ActionTemplates.Get(ctx, "atpl_1")
	rec.expect(t, "GET", "/v1/action_templates/atpl_1")
	_, _ = c.ActionTemplates.Update(ctx, "atpl_1", ActionTemplateParams{Summary: "s"})
	rec.expect(t, "PATCH", "/v1/action_templates/atpl_1")
	_, _ = c.ActionTemplates.AddVersion(ctx, "atpl_1", NewTemplateVersionParams{Version: "1.1.0", Code: "x"})
	rec.expect(t, "POST", "/v1/action_templates/atpl_1/versions")
	_, _ = c.ActionTemplates.SubmitVersion(ctx, "atpl_1", "1.1.0")
	rec.expect(t, "POST", "/v1/action_templates/atpl_1/versions/1.1.0/submit")
	_, _ = c.ActionTemplates.DeleteVersion(ctx, "atpl_1", "1.1.0")
	rec.expect(t, "DELETE", "/v1/action_templates/atpl_1/versions/1.1.0")
	_, _ = c.ActionTemplates.Publish(ctx, "atpl_1")
	rec.expect(t, "POST", "/v1/action_templates/atpl_1/publish")
	_, _ = c.ActionTemplates.Unlist(ctx, "atpl_1")
	rec.expect(t, "POST", "/v1/action_templates/atpl_1/unlist")
	_, _ = c.ActionTemplates.Delete(ctx, "atpl_1")
	rec.expect(t, "DELETE", "/v1/action_templates/atpl_1")

	c2, rec2 := recordingClient(t, `{"object":"action_test_result","http_requests":[{"method":"POST","url":"https://hooks.test/x?k=***","header_names":["content-type"],"has_body":true,"save_response_as":null}]}`)
	ev := ActionTestEvent{}
	ev.Request = &struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
		Country   string `json:"country,omitempty"`
	}{Country: "DE"}
	res, _ := c2.Actions.Test(ctx, "act_1", ev)
	if rec2.Body["event"].(map[string]interface{})["request"].(map[string]interface{})["country"] != "DE" || len(res.HTTPRequests) != 1 || !res.HTTPRequests[0].HasBody {
		t.Errorf("Test body=%v out=%+v", rec2.Body, res)
	}
}

// ── Sign-in items: session data, wallet RPC, rate-limit rules, config ───────

func TestSignInItemsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"session","id":"sess_1","custom_data":{"plan":"pro"},"chain_id":1,"set":true,"rules":[{"group":"fapi.sign_in","window_seconds":60,"max":5,"key":"ip"}],"groups":[{"group":"fapi.sign_in"}]}`)
	s, err := c.Sessions.SetCustomData(ctx, "sess_1", map[string]interface{}{"plan": "pro"})
	rec.expect(t, "PUT", "/v1/sessions/sess_1/custom_data")
	if err != nil || s.CustomData["plan"] != "pro" || rec.Body["custom_data"].(map[string]interface{})["plan"] != "pro" {
		t.Fatalf("SetCustomData = %+v body %v, %v", s, rec.Body, err)
	}
	_, _ = c.Sessions.SetCustomData(ctx, "sess_1", nil)
	if v, ok := rec.Body["custom_data"]; !ok || v != nil {
		t.Errorf("clear body = %s", rec.RawBody)
	}
	_, _ = c.Sessions.UpdateCustomData(ctx, "sess_1", map[string]interface{}{"plan": nil, "seat": 2})
	rec.expect(t, "PATCH", "/v1/sessions/sess_1/custom_data")
	if cd := rec.Body["custom_data"].(map[string]interface{}); cd["seat"] != 2.0 || cd["plan"] != nil {
		t.Errorf("merge body = %s", rec.RawBody)
	}
	_, _ = c.Sessions.Create(ctx, CreateSessionParams{UserID: "u_1", CustomData: map[string]interface{}{"a": 1}})
	if rec.Body["custom_data"] == nil {
		t.Errorf("create body = %v", rec.Body)
	}

	w, _ := c.InstanceSecurity.SetWalletRPCSecret(ctx, 1, "https://rpc.test")
	rec.expect(t, "PUT", "/v1/instance/wallet_rpc_secret")
	if rec.Body["chain_id"] != 1.0 || rec.Body["url"] != "https://rpc.test" || !w.Set {
		t.Errorf("wallet body=%v out=%+v", rec.Body, w)
	}

	pol, _ := c.RateLimitPolicy.Update(ctx, UpdateRateLimitPolicyParams{Rules: []RateLimitRule{{Group: "fapi.sign_in", WindowSeconds: 60, Max: 5, Key: RateLimitKeyIP}}})
	rec.expect(t, "PATCH", "/v1/rate_limit_policy")
	rules := rec.Body["rules"].([]interface{})
	if rules[0].(map[string]interface{})["window_seconds"] != 60.0 || len(pol.Rules) != 1 || pol.Rules[0].Key != "ip" {
		t.Errorf("rules body=%v out=%+v", rec.Body, pol)
	}
	_, _ = c.RateLimitPolicy.Update(ctx, UpdateRateLimitPolicyParams{Rules: []RateLimitRule{}})
	if r, ok := rec.Body["rules"].([]interface{}); !ok || len(r) != 0 {
		t.Errorf("clear rules body = %s", rec.RawBody)
	}
	_, _ = c.RateLimitPolicy.Update(ctx, UpdateRateLimitPolicyParams{})
	if _, ok := rec.Body["rules"]; ok {
		t.Errorf("nil rules sent: %s", rec.RawBody)
	}

	_, _ = c.Instance.SetAccountLinkingTrust(ctx, map[string]string{"google": LinkingTrustAlways, "custom_*": LinkingTrustNever})
	rec.expect(t, "PATCH", "/v1/instance")
	if rec.Body["auth_config"].(map[string]interface{})["accountLinkingTrust"].(map[string]interface{})["custom_*"] != "never" {
		t.Errorf("linking trust body = %s", rec.RawBody)
	}
	_, _ = c.Instance.SetCaptchaConfig(ctx, CaptchaConfig{Provider: CaptchaProviderVercelBotID, AttestationURL: "/api/atlas/botid"})
	if cap := rec.Body["auth_config"].(map[string]interface{})["captcha"].(map[string]interface{}); cap["provider"] != "vercel_botid" || cap["attestationUrl"] != "/api/atlas/botid" || cap["siteKey"] != nil {
		t.Errorf("captcha body = %s", rec.RawBody)
	}
	_, _ = c.InstanceSecurity.SetCaptchaSecretWithParams(ctx, SetCaptchaSecretParams{Secret: strings.Repeat("s", 32), Provider: CaptchaProviderCaptchaFox})
	if rec.Body["provider"] != "captchafox" {
		t.Errorf("captcha secret body = %v", rec.Body)
	}
}

func TestBotIDAttestation(t *testing.T) {
	secret := strings.Repeat("k", 32)
	now := time.Unix(1_800_000_000, 0)
	tok, err := CreateBotIDAttestation(secret, BotIDVerdict{IsBot: false}, &BotIDAttestationOptions{TTL: time.Hour, Now: func() time.Time { return now }})
	if err != nil || !strings.HasPrefix(tok, BotIDAttestationPrefix) {
		t.Fatalf("token = %q, %v", tok, err)
	}
	rest := strings.TrimPrefix(tok, BotIDAttestationPrefix)
	dot := strings.LastIndex(rest, ".")
	payload, sig := rest[:dot], rest[dot+1:]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(BotIDAttestationPrefix + payload))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != sig {
		t.Error("signature does not verify")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	var p map[string]interface{}
	_ = json.Unmarshal(raw, &p)
	if p["v"] != 1.0 || p["is_bot"] != false || p["exp"].(float64)-p["iat"].(float64) != 300 || p["iat"] != float64(now.Unix()) || len(p["jti"].(string)) < 20 {
		t.Errorf("payload = %v", p)
	}
	if _, err := CreateBotIDAttestation("short", BotIDVerdict{}, nil); err == nil {
		t.Error("short secret accepted")
	}

	h := BotIDAttestationHandler(secret, func(*http.Request) (BotIDVerdict, error) { return BotIDVerdict{IsBot: true}, nil }, nil)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("POST", "/api/atlas/botid", nil))
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(body["token"], BotIDAttestationPrefix) {
		t.Errorf("handler = %d %v", rr.Code, body)
	}
	fail := BotIDAttestationHandler(secret, func(*http.Request) (BotIDVerdict, error) { return BotIDVerdict{}, errors.New("down") }, nil)
	rr = httptest.NewRecorder()
	fail(rr, httptest.NewRequest("POST", "/", nil))
	if rr.Code != 503 || !strings.Contains(rr.Body.String(), "botid_unavailable") {
		t.Errorf("failing check = %d %s", rr.Code, rr.Body.String())
	}
}

// ── Enterprise: dormant accounts, risk signal ───────────────────────────────

func TestDormantAccountsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"attack_protection","dormant_accounts":{"enabled":true,"threshold_days":90,"require_mfa":true,"on_no_factor":"require_enroll","notify_user":true},"weights":{"dormantAccount":30},"signals":{"dormantAccount":true}}`)
	days := 120
	tr := true
	ap, err := c.AttackProtection.Update(ctx, UpdateAttackProtectionParams{DormantAccounts: &UpdateDormantAccountsParams{Enabled: &tr, ThresholdDays: &days, OnNoFactor: "block"}})
	rec.expect(t, "PATCH", "/v1/attack_protection")
	da := rec.Body["dormant_accounts"].(map[string]interface{})
	if err != nil || da["threshold_days"] != 120.0 || da["on_no_factor"] != "block" || ap.DormantAccounts == nil || ap.DormantAccounts.OnNoFactor != "require_enroll" {
		t.Fatalf("Update body=%v out=%+v, %v", rec.Body, ap, err)
	}
	r, _ := c.RiskBasedMFA.Get(ctx)
	if r.Weights.DormantAccount != 30 || !r.Signals.DormantAccount {
		t.Errorf("risk = %+v", r)
	}
	if EmailTemplateAccountReactivated != "account_reactivated" || WebhookEventUserReactivated != "user.reactivated" || WebhookEventSessionUpdated != "session.updated" {
		t.Error("constants")
	}
}

// ── OP: token format / lifetimes, introspection clients, KMS keys ───────────

func TestOPSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"oauth_client","access_token_format":"opaque","token_lifetimes":{"access_token_ttl_seconds":600},"introspection_client_ids":["oc_api"],"refresh_token_idle_ttl_seconds":3600,"provider":"aws_kms","config":{"region":"us-east-1"},"active":true,"key_version":"arn:aws:kms:k","rotation":{"kid":"k2"},"deleted":true}`)
	ttl := int64(600)
	_, _ = c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "A", RedirectURIs: []string{"https://a.test/cb"}, AccessTokenFormat: AccessTokenFormatOpaque, TokenLifetimes: &OAuthTokenLifetimes{AccessTokenTTLSeconds: &ttl}})
	if rec.Body["access_token_format"] != "opaque" || rec.Body["token_lifetimes"].(map[string]interface{})["access_token_ttl_seconds"] != 600.0 {
		t.Errorf("client create body = %s", rec.RawBody)
	}
	oc, _ := c.OAuthClients.Update(ctx, "oc_1", UpdateOAuthClientParams{ClearAccessTokenFormat: true, ClearTokenLifetimes: true})
	if v, ok := rec.Body["access_token_format"]; !ok || v != nil {
		t.Errorf("client clear body = %s", rec.RawBody)
	}
	if v, ok := rec.Body["token_lifetimes"]; !ok || v != nil {
		t.Errorf("client clear lifetimes = %s", rec.RawBody)
	}
	if *oc.AccessTokenFormat != "opaque" || *oc.TokenLifetimes.AccessTokenTTLSeconds != 600 {
		t.Errorf("client = %+v", oc)
	}
	idle := int64(3600)
	rs, _ := c.ResourceServers.Update(ctx, "rs_1", UpdateResourceServerParams{AccessTokenFormat: "jwt", RefreshTokenIdleTTLSeconds: &idle, IntrospectionClientIDs: []string{"oc_api"}, ClearRefreshTokenAbsoluteTTLSeconds: true})
	rec.expect(t, "PATCH", "/v1/resource_servers/rs_1")
	if rec.Body["access_token_format"] != "jwt" || rec.Body["refresh_token_idle_ttl_seconds"] != 3600.0 || rec.Body["introspection_client_ids"].([]interface{})[0] != "oc_api" {
		t.Errorf("rs body = %s", rec.RawBody)
	}
	if v, ok := rec.Body["refresh_token_absolute_ttl_seconds"]; !ok || v != nil {
		t.Errorf("rs clear = %s", rec.RawBody)
	}
	if rs.IntrospectionClientIDs[0] != "oc_api" || *rs.RefreshTokenIdleTTLSeconds != 3600 {
		t.Errorf("rs = %+v", rs)
	}

	kp, _ := c.InstanceSecurity.GetSigningKeyProvider(ctx)
	rec.expect(t, "GET", "/v1/instance/signing_key_provider")
	if kp.Provider != SigningKeyProviderAWSKMS || !kp.Active || *kp.KeyVersion != "arn:aws:kms:k" {
		t.Errorf("provider = %+v", kp)
	}
	set, _ := c.InstanceSecurity.SetSigningKeyProvider(ctx, SetSigningKeyProviderParams{Provider: SigningKeyProviderAWSKMS, Config: map[string]interface{}{"region": "us-east-1"}, Credentials: map[string]interface{}{"access_key_id": "a", "secret_access_key": "b"}})
	rec.expect(t, "PUT", "/v1/instance/signing_key_provider")
	if rec.Body["credentials"].(map[string]interface{})["access_key_id"] != "a" || set.Rotation == nil || set.Rotation.Kid != "k2" {
		t.Errorf("set body=%v out=%+v", rec.Body, set)
	}
	rm, _ := c.InstanceSecurity.RemoveSigningKeyProvider(ctx, RotateSigningKeyParams{Emergency: true})
	rec.expect(t, "DELETE", "/v1/instance/signing_key_provider")
	if rec.Body["emergency"] != true || !rm.Deleted {
		t.Errorf("remove body=%v out=%+v", rec.Body, rm)
	}
}

// ── Device authorization approval (Frontend API, session token) ─────────────

func TestDeviceAuthorizations(t *testing.T) {
	var last struct{ method, path, auth, pk, body string }
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		last.method, last.path, last.auth, last.pk, last.body = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("x-publishable-key"), string(raw)
		w.WriteHeader(status)
		if status != 200 {
			_, _ = w.Write([]byte(`{"errors":[{"code":"STEP_UP_REQUIRED","message":"Re-authenticate."}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"device_authorization","id":"da_1","user_code":"WDJB-MJHT","status":"pending","client":{"client_id":"oc_tv","name":"TV","first_party":true},"scopes":[{"scope":"openid","description":"Sign you in"}],"audience":null,"requires_step_up":true,"created_at":1,"expires_at":2}`))
	}))
	defer srv.Close()
	d := NewDeviceAuthorizations(srv.URL+"/", "sess_jwt", &DeviceAuthorizationsOptions{PublishableKey: "pk_test_x"})
	ctx := context.Background()
	auth, err := d.Lookup(ctx, " wdjb mjht ")
	if err != nil || last.path != "/v1/client/me/device_authorizations/lookup" || last.auth != "Bearer sess_jwt" || last.pk != "pk_test_x" || !strings.Contains(last.body, `"WDJB-MJHT"`) {
		t.Fatalf("lookup = %+v %+v, %v", auth, last, err)
	}
	if auth.Client.Name != "TV" || !auth.RequiresStepUp || auth.Scopes[0].Description != "Sign you in" {
		t.Errorf("auth = %+v", auth)
	}
	if _, err := d.Approve(ctx, auth); err != nil || last.path != "/v1/client/me/device_authorizations/da_1/approve" || !strings.Contains(last.body, `"user_code":"WDJB-MJHT"`) {
		t.Errorf("approve %+v %v", last, err)
	}
	if _, err := d.Deny(ctx, auth); err != nil || last.path != "/v1/client/me/device_authorizations/da_1/deny" {
		t.Errorf("deny %+v %v", last, err)
	}
	status = 403
	_, err = d.Approve(ctx, auth)
	var de *DeviceAuthorizationError
	if !errors.As(err, &de) || !de.NeedsReverification() || de.Status != 403 || de.IsInvalidCode() {
		t.Errorf("step-up error = %#v", err)
	}
	if FormatUserCode("abc") != "abc" || FormatUserCode("wdjbmjht") != "WDJB-MJHT" {
		t.Error("FormatUserCode")
	}
	if UserCodeFromURL("https://x.test/device?user_code=wdjbmjht") != "WDJB-MJHT" || UserCodeFromURL("nope") != "" {
		t.Error("UserCodeFromURL")
	}
}

// ── Opaque access tokens via introspection ──────────────────────────────────

func TestAccessTokenIntrospection(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var calls int32
	var lastAuth, lastForm string
	active := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = r.ParseForm()
		lastAuth, lastForm = r.Header.Get("Authorization"), r.PostForm.Encode()
		if r.PostForm.Get("token") == "oat_down" {
			w.WriteHeader(500)
			return
		}
		if !active || r.PostForm.Get("token") == "oat_dead" {
			_, _ = w.Write([]byte(`{"active":false}`))
			return
		}
		iss := "https://iss.test"
		if r.PostForm.Get("token") == "oat_foreign" {
			iss = "https://other.test"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true, "iss": iss, "sub": "u_1", "aud": "https://api.test",
			"scope": "read", "client_id": "oc_1", "exp": now.Unix() + 3600, "token_type": "Bearer"})
	}))
	defer srv.Close()
	v, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: "https://iss.test", Audiences: []string{"https://api.test"}, JWKSURL: srv.URL + "/jwks",
		Introspection: &IntrospectionOptions{ClientID: "oc_api", ClientSecret: "s3cret", Endpoint: srv.URL + "/oauth2/introspect"},
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := v.Verify(ctx, "Bearer oat_live", "read")
	if !r.OK || r.Subject != "u_1" || r.ClientID != "oc_1" {
		t.Fatalf("opaque = %+v", r)
	}
	if lastAuth != "Basic "+base64.StdEncoding.EncodeToString([]byte("oc_api:s3cret")) || !strings.Contains(lastForm, "token_type_hint=access_token") {
		t.Errorf("introspection request auth=%q form=%q", lastAuth, lastForm)
	}
	_ = v.Verify(ctx, "Bearer oat_live")
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("cache not used: %d calls", calls)
	}
	if r := v.Verify(ctx, "Bearer oat_live", "admin"); r.Status != 403 || r.Error != AccessTokenInsufficientScope {
		t.Errorf("scope check on opaque = %+v", r)
	}
	if r := v.Verify(ctx, "Bearer oat_dead"); r.OK || r.Error != AccessTokenInvalidToken {
		t.Errorf("inactive = %+v", r)
	}
	before := atomic.LoadInt32(&calls)
	_ = v.Verify(ctx, "Bearer oat_dead")
	if atomic.LoadInt32(&calls) != before {
		t.Error("negative answer not cached")
	}
	if r := v.Verify(ctx, "Bearer oat_foreign"); r.OK || !strings.Contains(r.Description, "another authorization server") {
		t.Errorf("foreign iss = %+v", r)
	}
	if r := v.Verify(ctx, "Bearer oat_down"); r.OK || !strings.Contains(r.Description, "could not be validated") {
		t.Errorf("unreachable = %+v", r)
	}

	// Without introspection an opaque token is refused with a pointer to it.
	plain, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: "https://iss.test", Audiences: []string{"https://api.test"}, JWKSURL: srv.URL + "/jwks"})
	if r := plain.Verify(ctx, "Bearer oat_live"); r.OK || !strings.Contains(r.Description, "Introspection") {
		t.Errorf("no introspection = %+v", r)
	}

	// IntrospectJWTs sends a locally valid JWT to Atlas too: a revoked one is refused.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := mixedJWKS(t, ec, rs)
	live, _ := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: "https://iss.test", Audiences: []string{"https://api.test"}, JWKSURL: jwks.URL, Now: func() time.Time { return now },
		Introspection: &IntrospectionOptions{ClientID: "oc_api", ClientSecret: "s3cret", Endpoint: srv.URL + "/oauth2/introspect", IntrospectJWTs: true},
	})
	jwt := signES256(t, ec, "ec1", map[string]interface{}{"iss": "https://iss.test", "sub": "u_2", "aud": "https://api.test", "exp": now.Unix() + 60, "token_use": "access_token"})
	active = false
	if r := live.Verify(ctx, "Bearer "+jwt); r.OK {
		t.Error("revoked JWT accepted with IntrospectJWTs")
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: "https://iss.test", AllowAnyAudience: true, Introspection: &IntrospectionOptions{}}); err == nil {
		t.Error("introspection without credentials accepted")
	}
}

func TestIntrospectorCacheBoundsAndExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true, "exp": now.Unix() + 5})
	}))
	defer srv.Close()
	clock := now
	in, _ := NewIntrospector("https://iss.test", IntrospectionOptions{ClientID: "a", ClientSecret: "b", Endpoint: srv.URL, CacheMax: 2}, nil, func() time.Time { return clock })
	ctx := context.Background()
	for _, tok := range []string{"t1", "t2", "t3"} {
		if c, err := in.Introspect(ctx, tok); err != nil || c == nil {
			t.Fatal(err)
		}
	}
	if len(in.cache) > 2 {
		t.Errorf("cache grew past CacheMax: %d", len(in.cache))
	}
	// The answer is never reused past the token's exp (5 s, under the 60 s TTL).
	_, _ = in.Introspect(ctx, "t3")
	n := atomic.LoadInt32(&calls)
	clock = now.Add(6 * time.Second)
	_, _ = in.Introspect(ctx, "t3")
	if atomic.LoadInt32(&calls) != n+1 {
		t.Error("cached answer outlived the token's exp")
	}
}

// ── RSK-02: risk-event timeline, feedback, fraud lookup ─────────────────────

func TestRiskEventsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"list","data":[{"object":"risk_event","id":"re_1","user_id":"usr_1","level":"high","score":80,"signals":["newDevice"],"action":"mfa","mode":"audit","ip":"1.2.3.4","feedback":null,"feedback_at":null,"created_at":"2026-01-01T00:00:00Z"}],"days":7,"total":3,"buckets":[{"level":"high","action":"mfa","mode":"audit","count":3}],"verdict":"challenge","reasons":["r"],"matched_rules":["fr_1"],"device_id":"d1"}`)
	page, err := c.RiskBasedMFA.ListEvents(ctx, ListRiskEventsParams{UserID: "usr_1", Level: "high", Limit: 10, Before: "2026-02-01T00:00:00Z"})
	rec.expect(t, "GET", "/v1/risk_events")
	if err != nil || len(page.Data) != 1 || page.Data[0].ID != "re_1" || page.Data[0].Signals[0] != "newDevice" || page.Data[0].Feedback != nil {
		t.Fatalf("ListEvents = %+v, %v", page, err)
	}
	if rec.Query != "before=2026-02-01T00%3A00%3A00Z&level=high&limit=10&user_id=usr_1" {
		t.Errorf("query = %q", rec.Query)
	}
	m, err := c.RiskBasedMFA.EventMetrics(ctx, 14)
	rec.expect(t, "GET", "/v1/risk_events/metrics")
	if err != nil || rec.Query != "days=14" || m.Total != 3 || m.Buckets[0].Count != 3 {
		t.Fatalf("EventMetrics = %+v (%q), %v", m, rec.Query, err)
	}
	_, err = c.RiskBasedMFA.EventFeedback(ctx, "re_1", "fraud")
	rec.expect(t, "POST", "/v1/risk_events/re_1/feedback")
	if err != nil || rec.Body["verdict"] != "fraud" {
		t.Errorf("EventFeedback body=%v, %v", rec.Body, err)
	}
	fl, err := c.RiskBasedMFA.FraudLookup(ctx, FraudLookupParams{IP: "1.2.3.4", Email: "a@b.test"})
	rec.expect(t, "POST", "/v1/fraud/lookup")
	if err != nil || rec.Body["ip"] != "1.2.3.4" || rec.Body["email"] != "a@b.test" || fl.Verdict != "challenge" || fl.MatchedRules[0] != "fr_1" {
		t.Errorf("FraudLookup body=%v out=%+v, %v", rec.Body, fl, err)
	}
}
