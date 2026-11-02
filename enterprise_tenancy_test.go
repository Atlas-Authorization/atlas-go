package atlas

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestEnterpriseTenancyRoutes checks the verb, path, query and body of every
// operation added for tenant organizations, setup links, trusted-JWT
// connections, chosen webhook secrets, initial-secret reveal and path mounts.
func TestEnterpriseTenancyRoutes(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/organizations/by_domain/acme.com":
			return `{"object":"organization","id":"org_1","name":"Acme","created_by":null,"external_id":"cust_1","role_mappings":{"org:admin":"owner"},"domain":{"object":"org_domain","id":"dom_1","domain":"acme.com","status":"verified","verified_at":5}}`
		case "/v1/organizations/org_1":
			return `{"object":"organization","id":"org_1","name":"Acme","created_by":null,"external_id":null,"role_mappings":null,"sso":{"connections":[{"id":"sso_1","type":"saml","status":"active"}],"scim_base_url":"https://acme-fapi.example.com/scim/v2/org_1"}}`
		case "/v1/platform/apps/ins_1/initial_secret/reveal":
			return `{"object":"initial_secret","app_id":"ins_1","instance_id":"ins_1","key_id":"key_1","secret":"sk_live_x","sibling_instance":{"instance_id":"ins_2","key_id":"key_2","secret":"sk_test_y"}}`
		case "/v1/webhook_endpoints/we_1/test":
			return `{"object":"webhook_test_result","delivery_id":"del_1","event_id":"evt_1","event_type":"webhook.test","status":"failed","http_status":500,"error_kind":"non_2xx","will_retry":false}`
		case "/v1/scim_tokens":
			return `{"object":"scim_token","id":"st_1","secret":"s","scim_base_url":"https://acme-fapi.example.com/scim/v2/org_1","warnings":[{"code":"no_sso_connection","message":"m"}],"note":"n"}`
		case "/v1/domains/dm_1/verify":
			return `{"object":"custom_domain","id":"dm_1","host":"app.example.com","method":"path","cname_target":null,"base_path":"/__atlas","routing":"customer_proxy","verified":true,"issuer":"https://app.example.com/__atlas"}`
		}
		return `{"object":"organization","id":"org_1"}`
	})
	ctx := context.Background()
	idx := func() platRecorded { return got[len(got)-1] }
	expect := func(method, path string) platRecorded {
		t.Helper()
		r := idx()
		if r.Method != method || r.Path != path {
			t.Fatalf("got %s %s, want %s %s", r.Method, r.Path, method, path)
		}
		return r
	}

	// Organizations: backend-created, filters, by_domain, policy, sso block.
	if _, err := c.Organizations.Create(ctx, CreateOrganizationParams{Name: "Acme", Slug: "acme", ExternalID: "cust_1", OwnerEmail: "it@acme.com", RoleMappings: map[string]string{"org:admin": "owner"}, PublicMetadata: Metadata{"plan": "pro"}}); err != nil {
		t.Fatal(err)
	}
	b := bodyMap(t, expect("POST", "/v1/organizations").Body)
	if _, has := b["created_by"]; has || b["external_id"] != "cust_1" || b["owner_email"] != "it@acme.com" {
		t.Fatalf("create body = %v", b)
	}
	if _, err := c.Organizations.Update(ctx, "org_1", UpdateOrganizationParams{ClearExternalID: true, ClearRoleMappings: true}); err != nil {
		t.Fatal(err)
	}
	b = bodyMap(t, expect("PATCH", "/v1/organizations/org_1").Body)
	if v, has := b["external_id"]; !has || v != nil {
		t.Fatalf("update body = %v, want external_id null", b)
	}
	if v, has := b["role_mappings"]; !has || v != nil {
		t.Fatalf("update body = %v, want role_mappings null", b)
	}
	if _, err := c.Organizations.ListFiltered(ctx, ListOrganizationsParams{ExternalID: "cust_1", Metadata: map[string]string{"plan": "pro"}}); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(expect("GET", "/v1/organizations").Query)
	if q.Get("external_id") != "cust_1" || q.Get("metadata[plan]") != "pro" {
		t.Fatalf("list query = %v", q)
	}
	byDomain, err := c.Organizations.FindByDomain(ctx, "acme.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if expect("GET", "/v1/organizations/by_domain/acme.com").Query != "include_unverified=true" {
		t.Fatalf("by_domain query = %q", idx().Query)
	}
	if byDomain.ID != "org_1" || byDomain.Domain.Status != "verified" || byDomain.CreatedBy != "" || *byDomain.ExternalID != "cust_1" || byDomain.RoleMappings["org:admin"] != "owner" {
		t.Fatalf("by_domain = %+v", byDomain)
	}
	if _, err := c.Organizations.GetPolicy(ctx, "org_1"); err != nil {
		t.Fatal(err)
	}
	expect("GET", "/v1/organizations/org_1/policy")
	org, err := c.Organizations.Get(ctx, "org_1")
	if err != nil {
		t.Fatal(err)
	}
	if org.SSO == nil || org.SSO.ScimBaseURL == "" || org.SSO.Connections[0].Status != "active" {
		t.Fatalf("sso = %+v", org.SSO)
	}

	// Domain verification: no body keeps the DNS check; a method sends one.
	if _, err := c.Organizations.Domains.Verify(ctx, "org_1", "dom_1"); err != nil {
		t.Fatal(err)
	}
	if r := expect("POST", "/v1/organizations/org_1/domains/dom_1/verify"); len(r.Body) != 0 {
		t.Fatalf("plain verify sent a body: %s", r.Body)
	}
	if _, err := c.Organizations.Domains.VerifyWith(ctx, "org_1", "dom_1", VerifyOrgDomainParams{Method: "email", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	b = bodyMap(t, expect("POST", "/v1/organizations/org_1/domains/dom_1/verify").Body)
	if b["method"] != "email" || b["code"] != "123456" {
		t.Fatalf("verify body = %v", b)
	}
	if _, err := c.Organizations.Domains.SendVerificationEmail(ctx, "org_1", "dom_1", "hostmaster"); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/organizations/org_1/domains/dom_1/verification_email").Body); b["address"] != "hostmaster" {
		t.Fatalf("verification_email body = %v", b)
	}

	// Trusted-JWT connections.
	maxAge := 120
	if _, err := c.JWTConnections.Create(ctx, JWTConnectionParams{JWKSURI: "https://idp.example.com/jwks.json", Issuer: "https://idp.example.com", Audience: "atlas", MaxAgeSeconds: &maxAge}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/jwt_connections").Body); b["jwks_uri"] != "https://idp.example.com/jwks.json" || b["max_age_seconds"] != float64(120) {
		t.Fatalf("jwt connection body = %v", b)
	}
	if _, err := c.JWTConnections.List(ctx); err != nil {
		t.Fatal(err)
	}
	expect("GET", "/v1/jwt_connections")
	if _, err := c.JWTConnections.Get(ctx, "jwc_1"); err != nil {
		t.Fatal(err)
	}
	expect("GET", "/v1/jwt_connections/jwc_1")
	if _, err := c.JWTConnections.Update(ctx, "jwc_1", JWTConnectionParams{Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("PATCH", "/v1/jwt_connections/jwc_1").Body); b["status"] != "active" || len(b) != 1 {
		t.Fatalf("jwt update body = %v", b)
	}
	if _, err := c.JWTConnections.Delete(ctx, "jwc_1"); err != nil {
		t.Fatal(err)
	}
	expect("DELETE", "/v1/jwt_connections/jwc_1")

	// SCIM token create returns the base URL and the no-connection warning.
	tok, err := c.SCIMTokens.Create(ctx, CreateScimTokenParams{OrganizationID: "org_1"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.ScimBaseURL == "" || len(tok.Warnings) != 1 || tok.Warnings[0].Code != "no_sso_connection" {
		t.Fatalf("scim token = %+v", tok)
	}

	// Setup links: return_url and the name filter.
	ret := "https://app.example.com/settings/sso"
	if _, err := c.SSOOnboarding.CreateTicket(ctx, "sop_1", CreateSSOOnboardingTicketParams{ReturnURL: &ret}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/sso_onboarding_profiles/sop_1/tickets").Body); b["return_url"] != ret {
		t.Fatalf("ticket body = %v", b)
	}
	if _, err := c.SSOOnboarding.ListByName(ctx, "Default"); err != nil {
		t.Fatal(err)
	}
	if expect("GET", "/v1/sso_onboarding_profiles").Query != "name=Default" {
		t.Fatalf("profiles query = %q", idx().Query)
	}

	// Webhook endpoints: inactive create with a chosen secret; rotate to one.
	off := false
	secret := "whsec_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	if _, err := c.Webhooks.Endpoints.Create(ctx, CreateWebhookEndpointParams{URL: "https://hooks.example.com/atlas", Active: &off, Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/webhook_endpoints").Body); b["active"] != false || b["secret"] != secret {
		t.Fatalf("endpoint body = %v", b)
	}
	if _, err := c.Webhooks.Endpoints.RotateSecretWithParams(ctx, "we_1", RotateWebhookSecretParams{Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/webhook_endpoints/we_1/rotate_secret").Body); b["secret"] != secret {
		t.Fatalf("rotate body = %v", b)
	}
	res, err := c.Webhooks.Endpoints.TestNow(ctx, "we_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.EventType != "webhook.test" || res.ErrorKind == nil || *res.ErrorKind != "non_2xx" {
		t.Fatalf("test result = %+v", res)
	}

	// Users: a hash that does not describe itself.
	if _, err := c.Users.Create(ctx, CreateUserParams{EmailAddress: "ada@example.com", PasswordHash: "c2FsdA==$aGFzaA==", PasswordHashAlgorithm: "scrypt", PasswordHashParams: map[string]interface{}{"n": 16384, "r": 8, "p": 1}}); err != nil {
		t.Fatal(err)
	}
	if b = bodyMap(t, expect("POST", "/v1/users").Body); b["password_hash_algorithm"] != "scrypt" || b["password_hash_params"].(map[string]interface{})["n"] != float64(16384) {
		t.Fatalf("user body = %v", b)
	}

	// Platform: initial-secret reveal (platform key, no body).
	reveal, err := c.Platform.Apps.RevealInitialSecret(ctx, "ins_1")
	if err != nil {
		t.Fatal(err)
	}
	if r := expect("POST", "/v1/platform/apps/ins_1/initial_secret/reveal"); r.Auth != "Bearer psk_test" {
		t.Fatalf("reveal auth = %q", r.Auth)
	}
	if reveal.Secret == nil || *reveal.Secret != "sk_live_x" || reveal.SiblingInstance == nil || *reveal.SiblingInstance.Secret != "sk_test_y" {
		t.Fatalf("reveal = %+v", reveal)
	}

	// Referral settings: the two new fields.
	yes := true
	if _, err := c.Referrals.Update(ctx, UpdateReferralSettingsParams{ReportLinkedAtlasIDSignups: &yes, PartnerPortalURL: "https://partners.example.com"}); err != nil {
		t.Fatal(err)
	}
	b = bodyMap(t, expect("PATCH", "/v1/instance/referrals").Body)
	if b["report_linked_atlas_id_signups"] != true || b["partner_portal_url"] != "https://partners.example.com" {
		t.Fatalf("referral body = %v", b)
	}

	// Path-mount domains.
	if _, err := c.Domains.Create(ctx, CreateDomainParams{Method: "path", Hostname: "app.example.com", BasePath: "/__atlas"}); err != nil {
		t.Fatal(err)
	}
	b = bodyMap(t, expect("POST", "/v1/domains").Body)
	if _, has := b["host"]; has || b["method"] != "path" || b["hostname"] != "app.example.com" || b["base_path"] != "/__atlas" {
		t.Fatalf("domain body = %v", b)
	}
	dom, err := c.Domains.Verify(ctx, "dm_1")
	if err != nil {
		t.Fatal(err)
	}
	if dom.Issuer != "https://app.example.com/__atlas" || dom.Method != "path" || dom.CNAMETarget != "" || *dom.Routing != "customer_proxy" {
		t.Fatalf("verified domain = %+v", dom)
	}

	// Cookie consent host aliases (an empty list clears, never null).
	if _, err := c.Instance.SetCookieConsentHostAliases(ctx, nil); err != nil {
		t.Fatal(err)
	}
	r := expect("PUT", "/v1/instance/cookie_consent")
	var hosts map[string][]string
	if err := json.Unmarshal(r.Body, &hosts); err != nil || hosts["host_aliases"] == nil || len(hosts["host_aliases"]) != 0 {
		t.Fatalf("cookie consent body = %s", r.Body)
	}
}

// TestOrgLDAPGroupRoleMappingsClear: ClearGroupRoleMappings sends null and
// keeps the other fields.
func TestOrgLDAPGroupRoleMappingsClear(t *testing.T) {
	raw, err := json.Marshal(OrgLDAPConnectionParams{URL: "ldaps://ldap.example.com", ClearGroupRoleMappings: true})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]interface{}{}
	_ = json.Unmarshal(raw, &m)
	if v, has := m["group_role_mappings"]; !has || v != nil || m["url"] != "ldaps://ldap.example.com" {
		t.Fatalf("body = %s", raw)
	}
	if _, has := m["default_role_id"]; has {
		t.Fatalf("default_role_id must stay absent: %s", raw)
	}
}

// TestVerifyAcceptsPreviousIssuers: a token from the instance's previous
// issuer verifies only when listed; any other issuer is still refused.
func TestVerifyAcceptsPreviousIssuers(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	srv := jwksServer(t, key, "kid-1", nil)
	const current, previous = "https://app.example.com/__atlas", "https://acme-fapi.example.com"
	tokenFor := func(iss string) string {
		return signToken(t, key, "kid-1", map[string]interface{}{"iss": iss, "sub": "user_1", "exp": now.Add(time.Minute).Unix()})
	}
	b, err := NewAtlasBackend(AtlasBackendOptions{JWKSURL: srv.URL, Issuer: current, PreviousIssuers: []string{previous}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range []string{current, previous} {
		if _, err := b.Verify(context.Background(), tokenFor(iss)); err != nil {
			t.Fatalf("iss %s: %v", iss, err)
		}
	}
	if _, err := b.Verify(context.Background(), tokenFor("https://other.example.com")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("other issuer: err = %v, want ErrInvalidToken", err)
	}
	strict := newVerifier(t, srv.URL, current, now)
	if _, err := strict.Verify(context.Background(), tokenFor(previous)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("previous issuer without the option: err = %v, want ErrInvalidToken", err)
	}
}
