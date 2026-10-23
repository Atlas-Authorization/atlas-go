package atlas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── App roles, org teams/roles, invitations ───────────────────────────────────

func TestAppRolesWireSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"app_role","id":"ar_1","key":"support","name":"Support","permissions":["tickets:read"],"user_id":"u_1","role_keys":["support"],"data":[{"object":"app_role","id":"ar_1","key":"support"}],"has_more":false}`)

	list, err := c.AppRoles.List(ctx)
	if err != nil || len(list.Data) != 1 || list.Data[0].Key != "support" {
		t.Fatalf("List = %+v, %v", list, err)
	}
	rec.expect(t, "GET", "/v1/app_roles")

	r, _ := c.AppRoles.Create(ctx, CreateAppRoleParams{Key: "support", Name: "Support", Permissions: []string{"tickets:read"}})
	rec.expect(t, "POST", "/v1/app_roles")
	if rec.Body["key"] != "support" || r.Permissions[0] != "tickets:read" {
		t.Errorf("Create body=%v out=%+v", rec.Body, r)
	}
	_, _ = c.AppRoles.Get(ctx, "support")
	rec.expect(t, "GET", "/v1/app_roles/support")
	_, _ = c.AppRoles.Update(ctx, "support", UpdateAppRoleParams{Permissions: []string{"a:b"}})
	rec.expect(t, "PATCH", "/v1/app_roles/support")
	_, _ = c.AppRoles.Delete(ctx, "ar_1")
	rec.expect(t, "DELETE", "/v1/app_roles/ar_1")
	_, _ = c.AppRoles.ListUsers(ctx, "ar_1", 10, 20)
	rec.expect(t, "GET", "/v1/app_roles/ar_1/users")
	if rec.Query != "limit=10&offset=20" {
		t.Errorf("ListUsers query = %q", rec.Query)
	}
	ua, _ := c.AppRoles.GetForUser(ctx, "u_1")
	rec.expect(t, "GET", "/v1/users/u_1/app_roles")
	if ua.UserID != "u_1" || ua.RoleKeys[0] != "support" {
		t.Errorf("GetForUser = %+v", ua)
	}
	_, _ = c.AppRoles.SetForUser(ctx, "u_1", SetUserAppRolesParams{Add: []string{"support"}})
	rec.expect(t, "POST", "/v1/users/u_1/app_roles")
	if _, ok := rec.Body["roles"]; ok || rec.Body["add"] == nil {
		t.Errorf("SetForUser body = %v", rec.Body)
	}
	_, _ = c.AppRoles.RemoveFromUser(ctx, "u_1", "support")
	rec.expect(t, "DELETE", "/v1/users/u_1/app_roles/support")
}

func TestOrgTeamsRolesAndInvitations(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"team","id":"tm_1","organization_id":"org_1","name":"Core","members_count":2,"data":[],"slug":"acme","valid":true,"available":false,"key":"editor","members_reassigned":3}`)

	_, _ = c.Organizations.Teams.List(ctx, "org_1", "u_1")
	rec.expect(t, "GET", "/v1/organizations/org_1/teams")
	if rec.Query != "user_id=u_1" {
		t.Errorf("teams query = %q", rec.Query)
	}
	desc := "core team"
	tm, _ := c.Organizations.Teams.Create(ctx, "org_1", TeamParams{Name: "Core", Description: &desc})
	rec.expect(t, "POST", "/v1/organizations/org_1/teams")
	if rec.Body["name"] != "Core" || tm.MembersCount != 2 {
		t.Errorf("team create body=%v out=%+v", rec.Body, tm)
	}
	_, _ = c.Organizations.Teams.Get(ctx, "org_1", "tm_1")
	rec.expect(t, "GET", "/v1/organizations/org_1/teams/tm_1")
	_, _ = c.Organizations.Teams.Update(ctx, "org_1", "tm_1", TeamParams{Name: "Platform"})
	rec.expect(t, "PATCH", "/v1/organizations/org_1/teams/tm_1")
	_, _ = c.Organizations.Teams.Delete(ctx, "org_1", "tm_1")
	rec.expect(t, "DELETE", "/v1/organizations/org_1/teams/tm_1")
	_, _ = c.Organizations.Teams.ListMembers(ctx, "org_1", "tm_1")
	rec.expect(t, "GET", "/v1/organizations/org_1/teams/tm_1/members")
	_, _ = c.Organizations.Teams.AddMember(ctx, "org_1", "tm_1", "u_2")
	rec.expect(t, "POST", "/v1/organizations/org_1/teams/tm_1/members")
	if rec.Body["user_id"] != "u_2" {
		t.Errorf("AddMember body = %v", rec.Body)
	}
	_, _ = c.Organizations.Teams.RemoveMember(ctx, "org_1", "tm_1", "u_2")
	rec.expect(t, "DELETE", "/v1/organizations/org_1/teams/tm_1/members/u_2")

	_, _ = c.Organizations.Roles.List(ctx, "org_1", true)
	rec.expect(t, "GET", "/v1/organizations/org_1/roles")
	if rec.Query != "own=true" {
		t.Errorf("roles query = %q", rec.Query)
	}
	_, _ = c.Organizations.Roles.Create(ctx, "org_1", CreateOrgRoleParams{Key: "editor", Name: "Editor", Permissions: []string{"docs:write"}})
	rec.expect(t, "POST", "/v1/organizations/org_1/roles")
	_, _ = c.Organizations.Roles.Update(ctx, "org_1", "role_1", UpdateOrgRoleParams{Name: "Writer"})
	rec.expect(t, "PATCH", "/v1/organizations/org_1/roles/role_1")
	del, _ := c.Organizations.Roles.Delete(ctx, "org_1", "role_1", "member")
	rec.expect(t, "DELETE", "/v1/organizations/org_1/roles/role_1")
	if rec.Query != "reassign_to=member" || del.MembersReassigned != 3 {
		t.Errorf("role delete query=%q out=%+v", rec.Query, del)
	}

	_, _ = c.Organizations.GetBySlug(ctx, "acme")
	rec.expect(t, "GET", "/v1/organizations/by_slug/acme")
	chk, _ := c.Organizations.CheckSlug(ctx, "acme")
	rec.expect(t, "GET", "/v1/organizations/check_slug")
	if rec.Query != "slug=acme" || !chk.Valid || chk.Available {
		t.Errorf("CheckSlug query=%q out=%+v", rec.Query, chk)
	}
	_, _ = c.Organizations.Invitations.Resend(ctx, "org_1", "inv_1")
	rec.expect(t, "POST", "/v1/organizations/org_1/invitations/inv_1/resend")
}

// ── Users: search filters and timed bans ────────────────────────────────────

func TestUserSearchAndTimedBan(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"data":[{"id":"u_1","banned":true,"ban_expires_at":1900000000000}],"has_more":true,"next_cursor":"u_1","total_count":42}`)
	yes, no := true, false
	page, err := c.Users.Search(ctx, UserListParams{
		Limit: 5, Offset: 10, Query: "ada", EmailAddress: "a@x.io", Username: "ada", PhoneNumber: "+15550001",
		ExternalID: "ext_1", OrganizationID: "org_1", Banned: &yes, EmailVerified: &no,
		CreatedAfter: 1000, CreatedBefore: 2000, OrderBy: "-created_at", IncludeTotalCount: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/users")
	for _, want := range []string{"limit=5", "offset=10", "query=ada", "email_address=a%40x.io", "username=ada", "phone_number=%2B15550001",
		"external_id=ext_1", "organization_id=org_1", "banned=true", "email_verified=false", "created_after=1000",
		"created_before=2000", "order_by=-created_at", "include_total_count=true"} {
		if !strings.Contains(rec.Query, want) {
			t.Errorf("query %q lacks %s", rec.Query, want)
		}
	}
	if page.TotalCount == nil || *page.TotalCount != 42 || !page.HasMore || page.Data[0].BanExpiresAt == nil {
		t.Errorf("Search page = %+v", page)
	}

	_, _ = c.Users.BanWithParams(ctx, "u_1", BanParams{Reason: "spam", ExpiresInSeconds: 3600})
	rec.expect(t, "POST", "/v1/users/u_1/ban")
	if rec.Body["reason"] != "spam" || rec.Body["expires_in_seconds"] != float64(3600) {
		t.Errorf("ban body = %v", rec.Body)
	}
	if _, ok := rec.Body["expires_at"]; ok {
		t.Errorf("ban body sent expires_at: %v", rec.Body)
	}
}

// ── API key controls and coded verify refusals ──────────────────────────────

func TestAPIKeyControls(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"api_key_verification","valid":false,"code":"insufficient_scope","missing_scopes":["write"],"id":"ak_1"}`)
	v, err := c.APIKeys.VerifyWithParams(ctx, VerifyAPIKeyParams{Secret: "ak_x", RequiredScopes: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/api_keys/verify")
	if rec.Body["secret"] != "ak_x" || len(rec.Body["required_scopes"].([]interface{})) != 2 {
		t.Errorf("verify body = %v", rec.Body)
	}
	if v.Valid || v.Code != APIKeyRefusalInsufficientScope || v.MissingScopes[0] != "write" {
		t.Errorf("verdict = %+v", v)
	}

	enabled := false
	remaining := int64(100)
	_, _ = c.APIKeys.Create(ctx, CreateAPIKeyParams{SubjectType: "user", SubjectID: "u_1", Prefix: "acme",
		ExpiresInSeconds: 86400, Enabled: &enabled, RateLimit: &APIKeyRateLimit{Max: 10, WindowSeconds: 60}, Remaining: &remaining})
	rec.expect(t, "POST", "/v1/api_keys")
	rl := rec.Body["rate_limit"].(map[string]interface{})
	if rec.Body["prefix"] != "acme" || rec.Body["enabled"] != false || rl["max"] != float64(10) || rec.Body["remaining"] != float64(100) || rec.Body["expires_in_seconds"] != float64(86400) {
		t.Errorf("create body = %v", rec.Body)
	}

	on := true
	_, _ = c.APIKeys.Update(ctx, "ak_1", UpdateAPIKeyParams{Enabled: &on, ClearRateLimit: true, ClearRemaining: true})
	rec.expect(t, "PATCH", "/v1/api_keys/ak_1")
	if !strings.Contains(rec.RawBody, `"rate_limit":null`) || !strings.Contains(rec.RawBody, `"remaining":null`) || rec.Body["enabled"] != true {
		t.Errorf("update body = %s", rec.RawBody)
	}
	if strings.Contains(rec.RawBody, `"limits"`) {
		t.Errorf("update sent limits: %s", rec.RawBody)
	}
}

// ── Billing providers and subscription management ──────────────────────────

func TestBillingProvidersAndSubscriptions(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"billing_provider","provider":"polar","environment":"test","secrets_set":{"access_token":true},"webhook_url":"https://api/x","ok":true,"deleted":true,"id":"sub_1","status":"active","cancel_at_period_end":true,"scheduled":true,"data":[]}`)

	_, _ = c.Billing.ListProviders(ctx)
	rec.expect(t, "GET", "/v1/billing/providers")
	p, _ := c.Billing.GetProvider(ctx, "polar")
	rec.expect(t, "GET", "/v1/billing/providers/polar")
	if !p.SecretsSet["access_token"] || p.WebhookURL == "" {
		t.Errorf("provider = %+v", p)
	}
	_, _ = c.Billing.SetProvider(ctx, BillingProviderPolar, SetBillingProviderParams{Environment: "test", Config: map[string]string{"access_token": "polar_x"}})
	rec.expect(t, "PUT", "/v1/billing/providers/polar")
	if rec.Body["environment"] != "test" || rec.Body["config"].(map[string]interface{})["access_token"] != "polar_x" {
		t.Errorf("set body = %v", rec.Body)
	}
	_, _ = c.Billing.TestProvider(ctx, "polar")
	rec.expect(t, "POST", "/v1/billing/providers/polar/test")
	_, _ = c.Billing.DeleteProvider(ctx, "polar", true)
	rec.expect(t, "DELETE", "/v1/billing/providers/polar")
	if rec.Query != "force=true" {
		t.Errorf("delete query = %q", rec.Query)
	}

	sub, _ := c.Billing.ChangeSubscription(ctx, "sub_1", ChangeSubscriptionParams{PlanID: "plan_2", Interval: "year", SchedulePeriodEnd: true})
	rec.expect(t, "POST", "/v1/billing/subscriptions/sub_1/change")
	if rec.Body["plan_id"] != "plan_2" || rec.Body["interval"] != "year" || rec.Body["schedule_at_period_end"] != true || !sub.Scheduled {
		t.Errorf("change body=%v out=%+v", rec.Body, sub)
	}
	_, _ = c.Billing.CancelSubscription(ctx, "sub_1", true)
	rec.expect(t, "POST", "/v1/billing/subscriptions/sub_1/cancel")
	if rec.Body["immediately"] != true {
		t.Errorf("cancel body = %v", rec.Body)
	}
	sub, _ = c.Billing.RestoreSubscription(ctx, "sub_1")
	rec.expect(t, "POST", "/v1/billing/subscriptions/sub_1/restore")
	if !sub.CancelAtPeriodEnd {
		t.Errorf("restore out = %+v", sub)
	}

	_, _ = c.Billing.CreatePlan(ctx, CreateBillingPlanParams{Name: "Pro", Slug: "pro", Provider: "polar", ProviderPriceID: "price_1", AnnualPriceID: "price_y", AnnualAmount: "99.00"})
	rec.expect(t, "POST", "/v1/billing/plans")
	if rec.Body["provider"] != "polar" || rec.Body["annual_price_id"] != "price_y" || rec.Body["annual_amount"] != "99.00" {
		t.Errorf("plan body = %v", rec.Body)
	}
	if _, ok := rec.Body["stripe_price_id"]; ok {
		t.Errorf("plan body sent an empty stripe_price_id: %v", rec.Body)
	}
}

// ── OAuth server admin: signing keys, initial access tokens, client fields ──

func TestOAuthServerAdmin(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","kid":"k2","alg":"ES256","previous_kid":"k1","emergency":false,"data":[{"kid":"k2","alg":"ES256","status":"current","role":"main"}],"id":"iat_1","token":"iat_secret","status":"active","has_more":false,"disabled":true,"require_pkce":true,"subject_type":"pairwise","client_secret_expires_at":5}`)

	keys, _ := c.InstanceSecurity.ListSigningKeys(ctx)
	rec.expect(t, "GET", "/v1/instance/signing_keys")
	if keys.Data[0].Alg != "ES256" || keys.Data[0].Role != "main" {
		t.Errorf("keys = %+v", keys)
	}
	rot, _ := c.InstanceSecurity.RotateSigningKey(ctx, RotateSigningKeyParams{Alg: "ES256"})
	rec.expect(t, "POST", "/v1/instance/signing_keys/rotate")
	if rec.Body["alg"] != "ES256" || rot.PreviousKid == nil {
		t.Errorf("rotate body=%v out=%+v", rec.Body, rot)
	}

	tok, _ := c.OAuthInitialAccessTokens.Create(ctx, CreateInitialAccessTokenParams{Description: "ci", MaxUses: 5})
	rec.expect(t, "POST", "/v1/oauth_initial_access_tokens")
	if tok.Token != "iat_secret" || rec.Body["max_uses"] != float64(5) {
		t.Errorf("iat create body=%v out=%+v", rec.Body, tok)
	}
	_, _ = c.OAuthInitialAccessTokens.List(ctx)
	rec.expect(t, "GET", "/v1/oauth_initial_access_tokens")
	_, _ = c.OAuthInitialAccessTokens.Revoke(ctx, "iat_1")
	rec.expect(t, "DELETE", "/v1/oauth_initial_access_tokens/iat_1")

	off, ttl := true, int64(3600)
	cl, _ := c.OAuthClients.Update(ctx, "oc_1", UpdateOAuthClientParams{Disabled: &off, RequirePKCE: &off, SubjectType: "pairwise", SectorIdentifierURI: "https://rp/sector.json", SecretExpiresInSeconds: &ttl})
	rec.expect(t, "PATCH", "/v1/oauth_clients/oc_1")
	if rec.Body["disabled"] != true || rec.Body["require_pkce"] != true || rec.Body["subject_type"] != "pairwise" || rec.Body["sector_identifier_uri"] == nil || rec.Body["secret_expires_in_seconds"] != float64(3600) {
		t.Errorf("client body = %v", rec.Body)
	}
	if !cl.Disabled || !cl.RequirePKCE || cl.SubjectType != "pairwise" || cl.ClientSecretExpiresAt == nil {
		t.Errorf("client out = %+v", cl)
	}

	pub := true
	_, _ = c.ResourceServers.Update(ctx, "rs_1", UpdateResourceServerParams{SigningAlg: "ES256", PublishResourceMetadata: &pub})
	rec.expect(t, "PATCH", "/v1/resource_servers/rs_1")
	if rec.Body["signing_alg"] != "ES256" || rec.Body["publish_resource_metadata"] != true {
		t.Errorf("resource server body = %v", rec.Body)
	}

	_, _ = c.SCIMTokens.Update(ctx, "st_1", UpdateScimTokenParams{Scopes: []string{"read"}, RoleMappings: []ScimRoleMapping{{Value: "Admins", Role: "admin"}}})
	rec.expect(t, "PATCH", "/v1/scim_tokens/st_1")
	if rec.Body["scopes"] == nil || rec.Body["role_mappings"] == nil {
		t.Errorf("scim body = %v", rec.Body)
	}

	test := true
	_, _ = c.UserHooks.ListBeforeUserCreateCalls(ctx, ListBeforeUserCreateCallsParams{Status: "failed", Test: &test})
	rec.expect(t, "GET", "/v1/instance/hooks/before_user_create/calls")
	if rec.Query != "status=failed&test=true" {
		t.Errorf("hook calls query = %q", rec.Query)
	}
	_, _ = c.Referrals.GetCall(ctx, "rc_1")
	rec.expect(t, "GET", "/v1/instance/referrals/calls/rc_1")
}

func TestImportNewFields(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"job","id":"job_1"}`)
	create := true
	_, _ = c.ImportExport.ImportUsers(ctx, ImportUsersParams{
		Users: []ImportUserRow{{
			Email: "a@x.io", ExternalID: "old_1", CreatedAt: "2020-01-01T00:00:00Z", PasswordSalt: "c2FsdA==",
			PhoneNumbers:            []ImportPhoneNumber{{PhoneNumber: "+15550001", Verified: true}},
			OrganizationMemberships: []ImportOrganizationMembership{{OrganizationExternalID: "team_9", Role: "admin"}},
		}},
		CreateOrganizations: &create,
		PasswordHashConfig:  &ImportPasswordHashConfig{Firebase: &FirebaseScryptConfig{SignerKey: "k", SaltSeparator: "Bw==", Rounds: 8, MemCost: 14}},
	})
	rec.expect(t, "POST", "/v1/user_imports")
	row := rec.Body["users"].([]interface{})[0].(map[string]interface{})
	if row["external_id"] != "old_1" || row["created_at"] == nil || row["phone_numbers"] == nil || row["organization_memberships"] == nil {
		t.Errorf("row = %v", row)
	}
	fb := rec.Body["password_hash_config"].(map[string]interface{})["firebase"].(map[string]interface{})
	if rec.Body["create_organizations"] != true || fb["rounds"] != float64(8) {
		t.Errorf("import body = %v", rec.Body)
	}
}

// ── Verifiers: ES256, alg pinning, app claims, access tokens ─────────────────

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	p, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func mixedJWKS(t *testing.T, ec *ecdsa.PrivateKey, rs *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{
			{"kty": "EC", "crv": "P-256", "kid": "ec1", "alg": "ES256", "x": b64(ec.PublicKey.X.FillBytes(make([]byte, 32))), "y": b64(ec.PublicKey.Y.FillBytes(make([]byte, 32)))},
			{"kty": "RSA", "kid": "rs1", "alg": "RS256", "n": b64(rs.N.Bytes()), "e": "AQAB"},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSessionVerifierAcceptsES256AndPinsAlgs(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := mixedJWKS(t, ec, rs)
	now := time.Unix(1_800_000_000, 0)
	b := newVerifier(t, srv.URL, "https://iss.test", now)
	claims := map[string]interface{}{"iss": "https://iss.test", "sub": "u_1", "exp": now.Unix() + 60, "app_roles": []string{"support"}, "app_permissions": []string{"tickets:read"}}

	got, err := b.Verify(context.Background(), signES256(t, ec, "ec1", claims))
	if err != nil || got.Sub != "u_1" {
		t.Fatalf("ES256 verify = %+v, %v", got, err)
	}
	if !got.HasAppRole("support") || !got.HasAppPermission("tickets:read") || got.HasAppPermission("tickets:write") || got.HasAppRole("admin") {
		t.Errorf("app claim helpers wrong: %+v", got.Raw)
	}
	if _, err := b.Verify(context.Background(), signRS256(t, rs, "rs1", claims)); err != nil {
		t.Errorf("RS256 still verifies: %v", err)
	}
	// An ES256 token naming the RSA kid, and an RS256 one naming the EC kid, fail.
	if _, err := b.Verify(context.Background(), signES256(t, ec, "rs1", claims)); err == nil {
		t.Error("ES256 over an RSA kid verified")
	}
	// alg header outside the pin list fails even with a valid ES256 signature.
	tok := signES256(t, ec, "ec1", claims)
	parts := strings.Split(tok, ".")
	h, _ := json.Marshal(map[string]string{"alg": "ES384", "kid": "ec1"})
	if _, err := b.Verify(context.Background(), b64(h)+"."+parts[1]+"."+parts[2]); err == nil {
		t.Error("ES384 header verified")
	}
	hn, _ := json.Marshal(map[string]string{"alg": "none", "kid": "ec1"})
	if _, err := b.Verify(context.Background(), b64(hn)+"."+parts[1]+"."); err == nil {
		t.Error("alg none verified")
	}
}

func TestAccessTokenVerifier(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := mixedJWKS(t, ec, rs)
	now := time.Unix(1_800_000_000, 0)
	v, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: "https://iss.test/", Audiences: []string{"https://api.test"}, RequiredScopes: []string{"read"},
		JWKSURL: srv.URL, ResourceMetadataURL: "https://api.test/.well-known/oauth-protected-resource",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	base := func() map[string]interface{} {
		return map[string]interface{}{"iss": "https://iss.test", "sub": "u_1", "aud": "https://api.test", "exp": now.Unix() + 60,
			"token_use": "access_token", "scope": "read write", "client_id": "oc_1"}
	}
	ctx := context.Background()

	ok := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", base()))
	if !ok.OK || ok.Subject != "u_1" || ok.ClientID != "oc_1" || len(ok.Scopes) != 2 {
		t.Fatalf("ES256 access token = %+v", ok)
	}
	if r := v.Verify(ctx, "Bearer "+signRS256(t, rs, "rs1", base())); !r.OK {
		t.Errorf("RS256 access token refused: %+v", r)
	}

	none := v.Verify(ctx, "")
	if none.Status != 401 || none.Error != "" || none.WWWAuthenticate != `Bearer scope="read", resource_metadata="https://api.test/.well-known/oauth-protected-resource"` {
		t.Errorf("no token = %+v", none)
	}
	if r := v.Verify(ctx, "Basic abc"); r.Status != 400 || r.Error != AccessTokenInvalidRequest {
		t.Errorf("malformed header = %+v", r)
	}
	wrongAud := base()
	wrongAud["aud"] = "https://other.test"
	if r := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", wrongAud)); r.Status != 401 || r.Error != AccessTokenInvalidToken || !strings.Contains(r.WWWAuthenticate, `error="invalid_token"`) {
		t.Errorf("wrong aud = %+v", r)
	}
	session := base()
	session["token_use"] = "session"
	if r := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", session)); r.OK {
		t.Error("session token accepted as access token")
	}
	expired := base()
	expired["exp"] = now.Unix() - 60
	if r := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", expired)); r.OK {
		t.Error("expired token accepted")
	}
	bound := base()
	bound["cnf"] = map[string]string{"jkt": "abc"}
	if r := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", bound)); r.OK {
		t.Error("DPoP-bound token accepted as Bearer")
	}
	short := base()
	short["scope"] = "write"
	r := v.Verify(ctx, "Bearer "+signES256(t, ec, "ec1", short), "admin")
	if r.Status != 403 || r.Error != AccessTokenInsufficientScope || !strings.Contains(r.WWWAuthenticate, `scope="read admin"`) {
		t.Errorf("insufficient scope = %+v", r)
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: "https://iss.test"}); err == nil {
		t.Error("verifier without audience built")
	}
	if p, _ := ProtectedResourceMetadataPath("https://api.test/v1/"); p != "/.well-known/oauth-protected-resource/v1" {
		t.Errorf("metadata path = %q", p)
	}
	doc := ProtectedResourceMetadata("https://api.test", "https://iss.test/", []string{"read"})
	if doc["authorization_servers"].([]string)[0] != "https://iss.test" {
		t.Errorf("metadata = %v", doc)
	}
}
