package atlas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// Gap-fix additions on top of the integrator-platform surface: partner link
// requests, key origin locks, ORIGIN_NOT_ALLOWED, since=failing_since,
// OIDC org / SSO claims and the browser atlas_id_tokens route.

func TestGapFixWireSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","data":[]}`, WithPlatformKey("psk_test"))

	cases := []struct {
		method, path, query, body string
		call                      func() error
	}{
		{"GET", "/v1/partner_links/requests", "direction=inbound&status=pending%2Cdelivery_failed", "", func() error {
			_, err := c.PartnerLinks.Requests.List(ctx, ListPartnerLinkRequestsParams{Direction: "inbound", Status: []string{"pending", "delivery_failed"}})
			return err
		}},
		{"GET", "/v1/partner_links/requests/plr_1", "", "", func() error { _, err := c.PartnerLinks.Requests.Get(ctx, "plr_1"); return err }},
		{"POST", "/v1/partner_links/requests/plr_1/approve", "", `{"scopes":["privacy:execute"]}`, func() error {
			_, err := c.PartnerLinks.Requests.Approve(ctx, "plr_1", ApprovePartnerLinkRequestParams{Scopes: []string{"privacy:execute"}})
			return err
		}},
		{"POST", "/v1/partner_links/requests/plr_1/deny", "", "", func() error { _, err := c.PartnerLinks.Requests.Deny(ctx, "plr_1"); return err }},
		{"PATCH", "/v1/partner_links/pl_1", "", `{"cert_fingerprints":["abc"]}`, func() error {
			_, err := c.PartnerLinks.SetCertificates(ctx, "pl_1", []string{"abc"})
			return err
		}},
		{"PATCH", "/v1/partner_links/pl_1", "", `{"cert_fingerprints":[]}`, func() error {
			_, err := c.PartnerLinks.SetCertificates(ctx, "pl_1", nil)
			return err
		}},
		{"POST", "/v1/partner_links/outbound/cm/request", "", `{"scopes":["privacy:execute"]}`, func() error {
			_, err := c.PartnerLinks.Outbound.Request(ctx, "cm", RequestOutboundPartnerLinkParams{Scopes: []string{"privacy:execute"}})
			return err
		}},
		{"POST", "/v1/secret_keys", "", `{"scopes":["a"],"allowed_origins":["https://app.example.com"],"owner":"user:u1"}`, func() error {
			_, err := c.SecretKeys.Create(ctx, CreateSecretKeyParams{Scopes: []string{"a"}, AllowedOrigins: []string{"https://app.example.com"}, Owner: "user:u1"})
			return err
		}},
		{"PATCH", "/v1/secret_keys/k1", "", `{"allowed_origins":["https://*.example.com"]}`, func() error {
			_, err := c.SecretKeys.Update(ctx, "k1", UpdateSecretKeyParams{AllowedOrigins: []string{"https://*.example.com"}})
			return err
		}},
		{"POST", "/v1/platform/keys", "", `{"scopes":["apps:read"],"allowed_origins":["https://a.example.com"]}`, func() error {
			_, err := c.Platform.Keys.Create(ctx, CreatePlatformKeyParams{Scopes: []string{"apps:read"}, AllowedOrigins: []string{"https://a.example.com"}})
			return err
		}},
		{"POST", "/v1/webhook_endpoints/we1/replay", "", `{"since":"failing_since"}`, func() error {
			_, err := c.Webhooks.Endpoints.Replay(ctx, "we1", ReplayWebhookParams{SinceKeyword: SinceFailingSince})
			return err
		}},
		{"POST", "/v1/webhook_endpoints/we1/replay", "", `{"since":5}`, func() error {
			_, err := c.Webhooks.Endpoints.Replay(ctx, "we1", ReplayWebhookParams{WebhookWindow: WebhookWindow{Since: 5}, SinceKeyword: SinceFailingSince})
			return err
		}},
		{"POST", "/v1/webhook_endpoints/we1/redeliver", "", `{"since":"failing_since","status":"failed"}`, func() error {
			_, err := c.Webhooks.Endpoints.RedeliverWindow(ctx, "we1", RedeliverWebhookWindowParams{Status: "failed", SinceKeyword: SinceFailingSince})
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

func TestOriginNotAllowedError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":[{"code":"ORIGIN_NOT_ALLOWED","message":"no"}]}`))
	})
	_, err := c.Whoami(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsOriginNotAllowed() || apiErr.Code() != ErrCodeOriginNotAllowed || apiErr.IsInsufficientScope() {
		t.Fatalf("err = %v", err)
	}
	if ErrCodeOriginNotAllowed != "ORIGIN_NOT_ALLOWED" {
		t.Error("code spelling")
	}
}

func TestLastFailingSinceDecodes(t *testing.T) {
	var ep WebhookEndpoint
	if err := json.Unmarshal([]byte(`{"id":"we1","failing_since":null,"last_failing_since":1700000000000}`), &ep); err != nil {
		t.Fatal(err)
	}
	if ep.FailingSince != nil || ep.LastFailingSince == nil || *ep.LastFailingSince != 1700000000000 {
		t.Errorf("endpoint = %+v", ep)
	}
	var k SecretKey
	if err := json.Unmarshal([]byte(`{"id":"k","allowed_origins":["https://a.example.com"],"origin_allowlist":["https://a.example.com"],"owner":"user:u1","expires_at":5}`), &k); err != nil {
		t.Fatal(err)
	}
	if len(k.AllowedOrigins) != 1 || *k.Owner != "user:u1" || *k.ExpiresAt != 5 {
		t.Errorf("key = %+v", k)
	}
}

func TestOIDCOrgAndSSOClaims(t *testing.T) {
	var claims map[string]interface{}
	_ = json.Unmarshal([]byte(`{"sub":"u1","org_id":"org_1","org_slug":"acme","org_role":"admin","org_permissions":["org:read",3],
		"orgs":[{"id":"org_1","slug":"acme","role":"admin"},{"slug":"x"}],
		"sso_connection_id":"sso_1","sso_tenant_id":"tid","sso_issuer":"https://idp","sso_domain":"acme.com"}`), &claims)
	org := OIDCOrganizationOf(claims)
	if org == nil || org.ID != "org_1" || org.Slug != "acme" || org.Role != "admin" || len(org.Permissions) != 1 || org.Permissions[0] != "org:read" {
		t.Errorf("org = %+v", org)
	}
	orgs := OIDCOrganizationsOf(claims)
	if len(orgs) != 1 || orgs[0] != (OIDCOrganizationMembership{ID: "org_1", Slug: "acme", Role: "admin"}) {
		t.Errorf("orgs = %+v", orgs)
	}
	sso := OIDCSSOOf(claims)
	if sso == nil || *sso != (OIDCSSOContext{ConnectionID: "sso_1", TenantID: "tid", Issuer: "https://idp", Domain: "acme.com"}) {
		t.Errorf("sso = %+v", sso)
	}
	plain := map[string]interface{}{"sub": "u"}
	if OIDCOrganizationOf(plain) != nil || OIDCOrganizationsOf(plain) != nil || OIDCSSOOf(plain) != nil {
		t.Error("claims absent but returned")
	}
	if OIDCScopeOrganizations != "organizations" {
		t.Error("scope")
	}
	u, err := OIDCAuthorizeURLWithOrganization("https://atlasauth.net/oauth2/authorize?client_id=c", "acme")
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	if pu.Query().Get("organization") != "acme" || pu.Query().Get("client_id") != "c" {
		t.Errorf("url = %s", u)
	}
	u2, _ := OIDCAuthorizeURLWithOrganization(u, "other")
	pu2, _ := url.Parse(u2)
	if got := pu2.Query()["organization"]; len(got) != 1 || got[0] != "other" {
		t.Errorf("url = %s", u2)
	}
}

func TestPartnerLinkRequestProtocol(t *testing.T) {
	ctx := context.Background()
	var gotAuth, gotMethod, gotPath string
	var gotBody map[string]interface{}
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotMethod, gotPath = r.Header.Get("Authorization"), r.Method, r.URL.Path
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		if fail {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errors":[{"code":"PARTNER_LINK_UNAVAILABLE","message":"no"}]}`))
			return
		}
		if r.Method == "POST" {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"object":"partner_link_request","protocol":"atlas.partner_link_request.v1","id":"plr_1","status":"pending","request_secret":"rs_1","expires_at":9}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"partner_link_request","id":"plr_1","status":"approved"}`))
	}))
	defer srv.Close()
	opts := &PartnerLinkRequestOptions{BaseURL: srv.URL}

	created, err := RequestPartnerLink(ctx, PartnerLinkRequestInput{Partner: "acme", Resource: "ins_1", Scopes: []string{"privacy:execute"}, CallbackURL: "https://acme.test/cb"}, opts)
	if err != nil || created.RequestSecret != "rs_1" || created.Protocol != PartnerLinkRequestProtocol {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if gotMethod != "POST" || gotPath != "/v1/partner_link_requests" || gotAuth != "" || gotBody["callback_url"] != "https://acme.test/cb" {
		t.Errorf("request = %s %s auth=%q body=%v", gotMethod, gotPath, gotAuth, gotBody)
	}
	got, err := GetPartnerLinkRequest(ctx, "plr_1", "rs_1", opts)
	if err != nil || got.Status != "approved" || gotAuth != "Bearer rs_1" || gotPath != "/v1/partner_link_requests/plr_1" {
		t.Fatalf("get = %+v, %v (auth=%q path=%q)", got, err, gotAuth, gotPath)
	}
	fail = true
	_, err = RequestPartnerLink(ctx, PartnerLinkRequestInput{Partner: "x"}, opts)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.HasCode(ErrCodePartnerLinkUnavailable) {
		t.Errorf("err = %v", err)
	}

	// the signed delivery
	now := time.UnixMilli(1_757_937_600_000)
	ts := now.UnixMilli()
	body := `{"object":"partner_link.credentials","protocol":"atlas.partner_link_request.v1","request_id":"plr_1","state":null,"partner":"acme","instance_id":"ins_1","client_id":"c","client_secret":"s","scopes":["privacy:execute"],"issued_at":1}`
	sign := func(version, secret, endpoint string) http.Header {
		mac := hmac.New(sha256.New, []byte(secret))
		signed := "evt_9." + strconv.FormatInt(ts, 10) + "."
		if version == "v2" {
			signed += endpoint + "."
		}
		mac.Write([]byte(signed + body))
		h := http.Header{}
		h.Set("Atlas-Id", "evt_9")
		h.Set("Atlas-Timestamp", strconv.FormatInt(ts, 10))
		h.Set("Atlas-Signature", version+","+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		return h
	}
	vo := &WebhookVerifyOptions{Now: now}
	d, err := VerifyPartnerLinkDelivery([]byte(body), sign("v1", "rs_1", ""), "rs_1", "", vo)
	if err != nil || d.Object != "partner_link.credentials" || d.ClientSecret != "s" || d.RequestID != "plr_1" {
		t.Fatalf("delivery = %+v, %v", d, err)
	}
	if _, err := VerifyPartnerLinkDelivery([]byte(body), sign("v1", "rs_1", ""), "other", "", vo); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := VerifyPartnerLinkDelivery([]byte(body), sign("v2", "rs_1", "https://acme.test/cb"), "rs_1", "https://acme.test/cb", vo); err != nil {
		t.Errorf("v2: %v", err)
	}
	if _, err := VerifyPartnerLinkDelivery([]byte(body), sign("v2", "rs_1", "https://acme.test/cb"), "rs_1", "https://evil.test/x", vo); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Errorf("replayed v2: %v", err)
	}
}

func TestAtlasIDIntegrationTokenRoute(t *testing.T) {
	ctx := context.Background()
	var gotAuth, gotDPoP, gotOrigin, gotPath, gotQuery string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotDPoP, gotOrigin, gotPath, gotQuery = r.Header.Get("Authorization"), r.Header.Get("DPoP"), r.Header.Get("Origin"), r.URL.Path, r.URL.RawQuery
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"jwt":"j","expires_in":60,"integration":"referalli","audience":"a","issuer":"i","jwks_uri":"u"}`))
	}))
	defer srv.Close()

	tok, err := AtlasIDIntegrationTokenFor(ctx, srv.URL+"/", "pk_test_1", "referalli", "at_1", &AtlasIDTokensOptions{Origin: "https://app.example.com"})
	if err != nil || tok == nil || tok.JWT != "j" || tok.JWKSURI != "u" {
		t.Fatalf("token = %+v, %v", tok, err)
	}
	if gotPath != "/v1/client/integrations/referalli/atlas_id_tokens" || gotQuery != "publishable_key=pk_test_1" || gotAuth != "Bearer at_1" || gotOrigin != "https://app.example.com" {
		t.Errorf("request path=%q query=%q auth=%q origin=%q", gotPath, gotQuery, gotAuth, gotOrigin)
	}
	if _, err := AtlasIDIntegrationTokenFor(ctx, srv.URL, "pk_test_1", "referalli", "at_1", &AtlasIDTokensOptions{DPoPProof: "proof"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "DPoP at_1" || gotDPoP != "proof" {
		t.Errorf("dpop auth=%q dpop=%q", gotAuth, gotDPoP)
	}
	status = 403
	if tok, err := AtlasIDIntegrationTokenFor(ctx, srv.URL, "pk", "x", "at_1", nil); tok != nil || err != nil {
		t.Errorf("refused call = %+v, %v", tok, err)
	}
	if tok, err := AtlasIDIntegrationTokenFor(ctx, srv.URL, "pk", "x", "", nil); tok != nil || err != nil {
		t.Errorf("empty token = %+v, %v", tok, err)
	}
}
