package atlas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const rpTestRedirect = "http://127.0.0.1:3000/auth/callback"

func newRPWithTestIssuer(t *testing.T, mod func(*RPConfig)) (*RelyingParty, *RPTestIssuer) {
	t.Helper()
	iss := NewRPTestIssuer("client_test")
	t.Cleanup(iss.Close)
	cfg := iss.Config(rpTestRedirect, strings.Repeat("s", 40))
	if mod != nil {
		mod(&cfg)
	}
	rp, err := NewRelyingParty(cfg)
	if err != nil {
		t.Fatalf("NewRelyingParty: %v", err)
	}
	return rp, iss
}

// signInVia runs Start, the issuer's Authorize and Callback.
func signInVia(t *testing.T, rp *RelyingParty, iss *RPTestIssuer, opts RPStartOptions) (*RPCallbackResult, error) {
	t.Helper()
	started, err := rp.Start(context.Background(), opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	back, err := iss.Authorize(started.URL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, back, nil)
	req.AddCookie(started.Cookie)
	return rp.Callback(context.Background(), req)
}

func TestRPTestIssuerSignIn(t *testing.T) {
	rp, iss := newRPWithTestIssuer(t, nil)
	res, err := signInVia(t, rp, iss, RPStartOptions{})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if res.User.Sub != "user_test" || res.User.SID != "sid_test" || res.User.Email != "user@example.com" || !res.User.EmailVerified {
		t.Errorf("user=%+v", res.User)
	}
	if res.Tokens.AccessToken == "" || res.Tokens.RefreshToken == "" {
		t.Errorf("tokens=%+v", res.Tokens)
	}
	if got := iss.LastAuthorizeRequest().Get("code_challenge"); got == "" {
		t.Errorf("the authorize request carried no PKCE challenge")
	}
	if live := iss.LiveSids(); len(live) != 1 || live[0] != "sid_test" {
		t.Errorf("live sids=%v", live)
	}
}

func TestRPTestIssuerBrowserRedirect(t *testing.T) {
	rp, iss := newRPWithTestIssuer(t, nil)
	started, err := rp.Start(context.Background(), RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(started.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil {
		t.Fatalf("authorize = %d %v", resp.StatusCode, err)
	}
	q := loc.Query()
	if q.Get("code") == "" || q.Get("state") != started.State || q.Get("iss") != iss.URL {
		t.Errorf("callback query=%v", q)
	}
}

func TestRPTestIssuerNextClaimsAndOrgSSO(t *testing.T) {
	rp, iss := newRPWithTestIssuer(t, nil)
	iss.NextClaims(map[string]interface{}{
		"org_id": "org_1", "org_slug": "acme", "org_role": "org:admin", "org_permissions": []string{"org:billing:manage"},
		"orgs":              []map[string]string{{"id": "org_1", "slug": "acme", "role": "org:admin"}, {"id": "org_2", "slug": "globex", "role": "org:member"}},
		"sso_connection_id": "sso_conn_1", "sso_organization_id": "org_3", "sso_connection_type": "saml",
		"sso_tenant_id": "tenant", "sso_issuer": "https://idp.example", "sso_domain": "acme.com",
	})
	res, err := signInVia(t, rp, iss, RPStartOptions{Organization: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if iss.LastAuthorizeRequest().Get("organization") != "acme" {
		t.Errorf("organization not sent")
	}
	if o := res.Organization; o == nil || o.ID != "org_1" || o.Slug != "acme" || o.Role != "org:admin" || len(o.Permissions) != 1 || o.Permissions[0] != "org:billing:manage" {
		t.Errorf("organization=%+v", o)
	}
	if len(res.Organizations) != 2 || res.Organizations[1].Slug != "globex" {
		t.Errorf("organizations=%+v", res.Organizations)
	}
	want := RPSsoContext{ConnectionID: "sso_conn_1", OrganizationID: "org_3", Type: "saml", TenantID: "tenant", Issuer: "https://idp.example", Domain: "acme.com"}
	if res.SSO == nil || *res.SSO != want {
		t.Errorf("sso=%+v", res.SSO)
	}
	if res.User.OrgID != "org_1" || res.User.OrgRole != "org:admin" {
		t.Errorf("user org=%+v", res.User)
	}
	// the claims were cleared: the next sign-in has no organization
	res, err = signInVia(t, rp, iss, RPStartOptions{})
	if err != nil || res.Organization != nil || res.Organizations != nil || res.SSO != nil {
		t.Errorf("a plain sign-in must carry no tenant context: %+v %v", res, err)
	}
}

func TestRPTestIssuerTamperedTokensAreRefused(t *testing.T) {
	cases := map[string]RPTestTamper{
		"nonce":    {WrongNonce: true},
		"nonce 2":  {NoNonce: true},
		"audience": {WrongAudience: true},
		"issuer":   {WrongIssuer: true},
		"expired":  {Expired: true},
	}
	for name, tamper := range cases {
		tamper := tamper
		t.Run(name, func(t *testing.T) {
			rp, iss := newRPWithTestIssuer(t, nil)
			iss.NextTamper(tamper)
			if _, err := signInVia(t, rp, iss, RPStartOptions{}); err == nil {
				t.Fatalf("a %s defect must be refused", name)
			}
		})
	}
}

func TestRPTestIssuerPKCEAndClientAuthChecked(t *testing.T) {
	_, iss := newRPWithTestIssuer(t, nil)
	started, _ := (func() (*RPStartResult, error) {
		rp, _ := NewRelyingParty(iss.Config(rpTestRedirect, strings.Repeat("s", 40)))
		return rp.Start(context.Background(), RPStartOptions{})
	})()
	back, err := iss.Authorize(started.URL)
	if err != nil {
		t.Fatal(err)
	}
	code := mustQuery(t, back).Get("code")
	post := func(form url.Values, user, pass string) int {
		req, _ := http.NewRequest(http.MethodPost, iss.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := iss.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpTestRedirect}, "code_verifier": {"not-the-verifier"}}
	if got := post(form, iss.ClientID, "wrong"); got != http.StatusUnauthorized {
		t.Errorf("a wrong client secret = %d", got)
	}
	if got := post(form, iss.ClientID, iss.ClientSecret); got != http.StatusBadRequest {
		t.Errorf("a wrong PKCE verifier = %d", got)
	}
	// the code was single use: even a right verifier fails now
	if got := post(form, iss.ClientID, iss.ClientSecret); got != http.StatusBadRequest {
		t.Errorf("a spent code = %d", got)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestRPTestIssuerBackchannelLogoutToken(t *testing.T) {
	var gotSids []string
	rp, iss := newRPWithTestIssuer(t, func(c *RPConfig) {
		c.BackchannelLogoutPath = "/auth/backchannel"
		c.SidStore = &RPMemorySidStore{}
		c.OnBackchannelLogout = func(_ context.Context, ids []string, claims *LogoutTokenClaims) error {
			gotSids = append(gotSids, claims.Sid)
			return nil
		}
	})
	h := rp.Handler()
	if rec := rpTestPost(h, "/auth/backchannel", iss.LogoutToken("sess_9", "user_9")); rec.Code != http.StatusOK || len(gotSids) != 1 || gotSids[0] != "sess_9" {
		t.Fatalf("a good logout token = %d %v", rec.Code, gotSids)
	}
	for name, tamper := range map[string]RPTestTamper{"audience": {WrongAudience: true}, "issuer": {WrongIssuer: true}, "expired": {Expired: true}} {
		if rec := rpTestPost(h, "/auth/backchannel", iss.LogoutTokenWith("sess_9", "", tamper)); rec.Code != http.StatusBadRequest {
			t.Errorf("a logout token with a wrong %s = %d", name, rec.Code)
		}
	}
}

func TestRPTestIssuerTouchEndAndUserinfo(t *testing.T) {
	rp, iss := newRPWithTestIssuer(t, nil)
	ctx := context.Background()
	res, err := signInVia(t, rp, iss, RPStartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rp.TouchIfDue(ctx, res.User.SID, time.Time{}); err != nil || got.Status != RPTouchTouched {
		t.Fatalf("touch: %+v %v", got, err)
	}
	if out, err := rp.EndAppSession(ctx, res.User.SID); err != nil || out != "ended" {
		t.Fatalf("end: %q %v", out, err)
	}
	if got, err := rp.TouchIfDue(ctx, res.User.SID, time.Time{}); err != nil || got.Status != RPTouchEnded || got.Reason != "not_found" {
		t.Errorf("a touch after the end: %+v %v", got, err)
	}

	req, _ := http.NewRequest(http.MethodGet, iss.URL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+res.Tokens.AccessToken)
	resp, err := iss.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("userinfo = %d", resp.StatusCode)
	}
}

func TestRPTestIssuerEndSessionRedirect(t *testing.T) {
	_, iss := newRPWithTestIssuer(t, nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(iss.URL + "/oauth2/logout?post_logout_redirect_uri=" + url.QueryEscape("http://127.0.0.1:3000/bye") + "&state=s1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "http://127.0.0.1:3000/bye?state=s1" {
		t.Errorf("end-session = %d %q", resp.StatusCode, loc)
	}
}

func TestRPClaimReadersIgnoreMalformedValues(t *testing.T) {
	if RPOrganizationOf(map[string]interface{}{"org_id": 5.0}) != nil || RPSsoOf(map[string]interface{}{"sso_connection_id": 1.0}) != nil || RPOrganizationsOf(map[string]interface{}{"orgs": "nope"}) != nil {
		t.Fatal("non-string ids must read as absent")
	}
	org := RPOrganizationOf(map[string]interface{}{"org_id": "org_1", "org_permissions": []interface{}{"a", 3.0}})
	if org == nil || org.Slug != "" || org.Role != "" || len(org.Permissions) != 1 || org.Permissions[0] != "a" {
		t.Errorf("org=%+v", org)
	}
	orgs := RPOrganizationsOf(map[string]interface{}{"orgs": []interface{}{nil, map[string]interface{}{"id": "org_1", "slug": "a", "role": "r"}, map[string]interface{}{"slug": "x"}}})
	if len(orgs) != 1 || orgs[0] != (RPOrganizationMembership{ID: "org_1", Slug: "a", Role: "r"}) {
		t.Errorf("orgs=%+v", orgs)
	}
	if s := RPSsoOf(map[string]interface{}{"sso_connection_id": "c", "sso_connection_type": "ldap"}); s == nil || s.Type != "" || s.OrganizationID != "" {
		t.Errorf("sso=%+v", s)
	}
}

func TestRPTestIssuerEveryAlg(t *testing.T) {
	for _, alg := range SigningAlgs {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			iss := NewRPTestIssuerAlg("client_alg", alg)
			defer iss.Close()
			var gotSids []string
			cfg := iss.Config(rpTestRedirect, strings.Repeat("s", 40))
			cfg.BackchannelLogoutPath = "/auth/backchannel"
			cfg.SidStore = &RPMemorySidStore{}
			cfg.OnBackchannelLogout = func(_ context.Context, ids []string, claims *LogoutTokenClaims) error {
				gotSids = append(gotSids, claims.Sid)
				return nil
			}
			rp, err := NewRelyingParty(cfg)
			if err != nil {
				t.Fatalf("NewRelyingParty: %v", err)
			}
			res, err := signInVia(t, rp, iss, RPStartOptions{})
			if err != nil || res.User.Sub != "user_test" {
				t.Fatalf("sign-in with %s: %v", alg, err)
			}
			if rec := rpTestPost(rp.Handler(), "/auth/backchannel", iss.LogoutToken("sess_alg", "user_test")); rec.Code != http.StatusOK || len(gotSids) != 1 {
				t.Fatalf("a %s logout token = %d %v", alg, rec.Code, gotSids)
			}
			// a token signed by a different key of the same alg is refused
			forged := newRPTestKey(alg).jws("logout+jwt", map[string]interface{}{
				"iss": iss.URL, "aud": iss.ClientID, "iat": time.Now().Unix(), "jti": "forged", "sid": "s",
				"events": map[string]interface{}{BackchannelLogoutEvent: map[string]interface{}{}},
			})
			if rec := rpTestPost(rp.Handler(), "/auth/backchannel", forged); rec.Code != http.StatusBadRequest {
				t.Errorf("a forged %s logout token = %d", alg, rec.Code)
			}
		})
	}
}
