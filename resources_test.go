package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestRolesCreateAndList exercises the roles namespace: a POST create with a
// typed body and a GET list decoding the {object:list} envelope.
func TestRolesCreateAndList(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody CreateRoleParams
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		switch r.Method {
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"object":"role","id":"role_1","key":"admin","name":"Admin","permissions":["a:read"]}`))
		default:
			_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"role","id":"role_1","key":"admin"}]}`))
		}
	})

	role, err := c.Roles.Create(context.Background(), CreateRoleParams{Key: "admin", Name: "Admin", Permissions: []string{"a:read"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/roles" {
		t.Errorf("create hit %s %s, want POST /v1/roles", gotMethod, gotPath)
	}
	if gotBody.Key != "admin" || len(gotBody.Permissions) != 1 {
		t.Errorf("create body = %+v, want key=admin one permission", gotBody)
	}
	if role.ID != "role_1" || role.Key != "admin" {
		t.Errorf("decoded role = %+v, want id=role_1 key=admin", role)
	}

	page, err := c.Roles.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.Object != "list" || len(page.Data) != 1 || page.Data[0].ID != "role_1" {
		t.Errorf("decoded list = %+v, want one role role_1", page)
	}
}

// TestRolesDeleteReassignQuery asserts the reassignTo arg becomes a query param
// and (mutation-check) is omitted when empty.
func TestRolesDeleteReassignQuery(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"role","id":"role_1","deleted":true,"members_reassigned":3}`))
	})

	res, err := c.Roles.Delete(context.Background(), "role_1", "role_member")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gotQuery != "reassign_to=role_member" {
		t.Errorf("query = %q, want reassign_to=role_member", gotQuery)
	}
	if !res.Deleted || res.MembersReassigned != 3 {
		t.Errorf("result = %+v, want deleted with 3 reassigned", res)
	}

	gotQuery = "sentinel"
	if _, err := c.Roles.Delete(context.Background(), "role_1", ""); err != nil {
		t.Fatalf("Delete (no reassign): %v", err)
	}
	if gotQuery != "" {
		t.Errorf("query = %q on a plain delete, want empty", gotQuery)
	}
}

// TestSessionsCreateMint exercises the sessions mint endpoint, asserting the
// in-body jwt + refresh token decode.
func TestSessionsCreateMint(t *testing.T) {
	var gotBody CreateSessionParams
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		if r.URL.Path != "/v1/sessions" || r.Method != http.MethodPost {
			t.Errorf("hit %s %s, want POST /v1/sessions", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"session","id":"sess_1","user_id":"user_1","jwt":"ey.j.wt","refresh_token":"rt_1","expires_in":3600}`))
	})

	s, err := c.Sessions.Create(context.Background(), CreateSessionParams{UserID: "user_1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if gotBody.UserID != "user_1" {
		t.Errorf("body user_id = %q, want user_1", gotBody.UserID)
	}
	if s.JWT != "ey.j.wt" || s.RefreshToken != "rt_1" || s.ExpiresIn != 3600 {
		t.Errorf("minted session = %+v, want jwt/refresh/expires populated", s)
	}
}

// TestTokensVerify asserts the authoritative token-verify endpoint threads the
// body and decodes the success verdict.
func TestTokensVerify(t *testing.T) {
	var gotBody VerifyTokenParams
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		if r.URL.Path != "/v1/tokens/verify" {
			t.Errorf("path = %s, want /v1/tokens/verify", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"token_verification","verified":true,"user_id":"user_1","session_id":"sess_1","organization_permissions":["a:read"],"checked_authoritatively":true}`))
	})

	v, err := c.Tokens.Verify(context.Background(), VerifyTokenParams{Token: "the-token"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotBody.Token != "the-token" {
		t.Errorf("body token = %q, want the-token", gotBody.Token)
	}
	if !v.Verified || v.UserID != "user_1" || !v.CheckedAuthoritatively {
		t.Errorf("verdict = %+v, want verified user_1 authoritative", v)
	}
}

// TestFGACheckBoundStore exercises a nested-namespace method (FGA store check via
// the default-store binding), asserting path + body + decode.
func TestFGACheckBoundStore(t *testing.T) {
	var gotPath string
	var gotBody FGACheckParams
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"object":"fga.check","allowed":true,"authorization_model_id":"model_1"}`))
	})

	res, err := c.FGA.Store("store_1").Check(context.Background(), FGACheckParams{
		User: "user:1", Relation: "viewer", Object: "doc:1",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if gotPath != "/v1/fga/stores/store_1/check" {
		t.Errorf("path = %s, want /v1/fga/stores/store_1/check", gotPath)
	}
	if gotBody.Relation != "viewer" || gotBody.Object != "doc:1" {
		t.Errorf("body = %+v, want viewer on doc:1", gotBody)
	}
	if !res.Allowed || res.AuthorizationModelID != "model_1" {
		t.Errorf("result = %+v, want allowed with model_1", res)
	}
}
