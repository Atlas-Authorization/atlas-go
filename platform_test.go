package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// platRecorded is one request seen by a recording test server.
type platRecorded struct {
	Method, Path, Query, Auth, ContentType, Strict string
	Body                                           []byte
}

// newRecordingClient returns a client whose server answers every request with
// respond(r) and records it in *got.
func newRecordingClient(t *testing.T, got *[]platRecorded, respond func(r *http.Request) string, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*got = append(*got, platRecorded{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"),
			Strict: r.Header.Get("Atlas-Strict"), Body: body,
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respond(r)))
	}))
	t.Cleanup(srv.Close)
	return New("sk_test", append([]Option{WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithPlatformKey("psk_test")}, opts...)...)
}

func bodyMap(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	m := map[string]interface{}{}
	if len(raw) == 0 {
		return m
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("body is not a JSON object: %s", raw)
	}
	return m
}

const platformAppJSON = `{"object":"platform_app","id":"ins_1","name":"Acme","environment":"production","publishable_key":"pk_live_1","allowed_origins":["https://acme.test"],"tags":["a"],"archived":false,"archived_at":null,"disabled":false,"created_at":1,"updated_at":2}`

func TestPlatformAppsRoutesAndPlatformKey(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/platform/apps":
			if r.Method == http.MethodGet {
				return `{"object":"list","data":[` + platformAppJSON + `],"has_more":false}`
			}
			return `{"object":"platform_app","id":"ins_1","name":"Acme","environment":"production","publishable_key":"pk","allowed_origins":[],"tags":[],"archived":false,"archived_at":null,"disabled":false,"created_at":1,"updated_at":1,"secret":"sk_live_x","sibling_instance":{"object":"platform_app","id":"ins_2","environment":"development","secret":"sk_test_y"}}`
		case "/v1/platform/apps/ins_1/rotate_secret":
			return `{"object":"secret_rotation","app_id":"ins_1","secret":"sk_new","overlap_seconds":0,"previous_keys_expire_at":null,"note":"n"}`
		case "/v1/platform/apps/bulk_delete":
			return `{"object":"list","results":[{"id":"ins_1","deleted":true},{"id":"ins_x","deleted":false,"reason":"not_found"}]}`
		case "/v1/platform/accountless_apps":
			return `{"object":"accountless_app","id":"ins_9","name":"n","environment":"development","publishable_key":"pk","claim_token":"ct_1","expires_at":5,"note":"n"}`
		case "/v1/platform/apps/ins_1/secret_keys":
			return `{"object":"list","data":[{"object":"secret_key","id":"key_1","prefix":"sk_live_ab","created_at":1,"expires_at":null}],"has_more":false}`
		case "/v1/platform/apps/ins_1/transfer":
			return `{"object":"app_transfer","id":"ins_1","transfer_token":"tt_1","expires_at":9,"note":"n"}`
		case "/v1/platform/apps/ins_1/instances/ins_2/rotate_secret":
			return `{"object":"instance_secret","id":"ins_2","secret":"sk_z","note":"n"}`
		}
		return platformAppJSON
	})
	ctx := context.Background()
	f := false
	created, err := c.Platform.Apps.Create(ctx, CreatePlatformAppParams{Name: "Acme", Environment: "production", CreateDevelopmentSibling: &f}, WithIdempotencyKey("idem-1"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Secret != "sk_live_x" || created.SiblingInstance == nil || created.SiblingInstance.Secret != "sk_test_y" {
		t.Errorf("provisioned = %+v", created)
	}
	if b := bodyMap(t, got[0].Body); b["create_development_sibling"] != false || b["name"] != "Acme" {
		t.Errorf("create body = %s", got[0].Body)
	}
	if got[0].Auth != "Bearer psk_test" {
		t.Errorf("platform call signed with %q", got[0].Auth)
	}

	list, err := c.Platform.Apps.List(ctx, ListPlatformAppsParams{IncludeArchived: true, Tag: "a"})
	if err != nil || len(list.Data) != 1 || list.Data[0].PublishableKey != "pk_live_1" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if got[1].Query != "include_archived=true&tag=a" {
		t.Errorf("list query = %q", got[1].Query)
	}

	zero := 0
	rot, err := c.Platform.Apps.RotateSecret(ctx, "ins_1", &zero)
	if err != nil || rot.Secret != "sk_new" {
		t.Fatalf("rotate = %+v, %v", rot, err)
	}
	if b := bodyMap(t, got[2].Body); b["overlap_seconds"] != float64(0) {
		t.Errorf("rotate body = %s", got[2].Body)
	}

	bulk, err := c.Platform.Apps.BulkDelete(ctx, []string{"ins_1", "ins_x"})
	if err != nil || len(bulk.Results) != 2 || bulk.Results[1].Reason != "not_found" {
		t.Fatalf("bulk = %+v, %v", bulk, err)
	}
	acc, err := c.Platform.Apps.CreateAccountless(ctx, CreateAccountlessAppParams{Name: "n"})
	if err != nil || acc.ClaimToken != "ct_1" {
		t.Fatalf("accountless = %+v, %v", acc, err)
	}
	keys, err := c.Platform.Apps.SecretKeys(ctx, "ins_1")
	if err != nil || keys.Data[0].Prefix != "sk_live_ab" {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
	tr, err := c.Platform.Apps.Transfer(ctx, "ins_1")
	if err != nil || tr.TransferToken != "tt_1" {
		t.Fatalf("transfer = %+v, %v", tr, err)
	}
	is, err := c.Platform.Apps.RotateInstanceSecret(ctx, "ins_1", "ins_2")
	if err != nil || is.Secret != "sk_z" {
		t.Fatalf("instance secret = %+v, %v", is, err)
	}

	calls := []func() error{
		func() error { _, err := c.Platform.Apps.Get(ctx, "ins_1"); return err },
		func() error {
			_, err := c.Platform.Apps.Update(ctx, "ins_1", UpdatePlatformAppParams{Name: "B"})
			return err
		},
		func() error { _, err := c.Platform.Apps.Delete(ctx, "ins_1"); return err },
		func() error { _, err := c.Platform.Apps.Archive(ctx, "ins_1"); return err },
		func() error { _, err := c.Platform.Apps.Unarchive(ctx, "ins_1"); return err },
		func() error {
			_, err := c.Platform.Apps.CreateInstance(ctx, "ins_1", CreatePlatformInstanceParams{Environment: "development"})
			return err
		},
		func() error { _, err := c.Platform.Apps.ListInstances(ctx, "ins_1"); return err },
		func() error { _, err := c.Platform.Apps.Claim(ctx, "ct_1"); return err },
		func() error { _, err := c.Platform.Apps.AcceptTransfer(ctx, "tt_1"); return err },
	}
	for _, call := range calls {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"POST /v1/platform/apps", "GET /v1/platform/apps", "POST /v1/platform/apps/ins_1/rotate_secret",
		"POST /v1/platform/apps/bulk_delete", "POST /v1/platform/accountless_apps", "GET /v1/platform/apps/ins_1/secret_keys",
		"POST /v1/platform/apps/ins_1/transfer", "POST /v1/platform/apps/ins_1/instances/ins_2/rotate_secret",
		"GET /v1/platform/apps/ins_1", "PATCH /v1/platform/apps/ins_1", "DELETE /v1/platform/apps/ins_1",
		"POST /v1/platform/apps/ins_1/archive", "POST /v1/platform/apps/ins_1/unarchive",
		"POST /v1/platform/apps/ins_1/instances", "GET /v1/platform/apps/ins_1/instances",
		"POST /v1/platform/apps/claim", "POST /v1/platform/apps/accept_transfer",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d requests, want %d", len(got), len(want))
	}
	for i, w := range want {
		if g := got[i].Method + " " + got[i].Path; g != w {
			t.Errorf("request %d = %s, want %s", i, g, w)
		}
		if got[i].Auth != "Bearer psk_test" {
			t.Errorf("request %d auth = %q", i, got[i].Auth)
		}
	}
	if b := bodyMap(t, got[15].Body); b["claim_token"] != "ct_1" {
		t.Errorf("claim body = %s", got[15].Body)
	}
}

const atlasIDAppJSON = `{"object":"atlas_id_app","id":"aid_1","client_id":"cid_1","name":"Shop","logo_url":null,"homepage_url":null,
"branding":{"theme":"dark","accent_color":"#112233","background_color":null,"privacy_policy_url":null,"terms_of_service_url":null,
"design":{"preset":"glass","palette":{"primary":"#0a7cff"}},"resolved_design":{"version":1,"preset":"glass","colorScheme":"auto","palette":{"primary":"#0a7cff"},"paletteDark":{},"typography":{"font":"inter"},"shape":{},"elevation":{},"spacing":{},"card":{},"layout":{},"buttons":{},"inputs":{},"background":{},"backgroundDark":{},"logo":{}},
"copy":{"sign_in_title":"Welcome to {app}"}},
"redirect_uris":["https://shop.test/cb"],"post_logout_redirect_uris":["https://shop.test/bye"],
"backchannel_logout_uri":"https://shop.test/bcl","backchannel_logout_session_required":true,
"frontchannel_logout_uri":null,"frontchannel_logout_session_required":false,"allowed_scopes":["openid","email"],
"type":"confidential","secret_prefix":"cs_ab","created_at":1,"updated_at":2,"client_secret":"cs_secret","user_count":4}`

func TestAtlasIDAppsCRUD(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch {
		case r.URL.Path == "/v1/platform/atlas_id_apps" && r.Method == http.MethodGet:
			return `{"object":"list","data":[` + atlasIDAppJSON + `],"issuer":"https://atlasauth.net","discovery_url":"https://atlasauth.net/.well-known/openid-configuration","limit":50}`
		case r.Method == http.MethodDelete:
			return `{"object":"atlas_id_app","id":"aid_1","deleted":true}`
		case r.URL.Path == "/v1/platform/atlas_id_apps/design/preview":
			return `{"object":"design_preview","scope":".atlas-root","css":".atlas-root{}","data_attributes":{"data-atlas-layout":"center"},"font_stylesheets":[],"resolved":{"preset":"glass"},"warnings":[{"code":"contrast","mode":"light","pair":["a","b"],"ratio":2.1,"required":4.5,"path":"palette.primaryInk","message":"m"}],"html":"<main></main>"}`
		}
		return atlasIDAppJSON
	}, WithStrict(true))
	ctx := context.Background()

	app, err := c.Platform.AtlasIDApps.Create(ctx, CreateAtlasIDAppParams{
		Name: "Shop", RedirectURIs: []string{"https://shop.test/cb"},
		PostLogoutRedirectURIs: []string{"https://shop.test/bye"},
		BackchannelLogoutURI:   "https://shop.test/bcl", BackchannelLogoutSessionRequired: true,
		FrontchannelLogoutURI: "https://shop.test/fcl",
		Branding: &AtlasIDAppBrandingParams{
			Theme: "dark", AccentColor: "#112233",
			Design: DesignPatch{"preset": "glass"},
			Copy:   &AtlasIDAppCopyParams{SignInTitle: "Welcome to {app}"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if app.ClientSecret != "cs_secret" || app.Branding == nil || app.Branding.Design.Preset != "glass" ||
		*app.Branding.Copy.SignInTitle != "Welcome to {app}" || app.Branding.ResolvedDesign.Typography["font"] != "inter" ||
		*app.BackchannelLogoutURI != "https://shop.test/bcl" || *app.UserCount != 4 {
		t.Errorf("decoded app = %+v", app)
	}
	b := bodyMap(t, got[0].Body)
	br := b["branding"].(map[string]interface{})
	if b["post_logout_redirect_uris"].([]interface{})[0] != "https://shop.test/bye" || b["backchannel_logout_session_required"] != true ||
		b["frontchannel_logout_uri"] != "https://shop.test/fcl" || br["theme"] != "dark" ||
		br["design"].(map[string]interface{})["preset"] != "glass" || br["copy"].(map[string]interface{})["sign_in_title"] != "Welcome to {app}" {
		t.Errorf("create body = %s", got[0].Body)
	}
	if got[0].Strict != "true" || got[0].Auth != "Bearer psk_test" {
		t.Errorf("create headers strict=%q auth=%q", got[0].Strict, got[0].Auth)
	}

	// Update: an empty slice clears post-logout URIs, a pointer to "" clears a
	// logout URI, Clear sends nulls (top level and in branding).
	empty := ""
	if _, err := c.Platform.AtlasIDApps.Update(ctx, "aid_1", UpdateAtlasIDAppParams{
		PostLogoutRedirectURIs: []string{},
		FrontchannelLogoutURI:  &empty,
		Branding:               &AtlasIDAppBrandingParams{Clear: []string{"accent_color", "design"}},
		Clear:                  []string{"logo_url"},
	}, StrictBody(false)); err != nil {
		t.Fatal(err)
	}
	ub := bodyMap(t, got[1].Body)
	if v, ok := ub["post_logout_redirect_uris"].([]interface{}); !ok || len(v) != 0 {
		t.Errorf("update must send [] for post_logout_redirect_uris: %s", got[1].Body)
	}
	if ub["frontchannel_logout_uri"] != "" {
		t.Errorf("update frontchannel = %v", ub["frontchannel_logout_uri"])
	}
	if v, ok := ub["logo_url"]; !ok || v != nil {
		t.Errorf("logo_url must be null: %s", got[1].Body)
	}
	ubr := ub["branding"].(map[string]interface{})
	if v, ok := ubr["accent_color"]; !ok || v != nil {
		t.Errorf("branding.accent_color must be null: %s", got[1].Body)
	}
	if _, ok := ub["name"]; ok {
		t.Errorf("unset name must be omitted: %s", got[1].Body)
	}
	if got[1].Method != http.MethodPatch || got[1].Path != "/v1/platform/atlas_id_apps/aid_1" || got[1].Strict != "false" {
		t.Errorf("update request = %+v", got[1])
	}

	// A nil PostLogoutRedirectURIs is omitted entirely.
	if _, err := c.Platform.AtlasIDApps.Update(ctx, "aid_1", UpdateAtlasIDAppParams{Name: "X"}); err != nil {
		t.Fatal(err)
	}
	if string(got[2].Body) != `{"name":"X"}` {
		t.Errorf("minimal update body = %s", got[2].Body)
	}

	list, err := c.Platform.AtlasIDApps.List(ctx)
	if err != nil || list.Issuer != "https://atlasauth.net" || len(list.Data) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if _, err := c.Platform.AtlasIDApps.Get(ctx, "aid_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Platform.AtlasIDApps.RotateSecret(ctx, "aid_1"); err != nil {
		t.Fatal(err)
	}
	del, err := c.Platform.AtlasIDApps.Delete(ctx, "aid_1")
	if err != nil || !del.Deleted {
		t.Fatalf("delete = %+v, %v", del, err)
	}
	prev, err := c.Platform.AtlasIDApps.PreviewDesign(ctx, Design{Preset: "glass", Shape: &DesignShape{Radius: new(int)}})
	if err != nil || prev.HTML != "<main></main>" || prev.Warnings[0].Required != 4.5 {
		t.Fatalf("preview = %+v, %v", prev, err)
	}
	if string(got[7].Body) != `{"design":{"preset":"glass","shape":{"radius":0}}}` {
		t.Errorf("preview body = %s", got[7].Body)
	}
	want := []string{"POST /v1/platform/atlas_id_apps", "PATCH /v1/platform/atlas_id_apps/aid_1", "PATCH /v1/platform/atlas_id_apps/aid_1",
		"GET /v1/platform/atlas_id_apps", "GET /v1/platform/atlas_id_apps/aid_1", "POST /v1/platform/atlas_id_apps/aid_1/rotate_secret",
		"DELETE /v1/platform/atlas_id_apps/aid_1", "POST /v1/platform/atlas_id_apps/design/preview"}
	for i, w := range want {
		if g := got[i].Method + " " + got[i].Path; g != w {
			t.Errorf("request %d = %s, want %s", i, g, w)
		}
	}
	if got[3].Strict != "" {
		t.Errorf("GET must not carry Atlas-Strict, got %q", got[3].Strict)
	}
}

func TestDesignAssetsRawUpload(t *testing.T) {
	var got []platRecorded
	assetJSON := `{"object":"design_asset","asset_id":"dasset_1","kind":"logo","url":"https://cdn.test/a.webp","width":10,"height":20,"dominant_color":null,"bytes":123,"created_at":"2026-10-13T00:00:00Z"}`
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch r.Method {
		case http.MethodGet:
			return `{"object":"list","data":[` + assetJSON + `]}`
		case http.MethodDelete:
			return `{"object":"design_asset","asset_id":"dasset_1","deleted":true}`
		}
		return assetJSON
	}, WithStrict(true))
	ctx := context.Background()
	png := []byte("\x89PNG\r\n\x1a\n0000")

	a, err := c.Design.Assets.Upload(ctx, png, "", "logo")
	if err != nil || a.AssetID != "dasset_1" || a.Bytes != 123 {
		t.Fatalf("upload = %+v, %v", a, err)
	}
	if got[0].Method != http.MethodPost || got[0].Path != "/v1/design/assets" || got[0].Query != "kind=logo" ||
		got[0].ContentType != "image/png" || string(got[0].Body) != string(png) || got[0].Auth != "Bearer sk_test" {
		t.Errorf("upload request = %+v", got[0])
	}
	if _, err := c.Platform.DesignAssets.Upload(ctx, []byte("RIFF....WEBP"), "image/webp", ""); err != nil {
		t.Fatal(err)
	}
	if got[1].Path != "/v1/platform/design/assets" || got[1].Query != "" || got[1].ContentType != "image/webp" || got[1].Auth != "Bearer psk_test" {
		t.Errorf("platform upload request = %+v", got[1])
	}
	if _, err := c.Design.Assets.Upload(ctx, nil, "image/png", ""); err == nil {
		t.Error("empty upload must fail before sending")
	}
	l, err := c.Design.Assets.List(ctx)
	if err != nil || len(l.Data) != 1 {
		t.Fatalf("list = %+v %v", l, err)
	}
	d, err := c.Platform.DesignAssets.Delete(ctx, "dasset_1")
	if err != nil || !d.Deleted || got[3].Path != "/v1/platform/design/assets/dasset_1" {
		t.Fatalf("delete = %+v %v", d, err)
	}
	if _, err := c.Platform.DesignAssets.List(ctx); err != nil || got[4].Path != "/v1/platform/design/assets" {
		t.Fatal(err)
	}
	if _, err := c.Design.Assets.Delete(ctx, "dasset_1"); err != nil || got[5].Method != http.MethodDelete || got[5].Path != "/v1/design/assets/dasset_1" {
		t.Fatal(err)
	}
}
