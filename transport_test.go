package atlas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// TestStrictBodiesClientDefaultAndPerCallOverride asserts WithStrict sends
// Atlas-Strict on writes only, and StrictBody overrides it per call.
func TestStrictBodiesClientDefaultAndPerCallOverride(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.Header.Get("Atlas-Strict"))
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithStrict(true))
	ctx := context.Background()

	_, _ = c.Roles.Create(ctx, CreateRoleParams{Key: "a", Name: "A"})
	_, _ = c.Roles.Create(ctx, CreateRoleParams{Key: "a", Name: "A"}, StrictBody(false))
	_, _ = c.Roles.List(ctx)
	_, _ = c.Domains.Delete(ctx, "dmn_1")

	want := []string{"POST true", "POST false", "GET ", "DELETE "}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Atlas-Strict per request = %q, want %q", got, want)
	}

	// No client default: nothing is sent unless a call opts in.
	got = nil
	plain := New("sk_test", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, _ = plain.Roles.Create(ctx, CreateRoleParams{Key: "a", Name: "A"})
	_, _ = plain.Roles.Create(ctx, CreateRoleParams{Key: "a", Name: "A"}, StrictBody(true))
	if want := []string{"POST ", "POST true"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Atlas-Strict without default = %q, want %q", got, want)
	}
}

// TestUnknownFieldsHandler asserts the Atlas-Unknown-Fields header reaches the
// registered callback, split and trimmed.
func TestUnknownFieldsHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Atlas-Unknown-Fields", "nmae, settings.colour")
		_, _ = w.Write([]byte(`{"object":"role","id":"role_1"}`))
	}))
	t.Cleanup(srv.Close)
	var gotMethod, gotPath string
	var gotFields []string
	c := New("sk_test", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithUnknownFieldsHandler(func(method, path string, fields []string) {
			gotMethod, gotPath, gotFields = method, path, fields
		}))
	if _, err := c.Roles.Create(context.Background(), CreateRoleParams{Key: "a"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if gotMethod != "POST" || gotPath != "/v1/roles" || !reflect.DeepEqual(gotFields, []string{"nmae", "settings.colour"}) {
		t.Errorf("handler got %s %s %q", gotMethod, gotPath, gotFields)
	}
}

// TestPlatformKeyAndRawUpload asserts platform calls are signed with the
// platform key and raw uploads carry their own content type and bytes.
func TestPlatformKeyAndRawUpload(t *testing.T) {
	var gotAuth, gotCT, gotQuery string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCT, gotQuery = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.RawQuery
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	c := New("sk_test", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithPlatformKey("psk_test"))
	var out map[string]interface{}
	if err := c.platGet(context.Background(), "/v1/platform/apps", nil, &out); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer psk_test" {
		t.Errorf("platform auth = %q, want Bearer psk_test", gotAuth)
	}
	if err := c.get(context.Background(), "/v1/users", nil, &out); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sk_test" {
		t.Errorf("BAPI auth = %q, want Bearer sk_test", gotAuth)
	}
	png := []byte{0x89, 'P', 'N', 'G'}
	err := c.doRaw(context.Background(), authSecret, http.MethodPost, "/v1/design/assets", map[string][]string{"kind": {"logo"}}, "image/png", png, &out)
	if err != nil {
		t.Fatal(err)
	}
	if gotCT != "image/png" || string(gotBody) != string(png) || gotQuery != "kind=logo" {
		t.Errorf("raw upload ct=%q body=%v query=%q", gotCT, gotBody, gotQuery)
	}

	pc := NewPlatform("psk_only", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_ = pc.platGet(context.Background(), "/v1/platform/apps", nil, &out)
	if gotAuth != "Bearer psk_only" {
		t.Errorf("NewPlatform auth = %q", gotAuth)
	}
}
