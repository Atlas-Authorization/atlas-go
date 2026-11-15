package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWTTemplateSettingsInputSendsOnlyWhatIsSet(t *testing.T) {
	life := int64(300)
	b, err := json.Marshal(JWTTemplateSettingsInput{LifetimeSeconds: &life, ClearAudience: true, Algorithm: "HS256", SigningSecret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["lifetime_seconds"] != float64(300) || m["algorithm"] != "HS256" || m["signing_secret"] != "0123456789abcdef" {
		t.Fatalf("body=%s", b)
	}
	if v, ok := m["audience"]; !ok || v != nil {
		t.Fatalf("ClearAudience must send null: %s", b)
	}
	empty, _ := json.Marshal(JWTTemplateSettingsInput{})
	if string(empty) != "{}" {
		t.Fatalf("an empty input must send nothing, got %s", empty)
	}
}

func TestJWTTemplatesWithSettings(t *testing.T) {
	var gotBody []byte
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"jwt_template","name":"hasura","claims":{"x":"y"},"settings":{"lifetime_seconds":120,"audience":null,"algorithm":"RS256","has_signing_secret":false}}`))
	}))
	defer srv.Close()
	c := New("sk_test", WithBaseURL(srv.URL))
	life := int64(120)
	out, err := c.JWTTemplates.UpdateWithSettings(context.Background(), "hasura", UpdateJWTTemplateParams{Settings: &JWTTemplateSettingsInput{LifetimeSeconds: &life}})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PATCH" || gotPath != "/v1/jwt_templates/hasura" || string(gotBody) != `{"settings":{"lifetime_seconds":120}}` {
		t.Fatalf("%s %s %s", gotMethod, gotPath, gotBody)
	}
	if out.Settings.LifetimeSeconds == nil || *out.Settings.LifetimeSeconds != 120 || out.Settings.Algorithm != "RS256" {
		t.Fatalf("settings=%+v", out.Settings)
	}
}
