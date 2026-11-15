package atlas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doctorServer(t *testing.T, instanceStatus int, date string, jwksKeys string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if date != "" {
			w.Header().Set("Date", date)
		}
		switch r.URL.Path {
		case "/v1/instance":
			w.WriteHeader(instanceStatus)
			_, _ = w.Write([]byte(`{"object":"instance","id":"ins_1","environment":"production","issuer":"https://x.example","jwks_uri":"` + srv.URL + `/jwks","allowed_origins":["https://app.example"]}`))
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":` + jwksKeys + `}`))
		case "/v1/status":
			_, _ = w.Write([]byte(`{"object":"status","status":"operational"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

func TestDoctorHealthy(t *testing.T) {
	srv := doctorServer(t, 200, time.Now().UTC().Format(http.TimeFormat), `[{"kid":"k1"}]`)
	defer srv.Close()
	rep, err := New("sk_test_abc", WithBaseURL(srv.URL)).Doctor(context.Background())
	if err != nil || !rep.OK {
		t.Fatalf("expected a healthy report: err=%v\n%s", err, rep)
	}
	for _, name := range []string{"key", "instance", "clock", "jwks", "status", "config"} {
		ch := rep.Check(name)
		if ch == nil || ch.Status != DoctorPass {
			t.Errorf("check %s: %+v", name, ch)
		}
	}
}

func TestDoctorFlagsBadKeyAndSkew(t *testing.T) {
	old := time.Now().Add(-10 * time.Minute).UTC().Format(http.TimeFormat)
	srv := doctorServer(t, 401, old, `[]`)
	defer srv.Close()
	rep, err := New("pk_live_x", WithBaseURL(srv.URL)).Doctor(context.Background())
	if err != nil || rep.OK {
		t.Fatalf("expected failures: err=%v", err)
	}
	if rep.Check("key").Status != DoctorFail || rep.Check("instance").Status != DoctorFail || rep.Check("clock").Status != DoctorFail {
		t.Fatalf("unexpected report:\n%s", rep)
	}
	if rep.Check("jwks").Status != DoctorSkip || !strings.Contains(rep.String(), "[fail] key") {
		t.Fatalf("unexpected report:\n%s", rep)
	}
}

func TestDoctorEmptyJWKS(t *testing.T) {
	srv := doctorServer(t, 200, time.Now().UTC().Format(http.TimeFormat), `[]`)
	defer srv.Close()
	rep, _ := New("sk_test_abc", WithBaseURL(srv.URL)).Doctor(context.Background())
	if rep.OK || rep.Check("jwks").Status != DoctorFail {
		t.Fatalf("an empty JWKS must fail:\n%s", rep)
	}
}
