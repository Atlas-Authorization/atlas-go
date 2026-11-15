package atlas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

const statusListTestIssuer = "https://id.example.test"

// signStatusList mints a statuslist+jwt over the sids; mutate edits the claims first.
func signStatusList(t *testing.T, key *rsa.PrivateKey, kid string, now time.Time, sids []string, mutate func(map[string]interface{}, map[string]interface{})) string {
	t.Helper()
	hashes := make([][]byte, 0, len(sids))
	for _, sid := range sids {
		sum := sha256.Sum256([]byte(sid))
		hashes = append(hashes, sum[:8])
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i], hashes[j]) < 0 })
	list := bytes.Join(hashes, nil)
	header := map[string]interface{}{"alg": "RS256", "typ": "statuslist+jwt", "kid": kid}
	claims := map[string]interface{}{
		"iss": statusListTestIssuer, "aud": "atlas:session-status-list", "token_use": "session_status_list",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "since": now.Add(-time.Hour).UnixMilli(),
		"hash_bytes": 8, "count": len(sids), "truncated": false, "h": base64.RawURLEncoding.EncodeToString(list),
	}
	if mutate != nil {
		mutate(header, claims)
	}
	enc := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func statusListKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVerifyStatusListToken(t *testing.T) {
	key, other := statusListKey(t), statusListKey(t)
	jwksSrv := jwksServer(t, key, "k1", nil)
	now := time.Unix(1_800_000_000, 0)
	opts := VerifyStatusListOptions{
		JWKS: NewJWKSCache(JWKSCacheOptions{URL: jwksSrv.URL}), Issuer: statusListTestIssuer, Now: func() time.Time { return now },
	}
	ctx := context.Background()

	list, err := VerifyStatusListToken(ctx, signStatusList(t, key, "k1", now, []string{"sess_a", "sess_b", "sess_c"}, nil), opts)
	if err != nil {
		t.Fatalf("valid list: %v", err)
	}
	if list.Count != 3 || list.Truncated || !list.Has("sess_a") || !list.Has("sess_c") || list.Has("sess_z") {
		t.Fatalf("lookup is wrong: %+v", list)
	}

	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"wrong key", signStatusList(t, other, "k1", now, []string{"x"}, nil), StatusListBadSignature},
		{"unknown kid", signStatusList(t, key, "nope", now, []string{"x"}, nil), StatusListBadSignature},
		{"wrong typ", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { h["typ"] = "JWT" }), StatusListUnsupported},
		{"wrong alg", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { h["alg"] = "none" }), StatusListUnsupported},
		{"wrong issuer", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { c["iss"] = "https://evil.test" }), StatusListBadClaims},
		{"wrong audience", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { c["aud"] = "other" }), StatusListBadClaims},
		{"expired", signStatusList(t, key, "k1", now.Add(-time.Hour), []string{"x"}, nil), StatusListExpired},
		{"issued in the future", signStatusList(t, key, "k1", now.Add(time.Hour), []string{"x"}, nil), StatusListBadClaims},
		{"count mismatch", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { c["count"] = 5 }), StatusListBadClaims},
		{"hash bytes out of range", signStatusList(t, key, "k1", now, []string{"x"}, func(h, c map[string]interface{}) { c["hash_bytes"] = 2 }), StatusListBadClaims},
		{"not a jwt", "abc", StatusListMalformed},
	}
	for _, tc := range cases {
		_, err := VerifyStatusListToken(ctx, tc.token, opts)
		var sle *StatusListError
		if !errors.As(err, &sle) || sle.Reason != tc.reason {
			t.Errorf("%s: want reason %s, got %v", tc.name, tc.reason, err)
		}
	}
}

// statusListServers serves the JWKS and the list endpoint; the list endpoint
// answers the current value of *sids and *truncated.
func statusListServers(t *testing.T, key *rsa.PrivateKey, now func() time.Time, sids *[]string, truncated *bool, hits *int) (listURL, jwksURL string) {
	t.Helper()
	jwksSrv := jwksServer(t, key, "k1", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions/revocations/status-list" || r.Header.Get("Authorization") != "Bearer sk_test" {
			t.Errorf("unexpected request %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		*hits++
		token := signStatusList(t, key, "k1", now(), *sids, func(h, c map[string]interface{}) { c["truncated"] = *truncated })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}))
	t.Cleanup(srv.Close)
	return srv.URL, jwksSrv.URL
}

func TestEdgeRevocationChecker(t *testing.T) {
	key := statusListKey(t)
	now := time.Unix(1_800_000_000, 0)
	sids, truncated, hits := []string{"sess_revoked"}, false, 0
	listURL, jwksURL := statusListServers(t, key, func() time.Time { return now }, &sids, &truncated, &hits)
	var errs []error
	checker, err := NewEdgeRevocationChecker(EdgeRevocationOptions{
		SecretKey: "sk_test", BaseURL: listURL, JWKSURL: jwksURL, Issuer: statusListTestIssuer,
		Refresh: time.Minute, StaleAfter: 2 * time.Minute, Now: func() time.Time { return now },
		OnError: func(e error) { errs = append(errs, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if v := checker.Check(ctx, "sess_revoked"); v != EdgeRevocationRevoked {
		t.Fatalf("listed sid: %s (errors %v)", v, errs)
	}
	if v := checker.Check(ctx, "sess_ok"); v != EdgeRevocationOK || hits != 1 {
		t.Fatalf("unlisted sid: %s, hits=%d", v, hits)
	}

	// A truncated list cannot clear a session.
	now = now.Add(2 * time.Minute)
	truncated = true
	if v := checker.Check(ctx, "sess_ok"); v != EdgeRevocationUnavailable {
		t.Fatalf("truncated list: %s", v)
	}
	if v := checker.Check(ctx, "sess_revoked"); v != EdgeRevocationRevoked {
		t.Fatalf("a hit in a truncated list is still revoked: %s", v)
	}
}

func TestEdgeRevocationCheckerFailsClosedWhenStale(t *testing.T) {
	key := statusListKey(t)
	now := time.Unix(1_800_000_000, 0)
	failing := false
	jwksSrv := jwksServer(t, key, "k1", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": signStatusList(t, key, "k1", now, []string{"sess_x"}, nil)})
	}))
	defer srv.Close()
	var served []time.Duration
	checker, _ := NewEdgeRevocationChecker(EdgeRevocationOptions{
		SecretKey: "sk_test", BaseURL: srv.URL, JWKSURL: jwksSrv.URL, Issuer: statusListTestIssuer,
		Refresh: time.Minute, StaleAfter: time.Minute, ServeStaleFor: 30 * time.Second, Now: func() time.Time { return now },
		OnServeStale: func(_ time.Time, d time.Duration) { served = append(served, d) },
	})
	ctx := context.Background()
	if v := checker.Check(ctx, "sess_ok"); v != EdgeRevocationOK {
		t.Fatalf("fresh list: %s", v)
	}
	failing = true
	now = now.Add(80 * time.Second) // 20s past StaleAfter, inside the grace
	if v := checker.Check(ctx, "sess_ok"); v != EdgeRevocationOK || len(served) != 1 {
		t.Fatalf("grace: %s served=%v", v, served)
	}
	now = now.Add(time.Minute) // past the grace
	if v := checker.Check(ctx, "sess_ok"); v != EdgeRevocationUnavailable {
		t.Fatalf("stale: %s", v)
	}
}

func TestSidRevocationListStatusListSource(t *testing.T) {
	key := statusListKey(t)
	now := time.Unix(1_800_000_000, 0)
	sids, truncated, hits := []string{"sess_revoked"}, false, 0
	listURL, jwksURL := statusListServers(t, key, func() time.Time { return now }, &sids, &truncated, &hits)

	if _, err := NewSidRevocationList(SidRevocationOptions{SecretKey: "sk_test", Source: "status_list"}); err == nil {
		t.Fatal("status_list without a JWKSURL must be refused")
	}
	list, err := NewSidRevocationList(SidRevocationOptions{
		SecretKey: "sk_test", BaseURL: listURL, Source: "status_list", JWKSURL: jwksURL, Issuer: statusListTestIssuer,
		Interval: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if !list.IsRevoked(ctx, "sess_revoked") || list.IsRevoked(ctx, "sess_ok") {
		t.Fatal("the signed list answers: listed sid revoked, another not")
	}
	if err := list.Check(ctx, &SessionClaims{Sid: "sess_revoked"}); err != ErrSessionRevoked {
		t.Fatalf("want ErrSessionRevoked, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("the refresh interval throttles fetching, hits=%d", hits)
	}
}
