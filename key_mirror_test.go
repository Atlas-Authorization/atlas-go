package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeKeyUpstream struct {
	created []CreateAPIKeyParams
	deleted []string
	revoked *KeyMirrorRevokedPage
	delErr  error
}

func (f *fakeKeyUpstream) CreateKey(_ context.Context, p CreateAPIKeyParams, _ ...RequestOption) (*KeyMirrorKeyRecord, error) {
	f.created = append(f.created, p)
	return &KeyMirrorKeyRecord{ID: "eak_1", Prefix: "ak_demo", SubjectType: p.SubjectType, SubjectID: p.SubjectID, Scopes: p.Scopes, Secret: "ak_demo_secret", Outcome: "created"}, nil
}

func (f *fakeKeyUpstream) DeleteKey(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return f.delErr
}

func (f *fakeKeyUpstream) ListRevoked(_ context.Context, _ string, _ int) (*KeyMirrorRevokedPage, error) {
	if f.revoked == nil {
		return &KeyMirrorRevokedPage{}, nil
	}
	return f.revoked, nil
}

func newKeyMirrorForTest(t *testing.T, up *fakeKeyUpstream, mutate func(*KeyMirrorOptions)) (*KeyMirror, *MemoryKeyMirrorStore, *time.Time) {
	t.Helper()
	now := time.UnixMilli(1_000_000)
	store := NewMemoryKeyMirrorStore()
	opts := KeyMirrorOptions{
		Store: store, Upstream: up, Now: func() time.Time { return now },
		ScopeImplications: map[string][]string{"admin": {"read", "write"}},
	}
	if mutate != nil {
		mutate(&opts)
	}
	m, err := NewKeyMirror(opts)
	if err != nil {
		t.Fatal(err)
	}
	return m, store, &now
}

func TestKeyMirrorMintVerifyScopesAndRevoke(t *testing.T) {
	up := &fakeKeyUpstream{}
	m, _, _ := newKeyMirrorForTest(t, up, nil)
	ctx := context.Background()
	rec, err := m.Mint(ctx, CreateAPIKeyParams{SubjectType: "user", SubjectID: "usr_1", Scopes: []string{"admin"}})
	if err != nil || rec.Secret != "ak_demo_secret" {
		t.Fatalf("mint: %+v %v", rec, err)
	}
	v, err := m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{RequiredScopes: []string{"read", "write"}})
	if err != nil || !v.Valid || len(v.EffectiveScopes) != 3 {
		t.Fatalf("scope implications must expand admin: %+v %v", v, err)
	}
	v, _ = m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{RequiredScopes: []string{"billing"}})
	if v.Valid || v.Code != KeyMirrorCodeInsufficientScope || len(v.MissingScopes) != 1 {
		t.Fatalf("missing scope: %+v", v)
	}
	if v, _ = m.Verify(ctx, "nope", KeyVerifyOptions{}); v.Valid || v.Code != "" {
		t.Fatalf("unknown key: %+v", v)
	}
	if err := m.Revoke(ctx, "eak_1"); err != nil || len(up.deleted) != 1 {
		t.Fatalf("revoke: %v %v", err, up.deleted)
	}
	if v, _ = m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{}); v.Valid {
		t.Fatal("a revoked key must not verify")
	}
}

func TestKeyMirrorAllowedIPsAndExpiry(t *testing.T) {
	up := &fakeKeyUpstream{}
	m, store, now := newKeyMirrorForTest(t, up, nil)
	ctx := context.Background()
	exp := now.UnixMilli() + 1000
	_ = store.Put(ctx, MirroredAPIKey{ID: "eak_ip", Hash: HashAPIKeySecret("s1"), SubjectType: "service", SubjectID: "svc", AllowedIPs: []string{"10.0.0.0/8", "2001:db8::1"}, ExpiresAt: &exp})
	if v, _ := m.Verify(ctx, "s1", KeyVerifyOptions{}); v.Code != KeyMirrorCodeClientIPRequired {
		t.Fatalf("no address fails closed: %+v", v)
	}
	if v, _ := m.Verify(ctx, "s1", KeyVerifyOptions{ClientIP: "11.1.1.1"}); v.Code != KeyMirrorCodeIPNotAllowed {
		t.Fatalf("outside the range: %+v", v)
	}
	if v, _ := m.Verify(ctx, "s1", KeyVerifyOptions{ClientIP: "10.2.3.4"}); !v.Valid {
		t.Fatalf("inside the range: %+v", v)
	}
	*now = now.Add(time.Minute)
	if v, _ := m.Verify(ctx, "s1", KeyVerifyOptions{ClientIP: "10.2.3.4"}); v.Valid {
		t.Fatal("an expired key must not verify")
	}
}

func TestIPInAllowlist(t *testing.T) {
	cases := []struct {
		ip   string
		list []string
		want bool
	}{
		{"192.168.1.5", []string{"192.168.0.0/16"}, true},
		{"192.169.1.5", []string{"192.168.0.0/16"}, false},
		{"1.2.3.4", []string{"1.2.3.4"}, true},
		{"::1", []string{"::1/128"}, true},
		{"::ffff:1.2.3.4", []string{"1.2.3.0/24"}, false},
		{"garbage", []string{"0.0.0.0/0"}, false},
	}
	for _, c := range cases {
		if got := IPInAllowlist(c.ip, c.list); got != c.want {
			t.Errorf("IPInAllowlist(%q, %v) = %v, want %v", c.ip, c.list, got, c.want)
		}
	}
}

func TestKeyMirrorStalenessAndSync(t *testing.T) {
	up := &fakeKeyUpstream{}
	m, store, now := newKeyMirrorForTest(t, up, func(o *KeyMirrorOptions) { o.MaxStaleness = time.Minute })
	ctx := context.Background()
	_ = store.Put(ctx, MirroredAPIKey{ID: "eak_s", Hash: HashAPIKeySecret("s2"), SubjectType: "service", SubjectID: "svc"})
	if v, _ := m.Verify(ctx, "s2", KeyVerifyOptions{}); v.Code != KeyMirrorCodeStale || v.LastSyncAt != nil {
		t.Fatalf("never synced is stale: %+v", v)
	}
	at := now.UnixMilli()
	up.revoked = &KeyMirrorRevokedPage{Data: []KeyMirrorRevokedKey{{ID: "eak_s", RevokedAt: &at}}}
	n, err := m.Sync(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sync: %d %v", n, err)
	}
	if v, _ := m.Verify(ctx, "s2", KeyVerifyOptions{}); v.Valid || v.Code != "" {
		t.Fatalf("a key revoked in the feed is refused (fresh mirror): %+v", v)
	}
	*now = now.Add(5 * time.Minute)
	if v, _ := m.Verify(ctx, "s2", KeyVerifyOptions{}); v.Code != KeyMirrorCodeStale || v.LastSyncAt == nil {
		t.Fatalf("an old sync is stale: %+v", v)
	}
}

func TestKeyMirrorApplyWebhook(t *testing.T) {
	up := &fakeKeyUpstream{}
	m, store, _ := newKeyMirrorForTest(t, up, nil)
	ctx := context.Background()
	_ = store.Put(ctx, MirroredAPIKey{ID: "eak_w", Hash: HashAPIKeySecret("s3"), SubjectType: "user", SubjectID: "usr_1", Scopes: []string{"read"}})
	changed, err := m.ApplyWebhook(ctx, "api_key.updated", json.RawMessage(`{"id":"eak_w","scopes":["write"]}`))
	held, _ := store.Get(ctx, "eak_w")
	if err != nil || !changed || len(held.Scopes) != 1 || held.Scopes[0] != "write" {
		t.Fatalf("updated: %v %v %+v", changed, err, held)
	}
	if changed, _ = m.ApplyWebhook(ctx, "api_key.revoked", json.RawMessage(`{"id":"eak_w","revoked_reason":"user_banned"}`)); !changed {
		t.Fatal("revoked must change the mirror")
	}
	if v, _ := m.Verify(ctx, "s3", KeyVerifyOptions{}); v.Valid {
		t.Fatal("revoked by webhook")
	}
	if changed, _ = m.ApplyWebhook(ctx, "api_key.restored", json.RawMessage(`{"id":"eak_w"}`)); !changed {
		t.Fatal("restored lifts the revocation")
	}
	if v, _ := m.Verify(ctx, "s3", KeyVerifyOptions{}); !v.Valid {
		t.Fatal("restored key verifies again")
	}
	if changed, _ = m.ApplyWebhook(ctx, "api_key.revoked", json.RawMessage(`{"id":"eak_unknown"}`)); changed {
		t.Fatal("an unknown key is ignored")
	}
}

func TestKeyMirrorOrgBoundKeyUsesMembership(t *testing.T) {
	up := &fakeKeyUpstream{}
	org := "org_1"
	m, store, _ := newKeyMirrorForTest(t, up, func(o *KeyMirrorOptions) {
		o.Membership = func(_ context.Context, userID, orgID string) (*KeyMirrorMembership, error) {
			if userID != "usr_1" || orgID != "org_1" {
				return nil, nil
			}
			return &KeyMirrorMembership{ID: "org_1", Role: "member", Permissions: []string{"docs:*"}}, nil
		}
	})
	ctx := context.Background()
	_ = store.Put(ctx, MirroredAPIKey{ID: "eak_o", Hash: HashAPIKeySecret("s4"), SubjectType: "user", SubjectID: "usr_1", OrganizationID: &org, Scopes: []string{"docs:read", "billing:read"}})
	v, err := m.Verify(ctx, "s4", KeyVerifyOptions{RequiredScopes: []string{"docs:read"}})
	if err != nil || !v.Valid || len(v.EffectiveScopes) != 1 || v.Organization == nil {
		t.Fatalf("scopes narrowed to the membership: %+v %v", v, err)
	}
	if v, _ = m.Verify(ctx, "s4", KeyVerifyOptions{RequiredScopes: []string{"billing:read"}}); v.Valid {
		t.Fatal("a scope the membership does not cover is refused")
	}
}

type rotatingKeyUpstream struct {
	fakeKeyUpstream
	revokeOld bool
	rotated   []string
}

func (f *rotatingKeyUpstream) RotateKey(_ context.Context, id string, p KeyMirrorRotateParams, _ ...RequestOption) (*KeyMirrorRotation, error) {
	f.rotated = append(f.rotated, id)
	out := &KeyMirrorRotation{KeyMirrorKeyRecord: KeyMirrorKeyRecord{
		ID: "eak_2", Prefix: "ak_new", SubjectType: "user", SubjectID: "usr_1", Scopes: []string{"read"}, Secret: "ak_new_secret",
	}}
	out.PreviousKey.ID = id
	if f.revokeOld {
		out.PreviousKey.Revoked = true
	} else {
		end := int64(1_000_000 + 3_600_000)
		out.PreviousKey.ExpiresAt = &end
		out.OverlapSeconds = 3600
	}
	return out, nil
}

func TestKeyMirrorRotateOverlapAndImmediate(t *testing.T) {
	for _, revokeOld := range []bool{false, true} {
		up := &rotatingKeyUpstream{revokeOld: revokeOld}
		m, store, _ := newKeyMirrorForTest(t, &up.fakeKeyUpstream, nil)
		m.opts.Upstream = up
		ctx := context.Background()
		if _, err := m.Mint(ctx, CreateAPIKeyParams{SubjectType: "user", SubjectID: "usr_1", Scopes: []string{"read"}}); err != nil {
			t.Fatal(err)
		}
		overlap := int64(3600)
		rot, err := m.Rotate(ctx, "eak_1", KeyMirrorRotateParams{OverlapSeconds: &overlap})
		if err != nil || rot.Secret != "ak_new_secret" || len(up.rotated) != 1 {
			t.Fatalf("rotate: %+v %v", rot, err)
		}
		// the successor verifies from the mirror
		if v, _ := m.Verify(ctx, "ak_new_secret", KeyVerifyOptions{}); !v.Valid {
			t.Fatalf("the successor must verify: %+v", v)
		}
		old, _ := store.Get(ctx, "eak_1")
		if revokeOld {
			if old.RevokedAt == nil || old.RevokedReason == nil || *old.RevokedReason != "rotated" {
				t.Fatalf("the old key must be revoked as rotated: %+v", old)
			}
		} else if old.RevokedAt != nil || old.ExpiresAt == nil || *old.ExpiresAt != 4_600_000 {
			t.Fatalf("the old key must end at the end of the overlap: %+v", old)
		}
	}
}

func TestKeyMirrorRotateNeedsARotatingUpstream(t *testing.T) {
	m, _, _ := newKeyMirrorForTest(t, &fakeKeyUpstream{}, nil)
	if _, err := m.Rotate(context.Background(), "eak_1", KeyMirrorRotateParams{}); err == nil {
		t.Fatal("an upstream without RotateKey must be refused")
	}
}

func TestKeyMirrorUpstreamRotatePath(t *testing.T) {
	var method, path string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"id":"eak_2","prefix":"ak_n","secret":"ak_n_s","previous_key":{"id":"eak_1","prefix":"ak_o","expires_at":99,"revoked":false},"overlap_seconds":5}`))
	}))
	defer srv.Close()
	up := NewKeyMirrorUpstream(New("sk_test", WithBaseURL(srv.URL))).(KeyMirrorRotator)
	secs := int64(5)
	rot, err := up.RotateKey(context.Background(), "eak_1", KeyMirrorRotateParams{OverlapSeconds: &secs})
	if err != nil || method != "POST" || path != "/v1/api_keys/eak_1/rotate" || body["overlap_seconds"] != float64(5) {
		t.Fatalf("%s %s %v %v", method, path, body, err)
	}
	if rot.ID != "eak_2" || rot.Secret != "ak_n_s" || rot.PreviousKey.ID != "eak_1" || rot.PreviousKey.ExpiresAt == nil || rot.OverlapSeconds != 5 {
		t.Fatalf("decoded %+v", rot)
	}
}

func TestKeyMirrorDisabledKeyIsRefusedAndWebhookCopiesEnabled(t *testing.T) {
	ctx := context.Background()
	up := &fakeKeyUpstream{}
	m, _, _ := newKeyMirrorForTest(t, up, nil)
	if _, err := m.Mint(ctx, CreateAPIKeyParams{SubjectType: "user", SubjectID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{}); !v.Valid {
		t.Fatal("enabled by default")
	}
	if ok, err := m.ApplyWebhook(ctx, "api_key.updated", json.RawMessage(`{"id":"eak_1","enabled":false}`)); !ok || err != nil {
		t.Fatalf("webhook: %v %v", ok, err)
	}
	if v, _ := m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{}); v.Valid || v.Code != "" {
		t.Fatalf("disabled: %+v", v)
	}
	_, _ = m.ApplyWebhook(ctx, "api_key.updated", json.RawMessage(`{"id":"eak_1","enabled":true}`))
	if v, _ := m.Verify(ctx, "ak_demo_secret", KeyVerifyOptions{}); !v.Valid {
		t.Fatal("re-enabled")
	}
}
