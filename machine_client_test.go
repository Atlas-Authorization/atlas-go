package atlas

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 8032 section 7.1, TEST 1: a published Ed25519 key and the signature over the empty message.
const machineTestPrivatePEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
const machineTestPublicPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
const machineRFC8032Test1Sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

func TestSignMachineChallengeWireVector(t *testing.T) {
	raw, _ := hex.DecodeString(machineRFC8032Test1Sig)
	got, err := SignMachineChallenge(machineTestPrivatePEM, "")
	if err != nil || got != base64.RawURLEncoding.EncodeToString(raw) {
		t.Fatalf("empty-message vector: %q %v", got, err)
	}
	nonce := "eyJtY2giOiJtY2hfMSJ9.c2lnbmF0dXJl"
	sig, _ := SignMachineChallenge(machineTestPrivatePEM, nonce)
	if len(sig) != 86 {
		t.Fatalf("a 64-byte signature is 86 base64url characters, got %d", len(sig))
	}
	block, _ := pem.Decode([]byte(machineTestPublicPEM))
	pubAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pub, _ := pubAny.(ed25519.PublicKey)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sig)
	if !ed25519.Verify(pub, []byte(nonce), sigBytes) || ed25519.Verify(pub, []byte(nonce+"x"), sigBytes) {
		t.Fatal("the signature verifies for the nonce and only the nonce")
	}
	derived, err := MachinePublicKeyPEMOf(machineTestPrivatePEM)
	if err != nil || strings.TrimSpace(derived) != strings.TrimSpace(machineTestPublicPEM) {
		t.Fatalf("public key re-derivation: %q %v", derived, err)
	}
}

type fakeMachineServer struct {
	calls  []string
	pubPEM string
	mints  int32
	proofs []string
}

func (f *fakeMachineServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := map[string]interface{}{}
		_ = json.Unmarshal(raw, &body)
		f.calls = append(f.calls, r.URL.Path)
		write := func(status int, v interface{}) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch r.URL.Path {
		case "/v1/machines/enroll":
			if body["enrolment_token"] == "bad" {
				write(401, map[string]interface{}{"errors": []map[string]string{{"code": "enrolment_token_invalid", "message": "The enrolment token is invalid or expired."}}})
				return
			}
			f.pubPEM, _ = body["public_key_pem"].(string)
			write(201, map[string]interface{}{"id": "mch_1", "status": "active", "approval_required": false, "enrolled_at": 1000})
		case "/v1/machines/challenge":
			write(200, map[string]interface{}{"nonce": "nonce-" + strings.Repeat("n", len(f.calls)), "expires_in_seconds": 120})
		case "/v1/machines/token":
			block, _ := pem.Decode([]byte(f.pubPEM))
			pubAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
			pub, _ := pubAny.(ed25519.PublicKey)
			sig, _ := base64.RawURLEncoding.DecodeString(body["signature"].(string))
			if !ed25519.Verify(pub, []byte(body["nonce"].(string)), sig) {
				write(400, map[string]interface{}{"errors": []map[string]string{{"code": "validation_failed", "message": "The signature does not verify."}}})
				return
			}
			f.proofs = append(f.proofs, r.Header.Get("DPoP"))
			n := atomic.AddInt32(&f.mints, 1)
			write(200, map[string]interface{}{"token": "tok-" + string(rune('0'+n)), "token_type": "Bearer", "expires_in": 600, "audience": body["audience"]})
		default:
			write(404, map[string]interface{}{})
		}
	})
}

func TestMachineClientEnrolMintAndCache(t *testing.T) {
	server := &fakeMachineServer{}
	srv := httptest.NewServer(server.handler(t))
	defer srv.Close()
	now := time.UnixMilli(1_000_000)
	store := NewMemoryMachineClientStore(nil)
	c, err := NewMachineClient(MachineClientOptions{Issuer: srv.URL + "/", Store: store, Now: func() time.Time { return now }, GenerateDPoPKey: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, _ := c.IsEnrolled(ctx); ok {
		t.Fatal("not enrolled yet")
	}
	if _, err := c.GetToken(ctx, MachineTokenRequest{}); err == nil || err.(*MachineClientError).Code != "not_enrolled" {
		t.Fatalf("minting before enrolment: %v", err)
	}
	if _, err := c.Enroll(ctx, MachineEnrolOptions{Credential: "bad", Name: "edge"}); err == nil || err.(*MachineClientError).Code != "enrolment_token_invalid" {
		t.Fatalf("a refused enrolment carries the server's code: %v", err)
	}
	res, err := c.Enroll(ctx, MachineEnrolOptions{Credential: " ABCD-EFGH ", Name: "edge-1", DeviceKey: "dev-1"})
	if err != nil || res.MachineID != "mch_1" || res.ApprovalRequired {
		t.Fatalf("enrol: %+v %v", res, err)
	}
	id, _ := store.Load(ctx)
	derived, _ := MachinePublicKeyPEMOf(id.PrivateKeyPEM)
	if id.Issuer != srv.URL || derived != id.PublicKeyPEM {
		t.Fatalf("stored identity: %+v", id)
	}

	req := MachineTokenRequest{Audience: "https://api.example.com", Scopes: []string{"b", "a"}}
	first, err := c.GetToken(ctx, req)
	if err != nil || first.Token != "tok-1" || first.ExpiresAt != now.UnixMilli()+600_000 {
		t.Fatalf("first token: %+v %v", first, err)
	}
	if again, _ := c.GetToken(ctx, MachineTokenRequest{Audience: "https://api.example.com", Scopes: []string{"a", "b"}}); again.Token != "tok-1" {
		t.Fatal("scope order does not change the cache key")
	}
	now = now.Add(9*time.Minute + 30*time.Second) // inside the 60s refresh skew
	if next, _ := c.GetToken(ctx, req); next.Token != "tok-2" {
		t.Fatal("a token near expiry is re-minted")
	}
	if server.proofs[0] == "" || c.DPoPThumbprint() == "" {
		t.Fatal("the token request carries a DPoP proof when a key is configured")
	}
	proof, err := c.DPoPProof("tok-2", "GET", "https://api.example.com/x?y=1", "")
	if err != nil || strings.Count(proof, ".") != 2 {
		t.Fatalf("dpop proof: %q %v", proof, err)
	}
	if err := c.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.IsEnrolled(ctx); ok {
		t.Fatal("reset forgets the identity")
	}
}

func TestFileMachineClientStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "machine.json")
	store := FileMachineClientStore(path)
	ctx := context.Background()
	if id, err := store.Load(ctx); id != nil || err != nil {
		t.Fatalf("empty store: %v %v", id, err)
	}
	want := MachineClientIdentity{Issuer: "https://id.example.com", MachineID: "mch_1", PrivateKeyPEM: "p", PublicKeyPEM: "q", EnrolledAt: 5}
	if err := store.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx)
	if err != nil || got == nil || *got != want {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ = store.Load(ctx); got != nil {
		t.Fatal("cleared")
	}
}
