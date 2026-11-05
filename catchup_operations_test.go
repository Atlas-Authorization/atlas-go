package atlas

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestMintExecutorKeySendsTheSignedBytesAndTheSignature(t *testing.T) {
	raw := `{ "nonce":"n",  "iat":1 }`
	var gotBody, gotSignature, gotType string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotSignature, gotType = string(body), r.Header.Get("x-signature"), r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{"secret":"sk","executorUrl":"https://api.test"}`))
	})
	out, err := c.PartnerPlatforms.MintExecutorKey(context.Background(), "p", "i", []byte(raw), "x-signature", "t=1")
	if err != nil {
		t.Fatal(err)
	}
	if gotBody != raw || gotSignature != "t=1" || gotType != "application/json" {
		t.Errorf("sent body %q signature %q type %q", gotBody, gotSignature, gotType)
	}
	if out.ExecutorURL != "https://api.test" {
		t.Errorf("executorUrl = %q", out.ExecutorURL)
	}
}

func TestStorageDeclarationCSVAsksForCSVAndReturnsTheBytes(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("name,provider\r\n"))
	})
	out, err := c.Instance.StorageDeclarationCSV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "format=csv" || string(out) != "name,provider\r\n" {
		t.Errorf("query %q body %q", gotQuery, out)
	}
}

func TestJWTSignInURLEncodesBothValues(t *testing.T) {
	got, err := JWTSignInURL("https://a.test/j?z=1", "t k", "https://b.test/?x=1")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://a.test/j?redirect_url=https%3A%2F%2Fb.test%2F%3Fx%3D1&token=t+k&z=1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
