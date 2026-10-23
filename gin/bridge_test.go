package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/gin-gonic/gin"
)

func TestBetterAuthBridge(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != atlas.BetterAuthExchangePath || r.Header.Get("X-Atlas-Client-User-Agent") != "UA" {
			t.Errorf("unexpected %s %v", r.URL.Path, r.Header)
		}
		_, _ = w.Write([]byte(`{"object":"session_tokens","jwt":"j.w.t","refresh_token":"rt"}`))
	}))
	t.Cleanup(api.Close)
	bridge, err := atlas.NewBetterAuthBridge(atlas.BetterAuthBridgeOptions{Client: atlas.New("sk_test", atlas.WithBaseURL(api.URL))})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(BetterAuthBridge(bridge))
	r.GET("/page", func(c *gin.Context) { c.String(200, "next") })

	req := httptest.NewRequest("GET", "/page", nil)
	req.Header.Set("Cookie", "better-auth.session_token=tok")
	req.Header.Set("User-Agent", "UA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/page" || w.Body.String() == "next" {
		t.Fatalf("bridge = %d %q %q", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/page", nil))
	if w.Code != 200 || w.Body.String() != "next" {
		t.Errorf("no cookie should pass through: %d %q", w.Code, w.Body.String())
	}
}
