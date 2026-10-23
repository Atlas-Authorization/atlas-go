package echo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/labstack/echo/v4"
)

func TestBetterAuthBridge(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"session_tokens","jwt":"j.w.t","refresh_token":"rt"}`))
	}))
	t.Cleanup(api.Close)
	bridge, err := atlas.NewBetterAuthBridge(atlas.BetterAuthBridgeOptions{Client: atlas.New("sk_test", atlas.WithBaseURL(api.URL))})
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use(BetterAuthBridge(bridge))
	e.GET("/page", func(c echo.Context) error { return c.String(200, "next") })

	req := httptest.NewRequest("GET", "/page?a=b", nil)
	req.Header.Set("Cookie", "better-auth.session_token=tok")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/page?a=b" {
		t.Fatalf("bridge = %d %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "/page", nil))
	if w.Code != 200 || w.Body.String() != "next" {
		t.Errorf("no cookie should pass through: %d %q", w.Code, w.Body.String())
	}
}
