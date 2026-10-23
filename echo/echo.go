// Package echo adapts the Atlas session verifier to an echo.MiddlewareFunc. It
// is a nested module (github.com/Atlas-Authorization/atlas-go/echo) so that only
// consumers who want Echo pay for it, leaving the base SDK framework-free. All
// verification is delegated to *atlas.AtlasBackend — this package adds no JWT or
// JWKS handling of its own.
package echo

import (
	"context"
	"net/http"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/labstack/echo/v4"
)

// ContextKey is the echo.Context key under which verified claims are stored.
const ContextKey = "atlas"

// Verifier is the slice of *atlas.AtlasBackend this adapter needs;
// *atlas.AtlasBackend satisfies it.
type Verifier interface {
	AuthenticateRequest(ctx context.Context, r *http.Request) (*atlas.SessionClaims, error)
}

// Auth returns an Echo middleware that verifies the request's Atlas session (an
// Authorization: Bearer header, preferred, or a __session cookie), stores the
// claims under ContextKey, and returns a 401 HTTPError when no valid token is
// present.
func Auth(v Verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := v.AuthenticateRequest(c.Request().Context(), c.Request())
			if err != nil || claims == nil {
				return echo.NewHTTPError(http.StatusUnauthorized)
			}
			c.Set(ContextKey, claims)
			return next(c)
		}
	}
}

// FromEcho returns the verified claims an Auth middleware stored on the context,
// and whether any were present.
func FromEcho(c echo.Context) (*atlas.SessionClaims, bool) {
	claims, ok := c.Get(ContextKey).(*atlas.SessionClaims)
	return claims, ok
}

// BetterAuthBridge returns an Echo middleware for a Better Auth cutover: a
// GET/HEAD carrying a Better Auth session cookie and no Atlas session is
// exchanged once for an Atlas session and redirected to the same URL signed in
// (or to the bridge's SignInURL when a second factor is owed). Put it before
// Auth. Build the bridge with atlas.NewBetterAuthBridge.
func BetterAuthBridge(b *atlas.BetterAuthBridge) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if b.Handle(c.Response(), c.Request()) {
				return nil
			}
			return next(c)
		}
	}
}
