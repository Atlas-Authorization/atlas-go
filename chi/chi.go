// Package chi adapts the Atlas session verifier to go-chi routers. chi middleware is plain
// net/http middleware, so this nested module (github.com/Atlas-Authorization/atlas-go/chi)
// mostly gives chi apps the idiomatic names: Auth (401 unless signed in), Optional, Require
// (401 or 403 on a condition) and FromRequest. All verification stays in *atlas.AtlasBackend.
package chi

import (
	"net/http"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/Atlas-Authorization/atlas-go/middleware"
)

// Verifier is the slice of *atlas.AtlasBackend this adapter needs.
type Verifier = middleware.Verifier

// Auth rejects a request without a valid Atlas session (Bearer header or __session cookie) with 401.
// Mount it with r.Use(chi.Auth(backend)) or on a r.Group.
func Auth(v Verifier) func(http.Handler) http.Handler { return middleware.RequireAuth(v) }

// Optional attaches the claims when a valid token is present and never blocks the request.
func Optional(v Verifier) func(http.Handler) http.Handler { return middleware.Optional(v) }

// FromRequest returns the verified claims an Auth or Optional middleware stored on the request.
func FromRequest(r *http.Request) (*atlas.SessionClaims, bool) {
	return middleware.FromContext(r.Context())
}

// Require runs after Auth and answers 401 when the request is signed out or 403 when check
// returns false, e.g. r.With(chi.Require(func(c *atlas.SessionClaims) bool { return c.OrgRole == "admin" })).
func Require(check func(*atlas.SessionClaims) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := FromRequest(r)
			if !ok || claims == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			if check != nil && !check(claims) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
