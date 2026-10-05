// Package middleware adapts the Atlas session verifier to net/http's
// func(http.Handler) http.Handler middleware shape — the peer of Auth0's
// go-jwt-middleware, but built entirely on *atlas.AtlasBackend. It adds no JWT or
// JWKS code of its own: every token still flows through AtlasBackend.Verify, so
// the local-verification, caching, and token-confusion guarantees in verify.go
// hold unchanged here.
//
// This package lives in the base module, so it pulls in no third-party
// dependency. The Gin and Echo adapters are separate nested modules precisely so
// that importing this one never drags a web framework into a consumer's build.
package middleware

import (
	"context"
	"net/http"

	atlas "github.com/Atlas-Authorization/atlas-go"
)

// Verifier is the slice of *atlas.AtlasBackend this package needs. Taking an
// interface rather than the concrete type keeps handlers testable and lets a
// caller wrap the verifier, while *atlas.AtlasBackend satisfies it as-is.
type Verifier interface {
	AuthenticateRequest(ctx context.Context, r *http.Request) (*atlas.SessionClaims, error)
}

// ctxKey is unexported so no other package can collide with our context slot.
type ctxKey struct{}

var claimsKey ctxKey

// NewContext returns a copy of ctx carrying claims, for callers composing their
// own middleware on top of this one.
func NewContext(ctx context.Context, claims *atlas.SessionClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// FromContext returns the verified claims a RequireAuth/Optional handler stored
// on the request context, and whether any were present.
func FromContext(ctx context.Context) (*atlas.SessionClaims, bool) {
	claims, ok := ctx.Value(claimsKey).(*atlas.SessionClaims)
	return claims, ok
}

// RequireAuth returns middleware that authenticates every request — an
// Authorization: Bearer <jwt> header (preferred) or a __session cookie — and
// responds 401 when the token is absent, malformed, or invalid. On success the
// claims are stored on the request context, readable with FromContext.
func RequireAuth(v Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := v.AuthenticateRequest(r.Context(), r)
			if err != nil || claims == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), claims)))
		})
	}
}

// Optional returns middleware that attaches claims when a valid token is present
// but never blocks the request: an absent or invalid token simply means
// FromContext reports no claims downstream. Use it for endpoints that serve both
// signed-in and anonymous callers.
func Optional(v Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if claims, err := v.AuthenticateRequest(r.Context(), r); err == nil && claims != nil {
				r = r.WithContext(NewContext(r.Context(), claims))
			}
			next.ServeHTTP(w, r)
		})
	}
}
