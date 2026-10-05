// Package gin adapts the Atlas session verifier to a gin.HandlerFunc. It is a
// nested module (github.com/Atlas-Authorization/atlas-go/gin) so that depending
// on it pulls Gin into a consumer's build, while the base SDK stays
// framework-free. All verification is delegated to *atlas.AtlasBackend — this
// package adds no JWT or JWKS handling of its own.
package gin

import (
	"context"
	"net/http"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"github.com/gin-gonic/gin"
)

// ContextKey is the gin.Context key under which verified claims are stored.
const ContextKey = "atlas"

// Verifier is the slice of *atlas.AtlasBackend this adapter needs;
// *atlas.AtlasBackend satisfies it.
type Verifier interface {
	AuthenticateRequest(ctx context.Context, r *http.Request) (*atlas.SessionClaims, error)
}

// Auth returns a gin middleware that verifies the request's Atlas session (an
// Authorization: Bearer header, preferred, or a __session cookie), stores the
// claims under ContextKey, and aborts with 401 when no valid token is present.
func Auth(v Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := v.AuthenticateRequest(c.Request.Context(), c.Request)
		if err != nil || claims == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set(ContextKey, claims)
		c.Next()
	}
}

// FromGin returns the verified claims an Auth middleware stored on the context,
// and whether any were present.
func FromGin(c *gin.Context) (*atlas.SessionClaims, bool) {
	v, ok := c.Get(ContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*atlas.SessionClaims)
	return claims, ok
}
