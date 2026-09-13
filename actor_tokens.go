package atlas

import (
	"context"
	"net/url"
)

// ActorTokensService is the /v1/actor_tokens namespace (impersonation).
type ActorTokensService struct{ client *Client }

// Actor names the impersonating subject.
type Actor struct {
	Sub string `json:"sub"`
}

// ActorToken is a one-time impersonation token, revealed once.
type ActorToken struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Actor     Actor  `json:"actor"`
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// CreateActorTokenParams is the body of POST /v1/actor_tokens. ExpiresInSeconds
// is clamped server-side to [1, 3600]; defaults to 60.
type CreateActorTokenParams struct {
	UserID           string `json:"user_id"`
	Actor            Actor  `json:"actor"`
	ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
}

// ActorTokenRevokeResult is the acknowledgement of a revoke.
type ActorTokenRevokeResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// Create mints an actor token; the response reveals it once.
// POST /v1/actor_tokens.
func (s *ActorTokensService) Create(ctx context.Context, params CreateActorTokenParams, opts ...RequestOption) (*ActorToken, error) {
	out := &ActorToken{}
	return out, s.client.post(ctx, "/v1/actor_tokens", params, out, opts...)
}

// Revoke revokes an actor token. POST /v1/actor_tokens/:id/revoke.
func (s *ActorTokensService) Revoke(ctx context.Context, id string) (*ActorTokenRevokeResult, error) {
	out := &ActorTokenRevokeResult{}
	return out, s.client.post(ctx, "/v1/actor_tokens/"+url.PathEscape(id)+"/revoke", nil, out)
}
