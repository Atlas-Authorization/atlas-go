package atlas

import (
	"context"
	"net/url"
)

// SignInTokensService is the /v1/sign_in_tokens namespace.
//
// Deprecated: POST /v1/sign_in_tokens is deprecated (Sunset 2026-04-01). Use
// SessionsService.Create (POST /v1/sessions), which mints a real redeemable
// session in one call.
type SignInTokensService struct{ client *Client }

// SignInToken is a one-time sign-in token.
type SignInToken struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// CreateSignInTokenParams is the body of POST /v1/sign_in_tokens.
// ExpiresInSeconds is accepted for shape parity but currently ignored
// server-side (the token always lives 60 seconds).
type CreateSignInTokenParams struct {
	UserID           string `json:"user_id"`
	ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
}

// Create mints a sign-in token. POST /v1/sign_in_tokens.
func (s *SignInTokensService) Create(ctx context.Context, params CreateSignInTokenParams, opts ...RequestOption) (*SignInToken, error) {
	out := &SignInToken{}
	return out, s.client.post(ctx, "/v1/sign_in_tokens", params, out, opts...)
}

// SignInTokenRevocation is the result of revoking a sign-in token.
type SignInTokenRevocation struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// Revoke revokes an unused sign-in token before its window elapses.
// POST /v1/sign_in_tokens/:id/revoke.
//
// Deprecated: part of the deprecated /v1/sign_in_tokens surface (Sunset
// 2027-04-01). Use SessionsService.Create (POST /v1/sessions).
func (s *SignInTokensService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*SignInTokenRevocation, error) {
	out := &SignInTokenRevocation{}
	return out, s.client.post(ctx, "/v1/sign_in_tokens/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}
