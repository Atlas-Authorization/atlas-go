package atlas

import "context"

// SignInTokensService is the /v1/sign_in_tokens namespace.
type SignInTokensService struct{ client *Client }

// SignInToken is a one-time sign-in token.
type SignInToken struct {
	Object    string `json:"object"`
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
