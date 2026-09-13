package atlas

import "context"

// TokensService is the /v1/tokens namespace — §7.7 authoritative token
// verification. Backend SDKs verify session JWTs locally against JWKS (see
// AtlasBackend.Verify); this endpoint is for the requests where "signed out a
// moment ago" has to mean now: it checks the revocation set and, when the cache
// cannot answer, falls through to the database.
type TokensService struct{ client *Client }

// VerifyTokenParams is the body of POST /v1/tokens/verify.
type VerifyTokenParams struct {
	Token string `json:"token"`
	// AuthorizedParties are the expected azp values, if the token carries one.
	AuthorizedParties []string `json:"authorized_parties,omitempty"`
}

// TokenVerification is the verify verdict. On success Verified is true and the
// session fields are populated; on failure Verified is false with a coarse
// Reason ("invalid" | "revoked").
type TokenVerification struct {
	Object   string `json:"object"`
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`

	UserID                  string   `json:"user_id,omitempty"`
	SessionID               string   `json:"session_id,omitempty"`
	OrganizationID          *string  `json:"organization_id,omitempty"`
	OrganizationRole        *string  `json:"organization_role,omitempty"`
	OrganizationPermissions []string `json:"organization_permissions,omitempty"`
	MFA                     bool     `json:"mfa,omitempty"`
	// CheckedAuthoritatively is true when the cache could not answer and the
	// database was consulted.
	CheckedAuthoritatively bool `json:"checked_authoritatively,omitempty"`
}

// Verify authoritatively checks a session token, honouring revocation.
// POST /v1/tokens/verify.
func (s *TokensService) Verify(ctx context.Context, params VerifyTokenParams) (*TokenVerification, error) {
	out := &TokenVerification{}
	return out, s.client.post(ctx, "/v1/tokens/verify", params, out)
}
