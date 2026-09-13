package atlas

import (
	"context"
	"net/url"
)

// UsersService is the /v1/users namespace.
type UsersService struct{ client *Client }

// User is a user as the BAPI serves it. private_metadata is never returned.
type User struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	Username       *string  `json:"username"`
	FirstName      *string  `json:"first_name"`
	LastName       *string  `json:"last_name"`
	ImageURL       *string  `json:"image_url"`
	PublicMetadata Metadata `json:"public_metadata"`
	MFAEnabled     bool     `json:"mfa_enabled"`
	Banned         bool     `json:"banned"`
	Locked         bool     `json:"locked"`
	// LastSignInAt is epoch milliseconds, or nil if never signed in.
	LastSignInAt *int64 `json:"last_sign_in_at"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// EmailAddress is a user's email address record.
type EmailAddress struct {
	Object       string `json:"object"`
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
	Verified     bool   `json:"verified"`
	Primary      bool   `json:"primary"`
	CreatedAt    int64  `json:"created_at"`
}

// UserSession is a session as listed under a user.
type UserSession struct {
	Object       string `json:"object"`
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Status       string `json:"status"`
	LastActiveAt int64  `json:"last_active_at"`
	ExpireAt     int64  `json:"expire_at"`
	AbandonAt    int64  `json:"abandon_at"`
	CreatedAt    int64  `json:"created_at"`
}

// OAuthAccessToken is a live provider credential. The field is `token`, not
// `access_token`.
type OAuthAccessToken struct {
	Object    string   `json:"object"`
	Provider  string   `json:"provider"`
	Token     string   `json:"token"`
	ExpiresAt *int64   `json:"expires_at"`
	Scopes    []string `json:"scopes"`
	Refreshed bool     `json:"refreshed"`
}

// CreateUserParams is the body of POST /v1/users.
type CreateUserParams struct {
	EmailAddress    string   `json:"email_address"`
	Password        string   `json:"password,omitempty"`
	FirstName       string   `json:"first_name,omitempty"`
	LastName        string   `json:"last_name,omitempty"`
	EmailVerified   *bool    `json:"email_verified,omitempty"`
	PublicMetadata  Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata Metadata `json:"private_metadata,omitempty"`
	UnsafeMetadata  Metadata `json:"unsafe_metadata,omitempty"`
}

// UpdateUserParams is the body of PATCH /v1/users/:id.
type UpdateUserParams struct {
	FirstName       string   `json:"first_name,omitempty"`
	LastName        string   `json:"last_name,omitempty"`
	PublicMetadata  Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata Metadata `json:"private_metadata,omitempty"`
}

// ReplaceUserMetadataParams is the body of PUT /v1/users/:id/metadata; the named
// bags are replaced wholesale.
type ReplaceUserMetadataParams struct {
	PublicMetadata  Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata Metadata `json:"private_metadata,omitempty"`
	UnsafeMetadata  Metadata `json:"unsafe_metadata,omitempty"`
}

// List returns one cursor page of users. GET /v1/users.
func (s *UsersService) List(ctx context.Context, params ListParams) (*CursorPage[User], error) {
	out := &CursorPage[User]{}
	return out, s.client.get(ctx, "/v1/users", params.values(), out)
}

// Get fetches a single user. GET /v1/users/:id.
func (s *UsersService) Get(ctx context.Context, id string) (*User, error) {
	out := &User{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id), nil, out)
}

// Create provisions a user. POST /v1/users. Pass WithIdempotencyKey to
// de-duplicate retries.
func (s *UsersService) Create(ctx context.Context, params CreateUserParams, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users", params, out, opts...)
}

// Update patches a user. PATCH /v1/users/:id.
func (s *UsersService) Update(ctx context.Context, id string, params UpdateUserParams) (*User, error) {
	out := &User{}
	return out, s.client.patch(ctx, "/v1/users/"+url.PathEscape(id), params, out)
}

// ReplaceMetadata replaces the named metadata bags wholesale.
// PUT /v1/users/:id/metadata.
func (s *UsersService) ReplaceMetadata(ctx context.Context, id string, params ReplaceUserMetadataParams) (*User, error) {
	out := &User{}
	return out, s.client.put(ctx, "/v1/users/"+url.PathEscape(id)+"/metadata", params, out)
}

// Ban bans a user. POST /v1/users/:id/ban.
func (s *UsersService) Ban(ctx context.Context, id string) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/ban", nil, out)
}

// Unban lifts a ban. POST /v1/users/:id/unban.
func (s *UsersService) Unban(ctx context.Context, id string) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/unban", nil, out)
}

// Lock locks a user, optionally for a bounded duration. POST /v1/users/:id/lock.
func (s *UsersService) Lock(ctx context.Context, id string, durationInSeconds int) (*User, error) {
	body := map[string]interface{}{}
	if durationInSeconds > 0 {
		body["duration_in_seconds"] = durationInSeconds
	}
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/lock", body, out)
}

// Unlock unlocks a user. POST /v1/users/:id/unlock.
func (s *UsersService) Unlock(ctx context.Context, id string) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/unlock", nil, out)
}

// Delete removes a user. DELETE /v1/users/:id.
func (s *UsersService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id), out)
}

// ResetMFA clears every MFA factor for a user. POST /v1/users/:id/reset_mfa.
func (s *UsersService) ResetMFA(ctx context.Context, id string) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/reset_mfa", nil, out)
}

// DeleteMFAFactor removes one MFA factor.
// DELETE /v1/users/:id/mfa/:factorId.
func (s *UsersService) DeleteMFAFactor(ctx context.Context, id, factorID string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/mfa/"+url.PathEscape(factorID), out)
}

// ListSessions lists a user's sessions. GET /v1/users/:id/sessions.
func (s *UsersService) ListSessions(ctx context.Context, id string) (*ListPage[UserSession], error) {
	out := &ListPage[UserSession]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/sessions", nil, out)
}

// RevokeSessions revokes all of a user's sessions.
// POST /v1/users/:id/sessions/revoke.
func (s *UsersService) RevokeSessions(ctx context.Context, id string) (*RevokeSessionsResult, error) {
	out := &RevokeSessionsResult{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/sessions/revoke", nil, out)
}

// RevokeSessionsResult is the acknowledgement of a bulk session revoke.
type RevokeSessionsResult struct {
	Object          string `json:"object"`
	ID              string `json:"id"`
	SessionsRevoked int    `json:"sessions_revoked"`
}

// AddEmail adds an email address to a user.
// POST /v1/users/:id/email_addresses.
func (s *UsersService) AddEmail(ctx context.Context, id, emailAddress string) (*EmailAddress, error) {
	out := &EmailAddress{}
	body := map[string]string{"email_address": emailAddress}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses", body, out)
}

// VerifyEmail marks an email verified.
// POST /v1/users/:id/email_addresses/:emailId/verify.
func (s *UsersService) VerifyEmail(ctx context.Context, id, emailID string) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses/"+url.PathEscape(emailID)+"/verify", nil, out)
}

// SetPrimaryEmail promotes an email to primary.
// POST /v1/users/:id/email_addresses/:emailId/primary.
func (s *UsersService) SetPrimaryEmail(ctx context.Context, id, emailID string) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses/"+url.PathEscape(emailID)+"/primary", nil, out)
}

// GetOAuthAccessToken fetches a live provider credential for a user.
// GET /v1/users/:id/oauth_access_tokens/:provider.
func (s *UsersService) GetOAuthAccessToken(ctx context.Context, id, provider string) (*OAuthAccessToken, error) {
	out := &OAuthAccessToken{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/oauth_access_tokens/"+url.PathEscape(provider), nil, out)
}

// Identity is one sign-in identity on a user: the base Atlas anchor, or a linked
// provider. Tokens are never included.
type Identity struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	Provider       string  `json:"provider"`
	ProviderUserID string  `json:"provider_user_id,omitempty"`
	Email          *string `json:"email,omitempty"`
	EmailVerified  *bool   `json:"email_verified,omitempty"`
	IsPrimary      bool    `json:"is_primary"`
	HasPassword    *bool   `json:"has_password,omitempty"`
}

// Grant is an OAuth consent grant — the scopes a user authorized a client for.
type Grant struct {
	Object     string   `json:"object"`
	ID         string   `json:"id"`
	ClientID   *string  `json:"client_id"`
	ClientName *string  `json:"client_name"`
	Scopes     []string `json:"scopes"`
	GrantedAt  int64    `json:"granted_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

// IdentityCollision reports a provider/email the primary already holds when a
// link is attempted.
type IdentityCollision struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// LinkIdentityResult is the response of merging a secondary user into a primary.
type LinkIdentityResult struct {
	Object     string              `json:"object"`
	Data       []Identity          `json:"data"`
	Collisions []IdentityCollision `json:"collisions"`
}

// UnlinkIdentityResult acknowledges extracting a linked identity into a new user.
type UnlinkIdentityResult struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Unlinked  bool   `json:"unlinked"`
	NewUserID string `json:"new_user_id"`
}

// ExternalAccountConnection is the backend-initiated OAuth connect response.
type ExternalAccountConnection struct {
	Object           string   `json:"object"`
	Provider         string   `json:"provider"`
	UserID           string   `json:"user_id"`
	AttemptID        string   `json:"attempt_id"`
	AuthorizationURL string   `json:"authorization_url"`
	Scopes           []string `json:"scopes"`
}

// ConnectExternalAccountParams is the body of the backend-initiated connect flow.
type ConnectExternalAccountParams struct {
	Provider         string   `json:"provider"`
	RedirectURL      string   `json:"redirect_url"`
	AdditionalScopes []string `json:"additional_scopes,omitempty"`
}

// RevokeGrantsResult acknowledges revoking every grant a user holds.
type RevokeGrantsResult struct {
	Object        string `json:"object"`
	ID            string `json:"id"`
	GrantsRevoked int    `json:"grants_revoked"`
	TokensRevoked int    `json:"tokens_revoked"`
}

// RevokeGrantResult acknowledges revoking one instance-scoped grant.
type RevokeGrantResult struct {
	Object        string `json:"object"`
	ID            string `json:"id"`
	Deleted       bool   `json:"deleted"`
	TokensRevoked int    `json:"tokens_revoked"`
}

// ListIdentities returns the base Atlas identity plus one entry per linked
// external account. GET /v1/users/:id/identities.
func (s *UsersService) ListIdentities(ctx context.Context, id string) (*ListPage[Identity], error) {
	out := &ListPage[Identity]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/identities", nil, out)
}

// LinkIdentity merges a secondary user INTO this one (Auth0 post_identities
// parity). POST /v1/users/:id/identities.
func (s *UsersService) LinkIdentity(ctx context.Context, id, secondaryUserID string, opts ...RequestOption) (*LinkIdentityResult, error) {
	out := &LinkIdentityResult{}
	body := map[string]string{"secondary_user_id": secondaryUserID}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/identities", body, out, opts...)
}

// ConnectExternalAccount starts a backend-initiated OAuth flow that links a NEW
// provider identity to this user. POST /v1/users/:id/external_accounts/connect.
func (s *UsersService) ConnectExternalAccount(ctx context.Context, id string, params ConnectExternalAccountParams, opts ...RequestOption) (*ExternalAccountConnection, error) {
	out := &ExternalAccountConnection{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/external_accounts/connect", params, out, opts...)
}

// UnlinkIdentity extracts a linked provider identity into a brand-new standalone
// user. DELETE /v1/users/:id/identities/:identityId.
func (s *UsersService) UnlinkIdentity(ctx context.Context, id, identityID string) (*UnlinkIdentityResult, error) {
	out := &UnlinkIdentityResult{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/identities/"+url.PathEscape(identityID), out)
}

// ListGrants returns the OAuth clients this user has authorized.
// GET /v1/users/:id/grants.
func (s *UsersService) ListGrants(ctx context.Context, id string) (*ListPage[Grant], error) {
	out := &ListPage[Grant]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/grants", nil, out)
}

// RevokeAllGrants revokes every consent grant the user holds, cascading to the
// associated tokens. DELETE /v1/users/:id/grants.
func (s *UsersService) RevokeAllGrants(ctx context.Context, id string) (*RevokeGrantsResult, error) {
	out := &RevokeGrantsResult{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/grants", out)
}

// RevokeGrant revokes ONE consent grant (and its live tokens). Grants are
// instance-scoped, so this is not nested under a user id. DELETE /v1/grants/:id.
func (s *UsersService) RevokeGrant(ctx context.Context, grantID string) (*RevokeGrantResult, error) {
	out := &RevokeGrantResult{}
	return out, s.client.del(ctx, "/v1/grants/"+url.PathEscape(grantID), out)
}
