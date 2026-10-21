package atlas

import (
	"context"
	"encoding/json"
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
	// Version strictly increases with every change to the user; webhook
	// payloads carry the same value. Apply an update only if its version is
	// higher than the one you hold.
	Version int64 `json:"version,omitempty"`
	// Referral is how the user arrived through a referral program (referral
	// attribution on), or nil when not referred, not answered yet, or
	// referrals are off.
	Referral *UserReferral `json:"referral,omitempty"`
	// ReferralCode is the user's own referral code, when they are a referrer.
	ReferralCode *string `json:"referral_code,omitempty"`
	// ReferralLink is the user's own referral link, when they are a referrer.
	ReferralLink *string `json:"referral_link,omitempty"`
}

// UserReferral is the inbound referral the referral platform matched for a user.
type UserReferral struct {
	// PartnerID is the platform's id for the referring partner.
	PartnerID *string `json:"partner_id"`
	// ReferrerExternalID is the referrer as the platform knows them (your
	// external_id for that user, or their Atlas id).
	ReferrerExternalID *string `json:"referrer_external_id"`
	// ReferrerUserID is the referrer's Atlas user id, when they are a user of
	// this instance.
	ReferrerUserID *string `json:"referrer_user_id"`
	// MatchedVia is how the platform matched the referral, e.g. code, click, coupon.
	MatchedVia *string `json:"matched_via"`
	// Status is the platform's own status for the referral.
	Status *string `json:"status"`
	// RiskLevel is low, medium or high when Atlas assessed the sign-up.
	RiskLevel *string `json:"risk_level,omitempty"`
	// Flagged is true once an admin marked the referral fraudulent.
	Flagged bool `json:"flagged,omitempty"`
}

// CreateUserReferral is an imported referral on POST /v1/users. Each id is
// 3-64 characters of A-Z a-z 0-9 _ -.
type CreateUserReferral struct {
	Code    string `json:"code,omitempty"`
	ClickID string `json:"click_id,omitempty"`
	AnonID  string `json:"anon_id,omitempty"`
}

// UserReferralFlag is the result of POST /v1/users/:id/referral/flag.
type UserReferralFlag struct {
	Object     string  `json:"object"`
	UserID     string  `json:"user_id"`
	Status     string  `json:"status"`
	Flagged    bool    `json:"flagged"`
	FlagReason *string `json:"flag_reason"`
	// FlaggedAt is epoch ms.
	FlaggedAt *int64  `json:"flagged_at"`
	RiskLevel *string `json:"risk_level"`
}

// UserReferralAttributedEvent is the data of a user.referral_attributed
// webhook: the referral platform answered after user.created was sent.
type UserReferralAttributedEvent struct {
	Object string `json:"object"`
	UserID string `json:"user_id"`
	// AttributionStatus is attributed, not_referred (no referrer found), failed, ...
	AttributionStatus string        `json:"attribution_status"`
	Referral          *UserReferral `json:"referral"`
	ReferralCode      *string       `json:"referral_code"`
	ReferralLink      *string       `json:"referral_link"`
	// SignedUpAt is epoch ms.
	SignedUpAt int64 `json:"signed_up_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// EmailAddress is a user's email address record.
type EmailAddress struct {
	Object       string `json:"object"`
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
	// Verified is true only when the address was proven. An address that signed
	// up while requireEmailVerification was false is false.
	Verified bool `json:"verified"`
	// Verification says whether and how the address was proven (nil from older
	// servers).
	Verification *EmailAddressVerification `json:"verification,omitempty"`
	Primary      bool                      `json:"primary"`
	CreatedAt    int64                     `json:"created_at"`
}

// EmailAddressVerification is an address's proof state.
type EmailAddressVerification struct {
	// Status is "verified" or "unverified"; it mirrors Verified.
	Status string `json:"status"`
	// Strategy is email_code, email_link, oauth, admin, import, scim or lti;
	// "skipped" for an address held for sign-in but never proven; nil when not
	// verified.
	Strategy *string `json:"strategy"`
}

// UserSession is a session as listed under a user.
type UserSession struct {
	Object                   string  `json:"object"`
	ID                       string  `json:"id"`
	UserID                   string  `json:"user_id"`
	Status                   string  `json:"status"`
	LastActiveOrganizationID *string `json:"last_active_organization_id"`
	ImpersonatedBy           *string `json:"impersonated_by"`
	LastActiveAt             int64   `json:"last_active_at"`
	ExpireAt                 int64   `json:"expire_at"`
	AbandonAt                int64   `json:"abandon_at"`
	// IdleExpiresAt is epoch ms when the session ends from inactivity unless
	// there is activity first (same value as AbandonAt).
	IdleExpiresAt int64 `json:"idle_expires_at,omitempty"`
	CreatedAt     int64 `json:"created_at"`
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
	// Notify says whether the create may notify the user. Unset or false
	// guarantees no email, SMS or push is sent as a consequence of the create.
	Notify *bool `json:"notify,omitempty"`
	// Referral imports how the user arrived; with referral attribution on, the
	// user is reported to the referral platform.
	Referral *CreateUserReferral `json:"referral,omitempty"`
	// ReferralCode is the user's own referral code, unique per instance (409
	// REFERRAL_CODE_TAKEN).
	ReferralCode string `json:"referral_code,omitempty"`
}

// UpdateUserParams is the body of PATCH /v1/users/:id.
type UpdateUserParams struct {
	FirstName       string   `json:"first_name,omitempty"`
	LastName        string   `json:"last_name,omitempty"`
	PublicMetadata  Metadata `json:"public_metadata,omitempty"`
	PrivateMetadata Metadata `json:"private_metadata,omitempty"`
	// ReferralCode sets the user's own referral code, unique per instance (409
	// REFERRAL_CODE_TAKEN).
	ReferralCode string `json:"referral_code,omitempty"`
	// ClearReferralCode sends referral_code: null (removes the user's code).
	ClearReferralCode bool `json:"-"`
}

// MarshalJSON sends referral_code: null when ClearReferralCode is set.
func (p UpdateUserParams) MarshalJSON() ([]byte, error) {
	type plain UpdateUserParams
	if !p.ClearReferralCode {
		return json.Marshal(plain(p))
	}
	return marshalWithExtra(plain(p), map[string]interface{}{"referral_code": nil})
}

// FlagReferralParams is the body of POST /v1/users/:id/referral/flag.
type FlagReferralParams struct {
	// Reason (at most 500 characters) is sent to the referral platform.
	Reason string `json:"reason,omitempty"`
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
func (s *UsersService) Update(ctx context.Context, id string, params UpdateUserParams, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.patch(ctx, "/v1/users/"+url.PathEscape(id), params, out, opts...)
}

// ReplaceMetadata replaces the named metadata bags wholesale.
// PUT /v1/users/:id/metadata.
func (s *UsersService) ReplaceMetadata(ctx context.Context, id string, params ReplaceUserMetadataParams, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.put(ctx, "/v1/users/"+url.PathEscape(id)+"/metadata", params, out, opts...)
}

// Ban bans a user. POST /v1/users/:id/ban.
func (s *UsersService) Ban(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/ban", nil, out, opts...)
}

// Unban lifts a ban. POST /v1/users/:id/unban.
func (s *UsersService) Unban(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/unban", nil, out, opts...)
}

// Lock locks a user, optionally for a bounded duration. POST /v1/users/:id/lock.
func (s *UsersService) Lock(ctx context.Context, id string, durationInSeconds int, opts ...RequestOption) (*User, error) {
	body := map[string]interface{}{}
	if durationInSeconds > 0 {
		body["duration_in_seconds"] = durationInSeconds
	}
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/lock", body, out, opts...)
}

// Unlock unlocks a user. POST /v1/users/:id/unlock.
func (s *UsersService) Unlock(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/unlock", nil, out, opts...)
}

// FlagReferral marks the user's referral fraudulent: it reads Flagged, the
// referral platform is sent a fraud_confirmed signal (when referrals are on)
// and the action is audited; the account is not changed. 404 when the user
// has no referral. POST /v1/users/:id/referral/flag.
func (s *UsersService) FlagReferral(ctx context.Context, id string, params FlagReferralParams, opts ...RequestOption) (*UserReferralFlag, error) {
	out := &UserReferralFlag{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/referral/flag", params, out, opts...)
}

// Delete removes a user. DELETE /v1/users/:id.
func (s *UsersService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id), out, opts...)
}

// ResetMFA clears every MFA factor for a user. POST /v1/users/:id/reset_mfa.
func (s *UsersService) ResetMFA(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/reset_mfa", nil, out, opts...)
}

// DeleteMFAFactor removes one MFA factor.
// DELETE /v1/users/:id/mfa/:factorId.
func (s *UsersService) DeleteMFAFactor(ctx context.Context, id, factorID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/mfa/"+url.PathEscape(factorID), out, opts...)
}

// ListSessions lists a user's sessions. GET /v1/users/:id/sessions.
func (s *UsersService) ListSessions(ctx context.Context, id string) (*ListPage[UserSession], error) {
	out := &ListPage[UserSession]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/sessions", nil, out)
}

// RevokeSessions revokes all of a user's sessions.
// POST /v1/users/:id/sessions/revoke.
func (s *UsersService) RevokeSessions(ctx context.Context, id string, opts ...RequestOption) (*RevokeSessionsResult, error) {
	out := &RevokeSessionsResult{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/sessions/revoke", nil, out, opts...)
}

// RevokeSessionsParams are the options of RevokeSessionsWithParams.
type RevokeSessionsParams struct {
	// RevokeGrants also revokes every OAuth grant the user holds, so app
	// refresh tokens stop minting access tokens.
	RevokeGrants bool `json:"revoke_grants,omitempty"`
}

// RevokeSessionsWithParams is RevokeSessions with options.
// POST /v1/users/:id/sessions/revoke.
func (s *UsersService) RevokeSessionsWithParams(ctx context.Context, id string, params RevokeSessionsParams, opts ...RequestOption) (*RevokeSessionsResult, error) {
	out := &RevokeSessionsResult{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/sessions/revoke", params, out, opts...)
}

// RevokeSessionsResult is the acknowledgement of a bulk session revoke.
type RevokeSessionsResult struct {
	Object          string `json:"object"`
	ID              string `json:"id"`
	SessionsRevoked int    `json:"sessions_revoked"`
	// GrantsRevoked is how many OAuth grants were revoked (with RevokeGrants).
	GrantsRevoked *int `json:"grants_revoked,omitempty"`
}

// AddEmail adds an email address to a user.
// POST /v1/users/:id/email_addresses.
func (s *UsersService) AddEmail(ctx context.Context, id, emailAddress string, opts ...RequestOption) (*EmailAddress, error) {
	out := &EmailAddress{}
	body := map[string]string{"email_address": emailAddress}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses", body, out, opts...)
}

// VerifyEmail marks an email verified.
// POST /v1/users/:id/email_addresses/:emailId/verify.
func (s *UsersService) VerifyEmail(ctx context.Context, id, emailID string, opts ...RequestOption) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses/"+url.PathEscape(emailID)+"/verify", nil, out, opts...)
}

// SetPrimaryEmail promotes an email to primary.
// POST /v1/users/:id/email_addresses/:emailId/primary.
func (s *UsersService) SetPrimaryEmail(ctx context.Context, id, emailID string, opts ...RequestOption) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/email_addresses/"+url.PathEscape(emailID)+"/primary", nil, out, opts...)
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
func (s *UsersService) UnlinkIdentity(ctx context.Context, id, identityID string, opts ...RequestOption) (*UnlinkIdentityResult, error) {
	out := &UnlinkIdentityResult{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/identities/"+url.PathEscape(identityID), out, opts...)
}

// ListGrants returns the OAuth clients this user has authorized.
// GET /v1/users/:id/grants.
func (s *UsersService) ListGrants(ctx context.Context, id string) (*ListPage[Grant], error) {
	out := &ListPage[Grant]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/grants", nil, out)
}

// RevokeAllGrants revokes every consent grant the user holds, cascading to the
// associated tokens. DELETE /v1/users/:id/grants.
func (s *UsersService) RevokeAllGrants(ctx context.Context, id string, opts ...RequestOption) (*RevokeGrantsResult, error) {
	out := &RevokeGrantsResult{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/grants", out, opts...)
}

// RevokeGrant revokes ONE consent grant (and its live tokens). Grants are
// instance-scoped, so this is not nested under a user id. DELETE /v1/grants/:id.
func (s *UsersService) RevokeGrant(ctx context.Context, grantID string, opts ...RequestOption) (*RevokeGrantResult, error) {
	out := &RevokeGrantResult{}
	return out, s.client.del(ctx, "/v1/grants/"+url.PathEscape(grantID), out, opts...)
}
