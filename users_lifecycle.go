package atlas

import (
	"context"
	"net/url"
)

// --- Passwords, phone numbers, profile image, passkeys --------------------

// SetUserPasswordParams is the body of POST /v1/users/:id/password.
type SetUserPasswordParams struct {
	Password string `json:"password"`
	// SkipPasswordChecks is accepted for Clerk parity; an admin set runs no
	// policy or breach check either way.
	SkipPasswordChecks bool `json:"skip_password_checks,omitempty"`
	// SignOutOfOtherSessions revokes the user's live sessions.
	SignOutOfOtherSessions bool `json:"sign_out_of_other_sessions,omitempty"`
}

// SetPassword sets (resets) a user's password from the backend.
// POST /v1/users/:id/password.
func (s *UsersService) SetPassword(ctx context.Context, id string, params SetUserPasswordParams, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/password", params, out, opts...)
}

// UserPhoneNumber is a phone number on a user.
type UserPhoneNumber struct {
	Object      string `json:"object"`
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
	Verified    bool   `json:"verified"`
	CreatedAt   int64  `json:"created_at"`
}

// AddPhoneNumber adds an (unverified) phone number to a user.
// POST /v1/users/:id/phone_numbers.
func (s *UsersService) AddPhoneNumber(ctx context.Context, id, phoneNumber string, opts ...RequestOption) (*UserPhoneNumber, error) {
	out := &UserPhoneNumber{}
	body := map[string]string{"phone_number": phoneNumber}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/phone_numbers", body, out, opts...)
}

// VerifyPhoneNumber marks a user's phone number verified.
// POST /v1/users/:id/phone_numbers/:pid/verify.
func (s *UsersService) VerifyPhoneNumber(ctx context.Context, id, phoneID string, opts ...RequestOption) (*UserPhoneNumber, error) {
	out := &UserPhoneNumber{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/phone_numbers/"+url.PathEscape(phoneID)+"/verify", nil, out, opts...)
}

// DeletePhoneNumber removes a phone number from a user.
// DELETE /v1/users/:id/phone_numbers/:pid.
func (s *UsersService) DeletePhoneNumber(ctx context.Context, id, phoneID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/phone_numbers/"+url.PathEscape(phoneID), out, opts...)
}

// DeleteProfileImage clears a user's profile image.
// DELETE /v1/users/:id/profile_image.
func (s *UsersService) DeleteProfileImage(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/profile_image", out, opts...)
}

// DeletePasskey removes one of a user's passkeys.
// DELETE /v1/users/:id/passkeys/:passkeyId.
func (s *UsersService) DeletePasskey(ctx context.Context, id, passkeyID string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/passkeys/"+url.PathEscape(passkeyID), out, opts...)
}

// --- Flat email-address aliases --------------------------------------------

// EmailAddressesService is the flat /v1/email_addresses namespace: the user is
// derived from the address id.
type EmailAddressesService struct{ client *Client }

// Verify marks an address verified. POST /v1/email_addresses/:eid/verify.
func (s *EmailAddressesService) Verify(ctx context.Context, emailID string, opts ...RequestOption) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/email_addresses/"+url.PathEscape(emailID)+"/verify", nil, out, opts...)
}

// SetPrimary makes a verified address its user's primary.
// POST /v1/email_addresses/:eid/primary.
func (s *EmailAddressesService) SetPrimary(ctx context.Context, emailID string, opts ...RequestOption) (*EmailAddress, error) {
	out := &EmailAddress{}
	return out, s.client.post(ctx, "/v1/email_addresses/"+url.PathEscape(emailID)+"/primary", nil, out, opts...)
}

// --- Lookups ----------------------------------------------------------------

// UsersByEmailsParams is the body of POST /v1/users/by_emails.
type UsersByEmailsParams struct {
	// EmailAddresses: up to 1000, deduped, case-insensitive.
	EmailAddresses []string `json:"email_addresses"`
	// IncludeUnverified also matches unverified addresses (use for DSAR /
	// rights fulfilment).
	IncludeUnverified bool `json:"include_unverified,omitempty"`
	// IncludeDeleted also matches soft-deleted users.
	IncludeDeleted bool `json:"include_deleted,omitempty"`
}

// UserEmailMatch is one resolved address.
type UserEmailMatch struct {
	EmailAddress string `json:"email_address"`
	UserID       string `json:"user_id"`
	Verified     bool   `json:"verified"`
	// Deleted is set when the match is a soft-deleted user (IncludeDeleted).
	Deleted bool `json:"deleted,omitempty"`
}

// ByEmails resolves a batch of email addresses to user ids.
// POST /v1/users/by_emails.
func (s *UsersService) ByEmails(ctx context.Context, params UsersByEmailsParams, opts ...RequestOption) (*ListPage[UserEmailMatch], error) {
	out := &ListPage[UserEmailMatch]{}
	return out, s.client.post(ctx, "/v1/users/by_emails", params, out, opts...)
}

// ResolvedIdentity is a provider identity on a ResolvedUser.
type ResolvedIdentity struct {
	Provider       string  `json:"provider"`
	ProviderUserID string  `json:"provider_user_id"`
	Email          *string `json:"email"`
}

// ResolvedUser is a flat identity view of a user.
type ResolvedUser struct {
	Object        string             `json:"object"`
	UserID        string             `json:"user_id"`
	Email         *string            `json:"email"`
	EmailVerified bool               `json:"email_verified"`
	Name          *string            `json:"name"`
	ImageURL      *string            `json:"image_url"`
	Identities    []ResolvedIdentity `json:"identities"`
}

// Resolved returns a flat identity for a user: the real primary email, name,
// image and linked provider identities. GET /v1/users/:id/resolved.
func (s *UsersService) Resolved(ctx context.Context, id string) (*ResolvedUser, error) {
	out := &ResolvedUser{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/resolved", nil, out)
}

// UserOrganizationMembership is one organization a user belongs to.
type UserOrganizationMembership struct {
	Object           string  `json:"object"`
	OrganizationID   string  `json:"organization_id"`
	OrganizationSlug string  `json:"organization_slug"`
	Role             string  `json:"role"`
	Plan             *string `json:"plan"`
	JoinedAt         int64   `json:"joined_at"`
}

// ListOrganizationMemberships lists the organizations a user belongs to, with
// role, resolved plan and join time. GET /v1/users/:id/organization_memberships.
func (s *UsersService) ListOrganizationMemberships(ctx context.Context, id string, params ListParams) (*CursorPage[UserOrganizationMembership], error) {
	out := &CursorPage[UserOrganizationMembership]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/organization_memberships", params.values(), out)
}

// SignInEvent is one successful sign-in in a user's history.
type SignInEvent struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Method         string  `json:"method"`
	Provider       *string `json:"provider"`
	ProviderEmail  *string `json:"provider_email"`
	IP             *string `json:"ip"`
	ImpersonatedBy *string `json:"impersonated_by"`
	CreatedAt      int64   `json:"created_at"`
}

// SignInHistory returns a user's successful sign-ins, newest first.
// GET /v1/users/:id/sign_in_history.
func (s *UsersService) SignInHistory(ctx context.Context, id string, params ListParams) (*CursorPage[SignInEvent], error) {
	out := &CursorPage[SignInEvent]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/sign_in_history", params.values(), out)
}

// --- Identity import / removal ----------------------------------------------

// ImportIdentityParams is the body of POST /v1/users/:id/identities/import.
type ImportIdentityParams struct {
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	EmailAddress   string `json:"email_address,omitempty"`
	Verified       *bool  `json:"verified,omitempty"`
}

// ImportedIdentity is the identity created by ImportIdentity.
type ImportedIdentity struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	Provider       string  `json:"provider"`
	ProviderUserID string  `json:"provider_user_id"`
	Email          *string `json:"email"`
	EmailVerified  bool    `json:"email_verified"`
	IsPrimary      bool    `json:"is_primary"`
	HasPassword    bool    `json:"has_password"`
}

// ImportIdentity links a known provider identity to a user without an OAuth
// flow (migrations). POST /v1/users/:id/identities/import.
func (s *UsersService) ImportIdentity(ctx context.Context, id string, params ImportIdentityParams, opts ...RequestOption) (*ImportedIdentity, error) {
	out := &ImportedIdentity{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/identities/import", params, out, opts...)
}

// RemovedProviderIdentity acknowledges RemoveIdentityByProvider.
type RemovedProviderIdentity struct {
	Object   string `json:"object"`
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Removed  bool   `json:"removed"`
}

// RemoveIdentityByProvider hard-removes a provider identity from a user.
// DELETE /v1/users/:id/identities/by-provider/:provider.
func (s *UsersService) RemoveIdentityByProvider(ctx context.Context, id, provider string, opts ...RequestOption) (*RemovedProviderIdentity, error) {
	out := &RemovedProviderIdentity{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/identities/by-provider/"+url.PathEscape(provider), out, opts...)
}

// --- Directives, progression, state -----------------------------------------

// ImposeDirectiveParams is the body of POST /v1/users/:id/directives.
type ImposeDirectiveParams struct {
	// SuspendedUntil is an ISO 8601 timestamp.
	SuspendedUntil string `json:"suspended_until,omitempty"`
	ReadOnly       bool   `json:"read_only,omitempty"`
	ForcedLogout   bool   `json:"forced_logout,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// UserDirective is the result of imposing or lifting a directive.
type UserDirective struct {
	Object          string `json:"object"`
	UserID          string `json:"user_id"`
	SuspendedUntil  string `json:"suspended_until,omitempty"`
	ReadOnly        bool   `json:"read_only,omitempty"`
	ForcedLogout    bool   `json:"forced_logout,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SessionsRevoked int    `json:"sessions_revoked,omitempty"`
	Lifted          bool   `json:"lifted,omitempty"`
}

// ImposeDirective imposes a cross-property directive (suspension, read-only,
// forced logout) on a user. POST /v1/users/:id/directives.
func (s *UsersService) ImposeDirective(ctx context.Context, id string, params ImposeDirectiveParams, opts ...RequestOption) (*UserDirective, error) {
	out := &UserDirective{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/directives", params, out, opts...)
}

// LiftDirective lifts a previously imposed directive.
// DELETE /v1/users/:id/directives.
func (s *UsersService) LiftDirective(ctx context.Context, id string, opts ...RequestOption) (*UserDirective, error) {
	out := &UserDirective{}
	return out, s.client.del(ctx, "/v1/users/"+url.PathEscape(id)+"/directives", out, opts...)
}

// ProgressionEventParams is the body of POST /v1/users/:id/progression/events.
type ProgressionEventParams struct {
	Track          string  `json:"track,omitempty"`
	Amount         float64 `json:"amount"`
	Reason         string  `json:"reason"`
	IdempotencyKey string  `json:"idempotency_key"`
}

// ProgressionEvent is the result of appending a progression event.
type ProgressionEvent struct {
	Object       string `json:"object"`
	Track        string `json:"track"`
	XP           int64  `json:"xp"`
	Level        int    `json:"level"`
	LevelChanged bool   `json:"level_changed"`
	Delta        int64  `json:"delta"`
}

// AppendProgressionEvent appends an idempotent progression (XP) event.
// POST /v1/users/:id/progression/events.
func (s *UsersService) AppendProgressionEvent(ctx context.Context, id string, params ProgressionEventParams, opts ...RequestOption) (*ProgressionEvent, error) {
	out := &ProgressionEvent{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/progression/events", params, out, opts...)
}

// ProgressionTrack is one track's standing.
type ProgressionTrack struct {
	XP    int64 `json:"xp"`
	Level int   `json:"level"`
}

// UserStateAttributes carries progression (keyed by track), tier and flair.
type UserStateAttributes struct {
	Progression map[string]ProgressionTrack `json:"progression"`
	Tier        interface{}                 `json:"tier,omitempty"`
	Flair       interface{}                 `json:"flair,omitempty"`
}

// UserState is a user's portable state.
type UserState struct {
	Object       string              `json:"object"`
	Attributes   UserStateAttributes `json:"attributes"`
	Entitlements []interface{}       `json:"entitlements"`
	Directives   []interface{}       `json:"directives"`
	Roles        []interface{}       `json:"roles"`
}

// State reads a user's portable state. GET /v1/users/:id/state.
func (s *UsersService) State(ctx context.Context, id string) (*UserState, error) {
	out := &UserState{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/state", nil, out)
}

// --- Consents ----------------------------------------------------------------

// UserConsent is one recorded consent.
type UserConsent struct {
	Object    string      `json:"object"`
	ID        string      `json:"id"`
	Policy    string      `json:"policy"`
	Version   string      `json:"version"`
	Status    string      `json:"status"`
	Source    *string     `json:"source"`
	Metadata  interface{} `json:"metadata,omitempty"`
	CreatedAt int64       `json:"created_at"`
	// Policy acceptance evidence (nil on records made outside a policy flow).
	PolicyVersionID *string `json:"policy_version_id,omitempty"`
	ContentSHA256   *string `json:"content_sha256,omitempty"`
	Display         *string `json:"display,omitempty"`
	ScrolledToEnd   *bool   `json:"scrolled_to_end,omitempty"`
	ViewMS          *int64  `json:"view_ms,omitempty"`
	Locale          *string `json:"locale,omitempty"`
}

// RecordConsentParams is the body of POST /v1/users/:id/consents.
type RecordConsentParams struct {
	Policy  string `json:"policy"`
	Version string `json:"version"`
	// Status is "accepted" (default) or "withdrawn".
	Status   string      `json:"status,omitempty"`
	Source   string      `json:"source,omitempty"`
	Metadata interface{} `json:"metadata,omitempty"`
	// Policy acceptance evidence: the exact version (must be that version of
	// that policy); ContentSHA256 must equal the version's content_sha256.
	PolicyVersionID string `json:"policy_version_id,omitempty"`
	ContentSHA256   string `json:"content_sha256,omitempty"`
	Display         string `json:"display,omitempty"`
	ScrolledToEnd   *bool  `json:"scrolled_to_end,omitempty"`
	ViewMS          *int64 `json:"view_ms,omitempty"`
	Locale          string `json:"locale,omitempty"`
}

// RecordConsent records a versioned consent grant or withdrawal.
// POST /v1/users/:id/consents.
func (s *UsersService) RecordConsent(ctx context.Context, id string, params RecordConsentParams, opts ...RequestOption) (*UserConsent, error) {
	out := &UserConsent{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/consents", params, out, opts...)
}

// ListConsents lists a user's recorded consents. GET /v1/users/:id/consents.
func (s *UsersService) ListConsents(ctx context.Context, id string) (*ListPage[UserConsent], error) {
	out := &ListPage[UserConsent]{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/consents", nil, out)
}

// --- Graceful deletion and erasure --------------------------------------------

// ScheduleDeletionParams is the body of POST /v1/users/:id/deletion.
type ScheduleDeletionParams struct {
	// GraceSeconds is the cancellation window; 0 uses the instance default.
	GraceSeconds int64 `json:"grace_seconds,omitempty"`
}

// ScheduleDeletion schedules a graceful deletion with a cancellation window.
// POST /v1/users/:id/deletion.
func (s *UsersService) ScheduleDeletion(ctx context.Context, id string, params ScheduleDeletionParams, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/deletion", params, out, opts...)
}

// CancelDeletion cancels a scheduled deletion inside its grace window.
// POST /v1/users/:id/deletion/cancel.
func (s *UsersService) CancelDeletion(ctx context.Context, id string, opts ...RequestOption) (*User, error) {
	out := &User{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/deletion/cancel", nil, out, opts...)
}

// FinalizeDeletion finalizes a scheduled deletion whose window has lapsed.
// POST /v1/users/:id/deletion/finalize.
func (s *UsersService) FinalizeDeletion(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/deletion/finalize", nil, out, opts...)
}

// ErasureAckParams is the body of POST /v1/users/:id/erasure_acks.
type ErasureAckParams struct {
	// Source is the acknowledging app or system.
	Source string `json:"source"`
	// Payload is the app's contributed data for the erasure export.
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// ErasureAck is a recorded acknowledgement.
type ErasureAck struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"created_at"`
}

// AcknowledgeErasure records that an integrating app purged its copy of the
// user's data, optionally contributing a payload to the erasure export.
// POST /v1/users/:id/erasure_acks.
func (s *UsersService) AcknowledgeErasure(ctx context.Context, id string, params ErasureAckParams, opts ...RequestOption) (*ErasureAck, error) {
	out := &ErasureAck{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/erasure_acks", params, out, opts...)
}

// ErasureContribution is one app's contributed blob.
type ErasureContribution struct {
	Source        string      `json:"source"`
	ContributedAt int64       `json:"contributed_at"`
	Payload       interface{} `json:"payload"`
}

// ErasureExport is the aggregated erasure export.
type ErasureExport struct {
	Object           string                 `json:"object"`
	FormatVersion    int                    `json:"format_version"`
	GeneratedAt      int64                  `json:"generated_at"`
	UserID           string                 `json:"user_id"`
	Atlas            map[string]interface{} `json:"atlas"`
	AppContributions []ErasureContribution  `json:"app_contributions"`
}

// ErasureExport returns Atlas's data about the user plus every app's
// contribution. GET /v1/users/:id/erasure_export.
func (s *UsersService) ErasureExport(ctx context.Context, id string) (*ErasureExport, error) {
	out := &ErasureExport{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/erasure_export", nil, out)
}

// --- Transaction approvals ------------------------------------------------------

// CreateApprovalRequestParams is the body of POST /v1/users/:id/approval_requests.
type CreateApprovalRequestParams struct {
	Description string            `json:"description"`
	Context     map[string]string `json:"context,omitempty"`
}

// ApprovalRequest is a number-matching transaction approval.
type ApprovalRequest struct {
	Object             string            `json:"object"`
	ID                 string            `json:"id"`
	Status             string            `json:"status"`
	MatchNumber        string            `json:"match_number,omitempty"`
	Description        string            `json:"description,omitempty"`
	Context            map[string]string `json:"context,omitempty"`
	ApprovedByDeviceID *string           `json:"approved_by_device_id,omitempty"`
	CreatedAt          int64             `json:"created_at,omitempty"`
	ExpiresAt          int64             `json:"expires_at"`
	ResolvedAt         *int64            `json:"resolved_at,omitempty"`
}

// RequestApproval pushes an "approve this action" prompt to the user's devices.
// Display the returned MatchNumber to the user. POST /v1/users/:id/approval_requests.
func (s *UsersService) RequestApproval(ctx context.Context, id string, params CreateApprovalRequestParams, opts ...RequestOption) (*ApprovalRequest, error) {
	out := &ApprovalRequest{}
	return out, s.client.post(ctx, "/v1/users/"+url.PathEscape(id)+"/approval_requests", params, out, opts...)
}

// GetApproval polls an approval request.
// GET /v1/users/:id/approval_requests/:approvalId.
func (s *UsersService) GetApproval(ctx context.Context, id, approvalID string) (*ApprovalRequest, error) {
	out := &ApprovalRequest{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/approval_requests/"+url.PathEscape(approvalID), nil, out)
}

// --- Notification preferences ------------------------------------------------

// NotificationPreference is one category toggle.
type NotificationPreference struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Enabled  bool   `json:"enabled"`
	Optional bool   `json:"optional"`
}

// NotificationPreferences is a user's security-notification preferences.
type NotificationPreferences struct {
	Object      string                   `json:"object"`
	Preferences []NotificationPreference `json:"preferences"`
}

// GetNotificationPreferences reads a user's notification preferences.
// GET /v1/users/:id/notification_preferences.
func (s *UsersService) GetNotificationPreferences(ctx context.Context, id string) (*NotificationPreferences, error) {
	out := &NotificationPreferences{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(id)+"/notification_preferences", nil, out)
}

// UpdateNotificationPreferences changes the listed categories (category →
// enabled). PATCH /v1/users/:id/notification_preferences.
func (s *UsersService) UpdateNotificationPreferences(ctx context.Context, id string, preferences map[string]bool, opts ...RequestOption) (*NotificationPreferences, error) {
	out := &NotificationPreferences{}
	body := map[string]interface{}{"preferences": preferences}
	return out, s.client.patch(ctx, "/v1/users/"+url.PathEscape(id)+"/notification_preferences", body, out, opts...)
}
