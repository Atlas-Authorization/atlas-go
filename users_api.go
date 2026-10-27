package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// UsersHistoryQuery holds the query parameters of UsersService.History.
type UsersHistoryQuery struct {
	// Entries per page.
	Limit int64
	// The id of the last entry of the previous page.
	StartingAfter string
	// Only these actions, comma-separated (for example user.banned,user.locked).
	Action string
}

func (q UsersHistoryQuery) values() url.Values {
	v := url.Values{}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.Action != "" {
		v.Set("action", q.Action)
	}
	return v
}

// History: The user change history, newest first: every profile, metadata and status change (ban,
// lock, directives and their reversal) with who made it, the reason and expiry, and each changed
// field with its value before and after. A password change and private_metadata values are
// recorded as redacted (the field name only). Pages with starting_after.
// GET /v1/users/{id}/history.
func (s *UsersService) History(ctx context.Context, id string, query UsersHistoryQuery) (*CursorPage[UsersHistoryItem], error) {
	out := &CursorPage[UsersHistoryItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/history", query.values(), nil, out)
}

// MinorStatus: A user's parental-consent state (not_required for anyone at or above the age of
// digital consent) and their guardian links, newest first.
// GET /v1/users/{id}/minor_status.
func (s *UsersService) MinorStatus(ctx context.Context, id string) (*UsersMinorStatusResult, error) {
	out := &UsersMinorStatusResult{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/minor_status", nil, nil, out)
}

// AssessMinor: Re-assess a user from their date-of-birth trait now (for users created before age
// gating was turned on). 400 when compliance.minors is off.
// POST /v1/users/{id}/minor_status/assess.
func (s *UsersService) AssessMinor(ctx context.Context, id string, opts ...RequestOption) (*UsersMinorStatusResult, error) {
	out := &UsersMinorStatusResult{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/minor_status/assess", nil, nil, out, opts...)
}

// CreateLink: Mint an email-verification or password-reset link (and code) for a user WITHOUT
// sending it, for support tools and invite flows that deliver it themselves. type
// "email_verification" needs an unverified address (default: the primary); the url opens GET
// /v1/client/email_addresses/verify and the code works wherever the address is verified by code.
// type "password_reset" needs a verified address and returns the url and/or code the instance's
// password-reset setting would have mailed, plus the reset attempt_id; redeeming it is the
// ordinary reset (it still asks for the second factor and sets a new password). Single-use,
// expires_in_seconds 60 to 86400 (default 3600). Audited as user.link_generated, never with the
// secret. Treat the response as a credential. → 201.
// POST /v1/users/{id}/links.
func (s *UsersService) CreateLink(ctx context.Context, id string, params UsersCreateLinkParams, opts ...RequestOption) (*UsersCreateLinkResult, error) {
	out := &UsersCreateLinkResult{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/links", nil, params, out, opts...)
}

// ListDeviceKeys: List a user’s device keys (native biometric sign-in). Never returns key
// material.
// GET /v1/users/{id}/device_keys.
func (s *UsersService) ListDeviceKeys(ctx context.Context, id string, params ListParams) (*CursorPage[UsersListDeviceKeysItem], error) {
	out := &CursorPage[UsersListDeviceKeysItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/device_keys", params.values(), nil, out)
}

// DeleteDeviceKey: Revoke one of a user’s device keys so that device can no longer sign in. Scoped
// to the user; the account holder is notified when account-change notices are on.
// DELETE /v1/users/{id}/device_keys/{keyId}.
func (s *UsersService) DeleteDeviceKey(ctx context.Context, id string, keyID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/device_keys/"+url.PathEscape(keyID), nil, nil, out, opts...)
}

// UsersRequiredActionsService is the users requiredActions group of UsersService.
type UsersRequiredActionsService struct {
	client *Client
}

// Request: Make a user owe an action at their next sign-in, whatever the method: update_password,
// verify_email, accept_policy, configure_mfa, update_profile, or custom (sent to an https url; the
// app closes it with DELETE). The sign-in attempt holds at needs_required_action until it is done
// (configure_mfa alone routes through MFA enrollment; accept_policy is closed once the policy gate
// passes; verify_email and configure_mfa clear themselves when already true). Re-requesting an
// open action is a 200 with the same row. Emits user.required_action_requested. → 201.
// POST /v1/users/{id}/required_actions.
func (s *UsersRequiredActionsService) Request(ctx context.Context, id string, params UsersRequiredActionsRequestParams, opts ...RequestOption) (*UsersRequiredActionsRequestResult, error) {
	out := &UsersRequiredActionsRequestResult{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/required_actions", nil, params, out, opts...)
}

// List: The actions a user currently owes, oldest first.
// GET /v1/users/{id}/required_actions.
func (s *UsersRequiredActionsService) List(ctx context.Context, id string, params ListParams) (*CursorPage[UsersRequiredActionsRequestResult], error) {
	out := &CursorPage[UsersRequiredActionsRequestResult]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/required_actions", params.values(), nil, out)
}

// Clear: Withdraw an owed action. This is also how an application closes a custom action once the
// user has finished its step. Emits user.required_action_cleared. 404 when it is not open.
// DELETE /v1/users/{id}/required_actions/{rid}.
func (s *UsersRequiredActionsService) Clear(ctx context.Context, id string, rid string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/required_actions/"+url.PathEscape(rid), nil, nil, out, opts...)
}

// Bulk: Owe the same action for many users at once: every member of one organization
// (organization_id) or an explicit user_ids list, at most 5000. Users outside the instance are
// skipped, and an already-open action counts as already_open. Emits user.required_action_requested
// per newly opened action.
// POST /v1/required_actions/bulk.
func (s *UsersRequiredActionsService) Bulk(ctx context.Context, params UsersRequiredActionsBulkParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/required_actions/bulk", nil, params, nil, opts...)
}

// UsersNotesService is the users notes group of UsersService.
type UsersNotesService struct {
	client *Client
}

// List: The notes on a user: pinned notes first, then newest first.
// GET /v1/users/{id}/notes.
func (s *UsersNotesService) List(ctx context.Context, id string, params ListParams) (*CursorPage[UsersNotesListItem], error) {
	out := &CursorPage[UsersNotesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/notes", params.values(), nil, out)
}

// Create: Add a note to a user (up to 5000 characters; at most 500 notes per user). The audit log
// records that a note was added, never its text. → 201.
// POST /v1/users/{id}/notes.
func (s *UsersNotesService) Create(ctx context.Context, id string, params UsersNotesCreateParams, opts ...RequestOption) (*UsersNotesListItem, error) {
	out := &UsersNotesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/notes", nil, params, out, opts...)
}

// Update: Edit a note: its text, its pin, or both.
// PATCH /v1/users/{id}/notes/{noteId}.
func (s *UsersNotesService) Update(ctx context.Context, id string, noteID string, params UsersNotesUpdateParams, opts ...RequestOption) (*UsersNotesListItem, error) {
	out := &UsersNotesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/users/"+url.PathEscape(id)+"/notes/"+url.PathEscape(noteID), nil, params, out, opts...)
}

// Delete: Delete a note from a user. The audit log keeps that it was deleted.
// DELETE /v1/users/{id}/notes/{noteId}.
func (s *UsersNotesService) Delete(ctx context.Context, id string, noteID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/notes/"+url.PathEscape(noteID), nil, nil, out, opts...)
}

// UsersGuardiansService is the users guardians group of UsersService.
type UsersGuardiansService struct {
	client *Client
}

// Request: Ask a parent or guardian to approve a minor's account. Name them by email or by
// guardian_user_id (their address is used). Returns the pending link with a one-time consent_url
// that expires after compliance.minors.consentTtlHours. With send_email: true Atlas mails it
// through the application's own email provider (422 when none is set up); otherwise deliver
// consent_url yourself. → 201.
// POST /v1/users/{id}/guardians.
func (s *UsersGuardiansService) Request(ctx context.Context, id string, params UsersGuardiansRequestParams, opts ...RequestOption) (*UsersGuardiansRequestResult, error) {
	out := &UsersGuardiansRequestResult{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/guardians", nil, params, out, opts...)
}

// Approve: Record consent obtained another way (a signed form, a verified call): the link becomes
// active with consent_method admin and the account is consented. 409 for a revoked link.
// POST /v1/users/{id}/guardians/{linkId}/approve.
func (s *UsersGuardiansService) Approve(ctx context.Context, id string, linkID string, params UsersGuardiansApproveParams, opts ...RequestOption) (*UsersMinorStatusResultGuardiansItem, error) {
	out := &UsersMinorStatusResultGuardiansItem{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/guardians/"+url.PathEscape(linkID)+"/approve", nil, params, out, opts...)
}

// Revoke: Withdraw a guardian link. When no active guardian is left, the account needs consent
// again.
// DELETE /v1/users/{id}/guardians/{linkId}.
func (s *UsersGuardiansService) Revoke(ctx context.Context, id string, linkID string, opts ...RequestOption) (*UsersMinorStatusResultGuardiansItem, error) {
	out := &UsersMinorStatusResultGuardiansItem{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/guardians/"+url.PathEscape(linkID), nil, nil, out, opts...)
}

// UsersSearchesService is the users search group of UsersService.
type UsersSearchesService struct {
	client *Client
	Views  *UsersSearchesViewsService
}

// Query: Search users with a boolean filter tree (and/or/not) over profile columns, traits and
// metadata keys, organization and org role, MFA enrolled/strategy, sign-in strategy, last sign-in
// country or IP, and date ranges. Sort with order_by; page with starting_after (creation/update
// order) or offset (last_sign_in_at order). include_total_count adds total_count. Containment
// tests on public metadata and traits are answered by an index. Same user objects as GET
// /v1/users.
// POST /v1/users/search.
func (s *UsersSearchesService) Query(ctx context.Context, params UsersSearchQueryParams, opts ...RequestOption) (*CursorPage[UsersSearchQueryItem], error) {
	out := &CursorPage[UsersSearchQueryItem]{}
	return out, s.client.do(ctx, "POST", "/v1/users/search", nil, params, out, opts...)
}

// Export: Export every user a search matches (up to 10,000; x-export-truncated says when more
// matched) as CSV (default) or NDJSON. fields picks columns: id, primary_email, username,
// first_name, last_name, external_id, created_at, last_sign_in_at, banned, mfa_enrolled, plus
// traits.<key> / public_metadata.<path>. CSV cells that start with = + - @ are prefixed with an
// apostrophe so a spreadsheet never runs them as formulas.
// POST /v1/users/search/export.
func (s *UsersSearchesService) Export(ctx context.Context, params UsersSearchExportParams, opts ...RequestOption) error {
	return s.client.do(ctx, "POST", "/v1/users/search/export", nil, params, nil, opts...)
}

// UsersSearchesViewsService is the users search views group of UsersSearchesService.
type UsersSearchesViewsService struct {
	client *Client
}

// List: The saved user-search views of the instance, by name.
// GET /v1/users/search/views.
func (s *UsersSearchesViewsService) List(ctx context.Context, params ListParams) (*CursorPage[UsersSearchViewsListItem], error) {
	out := &CursorPage[UsersSearchViewsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/search/views", params.values(), nil, out)
}

// Create: Save a named filter (and sort) to re-run. A filter that could never run is refused; a
// duplicate name is a 400. → 201.
// POST /v1/users/search/views.
func (s *UsersSearchesViewsService) Create(ctx context.Context, params UsersSearchViewsCreateParams, opts ...RequestOption) (*UsersSearchViewsListItem, error) {
	out := &UsersSearchViewsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/users/search/views", nil, params, out, opts...)
}

// Update: Rename a saved view or change its filter or sort.
// PATCH /v1/users/search/views/{id}.
func (s *UsersSearchesViewsService) Update(ctx context.Context, id string, params UsersSearchViewsUpdateParams, opts ...RequestOption) (*UsersSearchViewsListItem, error) {
	out := &UsersSearchViewsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/users/search/views/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a saved user-search view.
// DELETE /v1/users/search/views/{id}.
func (s *UsersSearchesViewsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/search/views/"+url.PathEscape(id), nil, nil, out, opts...)
}
