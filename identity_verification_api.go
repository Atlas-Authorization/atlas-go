package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// IdentityVerificationService is the identityVerification resource.
type IdentityVerificationService struct {
	client *Client
}

// Settings: Whether identity verification is on, and which connector does the checking.
// GET /v1/identity_verification/settings.
func (s *IdentityVerificationService) Settings(ctx context.Context) (*IdentityVerificationSettingsResult, error) {
	out := &IdentityVerificationSettingsResult{}
	return out, s.client.do(ctx, "GET", "/v1/identity_verification/settings", nil, nil, out)
}

// UpdateSettings: Turn identity verification on or off and choose the connector (a Persona,
// Onfido, Veriff or Stripe Identity service connector; its credentials stay in the vault).
// `as_challenge` offers a verified identity as the custom second step of sign-in (the custom
// challenge factor must be enabled).
// PUT /v1/identity_verification/settings.
func (s *IdentityVerificationService) UpdateSettings(ctx context.Context, params IdentityVerificationUpdateSettingsParams, opts ...RequestOption) (*IdentityVerificationSettingsResult, error) {
	out := &IdentityVerificationSettingsResult{}
	return out, s.client.do(ctx, "PUT", "/v1/identity_verification/settings", nil, params, out, opts...)
}

// IdentityVerificationListQuery holds the query parameters of IdentityVerificationService.List.
type IdentityVerificationListQuery struct {
	// Only checks in this state. Defaults to needs_review.
	Status string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IdentityVerificationListQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List checks by status (default `needs_review`, the review queue), newest first.
// GET /v1/identity_verifications.
func (s *IdentityVerificationService) List(ctx context.Context, query IdentityVerificationListQuery) (*CursorPage[IdentityVerificationListItem], error) {
	out := &CursorPage[IdentityVerificationListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/identity_verifications", query.values(), nil, out)
}

// Get: Read one check. A pending check is refreshed from the verification service first.
// GET /v1/identity_verifications/{id}.
func (s *IdentityVerificationService) Get(ctx context.Context, id string) (*IdentityVerificationListItem, error) {
	out := &IdentityVerificationListItem{}
	return out, s.client.do(ctx, "GET", "/v1/identity_verifications/"+url.PathEscape(id), nil, nil, out)
}

// Decide: Decide a check that is waiting for review (or override a pending one) as `approved` or
// `declined`. The outcome is written to the user as `verification.identity`. 409 when the check is
// already approved or declined.
// POST /v1/identity_verifications/{id}/decide.
func (s *IdentityVerificationService) Decide(ctx context.Context, id string, params IdentityVerificationDecideParams, opts ...RequestOption) (*IdentityVerificationListItem, error) {
	out := &IdentityVerificationListItem{}
	return out, s.client.do(ctx, "POST", "/v1/identity_verifications/"+url.PathEscape(id)+"/decide", nil, params, out, opts...)
}

// ForUser: A user's identity checks, newest first.
// GET /v1/users/{id}/identity_verifications.
func (s *IdentityVerificationService) ForUser(ctx context.Context, id string, params ListParams) (*CursorPage[IdentityVerificationListItem], error) {
	out := &CursorPage[IdentityVerificationListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/identity_verifications", params.values(), nil, out)
}

// Start: Start an identity check for a user and get the verification service's hosted page (`url`)
// to send them to. A check started in the last 30 minutes and still pending is returned instead of
// a new one; at most 5 checks per user per hour. 409 when identity verification is not turned on.
// POST /v1/users/{id}/identity_verifications.
func (s *IdentityVerificationService) Start(ctx context.Context, id string, params IdentityVerificationStartParams, opts ...RequestOption) (*IdentityVerificationListItem, error) {
	out := &IdentityVerificationListItem{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/identity_verifications", nil, params, out, opts...)
}
