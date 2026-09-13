package atlas

import (
	"context"
	"net/url"
)

// SSOOnboardingService is the /v1/sso_onboarding_* namespace — self-service SSO
// onboarding (WorkOS Admin Portal / Auth0 self-service-profiles model).
type SSOOnboardingService struct{ client *Client }

// SSOOnboardingProfile fixes which protocols an end-customer may configure.
type SSOOnboardingProfile struct {
	Object                 string   `json:"object"`
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	AllowedConnectionTypes []string `json:"allowed_connection_types"`
	OrganizationID         *string  `json:"organization_id"`
	CompanyName            *string  `json:"company_name"`
	AllowSCIM              bool     `json:"allow_scim"`
	CreatedAt              int64    `json:"created_at"`
	UpdatedAt              int64    `json:"updated_at"`
}

// SSOOnboardingTicket is a one-time, expiring ticket for a specific org.
type SSOOnboardingTicket struct {
	Object          string  `json:"object"`
	ID              string  `json:"id"`
	ProfileID       string  `json:"profile_id"`
	OrganizationID  string  `json:"organization_id"`
	SSOConnectionID *string `json:"sso_connection_id"`
	Status          string  `json:"status"`
	ExpiresAt       int64   `json:"expires_at"`
	CreatedAt       int64   `json:"created_at"`
	CompletedAt     *int64  `json:"completed_at"`
}

// IssuedSSOOnboardingTicket adds the once-only token and hosted URL.
type IssuedSSOOnboardingTicket struct {
	SSOOnboardingTicket
	Token     string `json:"token"`
	URL       string `json:"url"`
	ExpiresIn int64  `json:"expires_in"`
}

// CreateSSOOnboardingProfileParams is the body of POST /v1/sso_onboarding_profiles.
type CreateSSOOnboardingProfileParams struct {
	Name                   string   `json:"name"`
	AllowedConnectionTypes []string `json:"allowed_connection_types,omitempty"`
	OrganizationID         *string  `json:"organization_id,omitempty"`
	CompanyName            *string  `json:"company_name,omitempty"`
	AllowSCIM              *bool    `json:"allow_scim,omitempty"`
}

// CreateSSOOnboardingTicketParams is the body of POST .../tickets.
type CreateSSOOnboardingTicketParams struct {
	OrganizationID   *string `json:"organization_id,omitempty"`
	ExpiresInSeconds *int    `json:"expires_in_seconds,omitempty"`
}

// TicketRevokeResult acknowledges a ticket revoke.
type TicketRevokeResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// List returns the onboarding profiles. GET /v1/sso_onboarding_profiles.
func (s *SSOOnboardingService) List(ctx context.Context) (*ListPage[SSOOnboardingProfile], error) {
	out := &ListPage[SSOOnboardingProfile]{}
	return out, s.client.get(ctx, "/v1/sso_onboarding_profiles", nil, out)
}

// Get returns one profile. GET /v1/sso_onboarding_profiles/:id.
func (s *SSOOnboardingService) Get(ctx context.Context, id string) (*SSOOnboardingProfile, error) {
	out := &SSOOnboardingProfile{}
	return out, s.client.get(ctx, "/v1/sso_onboarding_profiles/"+url.PathEscape(id), nil, out)
}

// Create creates a profile. POST /v1/sso_onboarding_profiles.
func (s *SSOOnboardingService) Create(ctx context.Context, params CreateSSOOnboardingProfileParams, opts ...RequestOption) (*SSOOnboardingProfile, error) {
	out := &SSOOnboardingProfile{}
	return out, s.client.post(ctx, "/v1/sso_onboarding_profiles", params, out, opts...)
}

// Delete removes a profile. DELETE /v1/sso_onboarding_profiles/:id.
func (s *SSOOnboardingService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/sso_onboarding_profiles/"+url.PathEscape(id), out)
}

// CreateTicket issues a one-time ticket for a profile. The token is returned
// once, here. POST /v1/sso_onboarding_profiles/:profileId/tickets.
func (s *SSOOnboardingService) CreateTicket(ctx context.Context, profileID string, params CreateSSOOnboardingTicketParams, opts ...RequestOption) (*IssuedSSOOnboardingTicket, error) {
	out := &IssuedSSOOnboardingTicket{}
	return out, s.client.post(ctx, "/v1/sso_onboarding_profiles/"+url.PathEscape(profileID)+"/tickets", params, out, opts...)
}

// RevokeTicket kills a still-live ticket.
// POST /v1/sso_onboarding_tickets/:ticketId/revoke.
func (s *SSOOnboardingService) RevokeTicket(ctx context.Context, ticketID string) (*TicketRevokeResult, error) {
	out := &TicketRevokeResult{}
	return out, s.client.post(ctx, "/v1/sso_onboarding_tickets/"+url.PathEscape(ticketID)+"/revoke", nil, out)
}
