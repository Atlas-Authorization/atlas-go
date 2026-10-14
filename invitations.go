package atlas

import (
	"context"
	"net/url"
)

// InvitationsService is the /v1/invitations namespace.
type InvitationsService struct{ client *Client }

// Invitation is an instance-level invitation.
type Invitation struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	EmailAddress   string   `json:"email_address"`
	Status         string   `json:"status"`
	PublicMetadata Metadata `json:"public_metadata"`
	ExpiresAt      int64    `json:"expires_at"`
	AcceptedAt     *int64   `json:"accepted_at"`
	CreatedAt      int64    `json:"created_at"`
}

// CreateInvitationParams is the body of POST /v1/invitations.
type CreateInvitationParams struct {
	EmailAddress   string   `json:"email_address"`
	PublicMetadata Metadata `json:"public_metadata,omitempty"`
}

// List returns one cursor page of invitations. GET /v1/invitations.
func (s *InvitationsService) List(ctx context.Context, params ListParams) (*CursorPage[Invitation], error) {
	out := &CursorPage[Invitation]{}
	return out, s.client.get(ctx, "/v1/invitations", params.values(), out)
}

// Create issues an invitation. POST /v1/invitations.
func (s *InvitationsService) Create(ctx context.Context, params CreateInvitationParams, opts ...RequestOption) (*Invitation, error) {
	out := &Invitation{}
	return out, s.client.post(ctx, "/v1/invitations", params, out, opts...)
}

// Revoke revokes an invitation. POST /v1/invitations/:id/revoke.
func (s *InvitationsService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*Invitation, error) {
	out := &Invitation{}
	return out, s.client.post(ctx, "/v1/invitations/"+url.PathEscape(id)+"/revoke", nil, out, opts...)
}

// BulkError is one rejected entry of a bulk create: its index in the request,
// the address, and a stable error code.
type BulkError struct {
	Index        int     `json:"index"`
	EmailAddress *string `json:"email_address"`
	Code         string  `json:"code"`
	Message      string  `json:"message"`
}

// BulkInvitationsResponse lists the invitations created and the per-entry
// errors.
type BulkInvitationsResponse struct {
	Object string       `json:"object"`
	Data   []Invitation `json:"data"`
	Errors []BulkError  `json:"errors"`
}

// CreateBulk creates up to 100 invitations; invalid or duplicate entries are
// reported in Errors without failing the rest. POST /v1/invitations/bulk.
func (s *InvitationsService) CreateBulk(ctx context.Context, invitations []CreateInvitationParams, opts ...RequestOption) (*BulkInvitationsResponse, error) {
	out := &BulkInvitationsResponse{}
	body := map[string]interface{}{"invitations": invitations}
	return out, s.client.post(ctx, "/v1/invitations/bulk", body, out, opts...)
}
