package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// VCService is the vc resource.
type VCService struct {
	client               *Client
	CredentialTypes      *VCCredentialTypesService
	Credentials          *VCCredentialsService
	PresentationRequests *VCPresentationRequestsService
}

// CreateOffer: Create a wallet offer for a user (pre-authorized code flow). The response carries
// the code once, as an openid-credential-offer:// link.
// POST /v1/vc/offers.
func (s *VCService) CreateOffer(ctx context.Context, params VCCreateOfferParams, opts ...RequestOption) (*VCCreateOfferResult, error) {
	out := &VCCreateOfferResult{}
	return out, s.client.do(ctx, "POST", "/v1/vc/offers", nil, params, out, opts...)
}

// VCCredentialTypesService is the vc credentialTypes group of VCService.
type VCCredentialTypesService struct {
	client *Client
}

// List: List the credential types you issue.
// GET /v1/vc/credential_types.
func (s *VCCredentialTypesService) List(ctx context.Context, params ListParams) (*CursorPage[VCCredentialTypesListItem], error) {
	out := &CursorPage[VCCredentialTypesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/vc/credential_types", params.values(), nil, out)
}

// Create: Define a credential type: its vct, and how each claim is filled from a user’s
// attributes. Issued as SD-JWT VC.
// POST /v1/vc/credential_types.
func (s *VCCredentialTypesService) Create(ctx context.Context, params VCCredentialTypesCreateParams, opts ...RequestOption) (*VCCredentialTypesListItem, error) {
	out := &VCCredentialTypesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/vc/credential_types", nil, params, out, opts...)
}

// Get: Read one credential type.
// GET /v1/vc/credential_types/{id}.
func (s *VCCredentialTypesService) Get(ctx context.Context, id string) (*VCCredentialTypesListItem, error) {
	out := &VCCredentialTypesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/vc/credential_types/"+url.PathEscape(id), nil, nil, out)
}

// Delete: Delete a credential type and the records of what was issued under it.
// DELETE /v1/vc/credential_types/{id}.
func (s *VCCredentialTypesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/vc/credential_types/"+url.PathEscape(id), nil, nil, out, opts...)
}

// VCCredentialsService is the vc credentials group of VCService.
type VCCredentialsService struct {
	client *Client
}

// VCCredentialsListQuery holds the query parameters of VCCredentialsService.List.
type VCCredentialsListQuery struct {
	// Only credentials issued to this user.
	UserID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q VCCredentialsListQuery) values() url.Values {
	v := url.Values{}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List issued credentials (most recent 200), optionally for one user.
// GET /v1/vc/credentials.
func (s *VCCredentialsService) List(ctx context.Context, query VCCredentialsListQuery) (*CursorPage[VCCredentialsListItem], error) {
	out := &CursorPage[VCCredentialsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/vc/credentials", query.values(), nil, out)
}

// Revoke: Revoke an issued credential: its status-list bit is set and later presentations are
// refused.
// POST /v1/vc/credentials/{id}/revoke.
func (s *VCCredentialsService) Revoke(ctx context.Context, id string, params map[string]interface{}, opts ...RequestOption) (*VCCredentialsListItem, error) {
	out := &VCCredentialsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/vc/credentials/"+url.PathEscape(id)+"/revoke", nil, params, out, opts...)
}

// VCPresentationRequestsService is the vc presentationRequests group of VCService.
type VCPresentationRequestsService struct {
	client *Client
}

// Create: Start a verifier request for a credential type and claims. Show
// authorization_request_uri to the wallet, then read the request for the outcome.
// POST /v1/vc/presentation_requests.
func (s *VCPresentationRequestsService) Create(ctx context.Context, params VCPresentationRequestsCreateParams, opts ...RequestOption) (*VCPresentationRequestsCreateResult, error) {
	out := &VCPresentationRequestsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/vc/presentation_requests", nil, params, out, opts...)
}

// Get: Read a presentation request and its outcome.
// GET /v1/vc/presentation_requests/{id}.
func (s *VCPresentationRequestsService) Get(ctx context.Context, id string) (*VCPresentationRequestsCreateResult, error) {
	out := &VCPresentationRequestsCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/vc/presentation_requests/"+url.PathEscape(id), nil, nil, out)
}
