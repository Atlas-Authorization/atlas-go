package atlas

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Partner link requests (protocol atlas.partner_link_request.v1): a partner
// asks an instance for a link instead of the owner pasting a key. The owner
// approves or denies in the dashboard, or with PartnerLinks.Requests, and Atlas
// delivers the credentials to the partner's callback URL, signed with the
// request's secret. The owner never sees the secret.

// PartnerLinkRequestProtocol is the protocol id on requests and deliveries.
const PartnerLinkRequestProtocol = "atlas.partner_link_request.v1"

// PartnerLinkRequest is a partner asking this instance (Direction inbound), or
// Atlas asking a partner (outbound).
type PartnerLinkRequest struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Direction is inbound or outbound.
	Direction string   `json:"direction"`
	Partner   string   `json:"partner"`
	Name      string   `json:"name"`
	Preset    bool     `json:"preset"`
	Resource  *string  `json:"resource"`
	Scopes    []string `json:"scopes"`
	// CallbackURL is where Atlas delivers the credentials (inbound requests).
	CallbackURL      *string  `json:"callback_url"`
	CallbackHost     *string  `json:"callback_host"`
	CertFingerprints []string `json:"cert_fingerprints"`
	// Status is pending, approved, denied, expired, delivery_failed,
	// installed or failed.
	Status           string  `json:"status"`
	LinkID           *string `json:"link_id"`
	RemoteRequestID  *string `json:"remote_request_id"`
	DecidedBy        *string `json:"decided_by"`
	DecidedAt        *int64  `json:"decided_at"`
	DeliveryAttempts int     `json:"delivery_attempts"`
	DeliveredAt      *int64  `json:"delivered_at"`
	LastError        *string `json:"last_error"`
	ExpiresAt        int64   `json:"expires_at"`
	CreatedAt        int64   `json:"created_at"`
	// Note is set on the answer to an outbound request.
	Note string `json:"note,omitempty"`
}

// PartnerLinkRequestApproval is the answer to approving a request.
type PartnerLinkRequestApproval struct {
	PartnerLinkRequest
	// Delivered says whether the credentials reached the partner's callback.
	Delivered bool         `json:"delivered"`
	Link      *PartnerLink `json:"link"`
}

// ListPartnerLinkRequestsParams filters GET /v1/partner_links/requests.
type ListPartnerLinkRequestsParams struct {
	// Direction is inbound or outbound ("" = both).
	Direction string
	// Status filters by status (pending, approved, ...).
	Status []string
}

// ApprovePartnerLinkRequestParams is the body of approving a request.
type ApprovePartnerLinkRequestParams struct {
	// Scopes may narrow the request, never widen it (nil = as requested).
	Scopes []string `json:"scopes,omitempty"`
	// ExpiresAt is unix ms.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// PartnerLinkRequestsService is /v1/partner_links/requests.
type PartnerLinkRequestsService struct{ client *Client }

// List returns the requests. GET /v1/partner_links/requests.
func (s *PartnerLinkRequestsService) List(ctx context.Context, params ListPartnerLinkRequestsParams) (*ListPage[PartnerLinkRequest], error) {
	q := url.Values{}
	if params.Direction != "" {
		q.Set("direction", params.Direction)
	}
	if len(params.Status) > 0 {
		q.Set("status", strings.Join(params.Status, ","))
	}
	out := &ListPage[PartnerLinkRequest]{}
	return out, s.client.get(ctx, "/v1/partner_links/requests", q, out)
}

// Get returns one request. GET /v1/partner_links/requests/:id.
func (s *PartnerLinkRequestsService) Get(ctx context.Context, id string) (*PartnerLinkRequest, error) {
	out := &PartnerLinkRequest{}
	return out, s.client.get(ctx, "/v1/partner_links/requests/"+url.PathEscape(id), nil, out)
}

// Approve creates the link and delivers its credentials to the partner's
// callback, signed. POST /v1/partner_links/requests/:id/approve.
func (s *PartnerLinkRequestsService) Approve(ctx context.Context, id string, params ApprovePartnerLinkRequestParams, opts ...RequestOption) (*PartnerLinkRequestApproval, error) {
	out := &PartnerLinkRequestApproval{}
	return out, s.client.post(ctx, "/v1/partner_links/requests/"+url.PathEscape(id)+"/approve", params, out, opts...)
}

// Deny refuses the request (the denial is delivered to the partner too).
// POST /v1/partner_links/requests/:id/deny.
func (s *PartnerLinkRequestsService) Deny(ctx context.Context, id string, opts ...RequestOption) (*PartnerLinkRequest, error) {
	out := &PartnerLinkRequest{}
	return out, s.client.post(ctx, "/v1/partner_links/requests/"+url.PathEscape(id)+"/deny", nil, out, opts...)
}

// RequestOutboundPartnerLinkParams is the body of asking a partner for a link.
type RequestOutboundPartnerLinkParams struct {
	Scopes   []string `json:"scopes"`
	Resource string   `json:"resource,omitempty"`
	// BaseURL and TokenURL are required for a partner that is not a preset.
	BaseURL  string `json:"base_url,omitempty"`
	TokenURL string `json:"token_url,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Request asks a partner for a link; its credentials arrive by themselves once
// the partner approves. POST /v1/partner_links/outbound/:partner/request.
func (s *OutboundPartnerLinksService) Request(ctx context.Context, partner string, params RequestOutboundPartnerLinkParams, opts ...RequestOption) (*PartnerLinkRequest, error) {
	out := &PartnerLinkRequest{}
	return out, s.client.post(ctx, "/v1/partner_links/outbound/"+url.PathEscape(partner)+"/request", params, out, opts...)
}

// ---- the partner product's side ----------------------------------------------

// PartnerLinkRequestInput is what a partner product sends to ask an instance
// for a link.
type PartnerLinkRequestInput struct {
	// Partner is your product id (lowercase, 2-40 characters).
	Partner string `json:"partner"`
	Name    string `json:"name,omitempty"`
	// Resource is the Atlas instance: its ins_… id or publishable key.
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes"`
	// CallbackURL is where Atlas delivers the credentials (https).
	CallbackURL string `json:"callback_url"`
	State       string `json:"state,omitempty"`
	// CertFingerprints asks for a certificate-locked (mTLS) link.
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
}

// PartnerLinkRequestCreated is the answer to RequestPartnerLink.
type PartnerLinkRequestCreated struct {
	Object   string   `json:"object"`
	Protocol string   `json:"protocol"`
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes"`
	// RequestSecret verifies the delivery and reads the request. Shown once:
	// keep it.
	RequestSecret string `json:"request_secret"`
	ExpiresAt     int64  `json:"expires_at"`
}

// PartnerLinkDelivery is what Atlas POSTs to the callback once the owner
// decides: Object is partner_link.credentials (the credential fields are set)
// or partner_link.denied.
type PartnerLinkDelivery struct {
	Object           string   `json:"object"`
	Protocol         string   `json:"protocol"`
	RequestID        string   `json:"request_id"`
	State            *string  `json:"state"`
	Partner          string   `json:"partner"`
	InstanceID       string   `json:"instance_id"`
	Resource         string   `json:"resource,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	TokenEndpoint    string   `json:"token_endpoint,omitempty"`
	APIBaseURL       string   `json:"api_base_url,omitempty"`
	AuthMethods      []string `json:"auth_methods,omitempty"`
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
	ExpiresAt        *int64   `json:"expires_at,omitempty"`
	IssuedAt         int64    `json:"issued_at"`
}

// PartnerLinkRequestOptions tunes the partner-side calls.
type PartnerLinkRequestOptions struct {
	// BaseURL is the Atlas API origin (default DefaultBaseURL).
	BaseURL string
	// HTTPClient overrides the default client (10 s timeout).
	HTTPClient *http.Client
}

func (o *PartnerLinkRequestOptions) resolve() (string, *http.Client) {
	base, client := DefaultBaseURL, (*http.Client)(nil)
	if o != nil {
		if o.BaseURL != "" {
			base = o.BaseURL
		}
		client = o.HTTPClient
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return strings.TrimRight(base, "/"), client
}

func partnerRequestDo(ctx context.Context, client *http.Client, method, target string, headers map[string]string, body []byte, out interface{}) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return parseError(res.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}

// RequestPartnerLink is for a PARTNER product: ask an Atlas instance for a link
// (no Atlas credential needed). The owner approves it; the credentials then
// arrive at CallbackURL, signed with the returned RequestSecret (check them with
// VerifyPartnerLinkDelivery). POST /v1/partner_link_requests.
func RequestPartnerLink(ctx context.Context, input PartnerLinkRequestInput, opts *PartnerLinkRequestOptions) (*PartnerLinkRequestCreated, error) {
	base, client := opts.resolve()
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out := &PartnerLinkRequestCreated{}
	return out, partnerRequestDo(ctx, client, http.MethodPost, base+"/v1/partner_link_requests", map[string]string{"Content-Type": "application/json"}, body, out)
}

// GetPartnerLinkRequest is for a PARTNER product: read the status of a request
// it made, authenticating with the request secret.
// GET /v1/partner_link_requests/:id.
func GetPartnerLinkRequest(ctx context.Context, id, requestSecret string, opts *PartnerLinkRequestOptions) (*PartnerLinkRequest, error) {
	base, client := opts.resolve()
	out := &PartnerLinkRequest{}
	return out, partnerRequestDo(ctx, client, http.MethodGet, base+"/v1/partner_link_requests/"+url.PathEscape(id), map[string]string{"Authorization": "Bearer " + requestSecret}, nil, out)
}

// VerifyPartnerLinkDelivery is for a PARTNER product: verify and parse the
// credentials (or denial) Atlas delivered to your callback. requestSecret is the
// request's secret. Pass callbackURL (your callback URL) to also accept the
// URL-bound v2 signature.
func VerifyPartnerLinkDelivery(body []byte, header http.Header, requestSecret, callbackURL string, opts *WebhookVerifyOptions) (*PartnerLinkDelivery, error) {
	var err error
	if callbackURL != "" {
		_, err = VerifyWebhookURL(body, header, requestSecret, callbackURL, false, opts)
	} else {
		_, err = VerifyWebhook(body, header, requestSecret, opts)
	}
	if err != nil {
		return nil, err
	}
	out := &PartnerLinkDelivery{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, err
	}
	return out, nil
}
