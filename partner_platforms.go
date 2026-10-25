package atlas

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// Partner platforms: this instance acting as the PARTNER PLATFORM of another
// product. A product that signs its partner deliveries with a published
// Ed25519 key set delivers signed events to the instance's receiver. The
// partner registers from the registration details, and the partner token it
// hands back is stored once, encrypted, and never returned by any call.

// PartnerPlatformsService is /v1/partner_platforms.
type PartnerPlatformsService struct{ client *Client }

// PartnerPlatformRegistrationState is whether the partner registered.
type PartnerPlatformRegistrationState struct {
	// Status is unregistered or registered.
	Status       string `json:"status"`
	RegisteredAt *int64 `json:"registered_at"`
}

// PartnerPlatform is one partner platform setup. The partner token is never
// part of it: TokenSet says whether one is stored and TokenPrefix shows its
// first characters.
type PartnerPlatform struct {
	Object            string                           `json:"object"`
	ID                string                           `json:"id"`
	Partner           string                           `json:"partner"`
	Name              string                           `json:"name"`
	Preset            bool                             `json:"preset"`
	PlatformID        string                           `json:"platform_id"`
	Enabled           bool                             `json:"enabled"`
	JWKSURL           string                           `json:"jwks_url"`
	SignatureHeader   string                           `json:"signature_header"`
	SignatureScheme   string                           `json:"signature_scheme"`
	ToleranceSeconds  int                              `json:"tolerance_seconds"`
	AllowedSources    []string                         `json:"allowed_sources"`
	RecordConsents    bool                             `json:"record_consents"`
	ReceiverURL       string                           `json:"receiver_url"`
	ReceiverURLTmpl   string                           `json:"receiver_url_template"`
	ServesDeployment  bool                             `json:"serves_deployment"`
	Registration      PartnerPlatformRegistrationState `json:"registration"`
	TokenSet          bool                             `json:"token_set"`
	TokenPrefix       *string                          `json:"token_prefix"`
	LastDeliveryAt    *int64                           `json:"last_delivery_at"`
	LastDeliveryError *string                          `json:"last_delivery_error"`
	CreatedAt         int64                            `json:"created_at"`
	UpdatedAt         int64                            `json:"updated_at"`
}

// PartnerPlatformList is GET /v1/partner_platforms.
type PartnerPlatformList struct {
	ListPage[PartnerPlatform]
	// Presets are the ready-made partner profiles the instance can start from.
	Presets []map[string]interface{} `json:"presets"`
}

// SetPartnerPlatformParams is the body of PUT /v1/partner_platforms/:partner.
// A preset partner fills the defaults. Clear names nullable fields to send as
// null (name).
type SetPartnerPlatformParams struct {
	Name             string   `json:"name,omitempty"`
	PlatformID       string   `json:"platform_id,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	JWKSURL          string   `json:"jwks_url,omitempty"`
	SignatureHeader  string   `json:"signature_header,omitempty"`
	SignatureScheme  string   `json:"signature_scheme,omitempty"`
	ToleranceSeconds int      `json:"tolerance_seconds,omitempty"`
	AllowedSources   []string `json:"allowed_sources,omitempty"`
	RecordConsents   *bool    `json:"record_consents,omitempty"`
	ServesDeployment *bool    `json:"serves_deployment,omitempty"`
	Clear            []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p SetPartnerPlatformParams) MarshalJSON() ([]byte, error) {
	type plain SetPartnerPlatformParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// PartnerPlatformDeleted is the answer to Remove.
type PartnerPlatformDeleted struct {
	Object  string `json:"object"`
	Partner string `json:"partner"`
	Deleted bool   `json:"deleted"`
}

// PartnerPlatformSignature is the signature a partner must send.
type PartnerPlatformSignature struct {
	Header           string `json:"header"`
	Scheme           string `json:"scheme"`
	Format           string `json:"format"`
	JWKSURL          string `json:"jwks_url"`
	ToleranceSeconds int    `json:"tolerance_seconds"`
}

// PartnerPlatformSendTo says where to send the registration details.
type PartnerPlatformSendTo struct {
	Contact string `json:"contact"`
	Docs    string `json:"docs"`
}

// PartnerPlatformRegistration is what to hand the partner so it can register
// (the receiver URL, the signature it must use and where to send it).
type PartnerPlatformRegistration struct {
	Object                string                   `json:"object"`
	Partner               string                   `json:"partner"`
	PlatformID            string                   `json:"platform_id"`
	ReceiverURL           string                   `json:"receiver_url"`
	ReceiverURLIsTemplate bool                     `json:"receiver_url_is_template"`
	ExternalID            *string                  `json:"external_id"`
	Events                []string                 `json:"events"`
	Signature             PartnerPlatformSignature `json:"signature"`
	SendTo                *PartnerPlatformSendTo   `json:"send_to"`
	TokenPrefix           *string                  `json:"token_prefix"`
	NextStep              string                   `json:"next_step"`
}

// StorePartnerPlatformTokenParams is the body of POST
// /v1/partner_platforms/:partner/token. The token is write-only: it is stored
// encrypted, never returned, and redacted when this value is printed or
// formatted.
type StorePartnerPlatformTokenParams struct {
	// Token is the partner token the partner handed over.
	Token string `json:"token"`
	// Rotate replaces a token that is already stored.
	Rotate bool `json:"rotate,omitempty"`
	// APIBaseURL is the partner's API base, when it differs from the preset's.
	APIBaseURL string `json:"api_base_url,omitempty"`
}

// String redacts the token.
func (p StorePartnerPlatformTokenParams) String() string {
	return fmt.Sprintf("StorePartnerPlatformTokenParams{Token:[redacted] Rotate:%t APIBaseURL:%q}", p.Rotate, p.APIBaseURL)
}

// GoString redacts the token for %#v.
func (p StorePartnerPlatformTokenParams) GoString() string { return p.String() }

// PartnerDelivery is one signed delivery received from a partner.
type PartnerDelivery struct {
	Object    string  `json:"object"`
	EventID   *string `json:"event_id"`
	EventType *string `json:"event_type"`
	// Outcome is recorded, unchanged, no_subject, no_user, source_not_allowed
	// or ignored.
	Outcome    string  `json:"outcome"`
	UserID     *string `json:"user_id"`
	ReceivedAt int64   `json:"received_at"`
}

func partnerPlatformPath(partner, rest string) string {
	return "/v1/partner_platforms/" + url.PathEscape(partner) + rest
}

// List returns the partner platforms and the presets.
// GET /v1/partner_platforms.
func (s *PartnerPlatformsService) List(ctx context.Context) (*PartnerPlatformList, error) {
	out := &PartnerPlatformList{}
	return out, s.client.get(ctx, "/v1/partner_platforms", nil, out)
}

// Get returns one partner platform. GET /v1/partner_platforms/:partner.
func (s *PartnerPlatformsService) Get(ctx context.Context, partner string) (*PartnerPlatform, error) {
	out := &PartnerPlatform{}
	return out, s.client.get(ctx, partnerPlatformPath(partner, ""), nil, out)
}

// Set sets up or changes a partner platform (a preset fills the defaults).
// PUT /v1/partner_platforms/:partner.
func (s *PartnerPlatformsService) Set(ctx context.Context, partner string, params SetPartnerPlatformParams, opts ...RequestOption) (*PartnerPlatform, error) {
	out := &PartnerPlatform{}
	return out, s.client.put(ctx, partnerPlatformPath(partner, ""), params, out, opts...)
}

// Remove deletes a partner platform and its stored token.
// DELETE /v1/partner_platforms/:partner.
func (s *PartnerPlatformsService) Remove(ctx context.Context, partner string, opts ...RequestOption) (*PartnerPlatformDeleted, error) {
	out := &PartnerPlatformDeleted{}
	return out, s.client.del(ctx, partnerPlatformPath(partner, ""), out, opts...)
}

// Registration returns what to send the partner to be registered.
// GET /v1/partner_platforms/:partner/registration.
func (s *PartnerPlatformsService) Registration(ctx context.Context, partner string) (*PartnerPlatformRegistration, error) {
	out := &PartnerPlatformRegistration{}
	return out, s.client.get(ctx, partnerPlatformPath(partner, "/registration"), nil, out)
}

// StoreToken stores the partner token the partner handed over (once; Rotate
// replaces it). The answer never contains the token.
// POST /v1/partner_platforms/:partner/token.
func (s *PartnerPlatformsService) StoreToken(ctx context.Context, partner string, params StorePartnerPlatformTokenParams, opts ...RequestOption) (*PartnerPlatform, error) {
	out := &PartnerPlatform{}
	return out, s.client.post(ctx, partnerPlatformPath(partner, "/token"), params, out, opts...)
}

// Deliveries returns the latest deliveries received from the partner (limit 0
// = the default). GET /v1/partner_platforms/:partner/deliveries.
func (s *PartnerPlatformsService) Deliveries(ctx context.Context, partner string, limit int) (*ListPage[PartnerDelivery], error) {
	var q url.Values
	if limit > 0 {
		q = url.Values{"limit": {strconv.Itoa(limit)}}
	}
	out := &ListPage[PartnerDelivery]{}
	return out, s.client.get(ctx, partnerPlatformPath(partner, "/deliveries"), q, out)
}
