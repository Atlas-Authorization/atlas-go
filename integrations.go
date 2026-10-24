package atlas

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

// Identity integrations: any service that verifies a user with an Atlas-minted
// JWT, a preset (chatly, forumulate, cookiemunch, referalli) or a custom one.
// The claims of an integration token follow
// https://atlasauth.net/schemas/suite-token-v1.json.

// IntegrationReceiverHealth is a receiver's health, in the webhook health
// vocabulary.
type IntegrationReceiverHealth struct {
	URL        string  `json:"url"`
	EndpointID *string `json:"endpoint_id"`
	// State is healthy, failing, disabled or unknown.
	State               string              `json:"state"`
	FailingSince        *int64              `json:"failing_since"`
	DisabledAt          *int64              `json:"disabled_at"`
	LastSuccessAt       *int64              `json:"last_success_at"`
	LastFailure         *WebhookLastFailure `json:"last_failure"`
	ConsecutiveFailures int                 `json:"consecutive_failures"`
	SuccessRate24h      *float64            `json:"success_rate_24h"`
	Events              []string            `json:"events,omitempty"`
}

// IntegrationCMP is the consent-manager block of an integration.
type IntegrationCMP struct {
	ScriptURL      string   `json:"script_url"`
	ScriptID       *string  `json:"script_id"`
	SiteID         *string  `json:"site_id"`
	BlockingMode   *string  `json:"blocking_mode"`
	ExtraOrigins   []string `json:"extra_origins"`
	SettingsPreset *string  `json:"settings_preset"`
}

// IntegrationAtlasIDIssuer is the Sign in with Atlas issuer an integration trusts.
type IntegrationAtlasIDIssuer struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url"`
}

// IntegrationLastVerifyError is the latest token an integration refused.
type IntegrationLastVerifyError struct {
	Error      string  `json:"error"`
	Audience   *string `json:"audience"`
	At         int64   `json:"at"`
	ReportedAt int64   `json:"reported_at"`
}

// IntegrationHealth is an integration's mint, verify and receiver health.
type IntegrationHealth struct {
	LastMintedAt      *int64                      `json:"last_minted_at"`
	Mints24h          int                         `json:"mints_24h"`
	VerifyErrors24h   int                         `json:"verify_errors_24h"`
	LastVerifyError   *IntegrationLastVerifyError `json:"last_verify_error"`
	Events            *IntegrationReceiverHealth  `json:"events"`
	BackchannelLogout *IntegrationReceiverHealth  `json:"backchannel_logout"`
}

// Integration is an identity integration. Enabled=false, Connected=false when
// it was never connected. Preset-specific fields (chatly: channel, template;
// forumulate: org_id, spaces; cookiemunch: site_id; referalli: org_id) are
// read from Raw.
type Integration struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Product is the same value as ID.
	Product string `json:"product"`
	// Preset is chatly, forumulate, cookiemunch, referalli or nil (custom).
	Preset *string `json:"preset"`
	Name   string  `json:"name,omitempty"`
	// Role is support_chat, docs_community, consent, referrals or other.
	Role           string  `json:"role,omitempty"`
	Enabled        bool    `json:"enabled"`
	Connected      bool    `json:"connected"`
	Audience       string  `json:"audience,omitempty"`
	AudienceFormat *string `json:"audience_format,omitempty"`
	// PrincipalClaim is audience_hint or nil.
	PrincipalClaim *string `json:"principal_claim,omitempty"`
	// ExtClaim is external_id or nil.
	ExtClaim                    *string                   `json:"ext_claim,omitempty"`
	TTLSeconds                  int                       `json:"ttl_seconds,omitempty"`
	Issuer                      string                    `json:"issuer,omitempty"`
	JWKSURL                     string                    `json:"jwks_url,omitempty"`
	TokenSchema                 string                    `json:"token_schema,omitempty"`
	EventsURL                   *string                   `json:"events_url,omitempty"`
	EventsURLDefault            bool                      `json:"events_url_default,omitempty"`
	Events                      []string                  `json:"events,omitempty"`
	BackchannelLogoutURL        *string                   `json:"backchannel_logout_url,omitempty"`
	BackchannelLogoutURLDefault bool                      `json:"backchannel_logout_url_default,omitempty"`
	VerifyErrorReportURL        *string                   `json:"verify_error_report_url,omitempty"`
	CMP                         *IntegrationCMP           `json:"cmp,omitempty"`
	AtlasIDUsers                bool                      `json:"atlas_id_users,omitempty"`
	AtlasIDIssuer               *IntegrationAtlasIDIssuer `json:"atlas_id_issuer,omitempty"`
	ExternalRef                 *string                   `json:"external_ref,omitempty"`
	EnabledAt                   *int64                    `json:"enabled_at,omitempty"`
	UpdatedAt                   *int64                    `json:"updated_at,omitempty"`
	// DryRun is present on a ?dry_run=true answer.
	DryRun bool               `json:"dry_run,omitempty"`
	Health *IntegrationHealth `json:"health,omitempty"`
	// Raw is the whole response object, including the preset-specific fields.
	Raw map[string]interface{} `json:"-"`
}

// UnmarshalJSON decodes the typed fields and keeps the full object in Raw.
func (i *Integration) UnmarshalJSON(b []byte) error {
	type plain Integration
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*i = Integration(p)
	raw := map[string]interface{}{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	i.Raw = raw
	return nil
}

// IntegrationSpace is a Forumulate space in an integration body.
type IntegrationSpace struct {
	ID        string `json:"id"`
	RedeemURL string `json:"redeem_url,omitempty"`
}

// IntegrationCMPParams is the cmp block of SetIntegrationParams.
type IntegrationCMPParams struct {
	ScriptURL    string   `json:"script_url"`
	ScriptID     string   `json:"script_id,omitempty"`
	SiteID       string   `json:"site_id,omitempty"`
	BlockingMode string   `json:"blocking_mode,omitempty"`
	ExtraOrigins []string `json:"extra_origins,omitempty"`
	// SettingsPreset is cookiemunch, cookiebot, onetrust or custom.
	SettingsPreset string `json:"settings_preset,omitempty"`
}

// SetIntegrationParams is the body of PUT /v1/instance/integrations/:id.
// Clear names nullable fields to send as null: events_url,
// backchannel_logout_url, verify_error_report_url, cmp, audience_format,
// principal_claim, ext_claim, external_ref.
type SetIntegrationParams struct {
	Enabled *bool `json:"enabled,omitempty"`
	// Audience is "<preset>:<id>" for a preset; any value for a custom one.
	Audience string `json:"audience,omitempty"`
	// Name is the display name (required for a custom integration).
	Name           string `json:"name,omitempty"`
	Role           string `json:"role,omitempty"`
	AudienceFormat string `json:"audience_format,omitempty"`
	PrincipalClaim string `json:"principal_claim,omitempty"`
	ExtClaim       string `json:"ext_claim,omitempty"`
	// TTLSeconds is 10-120 (default 120).
	TTLSeconds           int                   `json:"ttl_seconds,omitempty"`
	EventsURL            string                `json:"events_url,omitempty"`
	BackchannelLogoutURL string                `json:"backchannel_logout_url,omitempty"`
	VerifyErrorReportURL string                `json:"verify_error_report_url,omitempty"`
	CMP                  *IntegrationCMPParams `json:"cmp,omitempty"`
	AtlasIDUsers         *bool                 `json:"atlas_id_users,omitempty"`
	ExternalRef          string                `json:"external_ref,omitempty"`
	// Channel (chatly), OrgID and Spaces (forumulate) are preset fields.
	Channel string             `json:"channel,omitempty"`
	OrgID   string             `json:"org_id,omitempty"`
	Spaces  []IntegrationSpace `json:"spaces,omitempty"`
	Clear   []string           `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p SetIntegrationParams) MarshalJSON() ([]byte, error) {
	type plain SetIntegrationParams
	return marshalWithExtra(plain(p), nullKeys(p.Clear))
}

// IntegrationDelivery is one event or back-channel logout delivery to an
// integration's receiver.
type IntegrationDelivery struct {
	Object string `json:"object"`
	// Kind is event or backchannel_logout.
	Kind        string  `json:"kind"`
	Integration string  `json:"integration"`
	ID          string  `json:"id"`
	URL         string  `json:"url"`
	EventID     string  `json:"event_id,omitempty"`
	EventType   *string `json:"event_type,omitempty"`
	Sid         *string `json:"sid,omitempty"`
	TraceID     *string `json:"trace_id"`
	// Status is pending, success or failed.
	Status        string  `json:"status"`
	AttemptNumber int     `json:"attempt_number"`
	HTTPStatus    *int    `json:"http_status"`
	Error         *string `json:"error"`
	CreatedAt     int64   `json:"created_at"`
}

// ListIntegrationDeliveriesParams filters an integration's deliveries.
type ListIntegrationDeliveriesParams struct {
	Limit int
	// Trace finds one operation by its trace id.
	Trace string
	// Kind is event or backchannel_logout.
	Kind string
}

func (p ListIntegrationDeliveriesParams) values() url.Values {
	v := url.Values{}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Trace != "" {
		v.Set("trace", p.Trace)
	}
	if p.Kind != "" {
		v.Set("kind", p.Kind)
	}
	return v
}

// IntegrationEventsSecret reveals an event receiver's signing secret.
type IntegrationEventsSecret struct {
	Object      string `json:"object"`
	Integration string `json:"integration"`
	EndpointID  string `json:"endpoint_id"`
	URL         string `json:"url"`
	Secret      string `json:"secret"`
}

// IntegrationToken is an identity-integration token; its claims follow
// /schemas/suite-token-v1.json.
type IntegrationToken struct {
	Object      string `json:"object"`
	Integration string `json:"integration"`
	Product     string `json:"product"`
	JWT         string `json:"jwt"`
	// ExpiresIn is seconds until the token expires (at most 120).
	ExpiresIn int    `json:"expires_in"`
	Audience  string `json:"audience"`
	OrgID     string `json:"org_id,omitempty"`
	SpaceID   string `json:"space_id,omitempty"`
	RedeemURL string `json:"redeem_url,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	JWKSURI   string `json:"jwks_uri,omitempty"`
}

// ListIntegrations returns every integration (the presets, connected or not,
// and every custom one) with its health. GET /v1/instance/integrations.
func (s *InstanceService) ListIntegrations(ctx context.Context) (*ListPage[Integration], error) {
	out := &ListPage[Integration]{}
	return out, s.client.get(ctx, "/v1/instance/integrations", nil, out)
}

// GetIntegration returns one integration. GET /v1/instance/integrations/:id.
func (s *InstanceService) GetIntegration(ctx context.Context, id string) (*Integration, error) {
	out := &Integration{}
	return out, s.client.get(ctx, "/v1/instance/integrations/"+url.PathEscape(id), nil, out)
}

// SetIntegration connects or replaces an integration. Pass WithDryRun to
// validate and save nothing. PUT /v1/instance/integrations/:id.
func (s *InstanceService) SetIntegration(ctx context.Context, id string, params SetIntegrationParams, opts ...RequestOption) (*Integration, error) {
	out := &Integration{}
	return out, s.client.put(ctx, "/v1/instance/integrations/"+url.PathEscape(id), params, out, opts...)
}

// DeleteIntegration disconnects an integration.
// DELETE /v1/instance/integrations/:id.
func (s *InstanceService) DeleteIntegration(ctx context.Context, id string, opts ...RequestOption) (*Integration, error) {
	out := &Integration{}
	return out, s.client.del(ctx, "/v1/instance/integrations/"+url.PathEscape(id), out, opts...)
}

// IntegrationDeliveries returns event and back-channel logout deliveries,
// newest first. GET /v1/instance/integrations/:id/deliveries.
func (s *InstanceService) IntegrationDeliveries(ctx context.Context, id string, params ListIntegrationDeliveriesParams) (*ListPage[IntegrationDelivery], error) {
	out := &ListPage[IntegrationDelivery]{}
	return out, s.client.get(ctx, "/v1/instance/integrations/"+url.PathEscape(id)+"/deliveries", params.values(), out)
}

// RevealIntegrationEventsSecret reveals the event receiver's signing secret
// (audited). POST /v1/instance/integrations/:id/events_secret.
func (s *InstanceService) RevealIntegrationEventsSecret(ctx context.Context, id string, opts ...RequestOption) (*IntegrationEventsSecret, error) {
	out := &IntegrationEventsSecret{}
	return out, s.client.post(ctx, "/v1/instance/integrations/"+url.PathEscape(id)+"/events_secret", nil, out, opts...)
}

// IntegrationAtlasIDToken mints an integration token for a Sign in with Atlas
// user from their Atlas ID access token.
// POST /v1/instance/integrations/:id/atlas_id_tokens.
func (s *InstanceService) IntegrationAtlasIDToken(ctx context.Context, id, accessToken string, opts ...RequestOption) (*IntegrationToken, error) {
	out := &IntegrationToken{}
	body := map[string]string{"access_token": accessToken}
	return out, s.client.post(ctx, "/v1/instance/integrations/"+url.PathEscape(id)+"/atlas_id_tokens", body, out, opts...)
}

// GetIntegrationToken mints an identity-integration token for this session,
// the Go form of getToken({ for }): a preset such as chatly, or a custom
// integration id. POST /v1/sessions/:id/integration_tokens/:integration.
func (s *SessionsService) GetIntegrationToken(ctx context.Context, id, integration string, opts ...RequestOption) (*IntegrationToken, error) {
	out := &IntegrationToken{}
	return out, s.client.post(ctx, "/v1/sessions/"+url.PathEscape(id)+"/integration_tokens/"+url.PathEscape(integration), nil, out, opts...)
}

// ---- integration-facing routes -----------------------------------------------

// IntegrationsService is /v1/integrations/*: the routes an integrated service
// calls with the instance secret key (or the partner link the instance owner
// granted it).
type IntegrationsService struct{ client *Client }

// Verify error codes an integration can report.
const (
	IntegrationVerifyAudMismatch    = "aud_mismatch"
	IntegrationVerifyExpired        = "expired"
	IntegrationVerifyBadSignature   = "bad_signature"
	IntegrationVerifyUnknownKid     = "unknown_kid"
	IntegrationVerifySessionRevoked = "session_revoked"
	IntegrationVerifyInvalidClaims  = "invalid_claims"
	IntegrationVerifyOther          = "other"
)

// ReportVerifyErrorParams is the body of POST /v1/integrations/verify_errors.
type ReportVerifyErrorParams struct {
	// Integration is the id the token was minted for.
	Integration string `json:"integration"`
	// Error is one of the IntegrationVerify* codes.
	Error    string `json:"error"`
	Audience string `json:"audience,omitempty"`
	// At is epoch ms (default now).
	At     int64  `json:"at,omitempty"`
	Kid    string `json:"kid,omitempty"`
	Sid    string `json:"sid,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// IntegrationVerifyError is a recorded verify error.
type IntegrationVerifyError struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Integration string  `json:"integration"`
	Audience    *string `json:"audience"`
	Error       string  `json:"error"`
	At          int64   `json:"at"`
	TraceID     *string `json:"trace_id"`
	CreatedAt   int64   `json:"created_at"`
}

// IntegrationCardOrg is an organization in the agent-sidebar card.
type IntegrationCardOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// IntegrationCardUser is the user in the agent-sidebar card.
type IntegrationCardUser struct {
	ID            string               `json:"id"`
	Email         *string              `json:"email"`
	EmailVerified bool                 `json:"email_verified"`
	Name          *string              `json:"name"`
	ExternalID    *string              `json:"external_id"`
	Banned        bool                 `json:"banned"`
	MFAEnabled    bool                 `json:"mfa_enabled"`
	LastSignInAt  *int64               `json:"last_sign_in_at"`
	CreatedAt     int64                `json:"created_at"`
	Organizations []IntegrationCardOrg `json:"organizations"`
}

// IntegrationCardAction is an action offered on the card.
type IntegrationCardAction struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Confirm       bool   `json:"confirm"`
	Available     bool   `json:"available"`
	RequiresScope string `json:"requires_scope"`
}

// IntegrationCard is the agent-sidebar card for a user.
type IntegrationCard struct {
	Object         string                  `json:"object"`
	Integration    string                  `json:"integration"`
	User           IntegrationCardUser     `json:"user"`
	SessionsActive int                     `json:"sessions_active"`
	Actions        []IntegrationCardAction `json:"actions"`
}

// IntegrationCardActionResult is the answer to a card action.
type IntegrationCardActionResult struct {
	Object          string `json:"object"`
	Integration     string `json:"integration"`
	Action          string `json:"action"`
	OK              bool   `json:"ok"`
	SessionsRevoked int    `json:"sessions_revoked"`
}

// IntegrationAgent says which support agent ran a card action (audited).
type IntegrationAgent struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// InstanceIssuer is an issuer an instance trusts (or trusted).
type InstanceIssuer struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
	// Kind is instance or atlas_id (trusted issuers only).
	Kind string `json:"kind,omitempty"`
	// ReplacedAt is when a previous issuer was replaced (epoch ms).
	ReplacedAt int64 `json:"replaced_at,omitempty"`
}

// InstanceIntegrationMeta is one integration in the public instance metadata.
type InstanceIntegrationMeta struct {
	Audience          string   `json:"audience"`
	Preset            *string  `json:"preset"`
	TTLSeconds        int      `json:"ttl_seconds"`
	AdditionalIssuers []string `json:"additional_issuers,omitempty"`
}

// InstanceMetadata is the public metadata of an instance.
type InstanceMetadata struct {
	Object          string                             `json:"object"`
	ID              string                             `json:"id"`
	Issuer          string                             `json:"issuer"`
	JWKSURI         string                             `json:"jwks_uri"`
	TokenSchema     string                             `json:"token_schema"`
	Integrations    map[string]InstanceIntegrationMeta `json:"integrations"`
	TrustedIssuers  []InstanceIssuer                   `json:"trusted_issuers"`
	PreviousIssuers []InstanceIssuer                   `json:"previous_issuers"`
}

// ReportVerifyError records a token an integrated service refused.
// POST /v1/integrations/verify_errors.
func (s *IntegrationsService) ReportVerifyError(ctx context.Context, params ReportVerifyErrorParams, opts ...RequestOption) (*IntegrationVerifyError, error) {
	out := &IntegrationVerifyError{}
	return out, s.client.post(ctx, "/v1/integrations/verify_errors", params, out, opts...)
}

// Card returns the agent-sidebar card for a user (by token sub, and iss when
// the user is not on this instance's issuer).
// GET /v1/integrations/:integration/card.
func (s *IntegrationsService) Card(ctx context.Context, integration, sub, iss string) (*IntegrationCard, error) {
	out := &IntegrationCard{}
	q := url.Values{"sub": {sub}}
	if iss != "" {
		q.Set("iss", iss)
	}
	return out, s.client.get(ctx, "/v1/integrations/"+url.PathEscape(integration)+"/card", q, out)
}

// RevokeSessions signs the user out everywhere, audited with the agent.
// POST /v1/integrations/:integration/card/actions/revoke_sessions.
func (s *IntegrationsService) RevokeSessions(ctx context.Context, integration, sub, iss string, agent *IntegrationAgent, opts ...RequestOption) (*IntegrationCardActionResult, error) {
	out := &IntegrationCardActionResult{}
	body := map[string]interface{}{"sub": sub}
	if iss != "" {
		body["iss"] = iss
	}
	if agent != nil {
		body["agent"] = agent
	}
	return out, s.client.post(ctx, "/v1/integrations/"+url.PathEscape(integration)+"/card/actions/revoke_sessions", body, out, opts...)
}

// InstanceMetadata reads the public metadata of an instance (no key needed).
// GET /v1/public/instances/:id.
func (s *IntegrationsService) InstanceMetadata(ctx context.Context, instanceID string) (*InstanceMetadata, error) {
	out := &InstanceMetadata{}
	return out, s.client.get(ctx, "/v1/public/instances/"+url.PathEscape(instanceID), nil, out)
}
