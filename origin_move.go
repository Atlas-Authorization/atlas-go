package atlas

import (
	"context"
	"net/url"
)

// ── Origin moves, instance connections and integrations ─────────────────────

// OriginMoveParams is the body of POST /v1/instance/move_origin and of the
// Sign in with Atlas app twin. From and To are scheme://host[:port] origins.
type OriginMoveParams struct {
	From string `json:"from"`
	To   string `json:"to"`
	// DryRun reports the diff and any problems and writes nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// OriginMoveChange is one field that moves (or moved). Before and After are a
// URL, a list of URLs, or nil.
type OriginMoveChange struct {
	// Object is instance, oauth_client, atlas_id_app, webhook_endpoint or
	// redirect_url.
	Object string      `json:"object"`
	ID     string      `json:"id"`
	Field  string      `json:"field"`
	Before interface{} `json:"before"`
	After  interface{} `json:"after"`
}

// OriginMoveProblem is a rewritten value the field would refuse.
type OriginMoveProblem struct {
	Object  string `json:"object,omitempty"`
	ID      string `json:"id,omitempty"`
	Field   string `json:"field,omitempty"`
	URL     string `json:"url,omitempty"`
	Message string `json:"message,omitempty"`
}

// OriginMove is the before → after diff of an origin move. A repeated run
// returns no changes; a real run with problems is a 422 and writes nothing.
type OriginMove struct {
	Object string `json:"object"`
	From   string `json:"from"`
	To     string `json:"to"`
	DryRun bool   `json:"dry_run"`
	// Applied is true when this run wrote changes.
	Applied  bool                `json:"applied"`
	Changes  []OriginMoveChange  `json:"changes"`
	Problems []OriginMoveProblem `json:"problems"`
	// App is the Sign in with Atlas app after the move (platform twin only).
	App map[string]interface{} `json:"app,omitempty"`
}

// MoveOrigin rewrites every URL that points at From to To (a domain move),
// across the instance, its OAuth clients, webhooks, redirect URLs and Sign in
// with Atlas apps. POST /v1/instance/move_origin.
func (s *InstanceService) MoveOrigin(ctx context.Context, params OriginMoveParams, opts ...RequestOption) (*OriginMove, error) {
	out := &OriginMove{}
	return out, s.client.post(ctx, "/v1/instance/move_origin", params, out, opts...)
}

// InstanceConnection is one link from the instance to another platform and its
// health.
type InstanceConnection struct {
	Object string `json:"object"`
	// Kind is privacy_webhook, cmp, atlas_id_app or jwt_template.
	Kind  string `json:"kind"`
	Check string `json:"check"`
	OK    bool   `json:"ok"`
	// Severity is error, warning or info.
	Severity      string                 `json:"severity"`
	Subject       map[string]string      `json:"subject"`
	FixHint       *string                `json:"fix_hint"`
	LastCheckedAt int64                  `json:"last_checked_at"`
	Details       map[string]interface{} `json:"details"`
}

// InstanceConnections is the list of the instance's links to other platforms.
type InstanceConnections struct {
	Object string `json:"object"`
	// OK is false when any warning- or error-severity row is not ok.
	OK        bool                 `json:"ok"`
	CheckedAt int64                `json:"checked_at"`
	Data      []InstanceConnection `json:"data"`
}

// Connections returns the instance's links to other platforms and their
// health. Read-only. GET /v1/instance/connections.
func (s *InstanceService) Connections(ctx context.Context) (*InstanceConnections, error) {
	out := &InstanceConnections{}
	return out, s.client.get(ctx, "/v1/instance/connections", nil, out)
}

// ChatlyIntegration is the Chatly connection (Enabled false and nothing else
// when none is set).
type ChatlyIntegration struct {
	Object  string `json:"object"`
	Enabled bool   `json:"enabled"`
	Channel string `json:"channel,omitempty"`
	// Template is the name to pass to getToken({ template: 'chatly' }).
	Template string `json:"template,omitempty"`
	// Audience is chatly:<channel>.
	Audience             string            `json:"audience,omitempty"`
	Issuer               string            `json:"issuer,omitempty"`
	JWKSURL              string            `json:"jwks_url,omitempty"`
	TokenTTLSeconds      int               `json:"token_ttl_seconds,omitempty"`
	IdentityVerification map[string]string `json:"identity_verification,omitempty"`
}

// SetChatlyIntegrationParams is the body of PUT /v1/instance/integrations/chatly.
type SetChatlyIntegrationParams struct {
	// Channel is the chat channel public id (letters, digits, _ and -).
	Channel string `json:"channel"`
}

// ChatlyIntegration reads the Chatly connection.
// GET /v1/instance/integrations/chatly.
func (s *InstanceService) ChatlyIntegration(ctx context.Context) (*ChatlyIntegration, error) {
	out := &ChatlyIntegration{}
	return out, s.client.get(ctx, "/v1/instance/integrations/chatly", nil, out)
}

// SetChatlyIntegration connects a Chatly channel.
// PUT /v1/instance/integrations/chatly.
func (s *InstanceService) SetChatlyIntegration(ctx context.Context, params SetChatlyIntegrationParams, opts ...RequestOption) (*ChatlyIntegration, error) {
	out := &ChatlyIntegration{}
	return out, s.client.put(ctx, "/v1/instance/integrations/chatly", params, out, opts...)
}

// DeleteChatlyIntegration removes the Chatly connection.
// DELETE /v1/instance/integrations/chatly.
func (s *InstanceService) DeleteChatlyIntegration(ctx context.Context, opts ...RequestOption) (*ChatlyIntegration, error) {
	out := &ChatlyIntegration{}
	return out, s.client.del(ctx, "/v1/instance/integrations/chatly", out, opts...)
}

// ForumulateSpace is a connected space and where readers redeem tokens.
type ForumulateSpace struct {
	ID        string `json:"id"`
	RedeemURL string `json:"redeem_url,omitempty"`
}

// ForumulateIntegration is the Forumulate connection (Enabled false and nothing
// else when none is set).
type ForumulateIntegration struct {
	Object          string            `json:"object"`
	Enabled         bool              `json:"enabled"`
	OrgID           string            `json:"org_id,omitempty"`
	Spaces          []ForumulateSpace `json:"spaces,omitempty"`
	Audience        string            `json:"audience,omitempty"`
	Issuer          string            `json:"issuer,omitempty"`
	JWKSURL         string            `json:"jwks_url,omitempty"`
	TokenTTLSeconds int               `json:"token_ttl_seconds,omitempty"`
	// ReaderAuthProvider is the external_jwt provider to store on each space.
	ReaderAuthProvider map[string]interface{} `json:"reader_auth_provider,omitempty"`
}

// SetForumulateIntegrationParams is the body of
// PUT /v1/instance/integrations/forumulate. It replaces the whole connection.
type SetForumulateIntegrationParams struct {
	OrgID string `json:"org_id"`
	// Spaces are 1-50 spaces; RedeemURL is optional on each.
	Spaces []ForumulateSpace `json:"spaces"`
	// Audience is the token aud; default forumulate:<org_id>.
	Audience string `json:"audience,omitempty"`
}

// ForumulateIntegration reads the Forumulate connection.
// GET /v1/instance/integrations/forumulate.
func (s *InstanceService) ForumulateIntegration(ctx context.Context) (*ForumulateIntegration, error) {
	out := &ForumulateIntegration{}
	return out, s.client.get(ctx, "/v1/instance/integrations/forumulate", nil, out)
}

// SetForumulateIntegration connects Forumulate spaces.
// PUT /v1/instance/integrations/forumulate.
func (s *InstanceService) SetForumulateIntegration(ctx context.Context, params SetForumulateIntegrationParams, opts ...RequestOption) (*ForumulateIntegration, error) {
	out := &ForumulateIntegration{}
	return out, s.client.put(ctx, "/v1/instance/integrations/forumulate", params, out, opts...)
}

// DeleteForumulateIntegration removes the Forumulate connection.
// DELETE /v1/instance/integrations/forumulate.
func (s *InstanceService) DeleteForumulateIntegration(ctx context.Context, opts ...RequestOption) (*ForumulateIntegration, error) {
	out := &ForumulateIntegration{}
	return out, s.client.del(ctx, "/v1/instance/integrations/forumulate", out, opts...)
}

// ── Managed email ───────────────────────────────────────────────────────────

// ManagedEmailRecord is a DNS record to publish for the managed sending domain.
type ManagedEmailRecord struct {
	// Purpose is dkim, spf, return_path, ownership, dmarc or other.
	Purpose string `json:"purpose"`
	// Type is TXT, MX or CNAME.
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority *int   `json:"priority,omitempty"`
	Status   string `json:"status,omitempty"`
}

// ManagedEmail is managed email: Atlas sets your sending domain up on your own
// Resend or Brevo account and sends through your key. Email sends only once
// Verified.
type ManagedEmail struct {
	Object      string `json:"object"`
	ID          string `json:"id"`
	FromAddress string `json:"from_address"`
	Domain      string `json:"domain"`
	Provider    string `json:"provider"`
	// Backend is the email service the domain lives on: resend or brevo.
	Backend string `json:"backend,omitempty"`
	// ProviderID is your email provider (mode managed_domain) that holds the key.
	ProviderID *string `json:"provider_id,omitempty"`
	// FeedbackWebhook is, on a Brevo create, registered or not_registered.
	FeedbackWebhook string  `json:"feedback_webhook,omitempty"`
	Region          *string `json:"region"`
	// Status is not_started, pending, verified, failed or temporary_failure.
	Status   string               `json:"status"`
	Verified bool                 `json:"verified"`
	Records  []ManagedEmailRecord `json:"records"`
	// Limits is null now (no Atlas sending limits apply; your provider
	// account's do), so it reads as zero. Servers before 2026-10 sent it.
	Limits struct {
		Hourly int `json:"hourly"`
		Daily  int `json:"daily"`
	} `json:"limits"`
	Usage struct {
		Sent            int    `json:"sent"`
		Bounces         int    `json:"bounces"`
		Complaints      int    `json:"complaints"`
		LastBounceAt    *int64 `json:"last_bounce_at"`
		LastComplaintAt *int64 `json:"last_complaint_at"`
	} `json:"usage"`
	// Reputation is your_provider_account.
	Reputation string `json:"reputation"`
	// DNS is the DNS automation (the token is never returned), or nil.
	DNS           *CustomDomainDNS `json:"dns"`
	FailureReason *string          `json:"failure_reason"`
	LastCheckedAt *int64           `json:"last_checked_at"`
	VerifiedAt    *int64           `json:"verified_at"`
	CreatedAt     int64            `json:"created_at"`
	UpdatedAt     int64            `json:"updated_at"`
	// DNSResult is set on create with DNS: the zone and the records written.
	DNSResult map[string]interface{} `json:"dns_result,omitempty"`
	NextStep  string                 `json:"next_step,omitempty"`
}

// CreateManagedEmailParams is the body of POST /v1/messaging_providers/email/managed.
type CreateManagedEmailParams struct {
	// FromAddress is bare or "Name <address>"; its domain is the sending domain.
	FromAddress string `json:"from_address"`
	// Transport is your own provider account Atlas sets the domain up on:
	// resend or brevo. Send it with Config, unless ProviderID is given.
	Transport string `json:"transport,omitempty"`
	// Config carries your provider API key (write-only).
	Config *ManagedEmailProviderKey `json:"config,omitempty"`
	// ProviderID is, instead of Transport + Config, your configured Resend or
	// Brevo email provider.
	ProviderID string `json:"provider_id,omitempty"`
	// Region is us-east-1, eu-west-1, sa-east-1 or ap-northeast-1 (Resend only).
	Region string `json:"region,omitempty"`
	// DNS has Atlas write the records itself (the token is write-only).
	DNS *CustomDomainDNSParams `json:"dns,omitempty"`
}

// ManagedEmailProviderKey is the provider API key managed email uses.
type ManagedEmailProviderKey struct {
	// APIKey is your Resend (re_...) or Brevo (xkeysib-...) API key, with
	// domain permissions. Write-only.
	APIKey string `json:"api_key"`
}

// DeletedManagedEmail acknowledges removing managed email.
type DeletedManagedEmail struct {
	Object  string `json:"object"`
	Domain  string `json:"domain"`
	Deleted bool   `json:"deleted"`
	// ProviderRemoved says whether the email provider that held the key (mode
	// managed_domain) was removed too.
	ProviderRemoved bool `json:"provider_removed,omitempty"`
}

// DevelopmentEmail is your own email provider in development mode: a
// development instance sends Atlas's sign-in emails without a verified domain.
type DevelopmentEmail struct {
	Object     string `json:"object"`
	ProviderID string `json:"provider_id"`
	Enabled    bool   `json:"enabled"`
	// Active is whether mail goes out through it now; always false on a
	// production instance.
	Active      bool    `json:"active"`
	Transport   string  `json:"transport"`
	FromAddress *string `json:"from_address"`
	// SubjectPrefix is added to every subject: "[Atlas test] ".
	SubjectPrefix string `json:"subject_prefix"`
	// Footer is the line added to the end of every message.
	Footer string `json:"footer"`
	// Templates are the only emails it sends: Atlas's own sign-in templates.
	Templates []string `json:"templates"`
	Limits    struct {
		Daily              int `json:"daily"`
		PerRecipientHourly int `json:"per_recipient_hourly"`
	} `json:"limits"`
	// Note is present for onboarding@resend.dev: Resend delivers it only to
	// your Resend account address.
	Note      string `json:"note,omitempty"`
	NextStep  string `json:"next_step,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

// EnableDevelopmentEmailParams is the body of
// POST /v1/messaging_providers/email/development: ProviderID, or Transport +
// Config exactly as SetEmail takes them.
type EnableDevelopmentEmailParams struct {
	ProviderID string `json:"provider_id,omitempty"`
	// Transport is resend, ses, smtp, brevo or mailgun.
	Transport string `json:"transport,omitempty"`
	// FromAddress is a sender your provider accepts without a verified domain
	// (default for Resend: onboarding@resend.dev).
	FromAddress string                 `json:"from_address,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// DisabledDevelopmentEmail acknowledges putting the provider back in standard mode.
type DisabledDevelopmentEmail struct {
	Object     string `json:"object"`
	Deleted    bool   `json:"deleted"`
	ProviderID string `json:"provider_id"`
	Mode       string `json:"mode"`
}

// DevelopmentEmail reads the email provider in development mode (404 when it
// is not). GET /v1/messaging_providers/email/development.
func (s *MessagingService) DevelopmentEmail(ctx context.Context) (*DevelopmentEmail, error) {
	out := &DevelopmentEmail{}
	return out, s.client.get(ctx, "/v1/messaging_providers/email/development", nil, out)
}

// EnableDevelopmentEmail puts your email provider in development mode. 409
// DEVELOPMENT_EMAIL_NOT_ALLOWED on a production instance.
// POST /v1/messaging_providers/email/development.
func (s *MessagingService) EnableDevelopmentEmail(ctx context.Context, params EnableDevelopmentEmailParams, opts ...RequestOption) (*DevelopmentEmail, error) {
	out := &DevelopmentEmail{}
	return out, s.client.post(ctx, "/v1/messaging_providers/email/development", params, out, opts...)
}

// DisableDevelopmentEmail puts the email provider back in standard mode (the
// provider and its key stay). DELETE /v1/messaging_providers/email/development.
func (s *MessagingService) DisableDevelopmentEmail(ctx context.Context, opts ...RequestOption) (*DisabledDevelopmentEmail, error) {
	out := &DisabledDevelopmentEmail{}
	return out, s.client.del(ctx, "/v1/messaging_providers/email/development", out, opts...)
}

// ManagedEmail reads the managed sending domain (404 when none).
// GET /v1/messaging_providers/email/managed.
func (s *MessagingService) ManagedEmail(ctx context.Context) (*ManagedEmail, error) {
	out := &ManagedEmail{}
	return out, s.client.get(ctx, "/v1/messaging_providers/email/managed", nil, out)
}

// CreateManagedEmail sets your sending domain up on your own Resend or Brevo
// account (Transport + Config, or ProviderID) and returns the DNS records to
// publish. POST /v1/messaging_providers/email/managed.
func (s *MessagingService) CreateManagedEmail(ctx context.Context, params CreateManagedEmailParams, opts ...RequestOption) (*ManagedEmail, error) {
	out := &ManagedEmail{}
	return out, s.client.post(ctx, "/v1/messaging_providers/email/managed", params, out, opts...)
}

// VerifyManagedEmail re-checks the DNS records now.
// POST /v1/messaging_providers/email/managed/verify.
func (s *MessagingService) VerifyManagedEmail(ctx context.Context, opts ...RequestOption) (*ManagedEmail, error) {
	out := &ManagedEmail{}
	return out, s.client.post(ctx, "/v1/messaging_providers/email/managed/verify", nil, out, opts...)
}

// DeleteManagedEmail stops using managed email (DNS records are left in
// place). Force removes it even while it is the only way to send email (else
// 409 EMAIL_PROVIDER_IN_USE). DELETE /v1/messaging_providers/email/managed.
func (s *MessagingService) DeleteManagedEmail(ctx context.Context, params DeleteMessagingProviderParams, opts ...RequestOption) (*DeletedManagedEmail, error) {
	q := url.Values{}
	if params.Force {
		q.Set("force", "true")
	}
	out := &DeletedManagedEmail{}
	return out, s.client.delQ(ctx, "/v1/messaging_providers/email/managed", q, out, opts...)
}
