package atlas

import (
	"context"
	"net/url"
)

// MessagingService is the /v1/messaging_providers namespace — use your own email
// or SMS provider. A provider secret is write-only; a response reports only which
// secret keys are set (SecretsSet).
//
// Prefer the typed SetEmailProvider / SetSMSProvider with a per-transport config
// struct (ResendConfig, SMTPConfig, TwilioConfig, ...): each struct carries exactly
// the keys the API accepts for that transport. Fields marked "Required on first
// setup" must be sent the first time you configure a transport (or switch to it).
// On an update of the SAME transport, an omitted (empty) field keeps its stored
// value — including a stored secret — so a from-address change need not re-send
// the API key.
type MessagingService struct{ client *Client }

// MessagingProvider is one configured channel provider, secrets omitted.
type MessagingProvider struct {
	Object      string                 `json:"object"`
	Channel     string                 `json:"channel"`
	Transport   string                 `json:"transport"`
	FromAddress *string                `json:"from_address"`
	Status      string                 `json:"status"`
	Config      map[string]interface{} `json:"config"`
	SecretsSet  map[string]bool        `json:"secrets_set"`
	UpdatedAt   int64                  `json:"updated_at"`
}

// MessagingProviders is the instance's configured email and SMS providers.
type MessagingProviders struct {
	Object string             `json:"object"`
	Email  *MessagingProvider `json:"email"`
	SMS    *MessagingProvider `json:"sms"`
}

// MessagingProviderInput is the untyped body of a provider set. Config carries
// the write-only secret keys on write. The API refuses any config key the
// transport does not use; prefer SetEmailProvider / SetSMSProvider with a typed
// config struct.
type MessagingProviderInput struct {
	Transport   string                 `json:"transport"`
	FromAddress string                 `json:"from_address,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// MessagingTestResult acknowledges a test send.
type MessagingTestResult struct {
	Object  string `json:"object"`
	Channel string `json:"channel"`
	SentTo  string `json:"sent_to"`
	OK      bool   `json:"ok"`
}

// DeletedMessagingProvider acknowledges a channel deletion.
type DeletedMessagingProvider struct {
	Object  string `json:"object"`
	Channel string `json:"channel"`
	Deleted bool   `json:"deleted"`
}

// Get returns the configured email and SMS providers, secrets omitted.
// GET /v1/messaging_providers.
func (s *MessagingService) Get(ctx context.Context) (*MessagingProviders, error) {
	out := &MessagingProviders{}
	return out, s.client.get(ctx, "/v1/messaging_providers", nil, out)
}

// SetEmail configures the email provider. PUT /v1/messaging_providers/email.
func (s *MessagingService) SetEmail(ctx context.Context, params MessagingProviderInput, opts ...RequestOption) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	return out, s.client.put(ctx, "/v1/messaging_providers/email", params, out, opts...)
}

// SetSMS configures the SMS provider. PUT /v1/messaging_providers/sms.
func (s *MessagingService) SetSMS(ctx context.Context, params MessagingProviderInput, opts ...RequestOption) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	return out, s.client.put(ctx, "/v1/messaging_providers/sms", params, out, opts...)
}

// DeleteMessagingProviderParams are the options of DeleteChannelWithParams.
type DeleteMessagingProviderParams struct {
	// Force removes the email provider even while email-dependent features are
	// on and nothing else would deliver email (sent as ?force=true).
	Force bool
}

// DeleteChannel removes a channel's provider config.
// DELETE /v1/messaging_providers/:channel.
//
// Removing the email provider is refused with 409 EMAIL_PROVIDER_IN_USE
// (ErrCodeEmailProviderInUse) while nothing else would deliver email; the
// error's Meta["features"] lists the email-dependent features that are on
// (for example "emailCode", "emailLink", "emailVerification",
// "passwordReset"). Use DeleteChannelWithParams with Force to remove it anyway.
func (s *MessagingService) DeleteChannel(ctx context.Context, channel string, opts ...RequestOption) (*DeletedMessagingProvider, error) {
	return s.DeleteChannelWithParams(ctx, channel, DeleteMessagingProviderParams{}, opts...)
}

// DeleteChannelWithParams is DeleteChannel with options. Force sends
// ?force=true, removing the email provider even when the API would otherwise
// refuse with 409 EMAIL_PROVIDER_IN_USE.
// DELETE /v1/messaging_providers/:channel.
func (s *MessagingService) DeleteChannelWithParams(ctx context.Context, channel string, params DeleteMessagingProviderParams, opts ...RequestOption) (*DeletedMessagingProvider, error) {
	q := url.Values{}
	if params.Force {
		q.Set("force", "true")
	}
	out := &DeletedMessagingProvider{}
	return out, s.client.delQ(ctx, "/v1/messaging_providers/"+url.PathEscape(channel), q, out, opts...)
}

// Test sends a fixed, clearly-marked test message through the channel.
// POST /v1/messaging_providers/:channel/test.
func (s *MessagingService) Test(ctx context.Context, channel, to string, opts ...RequestOption) (*MessagingTestResult, error) {
	out := &MessagingTestResult{}
	body := map[string]string{"to": to}
	return out, s.client.post(ctx, "/v1/messaging_providers/"+url.PathEscape(channel)+"/test", body, out, opts...)
}
