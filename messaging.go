package atlas

import (
	"context"
	"net/url"
)

// MessagingService is the /v1/messaging_providers namespace — §BYOK messaging
// provider config. A provider secret is write-only; a response reports only which
// secret keys are set (SecretsSet).
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

// MessagingProviderInput is the body of a provider set. Config carries the
// write-only secret keys on write.
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
func (s *MessagingService) SetEmail(ctx context.Context, params MessagingProviderInput) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	return out, s.client.put(ctx, "/v1/messaging_providers/email", params, out)
}

// SetSMS configures the SMS provider. PUT /v1/messaging_providers/sms.
func (s *MessagingService) SetSMS(ctx context.Context, params MessagingProviderInput) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	return out, s.client.put(ctx, "/v1/messaging_providers/sms", params, out)
}

// DeleteChannel removes a channel's provider config.
// DELETE /v1/messaging_providers/:channel.
func (s *MessagingService) DeleteChannel(ctx context.Context, channel string) (*DeletedMessagingProvider, error) {
	out := &DeletedMessagingProvider{}
	return out, s.client.del(ctx, "/v1/messaging_providers/"+url.PathEscape(channel), out)
}

// Test sends a fixed, clearly-marked test message through the channel.
// POST /v1/messaging_providers/:channel/test.
func (s *MessagingService) Test(ctx context.Context, channel, to string) (*MessagingTestResult, error) {
	out := &MessagingTestResult{}
	body := map[string]string{"to": to}
	return out, s.client.post(ctx, "/v1/messaging_providers/"+url.PathEscape(channel)+"/test", body, out)
}
