package atlas

import (
	"context"
	"net/url"
)

// Billing providers an instance can sell end-user plans through. End-user
// billing runs on the instance's OWN provider account (bring your own key).
const (
	BillingProviderStripe = "stripe"
	BillingProviderPolar  = "polar"
	BillingProviderDodo   = "dodo"
	BillingProviderCreem  = "creem"
)

// BillingProvider is one provider's settings. Secrets are never returned:
// SecretsSet reports which are stored. WebhookURL is the endpoint to register
// with the provider.
type BillingProvider struct {
	Object      string            `json:"object"`
	Provider    string            `json:"provider"`
	Environment string            `json:"environment"`
	Status      string            `json:"status"`
	Config      map[string]string `json:"config"`
	SecretsSet  map[string]bool   `json:"secrets_set"`
	WebhookURL  string            `json:"webhook_url"`
	// Capabilities is what the provider supports (nil until verified).
	Capabilities   map[string]interface{} `json:"capabilities"`
	LastVerifiedAt *int64                 `json:"last_verified_at"`
	LastWebhookAt  *int64                 `json:"last_webhook_at"`
	UpdatedAt      int64                  `json:"updated_at"`
}

// SetBillingProviderParams is the body of PUT /v1/billing/providers/:provider,
// merged onto what is stored. Config keys: Stripe secret_key, webhook_secret,
// publishable_key; Polar access_token, webhook_secret; Dodo and Creem api_key,
// webhook_secret. Environment is "live" or "test" (Stripe's follows its key).
type SetBillingProviderParams struct {
	Environment string            `json:"environment,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
}

// BillingProviderTest is the result of a read-only credential check.
type BillingProviderTest struct {
	Object   string  `json:"object"`
	Provider string  `json:"provider"`
	OK       bool    `json:"ok"`
	Error    *string `json:"error"`
	Account  *string `json:"account"`
}

// BillingProviderDeleted acknowledges a credential removal.
type BillingProviderDeleted struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Deleted  bool   `json:"deleted"`
}

func billingProviderPath(provider string) string {
	return "/v1/billing/providers/" + url.PathEscape(provider)
}

// ListProviders lists the providers the instance has credentials for.
// GET /v1/billing/providers.
func (s *BillingService) ListProviders(ctx context.Context) (*CursorPage[BillingProvider], error) {
	out := &CursorPage[BillingProvider]{}
	return out, s.client.get(ctx, "/v1/billing/providers", nil, out)
}

// GetProvider reads one provider's settings. GET /v1/billing/providers/:provider.
func (s *BillingService) GetProvider(ctx context.Context, provider string) (*BillingProvider, error) {
	out := &BillingProvider{}
	return out, s.client.get(ctx, billingProviderPath(provider), nil, out)
}

// SetProvider stores the instance's own credentials for a provider (secrets
// are write-only, encrypted at rest). PUT /v1/billing/providers/:provider.
func (s *BillingService) SetProvider(ctx context.Context, provider string, params SetBillingProviderParams, opts ...RequestOption) (*BillingProvider, error) {
	out := &BillingProvider{}
	return out, s.client.put(ctx, billingProviderPath(provider), params, out, opts...)
}

// TestProvider makes one read-only call with the stored credentials.
// POST /v1/billing/providers/:provider/test.
func (s *BillingService) TestProvider(ctx context.Context, provider string, opts ...RequestOption) (*BillingProviderTest, error) {
	out := &BillingProviderTest{}
	return out, s.client.post(ctx, billingProviderPath(provider)+"/test", nil, out, opts...)
}

// DeleteProvider removes a provider's credentials. It is refused while live
// subscriptions or plans depend on it unless force is true.
// DELETE /v1/billing/providers/:provider.
func (s *BillingService) DeleteProvider(ctx context.Context, provider string, force bool, opts ...RequestOption) (*BillingProviderDeleted, error) {
	var q url.Values
	if force {
		q = url.Values{"force": {"true"}}
	}
	out := &BillingProviderDeleted{}
	return out, s.client.delQ(ctx, billingProviderPath(provider), q, out, opts...)
}

// ChangeSubscriptionParams is the body of POST /v1/billing/subscriptions/:id/change.
// Interval is "month" or "year"; SchedulePeriodEnd defers the switch to the end
// of the current period instead of prorating now.
type ChangeSubscriptionParams struct {
	PlanID            string `json:"plan_id"`
	Interval          string `json:"interval,omitempty"`
	SchedulePeriodEnd bool   `json:"schedule_at_period_end,omitempty"`
}

// ChangeSubscription switches a subscription to another plan or interval on
// the billing provider. POST /v1/billing/subscriptions/:id/change.
func (s *BillingService) ChangeSubscription(ctx context.Context, id string, params ChangeSubscriptionParams, opts ...RequestOption) (*BillingSubscription, error) {
	out := &BillingSubscription{}
	return out, s.client.post(ctx, "/v1/billing/subscriptions/"+url.PathEscape(id)+"/change", params, out, opts...)
}

// CancelSubscription cancels at the end of the current period, or now when
// immediately is true. POST /v1/billing/subscriptions/:id/cancel.
func (s *BillingService) CancelSubscription(ctx context.Context, id string, immediately bool, opts ...RequestOption) (*BillingSubscription, error) {
	body := map[string]bool{}
	if immediately {
		body["immediately"] = true
	}
	out := &BillingSubscription{}
	return out, s.client.post(ctx, "/v1/billing/subscriptions/"+url.PathEscape(id)+"/cancel", body, out, opts...)
}

// RestoreSubscription undoes a cancellation scheduled for the period end.
// POST /v1/billing/subscriptions/:id/restore.
func (s *BillingService) RestoreSubscription(ctx context.Context, id string, opts ...RequestOption) (*BillingSubscription, error) {
	out := &BillingSubscription{}
	return out, s.client.post(ctx, "/v1/billing/subscriptions/"+url.PathEscape(id)+"/restore", nil, out, opts...)
}
