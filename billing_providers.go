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
	// BillingProviderChargebee sells through Chargebee (Product Catalog 2.0).
	// Config: api_key and webhook_password (secrets), site (the bare site name)
	// and webhook_username.
	BillingProviderChargebee = "chargebee"
	// BillingProviderAutumn sells and meters through Autumn. Config:
	// secret_key (am_sk_…) and webhook_secret (whsec_…).
	BillingProviderAutumn = "autumn"
	// BillingProviderCommet sells and meters through Commet. Config: api_key,
	// webhook_secret and optionally seat_feature_code.
	BillingProviderCommet = "commet"
)

// BillingProvider is one provider's settings. Secrets are never returned:
// SecretsSet reports which are stored. WebhookURL is the endpoint to register
// with the provider.
type BillingProvider struct {
	Object string `json:"object"`
	// Configured is false when the singleton has never been set (the GET
	// answers 200, no longer 404).
	Configured  *bool             `json:"configured,omitempty"`
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
// webhook_secret; Chargebee api_key, site, webhook_username + webhook_password;
// Autumn secret_key, webhook_secret; Commet api_key, webhook_secret,
// seat_feature_code. Environment is "live" or "test" (Stripe's follows its key).
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

// GetSubscription reads one subscription (a subject may hold several: a base
// plan plus add-ons). GET /v1/billing/subscriptions/:id.
func (s *BillingService) GetSubscription(ctx context.Context, id string) (*BillingSubscription, error) {
	out := &BillingSubscription{}
	return out, s.client.get(ctx, "/v1/billing/subscriptions/"+url.PathEscape(id), nil, out)
}

// SyncPlanEntitlements mirrors a plan's features and limits from its provider
// (Autumn, Commet). POST /v1/billing/plans/:id/sync_entitlements.
func (s *BillingService) SyncPlanEntitlements(ctx context.Context, planID string, opts ...RequestOption) (*BillingPlan, error) {
	out := &BillingPlan{}
	return out, s.client.post(ctx, "/v1/billing/plans/"+url.PathEscape(planID)+"/sync_entitlements", nil, out, opts...)
}

// BillingSettings say how numeric limits merge when a subject holds several
// entitling subscriptions: "max" (default) or "sum", per limit key.
type BillingSettings struct {
	Object            string            `json:"object"`
	DefaultLimitMerge string            `json:"default_limit_merge"`
	LimitMerge        map[string]string `json:"limit_merge"`
}

// UpdateBillingSettingsParams is the body of PUT /v1/billing/settings.
// LimitMerge (limit key → "max" | "sum") replaces the stored map.
type UpdateBillingSettingsParams struct {
	DefaultLimitMerge string            `json:"default_limit_merge,omitempty"`
	LimitMerge        map[string]string `json:"limit_merge,omitempty"`
}

// GetSettings reads the limit-merge policy. GET /v1/billing/settings.
func (s *BillingService) GetSettings(ctx context.Context) (*BillingSettings, error) {
	out := &BillingSettings{}
	return out, s.client.get(ctx, "/v1/billing/settings", nil, out)
}

// UpdateSettings writes the limit-merge policy. PUT /v1/billing/settings.
func (s *BillingService) UpdateSettings(ctx context.Context, params UpdateBillingSettingsParams, opts ...RequestOption) (*BillingSettings, error) {
	out := &BillingSettings{}
	return out, s.client.put(ctx, "/v1/billing/settings", params, out, opts...)
}

// CheckBillingFeatureParams asks whether a subject may use a feature.
// Required is the units about to be used (default 1).
type CheckBillingFeatureParams struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Feature     string   `json:"feature"`
	Required    *float64 `json:"required,omitempty"`
}

// BillingFeatureCheck is the answer. Source is "provider" (asked live of
// Autumn/Commet) or "atlas" (from the resolved entitlement and this period's
// usage).
type BillingFeatureCheck struct {
	Object    string   `json:"object"`
	Feature   string   `json:"feature"`
	Allowed   bool     `json:"allowed"`
	Source    string   `json:"source"`
	Provider  *string  `json:"provider"`
	Remaining *float64 `json:"remaining"`
	Granted   *float64 `json:"granted"`
	Usage     *float64 `json:"usage"`
	Unlimited bool     `json:"unlimited"`
}

// CheckFeature answers whether a subject may use a feature.
// POST /v1/billing/check.
func (s *BillingService) CheckFeature(ctx context.Context, params CheckBillingFeatureParams, opts ...RequestOption) (*BillingFeatureCheck, error) {
	out := &BillingFeatureCheck{}
	return out, s.client.post(ctx, "/v1/billing/check", params, out, opts...)
}
