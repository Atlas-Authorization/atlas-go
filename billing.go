package atlas

import (
	"context"
	"net/url"
)

// BillingService is the /v1/billing namespace — the plans a tenant defines for
// their app's users, and a read view of who is subscribed.
type BillingService struct{ client *Client }

// BillingPlan is a plan a tenant defines for their app's users.
type BillingPlan struct {
	Object        string   `json:"object"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Slug          string   `json:"slug"`
	StripePriceID string   `json:"stripe_price_id"`
	Interval      string   `json:"interval"`
	Amount        *string  `json:"amount"`
	Currency      string   `json:"currency"`
	Features      []string `json:"features"`
	Audience      string   `json:"audience"`
	Active        bool     `json:"active"`
	// Provider is the billing provider the plan sells through (stripe, polar,
	// dodo or creem); ProviderPriceID its price there (= StripePriceID).
	Provider        string  `json:"provider,omitempty"`
	ProviderPriceID *string `json:"provider_price_id,omitempty"`
	// AnnualPriceID / AnnualAmount offer the plan yearly too.
	AnnualPriceID *string `json:"annual_price_id,omitempty"`
	AnnualAmount  *string `json:"annual_amount,omitempty"`
	CreatedAt     int64   `json:"created_at"`
	UpdatedAt     int64   `json:"updated_at"`
}

// BillingSubscription is a read view of who is subscribed. Status is written only
// by the verified Stripe webhook.
type BillingSubscription struct {
	Object               string  `json:"object"`
	ID                   string  `json:"id"`
	SubjectType          string  `json:"subject_type"`
	SubjectID            string  `json:"subject_id"`
	PlanID               string  `json:"plan_id"`
	Status               string  `json:"status"`
	StripeSubscriptionID *string `json:"stripe_subscription_id"`
	StripeCustomerID     *string `json:"stripe_customer_id"`
	CurrentPeriodEnd     *int64  `json:"current_period_end"`
	// Provider is the billing provider the subscription lives on.
	Provider               string  `json:"provider,omitempty"`
	ProviderSubscriptionID *string `json:"provider_subscription_id,omitempty"`
	ProviderCustomerID     *string `json:"provider_customer_id,omitempty"`
	// Account is "instance" (your own provider account) or "platform" (a
	// legacy subscription on the shared account: mirrored, not manageable).
	Account  string `json:"account,omitempty"`
	Interval string `json:"interval,omitempty"`
	Quantity *int64 `json:"quantity,omitempty"`
	// CancelAtPeriodEnd is true while a cancellation is scheduled.
	CancelAtPeriodEnd bool    `json:"cancel_at_period_end,omitempty"`
	ScheduledPlanID   *string `json:"scheduled_plan_id,omitempty"`
	ScheduledInterval *string `json:"scheduled_interval,omitempty"`
	ScheduledChangeAt *int64  `json:"scheduled_change_at,omitempty"`
	TrialEnd          *int64  `json:"trial_end,omitempty"`
	CanceledAt        *int64  `json:"canceled_at,omitempty"`
	// Scheduled is set on a change response: true when the switch waits for
	// the period end.
	Scheduled bool  `json:"scheduled,omitempty"`
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// CreateBillingPlanParams is the body of POST /v1/billing/plans.
type CreateBillingPlanParams struct {
	Name          string   `json:"name"`
	Slug          string   `json:"slug"`
	StripePriceID string   `json:"stripe_price_id,omitempty"`
	Interval      string   `json:"interval,omitempty"`
	Amount        string   `json:"amount,omitempty"`
	Currency      string   `json:"currency,omitempty"`
	Features      []string `json:"features,omitempty"`
	Audience      string   `json:"audience,omitempty"`
	Active        *bool    `json:"active,omitempty"`
	// Provider is stripe (default), polar, dodo or creem; ProviderPriceID is
	// the neutral alias of StripePriceID (send one).
	Provider        string `json:"provider,omitempty"`
	ProviderPriceID string `json:"provider_price_id,omitempty"`
	// AnnualPriceID / AnnualAmount offer the plan yearly too.
	AnnualPriceID string `json:"annual_price_id,omitempty"`
	AnnualAmount  string `json:"annual_amount,omitempty"`
}

// UpdateBillingPlanParams is the body of PATCH /v1/billing/plans/:id.
type UpdateBillingPlanParams struct {
	Name          string   `json:"name,omitempty"`
	Slug          string   `json:"slug,omitempty"`
	StripePriceID string   `json:"stripe_price_id,omitempty"`
	Interval      string   `json:"interval,omitempty"`
	Amount        string   `json:"amount,omitempty"`
	Currency      string   `json:"currency,omitempty"`
	Features      []string `json:"features,omitempty"`
	Audience      string   `json:"audience,omitempty"`
	Active        *bool    `json:"active,omitempty"`
	// Provider is stripe (default), polar, dodo or creem; ProviderPriceID is
	// the neutral alias of StripePriceID (send one).
	Provider        string `json:"provider,omitempty"`
	ProviderPriceID string `json:"provider_price_id,omitempty"`
	// AnnualPriceID / AnnualAmount offer the plan yearly too.
	AnnualPriceID string `json:"annual_price_id,omitempty"`
	AnnualAmount  string `json:"annual_amount,omitempty"`
}

// ListSubscriptionsParams filters the subscription read view to one subject.
type ListSubscriptionsParams struct {
	SubjectType string
	SubjectID   string
}

func (p ListSubscriptionsParams) values() url.Values {
	v := url.Values{}
	if p.SubjectType != "" {
		v.Set("subject_type", p.SubjectType)
	}
	if p.SubjectID != "" {
		v.Set("subject_id", p.SubjectID)
	}
	return v
}

// ListPlans returns the plans. GET /v1/billing/plans.
func (s *BillingService) ListPlans(ctx context.Context) (*ListPage[BillingPlan], error) {
	out := &ListPage[BillingPlan]{}
	return out, s.client.get(ctx, "/v1/billing/plans", nil, out)
}

// CreatePlan creates a plan. POST /v1/billing/plans.
func (s *BillingService) CreatePlan(ctx context.Context, params CreateBillingPlanParams, opts ...RequestOption) (*BillingPlan, error) {
	out := &BillingPlan{}
	return out, s.client.post(ctx, "/v1/billing/plans", params, out, opts...)
}

// GetPlan returns one plan. GET /v1/billing/plans/:id.
func (s *BillingService) GetPlan(ctx context.Context, id string) (*BillingPlan, error) {
	out := &BillingPlan{}
	return out, s.client.get(ctx, "/v1/billing/plans/"+url.PathEscape(id), nil, out)
}

// UpdatePlan patches a plan. PATCH /v1/billing/plans/:id.
func (s *BillingService) UpdatePlan(ctx context.Context, id string, params UpdateBillingPlanParams, opts ...RequestOption) (*BillingPlan, error) {
	out := &BillingPlan{}
	return out, s.client.patch(ctx, "/v1/billing/plans/"+url.PathEscape(id), params, out, opts...)
}

// DeletePlan removes a plan. DELETE /v1/billing/plans/:id.
func (s *BillingService) DeletePlan(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/billing/plans/"+url.PathEscape(id), out, opts...)
}

// ListSubscriptions returns the subscription read view.
// GET /v1/billing/subscriptions.
func (s *BillingService) ListSubscriptions(ctx context.Context, params ListSubscriptionsParams) (*ListPage[BillingSubscription], error) {
	out := &ListPage[BillingSubscription]{}
	return out, s.client.get(ctx, "/v1/billing/subscriptions", params.values(), out)
}

// ImportSubscriptionParams adopts an existing Stripe subscription onto an Atlas
// subject. SubjectType is "user" or "org"; PlanID is resolved from the
// subscription price when empty.
type ImportSubscriptionParams struct {
	SubjectType          string `json:"subject_type"`
	SubjectID            string `json:"subject_id"`
	StripeSubscriptionID string `json:"stripe_subscription_id"`
	StripeCustomerID     string `json:"stripe_customer_id,omitempty"`
	PlanID               string `json:"plan_id,omitempty"`
}

// ReportUsageParams reports metered usage. IdempotencyKey de-duplicates
// retries; SubjectType is "user" or "org".
type ReportUsageParams struct {
	SubjectType    string  `json:"subject_type"`
	SubjectID      string  `json:"subject_id"`
	Quantity       float64 `json:"quantity"`
	IdempotencyKey string  `json:"idempotency_key"`
}

// UsageRecordResult is the result of reporting usage: whether it was newly
// recorded, whether the plan is metered, and the running total.
type UsageRecordResult struct {
	Object   string  `json:"object"`
	Recorded bool    `json:"recorded"`
	Metered  bool    `json:"metered"`
	Total    float64 `json:"total"`
}

// SeatSync is the result of syncing a per-seat subscription's quantity.
type SeatSync struct {
	Object      string `json:"object"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Quantity    int    `json:"quantity"`
}

// ImportSubscription adopts an existing Stripe subscription without
// re-charging. POST /v1/billing/subscriptions/import.
func (s *BillingService) ImportSubscription(ctx context.Context, params ImportSubscriptionParams, opts ...RequestOption) (*BillingSubscription, error) {
	out := &BillingSubscription{}
	return out, s.client.post(ctx, "/v1/billing/subscriptions/import", params, out, opts...)
}

// ReportUsage reports metered usage for a subject. POST /v1/billing/usage.
func (s *BillingService) ReportUsage(ctx context.Context, params ReportUsageParams, opts ...RequestOption) (*UsageRecordResult, error) {
	out := &UsageRecordResult{}
	return out, s.client.post(ctx, "/v1/billing/usage", params, out, opts...)
}

// SyncSeats syncs a per-seat subscription's Stripe quantity to the
// organization's member count. subjectType is "org" or "user".
// POST /v1/billing/subjects/:type/:id/sync_seats.
func (s *BillingService) SyncSeats(ctx context.Context, subjectType, subjectID string, opts ...RequestOption) (*SeatSync, error) {
	out := &SeatSync{}
	return out, s.client.post(ctx, "/v1/billing/subjects/"+url.PathEscape(subjectType)+"/"+url.PathEscape(subjectID)+"/sync_seats", nil, out, opts...)
}
