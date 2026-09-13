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
	CreatedAt     int64    `json:"created_at"`
	UpdatedAt     int64    `json:"updated_at"`
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
	CreatedAt            int64   `json:"created_at"`
	UpdatedAt            int64   `json:"updated_at"`
}

// CreateBillingPlanParams is the body of POST /v1/billing/plans.
type CreateBillingPlanParams struct {
	Name          string   `json:"name"`
	Slug          string   `json:"slug"`
	StripePriceID string   `json:"stripe_price_id"`
	Interval      string   `json:"interval,omitempty"`
	Amount        string   `json:"amount,omitempty"`
	Currency      string   `json:"currency,omitempty"`
	Features      []string `json:"features,omitempty"`
	Audience      string   `json:"audience,omitempty"`
	Active        *bool    `json:"active,omitempty"`
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
func (s *BillingService) UpdatePlan(ctx context.Context, id string, params UpdateBillingPlanParams) (*BillingPlan, error) {
	out := &BillingPlan{}
	return out, s.client.patch(ctx, "/v1/billing/plans/"+url.PathEscape(id), params, out)
}

// DeletePlan removes a plan. DELETE /v1/billing/plans/:id.
func (s *BillingService) DeletePlan(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/billing/plans/"+url.PathEscape(id), out)
}

// ListSubscriptions returns the subscription read view.
// GET /v1/billing/subscriptions.
func (s *BillingService) ListSubscriptions(ctx context.Context, params ListSubscriptionsParams) (*ListPage[BillingSubscription], error) {
	out := &ListPage[BillingSubscription]{}
	return out, s.client.get(ctx, "/v1/billing/subscriptions", params.values(), out)
}
