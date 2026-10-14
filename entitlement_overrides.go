package atlas

import (
	"context"
	"net/url"
)

// EntitlementOverridesService is /v1/entitlement_overrides: sales-led grants
// that pin a plan, features and/or limits onto a user or organization without
// Stripe. A live override wins over the Stripe-derived entitlement.
type EntitlementOverridesService struct{ client *Client }

// EntitlementOverride is one sales-led override.
type EntitlementOverride struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// SubjectType is "user" or "org".
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	// Plan is the pinned plan slug, or nil when only features/limits are set.
	Plan *string `json:"plan"`
	// Features replaces (does not add to) the resolved feature set; nil when
	// not overridden.
	Features []string               `json:"features"`
	Limits   map[string]interface{} `json:"limits"`
	// ExpiresAt is when the override lapses (epoch ms), or nil for open-ended.
	ExpiresAt *int64  `json:"expires_at"`
	CreatedBy *string `json:"created_by"`
	CreatedAt int64   `json:"created_at"`
}

// CreateEntitlementOverrideParams is the body of POST /v1/entitlement_overrides.
// At least one of Plan, Features or Limits is required.
type CreateEntitlementOverrideParams struct {
	// SubjectType is "user" or "org".
	SubjectType string                 `json:"subject_type"`
	SubjectID   string                 `json:"subject_id"`
	Plan        string                 `json:"plan,omitempty"`
	Features    []string               `json:"features,omitempty"`
	Limits      map[string]interface{} `json:"limits,omitempty"`
	// ExpiresAt is epoch ms; nil for open-ended.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// ListEntitlementOverridesParams filters GET /v1/entitlement_overrides.
type ListEntitlementOverridesParams struct {
	SubjectType string
	SubjectID   string
}

func (p ListEntitlementOverridesParams) values() url.Values {
	v := url.Values{}
	if p.SubjectType != "" {
		v.Set("subject_type", p.SubjectType)
	}
	if p.SubjectID != "" {
		v.Set("subject_id", p.SubjectID)
	}
	return v
}

// Create grants an override. POST /v1/entitlement_overrides.
func (s *EntitlementOverridesService) Create(ctx context.Context, params CreateEntitlementOverrideParams, opts ...RequestOption) (*EntitlementOverride, error) {
	out := &EntitlementOverride{}
	return out, s.client.post(ctx, "/v1/entitlement_overrides", params, out, opts...)
}

// List returns overrides (expired ones included, for audit).
// GET /v1/entitlement_overrides.
func (s *EntitlementOverridesService) List(ctx context.Context, params ListEntitlementOverridesParams) (*ListPage[EntitlementOverride], error) {
	out := &ListPage[EntitlementOverride]{}
	return out, s.client.get(ctx, "/v1/entitlement_overrides", params.values(), out)
}

// Delete revokes an override; the subject reverts to its Stripe-derived
// entitlement on the next session. DELETE /v1/entitlement_overrides/:id.
func (s *EntitlementOverridesService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/entitlement_overrides/"+url.PathEscape(id), out, opts...)
}
