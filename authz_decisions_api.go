package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// AuthzDecisionsService is the authzDecisions resource.
type AuthzDecisionsService struct {
	client   *Client
	Settings *AuthzDecisionsSettingsService
}

// AuthzDecisionsListQuery holds the query parameters of AuthzDecisionsService.List.
type AuthzDecisionsListQuery struct {
	// Only decisions from this engine.
	Source string
	// Only allows or only denies.
	Decision string
	// Exact principal (`User::alice`, an FGA user, a user id).
	Principal string
	// Exact action / relation / stage.
	Action string
	// Exact resource.
	Resource string
	// Only decisions made under this bundle revision.
	PolicyRevision string
	// ISO 8601 timestamp or epoch milliseconds: decisions at or after it.
	Since string
	// ISO 8601 timestamp or epoch milliseconds: decisions at or before it.
	Until string
	// Page size. A value outside 1-200 is refused.
	Limit int64
	// Cursor: the `next_cursor` of the previous page.
	StartingAfter string
}

func (q AuthzDecisionsListQuery) values() url.Values {
	v := url.Values{}
	if q.Source != "" {
		v.Set("source", q.Source)
	}
	if q.Decision != "" {
		v.Set("decision", q.Decision)
	}
	if q.Principal != "" {
		v.Set("principal", q.Principal)
	}
	if q.Action != "" {
		v.Set("action", q.Action)
	}
	if q.Resource != "" {
		v.Set("resource", q.Resource)
	}
	if q.PolicyRevision != "" {
		v.Set("policy_revision", q.PolicyRevision)
	}
	if q.Since != "" {
		v.Set("since", q.Since)
	}
	if q.Until != "" {
		v.Set("until", q.Until)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: Query the authorization decision log, newest first: ABAC, AuthZEN, FGA-check and
// access-policy decisions with their redacted input, result, the policy revision in force and
// latency. Only decisions that passed sampling are stored.
// GET /v1/authz_decisions.
func (s *AuthzDecisionsService) List(ctx context.Context, query AuthzDecisionsListQuery) (*CursorPage[AuthzDecisionsListItem], error) {
	out := &CursorPage[AuthzDecisionsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/authz_decisions", query.values(), nil, out)
}

// AuthzDecisionsStatsQuery holds the query parameters of AuthzDecisionsService.Stats.
type AuthzDecisionsStatsQuery struct {
	// ISO 8601 or epoch milliseconds. Default: 24 hours before `until`.
	Since string
	// ISO 8601 or epoch milliseconds. Default: now.
	Until string
}

func (q AuthzDecisionsStatsQuery) values() url.Values {
	v := url.Values{}
	if q.Since != "" {
		v.Set("since", q.Since)
	}
	if q.Until != "" {
		v.Set("until", q.Until)
	}
	return v
}

// Stats: Decision counts per engine and outcome over a window (the last 24 hours by default), with
// a sampling-corrected estimate of the true volume and latency percentiles of the recorded
// decisions.
// GET /v1/authz_decisions/stats.
func (s *AuthzDecisionsService) Stats(ctx context.Context, query AuthzDecisionsStatsQuery) (*AuthzDecisionsStatsResult, error) {
	out := &AuthzDecisionsStatsResult{}
	return out, s.client.do(ctx, "GET", "/v1/authz_decisions/stats", query.values(), nil, out)
}

// Get: Read one logged decision.
// GET /v1/authz_decisions/{id}.
func (s *AuthzDecisionsService) Get(ctx context.Context, id string) (*AuthzDecisionsListItem, error) {
	out := &AuthzDecisionsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/authz_decisions/"+url.PathEscape(id), nil, nil, out)
}

// AuthzDecisionsSettingsService is the authzDecisions settings group of AuthzDecisionsService.
type AuthzDecisionsSettingsService struct {
	client *Client
}

// Get: How authorization decisions are captured: on or off, sampling per outcome, how much of each
// request is kept, redaction paths, event shipping and retention.
// GET /v1/authz_decision_settings.
func (s *AuthzDecisionsSettingsService) Get(ctx context.Context) (*AuthzDecisionsSettingsGetResult, error) {
	out := &AuthzDecisionsSettingsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/authz_decision_settings", nil, nil, out)
}

// Update: Change how decisions are captured. Fields you omit keep their value. Capture is off by
// default; `input_mode` defaults to `ids` (identifiers only) so nothing personal is stored until
// you ask for it. With `ship_to_events` each recorded decision is also an `authz.decision` event
// for your log streams and webhooks.
// PUT /v1/authz_decision_settings.
func (s *AuthzDecisionsSettingsService) Update(ctx context.Context, params AuthzDecisionsSettingsUpdateParams, opts ...RequestOption) (*AuthzDecisionsSettingsGetResult, error) {
	out := &AuthzDecisionsSettingsGetResult{}
	return out, s.client.do(ctx, "PUT", "/v1/authz_decision_settings", nil, params, out, opts...)
}
