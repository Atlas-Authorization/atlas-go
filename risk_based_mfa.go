package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// RiskBasedMFAService is the /v1/risk_based_mfa namespace — adaptive / risk-based
// MFA (Auth0 "Adaptive MFA" parity). OFF by default; it can only ever ADD
// friction.
type RiskBasedMFAService struct{ client *Client }

// RiskWeights are per-signal score weights that feed the risk total.
type RiskWeights struct {
	NewDevice        float64 `json:"newDevice"`
	NewSubnet        float64 `json:"newSubnet"`
	NewIP            float64 `json:"newIp"`
	Velocity         float64 `json:"velocity"`
	ImpossibleTravel float64 `json:"impossibleTravel"`
	// DormantAccount: the account was idle past the dormant-account threshold
	// before this sign-in.
	DormantAccount float64 `json:"dormantAccount,omitempty"`
}

// RiskSignalToggles are per-signal on/off switches.
type RiskSignalToggles struct {
	NewDevice        bool `json:"newDevice"`
	NewSubnet        bool `json:"newSubnet"`
	NewIP            bool `json:"newIp"`
	Velocity         bool `json:"velocity"`
	ImpossibleTravel bool `json:"impossibleTravel"`
	DormantAccount   bool `json:"dormantAccount,omitempty"`
}

// RiskBasedMFA is the adaptive-MFA config.
type RiskBasedMFA struct {
	Object             string            `json:"object"`
	Enabled            bool              `json:"enabled"`
	StepUpThreshold    string            `json:"step_up_threshold"`
	OnHighRiskNoFactor string            `json:"on_high_risk_no_factor"`
	Weights            RiskWeights       `json:"weights"`
	Signals            RiskSignalToggles `json:"signals"`
	// Mode is "enforce" or "audit" (score and record without acting).
	Mode string `json:"mode,omitempty"`
	// LevelActions maps medium/high to default, allow, notify, mfa or block.
	LevelActions *RiskLevelActions `json:"level_actions,omitempty"`
	Reputation   *RiskReputation   `json:"reputation,omitempty"`
	Fraud        *FraudConfig      `json:"fraud,omitempty"`
	// Baseline: an unusual sign-in hour or never-seen country adds Weight points each.
	Baseline *RiskBaseline `json:"baseline,omitempty"`
	// MidSession re-evaluates a session when it refreshes from a different network.
	MidSession *RiskMidSession `json:"mid_session,omitempty"`
}

// RiskLevelActions is what a risk level does.
type RiskLevelActions struct {
	Medium string `json:"medium"`
	High   string `json:"high"`
}

// RiskReputation configures the external IP-reputation / email-risk feeds.
type RiskReputation struct {
	Provider        string  `json:"provider"`
	IPWeight        float64 `json:"ip_weight"`
	MinScore        float64 `json:"min_score"`
	FlagAnonymizers bool    `json:"flag_anonymizers"`
	EmailChecks     bool    `json:"email_checks"`
	EmailWeight     float64 `json:"email_weight"`
}

// FraudCondition is one condition of a fraud rule; all conditions must hold.
type FraudCondition struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

// FraudRule is one rule evaluated by POST /v1/fraud/lookup.
type FraudRule struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Enabled    bool             `json:"enabled"`
	Action     string           `json:"action"`
	Reason     string           `json:"reason"`
	Conditions []FraudCondition `json:"conditions"`
}

// FraudDeviceRateLimit caps lookups per device per hour.
type FraudDeviceRateLimit struct {
	Enabled  bool `json:"enabled"`
	PerHour  int  `json:"per_hour"`
	Adaptive bool `json:"adaptive"`
}

// FraudConfig is the fraud-rule configuration.
type FraudConfig struct {
	SanctionedCountries []string              `json:"sanctioned_countries"`
	Rules               []FraudRule           `json:"rules"`
	DeviceRateLimit     *FraudDeviceRateLimit `json:"device_rate_limit,omitempty"`
}

// RiskBaseline is the per-user baseline setting.
type RiskBaseline struct {
	Enabled bool    `json:"enabled"`
	Weight  float64 `json:"weight"`
}

// RiskMidSession is the mid-session re-evaluation setting (Action: revoke, notify or audit).
type RiskMidSession struct {
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"`
}

// UpdateRiskBasedMFAParams is the body of PATCH /v1/risk_based_mfa. Weights and
// Signals accept partial maps so a single knob can move.
type UpdateRiskBasedMFAParams struct {
	Enabled            *bool                  `json:"enabled,omitempty"`
	StepUpThreshold    string                 `json:"step_up_threshold,omitempty"`
	OnHighRiskNoFactor string                 `json:"on_high_risk_no_factor,omitempty"`
	Weights            map[string]float64     `json:"weights,omitempty"`
	Signals            map[string]bool        `json:"signals,omitempty"`
	Mode               string                 `json:"mode,omitempty"`
	LevelActions       map[string]string      `json:"level_actions,omitempty"`
	Reputation         map[string]interface{} `json:"reputation,omitempty"`
	Fraud              map[string]interface{} `json:"fraud,omitempty"`
	Baseline           map[string]interface{} `json:"baseline,omitempty"`
	MidSession         map[string]interface{} `json:"mid_session,omitempty"`
}

// Get reads the current adaptive-MFA config. GET /v1/risk_based_mfa.
func (s *RiskBasedMFAService) Get(ctx context.Context) (*RiskBasedMFA, error) {
	out := &RiskBasedMFA{}
	return out, s.client.get(ctx, "/v1/risk_based_mfa", nil, out)
}

// Update changes any subset of the config. PATCH /v1/risk_based_mfa.
func (s *RiskBasedMFAService) Update(ctx context.Context, params UpdateRiskBasedMFAParams, opts ...RequestOption) (*RiskBasedMFA, error) {
	out := &RiskBasedMFA{}
	return out, s.client.patch(ctx, "/v1/risk_based_mfa", params, out, opts...)
}

// RiskEvent is one risk-scored sign-in on the audit / shadow-mode timeline.
type RiskEvent struct {
	Object string  `json:"object"`
	ID     string  `json:"id"`
	UserID string  `json:"user_id"`
	Level  string  `json:"level"`
	Score  float64 `json:"score"`
	// Signals are the names of the signals that fired.
	Signals []string `json:"signals"`
	// Action is the action decided; in audit mode, what would have happened.
	Action     string  `json:"action"`
	Mode       string  `json:"mode"`
	IP         *string `json:"ip"`
	Feedback   *string `json:"feedback"`
	FeedbackAt *string `json:"feedback_at"`
	CreatedAt  string  `json:"created_at"`
}

// ListRiskEventsParams filters the risk-event timeline. Zero values are omitted.
type ListRiskEventsParams struct {
	UserID string
	// Level is low, medium or high.
	Level string
	// Limit is 1-200 (server default 50).
	Limit int
	// Before is an ISO timestamp cursor on created_at.
	Before string
}

// RiskEventMetricsBucket is one level/action/mode count.
type RiskEventMetricsBucket struct {
	Level  string `json:"level"`
	Action string `json:"action"`
	Mode   string `json:"mode"`
	Count  int    `json:"count"`
}

// RiskEventMetrics counts risk events over the last Days.
type RiskEventMetrics struct {
	Object  string                   `json:"object"`
	Days    int                      `json:"days"`
	Total   int                      `json:"total"`
	Buckets []RiskEventMetricsBucket `json:"buckets"`
}

// ListEvents returns the risk-event timeline, newest first. GET /v1/risk_events.
func (s *RiskBasedMFAService) ListEvents(ctx context.Context, params ListRiskEventsParams) (*ListPage[RiskEvent], error) {
	q := url.Values{}
	if params.UserID != "" {
		q.Set("user_id", params.UserID)
	}
	if params.Level != "" {
		q.Set("level", params.Level)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Before != "" {
		q.Set("before", params.Before)
	}
	out := &ListPage[RiskEvent]{}
	return out, s.client.get(ctx, "/v1/risk_events", q, out)
}

// EventMetrics counts events per level/action/mode over the last days (1-90;
// 0 for the default of 7). GET /v1/risk_events/metrics.
func (s *RiskBasedMFAService) EventMetrics(ctx context.Context, days int) (*RiskEventMetrics, error) {
	q := url.Values{}
	if days > 0 {
		q.Set("days", strconv.Itoa(days))
	}
	out := &RiskEventMetrics{}
	return out, s.client.get(ctx, "/v1/risk_events/metrics", q, out)
}

// EventFeedback marks a scored sign-in "legit" or "fraud"; the weight of each
// signal that fired moves accordingly. POST /v1/risk_events/:id/feedback.
func (s *RiskBasedMFAService) EventFeedback(ctx context.Context, id, verdict string, opts ...RequestOption) (*RiskEvent, error) {
	out := &RiskEvent{}
	return out, s.client.post(ctx, "/v1/risk_events/"+url.PathEscape(id)+"/feedback", map[string]string{"verdict": verdict}, out, opts...)
}

// FraudLookupParams is the body of POST /v1/fraud/lookup. IP is required.
type FraudLookupParams struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent,omitempty"`
	// DeviceID is the stable id from the JS SDK.
	DeviceID string `json:"device_id,omitempty"`
	Email    string `json:"email,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	OrgID    string `json:"org_id,omitempty"`
	// Device holds the device features reported by the SDK.
	Device map[string]interface{} `json:"device,omitempty"`
}

// FraudLookup is the allow / challenge / block verdict with its reasons.
type FraudLookup struct {
	Object       string                 `json:"object"`
	Verdict      string                 `json:"verdict"`
	Reasons      []string               `json:"reasons"`
	MatchedRules []string               `json:"matched_rules"`
	DeviceID     *string                `json:"device_id"`
	Signals      map[string]interface{} `json:"signals"`
}

// FraudLookup scores a sign-up, sign-in or checkout. POST /v1/fraud/lookup.
func (s *RiskBasedMFAService) FraudLookup(ctx context.Context, params FraudLookupParams, opts ...RequestOption) (*FraudLookup, error) {
	out := &FraudLookup{}
	return out, s.client.post(ctx, "/v1/fraud/lookup", params, out, opts...)
}
