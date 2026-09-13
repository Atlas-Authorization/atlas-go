package atlas

import "context"

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
}

// RiskSignalToggles are per-signal on/off switches.
type RiskSignalToggles struct {
	NewDevice        bool `json:"newDevice"`
	NewSubnet        bool `json:"newSubnet"`
	NewIP            bool `json:"newIp"`
	Velocity         bool `json:"velocity"`
	ImpossibleTravel bool `json:"impossibleTravel"`
}

// RiskBasedMFA is the adaptive-MFA config.
type RiskBasedMFA struct {
	Object             string            `json:"object"`
	Enabled            bool              `json:"enabled"`
	StepUpThreshold    string            `json:"step_up_threshold"`
	OnHighRiskNoFactor string            `json:"on_high_risk_no_factor"`
	Weights            RiskWeights       `json:"weights"`
	Signals            RiskSignalToggles `json:"signals"`
}

// UpdateRiskBasedMFAParams is the body of PATCH /v1/risk_based_mfa. Weights and
// Signals accept partial maps so a single knob can move.
type UpdateRiskBasedMFAParams struct {
	Enabled            *bool              `json:"enabled,omitempty"`
	StepUpThreshold    string             `json:"step_up_threshold,omitempty"`
	OnHighRiskNoFactor string             `json:"on_high_risk_no_factor,omitempty"`
	Weights            map[string]float64 `json:"weights,omitempty"`
	Signals            map[string]bool    `json:"signals,omitempty"`
}

// Get reads the current adaptive-MFA config. GET /v1/risk_based_mfa.
func (s *RiskBasedMFAService) Get(ctx context.Context) (*RiskBasedMFA, error) {
	out := &RiskBasedMFA{}
	return out, s.client.get(ctx, "/v1/risk_based_mfa", nil, out)
}

// Update changes any subset of the config. PATCH /v1/risk_based_mfa.
func (s *RiskBasedMFAService) Update(ctx context.Context, params UpdateRiskBasedMFAParams) (*RiskBasedMFA, error) {
	out := &RiskBasedMFA{}
	return out, s.client.patch(ctx, "/v1/risk_based_mfa", params, out)
}
