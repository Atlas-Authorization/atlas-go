package atlas

import (
	"context"
	"net/url"
)

// SetReputationSecret: Store (write-only, encrypted) the API key of your IP-reputation provider
// (ipqs, spur or minfraud; minFraud uses "<account id>:<license key>"). Then set
// `reputation.provider` on PATCH /v1/risk_based_mfa. Lookups are cached and fail open: a provider
// outage never blocks a sign-in.
// PUT /v1/risk_based_mfa/reputation_secret.
func (s *RiskBasedMFAService) SetReputationSecret(ctx context.Context, params RiskBasedMFASetReputationSecretParams, opts ...RequestOption) (*RiskBasedMFASetReputationSecretResult, error) {
	out := &RiskBasedMFASetReputationSecretResult{}
	return out, s.client.do(ctx, "PUT", "/v1/risk_based_mfa/reputation_secret", nil, params, out, opts...)
}

// RiskBasedMFARemoveReputationSecretQuery holds the query parameters of RiskBasedMFAService.RemoveReputationSecret.
type RiskBasedMFARemoveReputationSecretQuery struct {
	// ipqs, spur or minfraud. Default: reputation.provider.
	Provider string
}

func (q RiskBasedMFARemoveReputationSecretQuery) values() url.Values {
	v := url.Values{}
	if q.Provider != "" {
		v.Set("provider", q.Provider)
	}
	return v
}

// RemoveReputationSecret: Remove a stored IP-reputation provider key (default: the configured
// provider). IP lookups for that provider stop; sign-in is unaffected.
// DELETE /v1/risk_based_mfa/reputation_secret.
func (s *RiskBasedMFAService) RemoveReputationSecret(ctx context.Context, query RiskBasedMFARemoveReputationSecretQuery, opts ...RequestOption) (*RiskBasedMFARemoveReputationSecretResult, error) {
	out := &RiskBasedMFARemoveReputationSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/risk_based_mfa/reputation_secret", query.values(), nil, out, opts...)
}
