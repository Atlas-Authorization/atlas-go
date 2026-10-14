package atlas

import "context"

// Preflight finding severities.
const (
	PreflightError   = "error"
	PreflightWarning = "warning"
	PreflightInfo    = "info"
)

// PreflightFinding is one problem (or note) the setup check found.
type PreflightFinding struct {
	// Severity is error, warning or info.
	Severity string `json:"severity"`
	// Code is a stable snake_case identifier, e.g.
	// oauth_provider_missing_credentials.
	Code string `json:"code"`
	// Message says what is wrong, in a plain sentence.
	Message string `json:"message"`
	// Fix says what to do about it, in a plain sentence.
	Fix string `json:"fix"`
	// Subject holds the ids of what the finding is about (provider,
	// id/client_id, domain_id/host, …).
	Subject map[string]string `json:"subject,omitempty"`
}

// Preflight is the result of the one-call setup check.
type Preflight struct {
	Object string `json:"object"`
	// OK is true when there are no error-severity findings.
	OK bool `json:"ok"`
	// CheckedAt is when the check ran (epoch ms).
	CheckedAt int64 `json:"checked_at"`
	// Findings are ordered error, then warning, then info.
	Findings []PreflightFinding `json:"findings"`
}

// Errors returns only the error-severity findings.
func (p *Preflight) Errors() []PreflightFinding {
	var out []PreflightFinding
	for _, f := range p.Findings {
		if f.Severity == PreflightError {
			out = append(out, f)
		}
	}
	return out
}

// Preflight checks the instance's setup in one call: no sign-in method
// enabled, a provider enabled without credentials, OAuth clients without
// redirect URIs, custom domains not serving yet, email or SMS sign-in without
// a provider, and more. GET /v1/instance/preflight.
func (s *InstanceService) Preflight(ctx context.Context) (*Preflight, error) {
	out := &Preflight{}
	return out, s.client.get(ctx, "/v1/instance/preflight", nil, out)
}
