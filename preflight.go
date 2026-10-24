package atlas

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

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
	// Group is security_posture on the findings about settings weaker than the
	// defaults new instances get.
	Group string `json:"group,omitempty"`
	// Suppressed is set only with IncludeSuppressed: the finding does not
	// apply to how the instance integrates (SuppressedReason says why).
	Suppressed       bool   `json:"suppressed,omitempty"`
	SuppressedReason string `json:"suppressed_reason,omitempty"`
}

// PreflightSuppressedFinding is a finding that does not apply to how the
// instance integrates, and why.
type PreflightSuppressedFinding struct {
	Code     string            `json:"code"`
	Severity string            `json:"severity"`
	Subject  map[string]string `json:"subject"`
	Reason   string            `json:"reason"`
}

// PreflightOriginIntegration is how one allowed https origin signs in, as
// preflight judged it.
type PreflightOriginIntegration struct {
	Origin string `json:"origin"`
	// Integration is redirect or embedded.
	Integration string `json:"integration"`
	// Source is declared, embedded_traffic, redirect_clients or default.
	Source string `json:"source"`
	// Confident is false only for the default (nothing says how the origin
	// signs in).
	Confident bool   `json:"confident"`
	Reason    string `json:"reason"`
}

// PreflightParams tunes the setup check.
type PreflightParams struct {
	// MinSeverity keeps only findings at least this severe (error, warning or
	// info). OK still covers every finding.
	MinSeverity string
	// IncludeSuppressed also lists the suppressed findings in Findings.
	IncludeSuppressed bool
}

// Preflight codes added with the security-posture and integration checks.
const (
	PreflightOAuthClientNoBackchannelLogoutURI = "oauth_client_no_backchannel_logout_uri"
	PreflightPKCENotRequired                   = "pkce_not_required"
	PreflightPasskeyWithoutUV                  = "passkey_without_uv"
	PreflightAutoLinkUnverified                = "auto_link_unverified"
	PreflightIntegrationEnabledNeverMinted     = "integration_enabled_never_minted"
	PreflightIntegrationVerifyErrors           = "integration_verify_errors"
	PreflightIntegrationReceiverFailing        = "integration_receiver_failing"
	PreflightCookieConsentNotEnabled           = "cookie_consent_not_enabled"
)

// Preflight is the result of the one-call setup check.
type Preflight struct {
	Object string `json:"object"`
	// OK is true when there are no error-severity findings.
	OK bool `json:"ok"`
	// CheckedAt is when the check ran (epoch ms).
	CheckedAt int64 `json:"checked_at"`
	// Findings are ordered error, then warning, then info.
	Findings []PreflightFinding `json:"findings"`
	// SDKVersionsSeen lists the Atlas browser SDK versions that called the
	// instance in the last 7 days, with the advisories that apply to each.
	SDKVersionsSeen []SDKVersionSeen `json:"sdk_versions_seen,omitempty"`
	// MinSeverity is the min_severity the findings were filtered by (info =
	// everything).
	MinSeverity string `json:"min_severity,omitempty"`
	// Suppressed are the findings that do not apply to how the instance
	// integrates (not counted in OK).
	Suppressed []PreflightSuppressedFinding `json:"suppressed,omitempty"`
	// Integrations says how each allowed https origin signs in.
	Integrations []PreflightOriginIntegration `json:"integrations,omitempty"`
}

// SDKVersionSeen is an Atlas browser SDK version seen recently.
type SDKVersionSeen struct {
	Package    string        `json:"package"`
	Version    string        `json:"version"`
	LastSeenAt int64         `json:"last_seen_at"`
	Advisories []SDKAdvisory `json:"advisories"`
}

// SDKAdvisory is an advisory published for an Atlas browser SDK range.
type SDKAdvisory struct {
	Object   string `json:"object"`
	Package  string `json:"package"`
	Affected string `json:"affected"`
	FixedIn  string `json:"fixed_in"`
	// Reason is a stable code, e.g. email_code_sign_in.
	Reason string `json:"reason"`
	// Severity is critical, high, medium or low.
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	PublishedAt string `json:"published_at"`
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

// PreflightWithParams is Preflight with min_severity and include_suppressed.
// GET /v1/instance/preflight.
func (s *InstanceService) PreflightWithParams(ctx context.Context, params PreflightParams) (*Preflight, error) {
	out := &Preflight{}
	q := url.Values{}
	if params.MinSeverity != "" {
		q.Set("min_severity", params.MinSeverity)
	}
	if params.IncludeSuppressed {
		q.Set("include_suppressed", "true")
	}
	return out, s.client.get(ctx, "/v1/instance/preflight", q, out)
}

// UnknownFieldReportRow is one unknown body field your writes sent, aggregated
// over the report window.
type UnknownFieldReportRow struct {
	Method string `json:"method"`
	// Path is the route template, e.g. /v1/users/{id}.
	Path string `json:"path"`
	// Field is the field path, nested as parent.child.
	Field string `json:"field"`
	Count int    `json:"count"`
	// IgnoredCount: lenient requests, the field was ignored and named in
	// Atlas-Unknown-Fields. RejectedCount: strict requests, refused with 422
	// UNKNOWN_FIELD.
	IgnoredCount  int     `json:"ignored_count"`
	RejectedCount int     `json:"rejected_count"`
	LastSeenAt    int64   `json:"last_seen_at"`
	APIKeyID      *string `json:"api_key_id"`
}

// UnknownFieldsReport is GET /v1/instance/unknown_fields_report.
type UnknownFieldsReport struct {
	Object              string `json:"object"`
	Days                int    `json:"days"`
	RetentionDays       int    `json:"retention_days"`
	StrictRequestBodies bool   `json:"strict_request_bodies"`
	// SafeToEnableStrict is true when nothing in the window would be refused
	// by strict request bodies.
	SafeToEnableStrict bool                    `json:"safe_to_enable_strict"`
	Data               []UnknownFieldReportRow `json:"data"`
}

// UnknownFieldsReport returns the unknown body fields your writes sent over
// the last days (1-90; 0 = the server default of 30): fix every row with an
// IgnoredCount, then turn auth_config.strictRequestBodies on.
// GET /v1/instance/unknown_fields_report.
func (s *InstanceService) UnknownFieldsReport(ctx context.Context, days int) (*UnknownFieldsReport, error) {
	out := &UnknownFieldsReport{}
	var q url.Values
	if days > 0 {
		q = url.Values{"days": {strconv.Itoa(days)}}
	}
	return out, s.client.get(ctx, "/v1/instance/unknown_fields_report", q, out)
}

// OpenAPIDiffItem is one operation in an OpenAPI diff.
type OpenAPIDiffItem struct {
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	OperationID *string `json:"operation_id"`
	Summary     *string `json:"summary"`
	// At is the YYYY-MM-DD of the change.
	At string `json:"at"`
}

// OpenAPIDiff is what changed in the API since a date.
type OpenAPIDiff struct {
	Object string `json:"object"`
	Since  string `json:"since"`
	// Version is the API build the diff was computed on (<date>+<sha>).
	Version    string            `json:"version"`
	Added      []OpenAPIDiffItem `json:"added"`
	Deprecated []OpenAPIDiffItem `json:"deprecated"`
	Removed    []OpenAPIDiffItem `json:"removed"`
}

// OpenAPIDiff returns the operations added, deprecated and removed since a
// date (YYYY-MM-DD). surface limits it (for example bapi); empty = all.
// GET /v1/openapi/diff.
func (s *InstanceService) OpenAPIDiff(ctx context.Context, since, surface string) (*OpenAPIDiff, error) {
	out := &OpenAPIDiff{}
	q := url.Values{"since": {since}}
	if surface != "" {
		q.Set("surface", surface)
	}
	return out, s.client.get(ctx, "/v1/openapi/diff", q, out)
}

// IntegrationHealthCheck is one row of the integration-health report.
type IntegrationHealthCheck struct {
	// ID is a preflight code verbatim, or <source>.<check>.
	ID string `json:"id"`
	// OK is false when failing, nil when not known or not configured.
	OK     *bool   `json:"ok"`
	Detail string  `json:"detail"`
	Fix    *string `json:"fix"`
	Docs   *string `json:"docs"`
	// Hop is, for a check that calls your server, the hop that failed: dns,
	// tls, http, challenge or auth.
	Hop        string            `json:"hop,omitempty"`
	Status     int               `json:"status,omitempty"`
	ElapsedMS  int64             `json:"elapsedMs,omitempty"`
	Source     string            `json:"source"`
	Severity   string            `json:"severity,omitempty"`
	Subject    map[string]string `json:"subject,omitempty"`
	ObservedAt *int64            `json:"observedAt,omitempty"`
}

// IntegrationHealthReport is GET /v1/integration-health.
type IntegrationHealthReport struct {
	Object  string `json:"object"`
	OK      bool   `json:"ok"`
	Summary struct {
		Failing int `json:"failing"`
		Passing int `json:"passing"`
		Unknown int `json:"unknown"`
	} `json:"summary"`
	Checks []IntegrationHealthCheck `json:"checks"`
	// GeneratedAtISO is ISO 8601; GeneratedAt the same instant, epoch ms.
	GeneratedAtISO string `json:"generatedAt"`
	GeneratedAt    int64  `json:"generated_at"`
}

// IntegrationHealthParams limits the report.
type IntegrationHealthParams struct {
	// Only limits the sources.
	Only []string
	// NoProbe skips live reachability probes (probe=false).
	NoProbe bool
}

// IntegrationHealth is one report of everything that connects the instance to
// the outside world (setup checks, webhooks with the failing hop, back-channel
// logout, referrals, email, consent manager, SDK versions).
// GET /v1/integration-health.
func (s *InstanceService) IntegrationHealth(ctx context.Context, params IntegrationHealthParams) (*IntegrationHealthReport, error) {
	out := &IntegrationHealthReport{}
	q := url.Values{}
	if len(params.Only) > 0 {
		q.Set("only", strings.Join(params.Only, ","))
	}
	if params.NoProbe {
		q.Set("probe", "false")
	}
	return out, s.client.get(ctx, "/v1/integration-health", q, out)
}

// IntegrationHealthProvider is a check source this deployment reports.
type IntegrationHealthProvider struct {
	Object      string `json:"object"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// IntegrationHealthProviders lists the check sources.
// GET /v1/integration-health/providers.
func (s *InstanceService) IntegrationHealthProviders(ctx context.Context) (*ListPage[IntegrationHealthProvider], error) {
	out := &ListPage[IntegrationHealthProvider]{}
	return out, s.client.get(ctx, "/v1/integration-health/providers", nil, out)
}

// EmbedSurface is one surface of the embed manifest.
type EmbedSurface struct {
	Tenant          bool                     `json:"tenant,omitempty"`
	ServedBy        string                   `json:"servedBy,omitempty"`
	CSP             map[string][]string      `json:"csp,omitempty"`
	Requires        map[string][]string      `json:"requires,omitempty"`
	TrustedTypes    []string                 `json:"trustedTypes,omitempty"`
	ConsentCategory string                   `json:"consentCategory,omitempty"`
	Storage         []map[string]interface{} `json:"storage,omitempty"`
	SRI             map[string]string        `json:"sri,omitempty"`
	Notes           []string                 `json:"notes,omitempty"`
}

// EmbedManifestTenant is the per-instance part of the embed manifest.
type EmbedManifestTenant struct {
	Instance         string   `json:"instance"`
	Environment      string   `json:"environment"`
	FrontendAPIHosts []string `json:"frontendApiHosts"`
	// Shape is redirect, panel, button or nil.
	Shape         *string `json:"shape"`
	Origin        *string `json:"origin"`
	OriginAllowed *bool   `json:"originAllowed"`
	// Policy is the merged sources for your pages, as one
	// Content-Security-Policy value.
	Policy  string              `json:"policy"`
	Sources map[string][]string `json:"sources"`
}

// EmbedChange is a dated change to a surface's CSP sources.
type EmbedChange struct {
	Effective string              `json:"effective"`
	Surface   string              `json:"surface"`
	Add       map[string][]string `json:"add"`
	Remove    map[string][]string `json:"remove"`
	Note      string              `json:"note,omitempty"`
}

// EmbedManifestCheckers describes the callers that probe your pages.
type EmbedManifestCheckers struct {
	UserAgent  string   `json:"userAgent"`
	UserAgents []string `json:"userAgents,omitempty"`
	Egress     []string `json:"egress"`
}

// EmbedManifest is the embed manifest (embed-v1) for one instance: CSP sources
// per surface, storage, SRI and the merged policy.
type EmbedManifest struct {
	Schema   string                  `json:"schema"`
	Product  string                  `json:"product"`
	Updated  string                  `json:"updated"`
	OpenAPI  string                  `json:"openapi,omitempty"`
	LLMS     string                  `json:"llms,omitempty"`
	Status   string                  `json:"status,omitempty"`
	Docs     string                  `json:"docs,omitempty"`
	Checkers *EmbedManifestCheckers  `json:"checkers,omitempty"`
	Surfaces map[string]EmbedSurface `json:"surfaces"`
	Changes  []EmbedChange           `json:"changes"`
	Tenant   *EmbedManifestTenant    `json:"tenant,omitempty"`
}

// EmbedParams selects the embed manifest.
type EmbedParams struct {
	// Instance is the instance id (required).
	Instance string
	// Origin is the page origin to check against the allowed origins.
	Origin string
	// Shape is redirect, panel or button.
	Shape string
}

// Embed returns the embed manifest for an instance (public; no key needed):
// CSP sources per surface with its hosts filled in, and the merged policy in
// Tenant.Policy. GET /v1/embed.
func (s *InstanceService) Embed(ctx context.Context, params EmbedParams) (*EmbedManifest, error) {
	out := &EmbedManifest{}
	q := url.Values{"instance": {params.Instance}}
	if params.Origin != "" {
		q.Set("origin", params.Origin)
	}
	if params.Shape != "" {
		q.Set("shape", params.Shape)
	}
	return out, s.client.get(ctx, "/v1/embed", q, out)
}
