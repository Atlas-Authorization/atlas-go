package atlas

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// Policy acceptance: the policies (Terms of Service, privacy policy, any key)
// your users accept at sign-up and, per policy, again at sign-in when a new
// version takes effect. A policy's versions go draft, published (with an
// effective_at), retired. Acceptances are append-only evidence (version,
// content hash, how it was shown). Anywhere a policy is named, either its id
// or its key works.
//
// Content can also come from any external system through the policy source
// protocol: see PolicySourceService and VerifyPolicyFeedRequest.

// Webhook event types for policy acceptance.
const (
	// WebhookEventUserPolicyAccepted: a user accepted a policy version (the
	// payload carries policy_acceptance with its evidence).
	WebhookEventUserPolicyAccepted = "user.policy_accepted"
	// WebhookEventPolicyVersionPublished: a policy version was published.
	WebhookEventPolicyVersionPublished = "policy.version_published"
)

// Policy display modes, scopes and re-accept rules.
const (
	PolicyDisplayCheckbox = "checkbox"
	PolicyDisplayScroll   = "scroll"
	PolicyDisplayLink     = "link"

	PolicyAppliesToSignUp          = "sign_up"
	PolicyAppliesToSignInAndSignUp = "sign_in_and_sign_up"

	PolicyReacceptNone       = "none"
	PolicyReacceptNextSignIn = "next_sign_in"
	PolicyReacceptGrace      = "grace"
)

// PolicyVersionRef is a policy's current, upcoming or latest version.
type PolicyVersionRef struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	ContentSHA256 string `json:"content_sha256"`
	PublishedAt   *int64 `json:"published_at"`
	EffectiveAt   *int64 `json:"effective_at"`
}

// Policy is one policy.
type Policy struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Key       string `json:"key"`
	Title     string `json:"title"`
	Display   string `json:"display"`
	Required  bool   `json:"required"`
	AppliesTo string `json:"applies_to"`
	Reaccept  string `json:"reaccept"`
	GraceDays *int   `json:"grace_days"`
	Source    string `json:"source"` // "atlas" or "external"
	Position  int    `json:"position"`
	Status    string `json:"status"` // "active" or "retired"
	// Overrides lists the fields of an external policy changed in Atlas that
	// a sync keeps.
	Overrides []string `json:"overrides"`
	// CurrentVersion is the version in effect now; UpcomingVersion a newer
	// published one that is not in effect yet; LatestVersion the newest of any
	// status (drafts included).
	CurrentVersion  *PolicyVersionRef `json:"current_version"`
	UpcomingVersion *PolicyVersionRef `json:"upcoming_version"`
	LatestVersion   *PolicyVersionRef `json:"latest_version"`
	RetiredAt       *int64            `json:"retired_at"`
	CreatedAt       int64             `json:"created_at"`
	UpdatedAt       int64             `json:"updated_at"`
}

// PolicyVersion is one version of a policy.
type PolicyVersion struct {
	Object          string  `json:"object"`
	ID              string  `json:"id"`
	PolicyID        string  `json:"policy_id"`
	Policy          string  `json:"policy"`
	Version         string  `json:"version"`
	Status          string  `json:"status"` // draft, published or retired
	ContentMarkdown *string `json:"content_markdown"`
	// ContentHTML is the sanitised HTML clients render.
	ContentHTML string  `json:"content_html"`
	ContentURL  *string `json:"content_url"`
	// ContentSHA256 is the hex SHA-256 of ContentHTML.
	ContentSHA256    string  `json:"content_sha256"`
	SummaryOfChanges *string `json:"summary_of_changes"`
	Locale           *string `json:"locale"`
	PublishedAt      *int64  `json:"published_at"`
	EffectiveAt      *int64  `json:"effective_at"`
	RetiredAt        *int64  `json:"retired_at"`
	CreatedAt        int64   `json:"created_at"`
	UpdatedAt        int64   `json:"updated_at"`
	// AcceptanceCount is set on a list: how many users accepted this version.
	AcceptanceCount *int `json:"acceptance_count,omitempty"`
}

// PolicyAcceptance is one acceptance (or withdrawal) with its evidence.
type PolicyAcceptance struct {
	Object          string  `json:"object"`
	ID              string  `json:"id"`
	UserID          string  `json:"user_id"`
	Policy          string  `json:"policy"`
	Version         string  `json:"version"`
	PolicyVersionID *string `json:"policy_version_id"`
	Status          string  `json:"status"` // accepted or withdrawn
	// Source is signup, signin, reaccept, api, import or another string.
	Source        *string `json:"source"`
	ContentSHA256 *string `json:"content_sha256"`
	Display       *string `json:"display"`
	ScrolledToEnd *bool   `json:"scrolled_to_end"`
	ViewMS        *int64  `json:"view_ms"`
	Locale        *string `json:"locale"`
	IP            *string `json:"ip"`
	UserAgent     *string `json:"user_agent"`
	AcceptedAt    int64   `json:"accepted_at"`
}

// PolicyStanding is a user's standing on one policy.
type PolicyStanding struct {
	Object            string  `json:"object"`
	Policy            string  `json:"policy"`
	PolicyID          string  `json:"policy_id"`
	Title             string  `json:"title"`
	Display           string  `json:"display"`
	Required          bool    `json:"required"`
	AppliesTo         string  `json:"applies_to"`
	Reaccept          string  `json:"reaccept"`
	CurrentVersionID  *string `json:"current_version_id"`
	CurrentVersion    *string `json:"current_version"`
	ContentSHA256     *string `json:"content_sha256"`
	SummaryOfChanges  *string `json:"summary_of_changes"`
	AcceptedVersionID *string `json:"accepted_version_id"`
	AcceptedVersion   *string `json:"accepted_version"`
	AcceptedAt        *int64  `json:"accepted_at"`
	NeedsReaccept     bool    `json:"needs_reaccept"`
	// Blocking: accepting is required before the user's next sign-in completes.
	Blocking    bool   `json:"blocking"`
	GraceEndsAt *int64 `json:"grace_ends_at"`
}

// UserPolicies is GET /v1/users/:id/policies.
type UserPolicies struct {
	Object          string           `json:"object"`
	UserID          string           `json:"user_id"`
	Data            []PolicyStanding `json:"data"`
	NeedsAcceptance bool             `json:"needs_acceptance"`
}

// PolicySettings are the instance's policy settings.
type PolicySettings struct {
	Object string `json:"object"`
	// SessionClaim puts the pol claim (the accepted version of each required
	// policy) on session tokens.
	SessionClaim bool `json:"session_claim"`
}

// CreatePolicyParams is the body of POST /v1/policies.
type CreatePolicyParams struct {
	// Key is a slug, unique per instance (tos, privacy). It becomes the
	// consent record's policy.
	Key       string `json:"key"`
	Title     string `json:"title"`
	Display   string `json:"display,omitempty"`
	Required  *bool  `json:"required,omitempty"`
	AppliesTo string `json:"applies_to,omitempty"`
	Reaccept  string `json:"reaccept,omitempty"`
	// GraceDays is required with Reaccept "grace" (1-365).
	GraceDays *int `json:"grace_days,omitempty"`
	Position  *int `json:"position,omitempty"`
}

// UpdatePolicyParams is the body of PATCH /v1/policies/:id. The key cannot
// change. Only the fields set are sent; ClearGraceDays sends null.
type UpdatePolicyParams struct {
	Title     string `json:"title,omitempty"`
	Display   string `json:"display,omitempty"`
	Required  *bool  `json:"required,omitempty"`
	AppliesTo string `json:"applies_to,omitempty"`
	Reaccept  string `json:"reaccept,omitempty"`
	GraceDays *int   `json:"grace_days,omitempty"`
	Position  *int   `json:"position,omitempty"`
	// Status "retired" stops the policy gating (history is kept); "active"
	// brings it back.
	Status         string `json:"status,omitempty"`
	ClearGraceDays bool   `json:"-"`
}

// MarshalJSON sends grace_days as null when ClearGraceDays is set.
func (p UpdatePolicyParams) MarshalJSON() ([]byte, error) {
	type plain UpdatePolicyParams
	var extra map[string]interface{}
	if p.ClearGraceDays {
		extra = map[string]interface{}{"grace_days": nil}
	}
	return marshalWithExtra(plain(p), extra)
}

// CreatePolicyVersionParams is the body of POST /v1/policies/:id/versions.
type CreatePolicyVersionParams struct {
	// Version is a label such as 2026-10-24 or 1.2.0, unique per policy.
	Version string `json:"version"`
	// ContentMarkdown is rendered and sanitised by Atlas; or send ContentHTML.
	ContentMarkdown  string `json:"content_markdown,omitempty"`
	ContentHTML      string `json:"content_html,omitempty"`
	ContentURL       string `json:"content_url,omitempty"`
	SummaryOfChanges string `json:"summary_of_changes,omitempty"`
	Locale           string `json:"locale,omitempty"`
	// Publish publishes at once instead of saving a draft.
	Publish bool `json:"publish,omitempty"`
	// EffectiveAt (with Publish): when the gate starts asking for it, epoch
	// ms (int64) or an ISO 8601 string; default now.
	EffectiveAt interface{} `json:"effective_at,omitempty"`
}

// UpdatePolicyVersionParams is the body of PATCH /v1/policies/:id/versions/:versionId
// (drafts only). The Clear flags send null.
type UpdatePolicyVersionParams struct {
	Version          string `json:"version,omitempty"`
	ContentMarkdown  string `json:"content_markdown,omitempty"`
	ContentHTML      string `json:"content_html,omitempty"`
	ContentURL       string `json:"content_url,omitempty"`
	SummaryOfChanges string `json:"summary_of_changes,omitempty"`
	Locale           string `json:"locale,omitempty"`

	ClearContentURL       bool `json:"-"`
	ClearSummaryOfChanges bool `json:"-"`
	ClearLocale           bool `json:"-"`
}

// MarshalJSON sends the Clear* fields as null.
func (p UpdatePolicyVersionParams) MarshalJSON() ([]byte, error) {
	type plain UpdatePolicyVersionParams
	extra := map[string]interface{}{}
	if p.ClearContentURL {
		extra["content_url"] = nil
	}
	if p.ClearSummaryOfChanges {
		extra["summary_of_changes"] = nil
	}
	if p.ClearLocale {
		extra["locale"] = nil
	}
	return marshalWithExtra(plain(p), extra)
}

// PublishPolicyVersionParams is the body of the publish call.
type PublishPolicyVersionParams struct {
	// EffectiveAt is when sign-ups must accept it and sign-ins re-ask per the
	// policy's reaccept rule: epoch ms (int64) or ISO 8601; default now.
	EffectiveAt interface{} `json:"effective_at,omitempty"`
}

// ListPolicyAcceptancesParams filters the acceptances of a policy.
type ListPolicyAcceptancesParams struct {
	// Version is a version id or label.
	Version string
	// Status is accepted (default), withdrawn or all.
	Status        string
	Limit         int
	StartingAfter string
}

func (p ListPolicyAcceptancesParams) values() url.Values {
	q := url.Values{}
	if p.Version != "" {
		q.Set("version", p.Version)
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.StartingAfter != "" {
		q.Set("starting_after", p.StartingAfter)
	}
	return q
}

// DeletedPolicy is the answer to deleting a policy: Deleted for a never-published
// policy, Retired (with Policy) for one with history.
type DeletedPolicy struct {
	Object  string  `json:"object"`
	ID      string  `json:"id"`
	Key     string  `json:"key"`
	Deleted bool    `json:"deleted"`
	Retired bool    `json:"retired"`
	Policy  *Policy `json:"policy,omitempty"`
}

// DeletedPolicyVersion is the answer to deleting a draft version.
type DeletedPolicyVersion struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// PoliciesService is /v1/policies.
type PoliciesService struct {
	client *Client
	// Versions are a policy's versions.
	Versions *PolicyVersionsService
	// Settings are the instance's policy settings.
	Settings *PolicySettingsService
}

// List returns the active policies (includeRetired for all), each with its
// current, upcoming and latest version. GET /v1/policies.
func (s *PoliciesService) List(ctx context.Context, includeRetired bool) (*ListPage[Policy], error) {
	q := url.Values{}
	if includeRetired {
		q.Set("include_retired", "true")
	}
	out := &ListPage[Policy]{}
	return out, s.client.get(ctx, "/v1/policies", q, out)
}

// Create creates a policy. It asks nobody anything until a version is
// published. POST /v1/policies.
func (s *PoliciesService) Create(ctx context.Context, params CreatePolicyParams, opts ...RequestOption) (*Policy, error) {
	out := &Policy{}
	return out, s.client.post(ctx, "/v1/policies", params, out, opts...)
}

// Get returns one policy by id or key. GET /v1/policies/:id.
func (s *PoliciesService) Get(ctx context.Context, idOrKey string) (*Policy, error) {
	out := &Policy{}
	return out, s.client.get(ctx, "/v1/policies/"+url.PathEscape(idOrKey), nil, out)
}

// Update updates a policy. PATCH /v1/policies/:id.
func (s *PoliciesService) Update(ctx context.Context, idOrKey string, params UpdatePolicyParams, opts ...RequestOption) (*Policy, error) {
	out := &Policy{}
	return out, s.client.patch(ctx, "/v1/policies/"+url.PathEscape(idOrKey), params, out, opts...)
}

// Delete deletes a policy that was never published; one with a published
// version is retired instead (check Deleted / Retired). DELETE /v1/policies/:id.
func (s *PoliciesService) Delete(ctx context.Context, idOrKey string, opts ...RequestOption) (*DeletedPolicy, error) {
	out := &DeletedPolicy{}
	return out, s.client.del(ctx, "/v1/policies/"+url.PathEscape(idOrKey), out, opts...)
}

// ListAcceptances returns who accepted the policy, newest first, with the
// evidence. GET /v1/policies/:id/acceptances.
func (s *PoliciesService) ListAcceptances(ctx context.Context, idOrKey string, params ListPolicyAcceptancesParams) (*CursorPage[PolicyAcceptance], error) {
	out := &CursorPage[PolicyAcceptance]{}
	return out, s.client.get(ctx, "/v1/policies/"+url.PathEscape(idOrKey)+"/acceptances", params.values(), out)
}

// ExportAcceptancesCSV returns the acceptances as CSV (up to 100,000 rows);
// Limit and StartingAfter are ignored. GET /v1/policies/:id/acceptances?format=csv.
func (s *PoliciesService) ExportAcceptancesCSV(ctx context.Context, idOrKey string, params ListPolicyAcceptancesParams) ([]byte, error) {
	q := params.values()
	q.Del("limit")
	q.Del("starting_after")
	q.Set("format", "csv")
	return s.client.doBytes(ctx, http.MethodGet, "/v1/policies/"+url.PathEscape(idOrKey)+"/acceptances", q)
}

// ForUser returns a user's standing on every policy (accepted and current
// version, needs_reaccept, blocking, grace_ends_at). GET /v1/users/:id/policies.
func (s *PoliciesService) ForUser(ctx context.Context, userID string) (*UserPolicies, error) {
	out := &UserPolicies{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(userID)+"/policies", nil, out)
}

// PolicyVersionsService is /v1/policies/:id/versions.
type PolicyVersionsService struct{ client *Client }

func policyVersionPath(idOrKey, version string) string {
	return "/v1/policies/" + url.PathEscape(idOrKey) + "/versions/" + url.PathEscape(version)
}

// List returns the policy's versions, newest first, each with AcceptanceCount.
// GET /v1/policies/:id/versions.
func (s *PolicyVersionsService) List(ctx context.Context, idOrKey string) (*ListPage[PolicyVersion], error) {
	out := &ListPage[PolicyVersion]{}
	return out, s.client.get(ctx, "/v1/policies/"+url.PathEscape(idOrKey)+"/versions", nil, out)
}

// Create creates a draft, or publishes at once with Publish (and EffectiveAt).
// It is a 400 for an external policy: its versions come from the policy
// source. POST /v1/policies/:id/versions.
func (s *PolicyVersionsService) Create(ctx context.Context, idOrKey string, params CreatePolicyVersionParams, opts ...RequestOption) (*PolicyVersion, error) {
	out := &PolicyVersion{}
	return out, s.client.post(ctx, "/v1/policies/"+url.PathEscape(idOrKey)+"/versions", params, out, opts...)
}

// Get returns one version by id or label. GET /v1/policies/:id/versions/:versionId.
func (s *PolicyVersionsService) Get(ctx context.Context, idOrKey, versionIDOrLabel string) (*PolicyVersion, error) {
	out := &PolicyVersion{}
	return out, s.client.get(ctx, policyVersionPath(idOrKey, versionIDOrLabel), nil, out)
}

// Update edits a draft (409 for a published version: publish a new one).
// PATCH /v1/policies/:id/versions/:versionId.
func (s *PolicyVersionsService) Update(ctx context.Context, idOrKey, versionIDOrLabel string, params UpdatePolicyVersionParams, opts ...RequestOption) (*PolicyVersion, error) {
	out := &PolicyVersion{}
	return out, s.client.patch(ctx, policyVersionPath(idOrKey, versionIDOrLabel), params, out, opts...)
}

// Delete deletes a draft (409 for a published version: retire it instead).
// DELETE /v1/policies/:id/versions/:versionId.
func (s *PolicyVersionsService) Delete(ctx context.Context, idOrKey, versionIDOrLabel string, opts ...RequestOption) (*DeletedPolicyVersion, error) {
	out := &DeletedPolicyVersion{}
	return out, s.client.del(ctx, policyVersionPath(idOrKey, versionIDOrLabel), out, opts...)
}

// Publish publishes a draft. POST /v1/policies/:id/versions/:versionId/publish.
func (s *PolicyVersionsService) Publish(ctx context.Context, idOrKey, versionIDOrLabel string, params PublishPolicyVersionParams, opts ...RequestOption) (*PolicyVersion, error) {
	out := &PolicyVersion{}
	return out, s.client.post(ctx, policyVersionPath(idOrKey, versionIDOrLabel)+"/publish", params, out, opts...)
}

// Retire retires a published version: it no longer gates or is offered; its
// acceptances stay. POST /v1/policies/:id/versions/:versionId/retire.
func (s *PolicyVersionsService) Retire(ctx context.Context, idOrKey, versionIDOrLabel string, opts ...RequestOption) (*PolicyVersion, error) {
	out := &PolicyVersion{}
	return out, s.client.post(ctx, policyVersionPath(idOrKey, versionIDOrLabel)+"/retire", nil, out, opts...)
}

// PolicySettingsService is /v1/instance/policy_settings.
type PolicySettingsService struct{ client *Client }

// UpdatePolicySettingsParams is the body of PATCH /v1/instance/policy_settings.
type UpdatePolicySettingsParams struct {
	SessionClaim *bool `json:"session_claim,omitempty"`
}

// Get reads the policy settings. GET /v1/instance/policy_settings.
func (s *PolicySettingsService) Get(ctx context.Context) (*PolicySettings, error) {
	out := &PolicySettings{}
	return out, s.client.get(ctx, "/v1/instance/policy_settings", nil, out)
}

// Update turns the pol session claim on or off (tokens minted after the
// change; up to 30 seconds to take effect everywhere).
// PATCH /v1/instance/policy_settings.
func (s *PolicySettingsService) Update(ctx context.Context, params UpdatePolicySettingsParams, opts ...RequestOption) (*PolicySettings, error) {
	out := &PolicySettings{}
	return out, s.client.patch(ctx, "/v1/instance/policy_settings", params, out, opts...)
}

// Policies returns the accepted version of each required policy by policy
// key, from the pol claim (empty unless the instance turned the session claim on).
func (c *SessionClaims) Policies() map[string]string {
	out := map[string]string{}
	pol, _ := c.Raw["pol"].(map[string]interface{})
	for k, v := range pol {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		}
	}
	return out
}

// AcceptedPolicyVersion returns the version of policy key the user accepted,
// from the pol claim.
func (c *SessionClaims) AcceptedPolicyVersion(key string) (string, bool) {
	v, ok := c.Policies()[key]
	return v, ok
}
