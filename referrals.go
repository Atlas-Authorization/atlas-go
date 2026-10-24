package atlas

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ReferralsService is the /v1/instance/referrals namespace: the instance's
// connection to a referral platform, the connection test and the call log.
//
// With referrals on, every interactive sign-up is reported to the platform
// before user.created is sent and before the session is issued; the answer
// lands on the user (Referral, ReferralCode, ReferralLink). A slow or failing
// platform never fails a sign-up: the call is retried, and
// user.referral_attributed is sent when it resolves. SigningSecret, APIKey and
// InboundSecret are write-only: reads return SigningSecretSet / APIKeySet /
// Inbound.SecretSet.
//
// Two-way sync: a provider with the Inbound capability sends referral changes
// made after sign-up to Inbound.URL; Atlas applies them to the user's referral
// and reports the latest one in Inbound.LastEvent.
type ReferralsService struct{ client *Client }

// ReferralProviderCapabilities says what a provider can do. An operation it
// lacks is recorded as skipped.
type ReferralProviderCapabilities struct {
	Signup     bool `json:"signup"`
	Erase      bool `json:"erase"`
	Export     bool `json:"export"`
	Partner    bool `json:"partner"`
	AutoEnroll bool `json:"auto_enroll"`
	Signal     bool `json:"signal"`
	// Alias re-keys a customer whose external_id changed after sign-up.
	Alias bool `json:"alias,omitempty"`
	// User takes user lifecycle updates (email, name, suspension).
	User bool `json:"user,omitempty"`
	// Ping answers a ping for the connection test (org, program, clock).
	Ping bool `json:"ping,omitempty"`
	// Inbound sends referral changes made after sign-up to Atlas (two-way sync).
	Inbound bool `json:"inbound,omitempty"`
}

// ReferralProvider is a referral provider Atlas supports.
type ReferralProvider struct {
	// ID is "webhook" (the Atlas referral protocol), "referalli" or another
	// vendor adapter id.
	ID           string                       `json:"id"`
	Name         string                       `json:"name"`
	Capabilities ReferralProviderCapabilities `json:"capabilities"`
	// Needs lists what must be set before Enabled can be true: endpoint_url,
	// signing_secret, api_key, connection_id, tracking_token.
	Needs                []string `json:"needs"`
	DefaultContextCookie *string  `json:"default_context_cookie"`
	DocsURL              *string  `json:"docs_url"`
	// DefaultContextCookies is every cookie the vendor has written, in the
	// order Atlas tries them.
	DefaultContextCookies []string `json:"default_context_cookies,omitempty"`
	// Aliases are retired spellings of ID that are still accepted on write
	// (for example "referally" for "referalli").
	Aliases []string `json:"aliases,omitempty"`
}

// Referral provider ids. The built-in adapter was renamed from "referally" to
// "referalli"; the API accepts both on write.
const (
	ReferralProviderWebhook         = "webhook"
	ReferralProviderReferalli       = "referalli"
	ReferralProviderReferalliLegacy = "referally"
)

// ReferralOneClick is a one-click (OAuth) install a deployment offers for a
// referral platform.
type ReferralOneClick struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Provider is what the connection is saved as: referalli or webhook (the
	// generic protocol).
	Provider    string `json:"provider"`
	Scope       string `json:"scope"`
	RedirectURI string `json:"redirect_uri"`
}

// ReferralInstall is POST /v1/instance/referrals/:preset/install.
type ReferralInstall struct {
	Object   string `json:"object"`
	Preset   string `json:"preset"`
	Provider string `json:"provider"`
	// AuthorizeURL is where to send the merchant to pick an organization and
	// program.
	AuthorizeURL string `json:"authorize_url"`
	RedirectURI  string `json:"redirect_uri"`
	// ExpiresAt is epoch ms; the link lasts 15 minutes.
	ExpiresAt int64 `json:"expires_at"`
}

// InstallReferralParams is the body of the one-click install.
type InstallReferralParams struct {
	// ReturnTo is where to send the merchant afterwards.
	ReturnTo string `json:"return_to,omitempty"`
}

// ReferralSecuritySettings is fraud and bot protection for referred sign-ups.
type ReferralSecuritySettings struct {
	// ChallengeReferredSignups is "always" (default: a sign-up carrying a
	// referral code must pass the bot challenge) or "inherit".
	ChallengeReferredSignups string `json:"challenge_referred_signups"`
	// OnHighRisk is "flag" (default), "strip" or "hold".
	OnHighRisk string `json:"on_high_risk"`
	// HoldUntilEmailVerified holds every referred sign-up until the email is proven.
	HoldUntilEmailVerified bool `json:"hold_until_email_verified"`
	// MaxReferredSignupsPerIPHour is referred sign-ups per code from one IP
	// network or device per hour before a velocity signal (1-1000, default 5).
	MaxReferredSignupsPerIPHour int `json:"max_referred_signups_per_ip_hour"`
}

// UpdateReferralSecurityParams is a partial update of the security settings:
// only the fields set change.
type UpdateReferralSecurityParams struct {
	ChallengeReferredSignups    *string `json:"challenge_referred_signups,omitempty"`
	OnHighRisk                  *string `json:"on_high_risk,omitempty"`
	HoldUntilEmailVerified      *bool   `json:"hold_until_email_verified,omitempty"`
	MaxReferredSignupsPerIPHour *int    `json:"max_referred_signups_per_ip_hour,omitempty"`
}

// ReferralLastTest is the last connection test.
type ReferralLastTest struct {
	OK bool `json:"ok"`
	// At is epoch ms.
	At         int64   `json:"at"`
	HTTPStatus *int    `json:"http_status"`
	Error      *string `json:"error"`
}

// ReferralPing is what a platform answered to a ping (the connection test,
// where the provider supports it).
type ReferralPing struct {
	OK bool `json:"ok"`
	// At is epoch ms.
	At         *int64 `json:"at,omitempty"`
	HTTPStatus *int   `json:"http_status,omitempty"`
	// ErrorCode is e.g. signature_rejected, connection_paused, timeout,
	// network_error, ping_not_ok.
	ErrorCode    *string `json:"error_code,omitempty"`
	Error        *string `json:"error,omitempty"`
	LatencyMS    *int    `json:"latency_ms,omitempty"`
	ConnectionID *string `json:"connection_id,omitempty"`
	ProgramID    *string `json:"program_id,omitempty"`
	ProgramName  *string `json:"program_name,omitempty"`
	OrgName      *string `json:"org_name,omitempty"`
	// AutoEnrollUsers is the platform connection's own auto-enrol setting.
	AutoEnrollUsers *bool `json:"auto_enroll_users,omitempty"`
	// ServerTime is the platform's clock, as it reported it.
	ServerTime *string `json:"server_time,omitempty"`
	// ClockSkewMS is the platform's clock minus Atlas's, in ms. Signed calls
	// fail past 5 minutes.
	ClockSkewMS *int64 `json:"clock_skew_ms,omitempty"`
	// ClockSkewWarning is true when the skew is over 60 seconds.
	ClockSkewWarning bool `json:"clock_skew_warning,omitempty"`
	// AdvertisedCapabilities is what the platform said it can do.
	AdvertisedCapabilities *ReferralProviderCapabilities `json:"advertised_capabilities,omitempty"`
}

// ReferralAlert is set while delivery is blocked on something only a person
// can fix. Show it as a banner.
type ReferralAlert struct {
	// Code is signature_rejected (the platform answered 401: a rotated secret
	// or clock skew) or connection_paused.
	Code    string `json:"code"`
	Message string `json:"message"`
	// At is epoch ms.
	At     int64   `json:"at"`
	CallID *string `json:"call_id,omitempty"`
}

// ReferralConnectionStatus is the connection's health.
type ReferralConnectionStatus struct {
	LastTest *ReferralLastTest `json:"last_test"`
	// LastPing is the last ping, when the provider answers one.
	LastPing *ReferralPing `json:"last_ping,omitempty"`
	// Alert is set while delivery is blocked on something only a person can fix.
	Alert *ReferralAlert `json:"alert,omitempty"`
	// FailedCalls7d counts calls that failed permanently in the last 7 days.
	FailedCalls7d int `json:"failed_calls_7d"`
	// RetryingCalls counts calls waiting for a retry.
	RetryingCalls int    `json:"retrying_calls"`
	LastSuccessAt *int64 `json:"last_success_at"`
}

// ReferralInboundEvent is the latest event a platform sent to the inbound URL.
type ReferralInboundEvent struct {
	// At is epoch ms (when Atlas received it).
	At   int64  `json:"at"`
	Type string `json:"type"`
	// Outcome is applied, unchanged, stale, unknown_customer, other_program or ignored.
	Outcome string `json:"outcome"`
}

// ReferralInboundStatus is two-way sync: where the platform sends referral
// changes made after sign-up, and the latest one received.
type ReferralInboundStatus struct {
	// URL is the URL to give the platform; nil when the provider sends no events.
	URL *string `json:"url"`
	// SecretSet says whether an inbound secret is stored (the value is never returned).
	SecretSet bool `json:"secret_set"`
	// EndpointID is the platform's id for Atlas's event subscription.
	EndpointID *string `json:"endpoint_id"`
	// LastEvent is the latest event received, or nil.
	LastEvent *ReferralInboundEvent `json:"last_event"`
}

// ReferralSettings is GET /v1/instance/referrals. Secrets are never returned.
type ReferralSettings struct {
	Object   string `json:"object"`
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	// EndpointURL is the base URL of the platform connection (Atlas referral protocol).
	EndpointURL      *string `json:"endpoint_url"`
	ProgramID        *string `json:"program_id"`
	ConnectionID     *string `json:"connection_id"`
	SigningSecretSet bool    `json:"signing_secret_set"`
	APIKeySet        bool    `json:"api_key_set"`
	// URLParams are the query parameters that carry a referral code, in priority order.
	URLParams     []string `json:"url_params"`
	ContextCookie *string  `json:"context_cookie"`
	// ContextCookies lists every tracking cookie, in the order they are tried.
	ContextCookies []string `json:"context_cookies,omitempty"`
	// ProviderAliases are retired spellings of Provider still accepted on write.
	ProviderAliases []string `json:"provider_aliases,omitempty"`
	// Capabilities is what the chosen provider can do now: its built-in
	// capabilities plus what its last ping advertised.
	Capabilities *ReferralProviderCapabilities `json:"capabilities,omitempty"`
	// OneClick is the one-click connect to Referalli (the referalli preset).
	OneClick *ReferralOneClick `json:"one_click,omitempty"`
	// OneClickPresets is every platform this deployment offers a one-click
	// install for.
	OneClickPresets         []ReferralOneClick `json:"one_click_presets,omitempty"`
	ConsentCategory         string             `json:"consent_category"`
	ConsentFallbackCategory *string            `json:"consent_fallback_category"`
	AutoEnrollUsers         bool               `json:"auto_enroll_users"`
	// LinkTemplate (e.g. https://app.example.com/join?ref={code}) builds referral_link.
	LinkTemplate *string                  `json:"link_template"`
	TimeoutMS    int                      `json:"timeout_ms"`
	Security     ReferralSecuritySettings `json:"security"`
	// TrackingToken is the public tracking token (the referalli provider
	// derives the code lookup from it). Not a secret.
	TrackingToken *string `json:"tracking_token,omitempty"`
	// CodeLookupURL is a public, CORS-enabled URL template with {code} for
	// "X invited you" on hosted sign-up.
	CodeLookupURL *string `json:"code_lookup_url,omitempty"`
	// SignupCodeField shows an optional "Referral code" field on hosted sign-up.
	SignupCodeField bool `json:"signup_code_field,omitempty"`
	// BrowserSources are the referral programs whose script or cookie the
	// browser reads, in order (referalli, rewardful, tolt, promotekit,
	// firstpromoter, partnerstack, dub); the provider's default unless set.
	BrowserSources []string `json:"browser_sources,omitempty"`
	// BrowserSourcesDefault is true when BrowserSources is the provider's default.
	BrowserSourcesDefault bool `json:"browser_sources_default,omitempty"`
	// ConsentProvider is the consent manager that decides on the tracking
	// cookie's ids: auto (any common one), one manager (cookiemunch, onetrust,
	// cookiebot, didomi, usercentrics, osano, cookieyes, complianz, klaro, tcf,
	// consent_mode, gpc), or app (only the app's own decision).
	ConsentProvider string `json:"consent_provider,omitempty"`
	// ForwardLifecycle forwards email, name and suspension changes to the
	// platform (default true).
	ForwardLifecycle bool `json:"forward_lifecycle,omitempty"`
	// MirrorToPublicMetadata mirrors the result into public_metadata.referral.
	MirrorToPublicMetadata bool `json:"mirror_to_public_metadata,omitempty"`
	// IncludeReferralClaims adds the user's own code as a referral_code claim
	// to session tokens and ID tokens.
	IncludeReferralClaims bool `json:"include_referral_claims,omitempty"`
	// Missing lists what the chosen provider still needs before referrals can be enabled.
	Missing    []string                  `json:"missing"`
	Connection *ReferralConnectionStatus `json:"connection"`
	// Inbound is two-way sync: the URL the platform sends referral changes to
	// and the latest one received.
	Inbound   *ReferralInboundStatus `json:"inbound,omitempty"`
	Providers []ReferralProvider     `json:"providers"`
	UpdatedAt *int64                 `json:"updated_at"`
}

// UpdateReferralSettingsParams is the body of PATCH /v1/instance/referrals:
// only the fields set change. Clear names nullable fields to clear (sent as
// null): endpoint_url, program_id, connection_id, signing_secret, api_key,
// inbound_secret, inbound_endpoint_id, context_cookie,
// consent_fallback_category, link_template, tracking_token, code_lookup_url,
// browser_sources (null goes back to the provider's default). Enabling without
// what the provider needs is 422 REFERRALS_NOT_CONFIGURED.
type UpdateReferralSettingsParams struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Provider string `json:"provider,omitempty"`
	// EndpointURL must be https (http only for localhost on a development instance).
	EndpointURL  string `json:"endpoint_url,omitempty"`
	ProgramID    string `json:"program_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	// SigningSecret is write-only, 16-512 characters.
	SigningSecret string `json:"signing_secret,omitempty"`
	// APIKey is the write-only vendor API key.
	APIKey string `json:"api_key,omitempty"`
	// InboundSecret is write-only, 16-512 characters: it verifies the
	// platform's events to Inbound.URL. Optional for the Atlas referral
	// protocol (the signing secret is used when unset).
	InboundSecret string `json:"inbound_secret,omitempty"`
	// InboundEndpointID is the platform's id for Atlas's event subscription,
	// kept for reference.
	InboundEndpointID string   `json:"inbound_endpoint_id,omitempty"`
	URLParams         []string `json:"url_params,omitempty"`
	ContextCookie     string   `json:"context_cookie,omitempty"`
	// ContextCookies is a list of up to 5 cookie names tried in order; it
	// wins over ContextCookie.
	ContextCookies          []string                      `json:"context_cookies,omitempty"`
	ConsentCategory         string                        `json:"consent_category,omitempty"`
	ConsentFallbackCategory string                        `json:"consent_fallback_category,omitempty"`
	AutoEnrollUsers         *bool                         `json:"auto_enroll_users,omitempty"`
	LinkTemplate            string                        `json:"link_template,omitempty"`
	TimeoutMS               int                           `json:"timeout_ms,omitempty"`
	Security                *UpdateReferralSecurityParams `json:"security,omitempty"`
	// TrackingToken is 1-128 of A-Z a-z 0-9 _ -.
	TrackingToken string `json:"tracking_token,omitempty"`
	// CodeLookupURL is an https URL template containing {code}.
	CodeLookupURL   string `json:"code_lookup_url,omitempty"`
	SignupCodeField *bool  `json:"signup_code_field,omitempty"`
	// BrowserSources are the programs to read, in order; clear
	// browser_sources to go back to the provider's default.
	BrowserSources []string `json:"browser_sources,omitempty"`
	// ConsentProvider is auto, one consent manager, or app.
	ConsentProvider        string   `json:"consent_provider,omitempty"`
	ForwardLifecycle       *bool    `json:"forward_lifecycle,omitempty"`
	MirrorToPublicMetadata *bool    `json:"mirror_to_public_metadata,omitempty"`
	IncludeReferralClaims  *bool    `json:"include_referral_claims,omitempty"`
	Clear                  []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdateReferralSettingsParams) MarshalJSON() ([]byte, error) {
	type plain UpdateReferralSettingsParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
}

// ReferralTestError says why a connection test failed.
type ReferralTestError struct {
	// Code is e.g. signature_rejected (the platform answered 401/403), timeout,
	// network_error, url_blocked, http_500.
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ReferralConnectionTest is POST /v1/instance/referrals/test.
type ReferralConnectionTest struct {
	OK         bool               `json:"ok"`
	HTTPStatus *int               `json:"http_status"`
	LatencyMS  *int               `json:"latency_ms"`
	Error      *ReferralTestError `json:"error,omitempty"`
	// Method is ping when the platform answered a ping, probe for the signed
	// export probe.
	Method string `json:"method,omitempty"`
	// Ping is the ping answer, when the provider supports ping.
	Ping *ReferralPing `json:"ping,omitempty"`
	// Warnings are e.g. a clock more than 60 seconds off.
	Warnings []string `json:"warnings,omitempty"`
}

// ReferralSimulateParams is the body of POST /v1/instance/referrals/simulate.
type ReferralSimulateParams struct {
	// Code is the referral code to try; empty sends a sign-up with no code.
	Code string `json:"code,omitempty"`
}

// ReferralSimulationMatch is the matched referral in a simulation.
type ReferralSimulationMatch struct {
	PartnerID          *string `json:"partner_id"`
	PartnerExternalRef *string `json:"partner_external_ref"`
	MatchedVia         *string `json:"matched_via"`
	Status             *string `json:"status"`
}

// ReferralSimulationPartner is the partner record a simulation returned.
type ReferralSimulationPartner struct {
	ID   *string `json:"id"`
	Code *string `json:"code"`
	Link *string `json:"link"`
}

// ReferralSimulationResult is the platform's answer to a simulation, normalised.
type ReferralSimulationResult struct {
	Referral *ReferralSimulationMatch   `json:"referral"`
	Partner  *ReferralSimulationPartner `json:"partner"`
	Notes    []string                   `json:"notes"`
}

// ReferralSimulateResult is POST /v1/instance/referrals/simulate: a sign-up
// call for a made-up user. No user is created.
type ReferralSimulateResult struct {
	Object string `json:"object"`
	OK     bool   `json:"ok"`
	// CallID is the logged call, in the delivery log.
	CallID *string `json:"call_id"`
	// CustomerRef is atlas_test_<random>.
	CustomerRef string `json:"customer_ref"`
	HTTPStatus  *int   `json:"http_status"`
	LatencyMS   *int   `json:"latency_ms"`
	// Result is nil when the call failed.
	Result *ReferralSimulationResult `json:"result"`
	// Response is the platform's raw answer, personal fields removed.
	Response map[string]interface{} `json:"response"`
	Error    *ReferralTestError     `json:"error"`
}

// RetryFailedReferralCallsParams is the body of
// POST /v1/instance/referrals/calls/retry_failed. Zero values are omitted.
type RetryFailedReferralCallsParams struct {
	// Kind is signup, erase, partner, signal, alias or user.
	Kind string `json:"kind,omitempty"`
	// ErrorCode is e.g. signature_rejected after replacing the secret.
	ErrorCode string `json:"error_code,omitempty"`
}

// ReferralRetryFailedResult is POST /v1/instance/referrals/calls/retry_failed.
type ReferralRetryFailedResult struct {
	Object string `json:"object"`
	// Requeued counts the failed calls queued to send now.
	Requeued int `json:"requeued"`
}

// ReferralBackfillParams is the body of POST /v1/instance/referrals/backfill.
type ReferralBackfillParams struct {
	// Since is an ISO 8601 date or date-time: users created at or after it.
	Since string `json:"since"`
	// Codes maps customerRef (external_id or user id) to a referral code, up
	// to 10,000. It wins over CodeMetadataPath.
	Codes map[string]string `json:"codes,omitempty"`
	// CodeMetadataPath is where each user keeps the code they arrived with,
	// e.g. public_metadata.referral_code.
	CodeMetadataPath string `json:"code_metadata_path,omitempty"`
}

// ReferralBackfillCalls says where a backfill's queued calls stand.
type ReferralBackfillCalls struct {
	Pending   int `json:"pending"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
	Held      int `json:"held"`
}

// ReferralBackfillJob is a backfill job. Users already reported are skipped.
type ReferralBackfillJob struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Status is running while any queued call is still to be sent, then completed.
	Status string `json:"status"`
	// Since is epoch ms.
	Since            int64   `json:"since"`
	CodeMetadataPath *string `json:"code_metadata_path"`
	// CodesGiven counts the codes given in Codes.
	CodesGiven   int `json:"codes_given"`
	UsersScanned int `json:"users_scanned"`
	// UsersSkipped counts users already reported, or with no code while
	// auto-enrol is off.
	UsersSkipped int `json:"users_skipped"`
	CallsQueued  int `json:"calls_queued"`
	// Truncated is true when more users matched than one backfill takes: run
	// again from NextSince.
	Truncated bool `json:"truncated"`
	// NextSince is epoch ms, when Truncated.
	NextSince  *int64                `json:"next_since"`
	Calls      ReferralBackfillCalls `json:"calls"`
	CreatedAt  int64                 `json:"created_at"`
	FinishedAt *int64                `json:"finished_at"`
}

// UserReferralResult is GET /v1/users/:id/referral: the stored result of a
// user's referral calls, with no call to the platform.
type UserReferralResult struct {
	Object string `json:"object"`
	UserID string `json:"user_id"`
	// Status is pending, attributed, none, failed, held or flagged.
	Status string `json:"status"`
	// CustomerRef is the id the platform knows the user by: their
	// external_id, else the Atlas user id.
	CustomerRef string  `json:"customer_ref"`
	PartnerID   *string `json:"partner_id"`
	// PartnerExternalRef is the referrer as the platform knows them.
	PartnerExternalRef *string `json:"partner_external_ref"`
	ReferrerUserID     *string `json:"referrer_user_id"`
	MatchedVia         *string `json:"matched_via"`
	// ReferralStatus is the platform's own status for the referral.
	ReferralStatus *string `json:"referral_status"`
	// Notes are the platform's reasoning notes.
	Notes        []string `json:"notes"`
	ReferralCode *string  `json:"referral_code"`
	ReferralLink *string  `json:"referral_link"`
	// Context is the referral captured at sign-up, as sent (camelCase).
	Context   map[string]interface{} `json:"context"`
	RiskLevel *string                `json:"risk_level"`
	Flagged   bool                   `json:"flagged"`
	// HoldReason says why the sign-up report is held, while Status is held.
	HoldReason *string `json:"hold_reason"`
	// SignedUpAt and UpdatedAt are epoch ms.
	SignedUpAt int64 `json:"signed_up_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// ReferralCallHighlights says, for a sign-up call, how the platform matched
// the referral and why.
type ReferralCallHighlights struct {
	MatchedVia         *string  `json:"matched_via"`
	PartnerExternalRef *string  `json:"partner_external_ref"`
	Notes              []string `json:"notes"`
}

// ReferralRisk is the risk verdict sent with a sign-up (camelCase, as on the
// referral protocol).
type ReferralRisk struct {
	// Level is low, medium or high.
	Level string `json:"level"`
	// Score is 0-100.
	Score int `json:"score"`
	// Signals are e.g. self_referral, ip_velocity, device_velocity,
	// disposable_email, datacenter_ip, tor_ip, captcha_not_passed,
	// email_unverified, restricted_identifier.
	Signals []string `json:"signals"`
	// Captcha is passed, not_required or not_configured.
	Captcha       string `json:"captcha"`
	EmailVerified bool   `json:"emailVerified"`
}

// ReferralCall is one call in the referral call log.
type ReferralCall struct {
	Object string `json:"object"`
	// ID is also the signed atlas-id header of every attempt.
	ID string `json:"id"`
	// TraceID correlates the call with the request that caused it (W3C
	// traceparent trace-id).
	TraceID *string `json:"trace_id,omitempty"`
	// Kind is signup, erase, export, partner, signal, alias, user, ping or test.
	Kind string `json:"kind"`
	// Status is pending, succeeded, retrying, failed, held or skipped.
	Status string `json:"status"`
	// Outcome (sign-ups) is referred, not_referred or stripped.
	Outcome     *string `json:"outcome"`
	CustomerRef string  `json:"customer_ref"`
	UserID      *string `json:"user_id"`
	HTTPStatus  *int    `json:"http_status"`
	LastError   *string `json:"last_error"`
	Attempts    int     `json:"attempts"`
	// NextAttemptAt is epoch ms of the next retry, while pending or retrying.
	NextAttemptAt *int64        `json:"next_attempt_at"`
	Risk          *ReferralRisk `json:"risk"`
	// Payload is what was sent (never secrets).
	Payload map[string]interface{} `json:"payload"`
	// LatencyMS is the round trip of the last attempt.
	LatencyMS *int `json:"latency_ms,omitempty"`
	// ErrorCode says why the last attempt failed, e.g. signature_rejected
	// (401, not retried), connection_paused (not retried), rate_limited,
	// timeout, network_error, alias_conflict, http_<status>.
	ErrorCode *string `json:"error_code,omitempty"`
	// Response is the platform's last answer, personal fields removed.
	Response map[string]interface{} `json:"response,omitempty"`
	// Highlights (sign-up calls) say how the platform matched and why.
	Highlights *ReferralCallHighlights `json:"highlights,omitempty"`
	// RequestID is the platform's request id for its last answer.
	RequestID *string `json:"request_id,omitempty"`
	// BatchID is the backfill job that queued the call.
	BatchID   *string `json:"batch_id,omitempty"`
	CreatedAt int64   `json:"created_at"`
	UpdatedAt int64   `json:"updated_at"`
}

// ListReferralCallsParams filters the call log. Zero values are omitted.
type ListReferralCallsParams struct {
	// Limit is 1-1000 (default 50; servers before referral attribution v2
	// take at most 200), newest first.
	Limit  int
	Status string
	Kind   string
	UserID string
	// ErrorCode keeps only calls whose last failure had this code, e.g.
	// signature_rejected.
	ErrorCode string
	// Trace keeps only the calls of one operation (trace id).
	Trace string
	// StartingAfter is the id of the last call of the previous page.
	StartingAfter string
}

func (p ListReferralCallsParams) values() url.Values {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Kind != "" {
		q.Set("kind", p.Kind)
	}
	if p.UserID != "" {
		q.Set("user_id", p.UserID)
	}
	if p.ErrorCode != "" {
		q.Set("error_code", p.ErrorCode)
	}
	if p.Trace != "" {
		q.Set("trace", p.Trace)
	}
	if p.StartingAfter != "" {
		q.Set("starting_after", p.StartingAfter)
	}
	return q
}

// Get reads the referral settings, connection status and supported providers.
// GET /v1/instance/referrals.
func (s *ReferralsService) Get(ctx context.Context) (*ReferralSettings, error) {
	out := &ReferralSettings{}
	return out, s.client.get(ctx, "/v1/instance/referrals", nil, out)
}

// Update patches the referral settings. PATCH /v1/instance/referrals.
func (s *ReferralsService) Update(ctx context.Context, params UpdateReferralSettingsParams, opts ...RequestOption) (*ReferralSettings, error) {
	out := &ReferralSettings{}
	return out, s.client.patch(ctx, "/v1/instance/referrals", params, out, opts...)
}

// Test tests the connection: a ping where the provider answers one (Method
// ping, with Ping and Warnings such as clock skew), else a signed probe
// (Method probe: OK on 2xx or 404). Error.Code is signature_rejected on
// 401/403. POST /v1/instance/referrals/test.
func (s *ReferralsService) Test(ctx context.Context) (*ReferralConnectionTest, error) {
	out := &ReferralConnectionTest{}
	return out, s.client.post(ctx, "/v1/instance/referrals/test", nil, out)
}

// ListCalls returns the call log, newest first. GET /v1/instance/referrals/calls.
func (s *ReferralsService) ListCalls(ctx context.Context, params ListReferralCallsParams) (*ListPage[ReferralCall], error) {
	out := &ListPage[ReferralCall]{}
	return out, s.client.get(ctx, "/v1/instance/referrals/calls", params.values(), out)
}

// RetryCall retries a failed, retrying or skipped call now (not a connection
// test). POST /v1/instance/referrals/calls/:id/retry.
func (s *ReferralsService) RetryCall(ctx context.Context, id string, opts ...RequestOption) (*ReferralCall, error) {
	out := &ReferralCall{}
	return out, s.client.post(ctx, "/v1/instance/referrals/calls/"+url.PathEscape(id)+"/retry", nil, out, opts...)
}

// RetryFailed re-queues every failed call (not tests) to send now, optionally
// only one kind or one error code. POST /v1/instance/referrals/calls/retry_failed.
func (s *ReferralsService) RetryFailed(ctx context.Context, params RetryFailedReferralCallsParams, opts ...RequestOption) (*ReferralRetryFailedResult, error) {
	out := &ReferralRetryFailedResult{}
	return out, s.client.post(ctx, "/v1/instance/referrals/calls/retry_failed", params, out, opts...)
}

// Simulate sends a sign-up call for a made-up user (atlas_test_<random>; no
// user is created) with an optional code, and returns what the platform
// answered. POST /v1/instance/referrals/simulate.
func (s *ReferralsService) Simulate(ctx context.Context, params ReferralSimulateParams) (*ReferralSimulateResult, error) {
	out := &ReferralSimulateResult{}
	return out, s.client.post(ctx, "/v1/instance/referrals/simulate", params, out)
}

// Backfill queues sign-up calls for existing users created at or after Since,
// with their real sign-up time. Users already reported are skipped. Referrals
// must be on (422 REFERRALS_NOT_CONFIGURED otherwise). Poll GetBackfill.
// POST /v1/instance/referrals/backfill.
func (s *ReferralsService) Backfill(ctx context.Context, params ReferralBackfillParams, opts ...RequestOption) (*ReferralBackfillJob, error) {
	out := &ReferralBackfillJob{}
	return out, s.client.post(ctx, "/v1/instance/referrals/backfill", params, out, opts...)
}

// GetBackfill reads a backfill job. GET /v1/instance/referrals/backfill/:id.
func (s *ReferralsService) GetBackfill(ctx context.Context, id string) (*ReferralBackfillJob, error) {
	out := &ReferralBackfillJob{}
	return out, s.client.get(ctx, "/v1/instance/referrals/backfill/"+url.PathEscape(id), nil, out)
}

// GetForUser returns the stored referral result for one user (who referred
// them, how, their own code), with no call to the platform. 404 when the user
// was never reported. GET /v1/users/:id/referral.
func (s *ReferralsService) GetForUser(ctx context.Context, userID string) (*UserReferralResult, error) {
	out := &UserReferralResult{}
	return out, s.client.get(ctx, "/v1/users/"+url.PathEscape(userID)+"/referral", nil, out)
}

// ---------------------------------------------------------------------------
// The Atlas referral protocol, for a referral platform receiving Atlas's calls
// ---------------------------------------------------------------------------

// The Atlas referral protocol. An Atlas instance with referral
// attribution on (provider "webhook") calls the platform's base URL. Every
// call is a signed POST whose JSON body says which operation it is (op) and
// which customer it is about:
//
//	POST {base}/signups   {op: signup, customerRef, ...}                    → 200 ReferralSignupResponse
//	POST {base}/erase     {op: erase, customerRef}                          → 2xx (404 = already gone)
//	POST {base}/export    {op: export, customerRef, test}                   → 200 JSON (any shape) | 404
//	POST {base}/partners  {op: partner, customerRef, code, emailHash}       → 2xx | 409 taken | 404/405/501 unsupported
//	POST {base}/signals   {op: signal, customerRef, type, occurredAt, data} → 2xx | 404/405/501 unsupported
//	POST {base}/aliases   {op: alias, customerRef, fromCustomerRef, toCustomerRef} → 2xx | 409 (permanent)
//	POST {base}/users     {op: user, customerRef, email?, name?, status?}  → 2xx
//	POST {base}/ping      {op: ping, customerRef: atlas_connection_test}    → 200 ReferralPingResponse
//
// The connection test is POST {base}/export with {op: export, customerRef:
// atlas_connection_test, test: true} (answer 2xx or 404). Every call is signed
// exactly like an Atlas webhook (atlas-id, atlas-timestamp, atlas-signature
// over "<id>.<timestamp>.<raw body>"), with Idempotency-Key,
// User-Agent: Atlas-Referrals/1 and Atlas-Referrals-Version: 2026-10-21.
// atlas-id is the call id, the same on every retry.
//
// The signature covers the body, not the URL. Pass the path the call arrived
// on (or the operation you expect): a signed body whose op does not match it
// is refused, so a captured call cannot be replayed against another endpoint.

const (
	// ReferralConnectionTestRef is the customerRef of the connection test.
	ReferralConnectionTestRef = "atlas_connection_test"
	// ReferralProtocolUserAgent is the User-Agent Atlas sends on every referral call.
	ReferralProtocolUserAgent = "Atlas-Referrals/1"
	// ReferralProtocolVersion is the Atlas-Referrals-Version Atlas sends on
	// every call; shapes only grow, additively, under it.
	ReferralProtocolVersion = "2026-10-21"
	// ReferralProtocolVersionHeader is the name of the version header.
	ReferralProtocolVersionHeader = "Atlas-Referrals-Version"
)

// Referral protocol operations (the op of every call, ReferralRequest.Op).
const (
	ReferralOpSignup  = "signup"
	ReferralOpErase   = "erase"
	ReferralOpExport  = "export"
	ReferralOpPartner = "partner"
	ReferralOpSignal  = "signal"
	ReferralOpAlias   = "alias"
	ReferralOpUser    = "user"
	ReferralOpPing    = "ping"
)

// ReferralOpEndpoints maps each operation to the endpoint (last path segment)
// it is sent to.
var ReferralOpEndpoints = map[string]string{
	ReferralOpSignup:  "signups",
	ReferralOpErase:   "erase",
	ReferralOpExport:  "export",
	ReferralOpPartner: "partners",
	ReferralOpSignal:  "signals",
	ReferralOpAlias:   "aliases",
	ReferralOpUser:    "users",
	ReferralOpPing:    "ping",
}

// Errors returned by VerifyReferralRequest besides the VerifyWebhook ones.
var (
	// ErrReferralMalformedBody: the signed body is not a JSON object.
	ErrReferralMalformedBody = errors.New("atlas referral: body is not a JSON object")
	// ErrReferralMissingOp: the signed body has no op.
	ErrReferralMissingOp = errors.New("atlas referral: body has no op")
	// ErrReferralUnknownOp: the signed op is not a protocol operation.
	ErrReferralUnknownOp = errors.New("atlas referral: unknown op")
	// ErrReferralUnknownEndpoint: the path's last segment is not a protocol endpoint.
	ErrReferralUnknownEndpoint = errors.New("atlas referral: path is not a referral protocol endpoint")
	// ErrReferralOpMismatch: the signed op is not the operation of the endpoint
	// the call arrived on, or not the expected operation (a replay against
	// another endpoint).
	ErrReferralOpMismatch = errors.New("atlas referral: op does not match the endpoint")
)

// Lifecycle signal types (ReferralSignalPayload.Type).
const (
	ReferralSignalEmailVerified  = "email_verified"
	ReferralSignalUserBanned     = "user_banned"
	ReferralSignalUserUnbanned   = "user_unbanned"
	ReferralSignalUserLocked     = "user_locked"
	ReferralSignalRiskElevated   = "risk_elevated"
	ReferralSignalFraudConfirmed = "fraud_confirmed"
)

// ReferralContext is the referral captured at sign-up. Never trusted.
type ReferralContext struct {
	Code    *string `json:"code"`
	ClickID *string `json:"clickId"`
	AnonID  *string `json:"anonId"`
	// CapturedAt is ISO 8601.
	CapturedAt string `json:"capturedAt"`
	// Consent is "granted" (cookie read under consent) or "not_required" (URL code only).
	Consent string `json:"consent"`
}

// ReferralRejection is set when Atlas stripped the referral (risk policy).
type ReferralRejection struct {
	Reason string `json:"reason"`
}

// ReferralSignupPayload is the body of POST {base}/signups. Idempotent on CustomerRef.
type ReferralSignupPayload struct {
	Op string `json:"op"`
	// CustomerRef is the app's id for the user: its external_id when set, else the Atlas user id.
	CustomerRef string `json:"customerRef"`
	// EmailHash is the sha256 hex of the lower-cased, trimmed primary email; nil without one.
	EmailHash *string `json:"emailHash"`
	IP        *string `json:"ip"`
	UA        *string `json:"ua"`
	// SignedUpAt is ISO 8601: the original sign-up time, the same on every retry.
	SignedUpAt string  `json:"signedUpAt"`
	ProgramID  *string `json:"programId"`
	// AutoEnroll asks the platform to make the user a referrer (answer with Partner).
	AutoEnroll bool               `json:"autoEnroll"`
	Referral   *ReferralContext   `json:"referral"`
	Risk       *ReferralRisk      `json:"risk,omitempty"`
	Rejected   *ReferralRejection `json:"rejected,omitempty"`
}

// ReferralSignupMatch is the matched referral in a ReferralSignupResponse.
type ReferralSignupMatch struct {
	PartnerID *string `json:"partnerId"`
	// ReferrerExternalRef is the referrer's customerRef; Atlas maps it to a local user.
	ReferrerExternalRef *string `json:"referrerExternalRef"`
	MatchedVia          *string `json:"matchedVia"`
	Status              *string `json:"status"`
}

// ReferralPartner is the user's own partner record when AutoEnroll was true.
type ReferralPartner struct {
	ID   *string `json:"id"`
	Code *string `json:"code"`
	// Link may be omitted: Atlas builds it from its link template.
	Link *string `json:"link,omitempty"`
}

// ReferralSignupResponse is the answer to POST {base}/signups.
type ReferralSignupResponse struct {
	Referral *ReferralSignupMatch `json:"referral"`
	Partner  *ReferralPartner     `json:"partner,omitempty"`
	// Notes say why you matched or did not (shown in the Atlas delivery log
	// and on the user).
	Notes []string `json:"notes,omitempty"`
}

// ReferralErasePayload is the body of POST {base}/erase.
type ReferralErasePayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
}

// ReferralExportPayload is the body of POST {base}/export: answer what you
// hold about the customer as any JSON, or 404.
type ReferralExportPayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
	// Test is true for the connection test (customerRef atlas_connection_test).
	Test bool `json:"test"`
}

// ReferralPartnerPayload is the body of POST {base}/partners.
type ReferralPartnerPayload struct {
	Op          string  `json:"op"`
	CustomerRef string  `json:"customerRef"`
	Code        string  `json:"code"`
	EmailHash   *string `json:"emailHash"`
}

// ReferralSignalPayload is the body of POST {base}/signals.
type ReferralSignalPayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
	// Type is one of the ReferralSignal* constants (new types may appear).
	Type string `json:"type"`
	// OccurredAt is ISO 8601.
	OccurredAt string                 `json:"occurredAt"`
	Data       map[string]interface{} `json:"data"`
}

// ReferralAliasPayload is the body of POST {base}/aliases: the user's
// external_id was set or changed after the sign-up call. Re-key the customer
// from FromCustomerRef (the old value, or the Atlas user id) to
// ToCustomerRef. CustomerRef equals ToCustomerRef. A 409 is treated as
// permanent.
type ReferralAliasPayload struct {
	Op              string `json:"op"`
	CustomerRef     string `json:"customerRef"`
	FromCustomerRef string `json:"fromCustomerRef"`
	ToCustomerRef   string `json:"toCustomerRef"`
}

// ReferralUserPayload is the body of POST {base}/users: a lifecycle change.
// Email / Name are set when they changed; Status is suspended on a ban, active
// on an unban, deleted on deletion (deletion is also sent to /erase).
type ReferralUserPayload struct {
	Op          string  `json:"op"`
	CustomerRef string  `json:"customerRef"`
	Email       *string `json:"email,omitempty"`
	Name        *string `json:"name,omitempty"`
	Status      string  `json:"status,omitempty"`
}

// ReferralPingPayload is the body of POST {base}/ping: the connection test
// where the platform supports it.
type ReferralPingPayload struct {
	Op          string `json:"op"`
	CustomerRef string `json:"customerRef"`
}

// ReferralPingResponse is the answer to a ping. Every field but OK is
// optional and shown on the Atlas dashboard.
type ReferralPingResponse struct {
	OK              bool   `json:"ok"`
	ProgramName     string `json:"programName,omitempty"`
	OrgName         string `json:"orgName,omitempty"`
	AutoEnrollUsers *bool  `json:"autoEnrollUsers,omitempty"`
	// ServerTime is ISO 8601. Atlas warns when it is more than 60 seconds off.
	ServerTime string `json:"serverTime,omitempty"`
}

// ReferralRequest is a verified call from Atlas. Exactly one payload field is
// set, matching Op.
type ReferralRequest struct {
	// Op is one of the ReferralOp* constants.
	Op string
	// CustomerRef is the signed customerRef.
	CustomerRef string
	// Test is true for the connection test (an export with test: true): answer 2xx or 404.
	Test    bool
	Signup  *ReferralSignupPayload
	Erase   *ReferralErasePayload
	Export  *ReferralExportPayload
	Partner *ReferralPartnerPayload
	Signal  *ReferralSignalPayload
	Alias   *ReferralAliasPayload
	User    *ReferralUserPayload
	Ping    *ReferralPingPayload
	// Raw is the verified body.
	Raw []byte
	// DeliveryID is the signed atlas-id (the call id), the same on every retry.
	DeliveryID string
	// Timestamp is the signed atlas-timestamp (epoch ms).
	Timestamp int64
	// IdempotencyKey is the Idempotency-Key header (not signed).
	IdempotencyKey string
	// ProtocolVersion is the Atlas-Referrals-Version header, when sent (not signed).
	ProtocolVersion string
}

// ReferralVerifyOptions tunes VerifyReferralRequest. The zero value checks
// only the signature and the op.
type ReferralVerifyOptions struct {
	WebhookVerifyOptions
	// Path is the path (or URL) the call arrived on, e.g. r.URL.Path. Its last
	// segment (signups, erase, export, partners, signals, aliases, users, ping)
	// must match the signed op.
	Path string
	// ExpectedOp is the operation this handler serves; the signed op must equal it.
	ExpectedOp string
}

// ReferralOpForPath returns the operation of a path's (or URL's) last segment,
// or "" when it is not a protocol endpoint.
func ReferralOpForPath(path string) string {
	if u, err := url.Parse(path); err == nil {
		path = u.Path
	}
	segments := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(segments) == 0 {
		return ""
	}
	last := segments[len(segments)-1]
	for op, endpoint := range ReferralOpEndpoints {
		if endpoint == last {
			return op
		}
	}
	return ""
}

// VerifyReferralRequest verifies a call from Atlas to a referral platform and
// tells which operation it is. Pass the RAW body, the headers, the signing
// secret configured on the Atlas instance and, in opts, the Path the call
// arrived on (or the ExpectedOp): a signed op that does not match is
// ErrReferralOpMismatch. It also returns the VerifyWebhook errors and
// ErrReferralMalformedBody, ErrReferralMissingOp, ErrReferralUnknownOp and
// ErrReferralUnknownEndpoint.
//
//	body, _ := io.ReadAll(r.Body)
//	req, err := atlas.VerifyReferralRequest(body, r.Header, secret, &atlas.ReferralVerifyOptions{Path: r.URL.Path})
//	if err != nil { w.WriteHeader(401); return }
//	switch req.Op {
//	case atlas.ReferralOpSignup:
//		_ = json.NewEncoder(w).Encode(attribute(req.Signup)) // a ReferralSignupResponse
//	case atlas.ReferralOpExport:
//		if req.Test { w.WriteHeader(404); return }
//	case atlas.ReferralOpPing:
//		_ = json.NewEncoder(w).Encode(atlas.ReferralPingResponse{OK: true, ServerTime: time.Now().UTC().Format(time.RFC3339)})
//	}
func VerifyReferralRequest(body []byte, header http.Header, secret string, opts *ReferralVerifyOptions) (*ReferralRequest, error) {
	var hookOpts *WebhookVerifyOptions
	if opts != nil {
		hookOpts = &opts.WebhookVerifyOptions
	}
	hook, err := VerifyWebhook(body, header, secret, hookOpts)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil || envelope == nil {
		return nil, ErrReferralMalformedBody
	}
	rawOp, ok := envelope["op"]
	if !ok || string(rawOp) == "null" || string(rawOp) == `""` {
		return nil, ErrReferralMissingOp
	}
	var op string
	if json.Unmarshal(rawOp, &op) != nil {
		return nil, ErrReferralUnknownOp
	}
	if _, known := ReferralOpEndpoints[op]; !known {
		return nil, ErrReferralUnknownOp
	}
	if opts != nil && opts.Path != "" {
		endpointOp := ReferralOpForPath(opts.Path)
		if endpointOp == "" {
			return nil, ErrReferralUnknownEndpoint
		}
		if endpointOp != op {
			return nil, ErrReferralOpMismatch
		}
	}
	if opts != nil && opts.ExpectedOp != "" && opts.ExpectedOp != op {
		return nil, ErrReferralOpMismatch
	}
	out := &ReferralRequest{
		Op:              op,
		Raw:             body,
		DeliveryID:      hook.DeliveryID,
		Timestamp:       hook.Timestamp,
		IdempotencyKey:  header.Get("Idempotency-Key"),
		ProtocolVersion: header.Get(ReferralProtocolVersionHeader),
	}
	decode := func(v interface{}) error {
		if err := json.Unmarshal(body, v); err != nil {
			return ErrReferralMalformedBody
		}
		return nil
	}
	switch op {
	case ReferralOpSignup:
		p := &ReferralSignupPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Signup, out.CustomerRef = p, p.CustomerRef
	case ReferralOpErase:
		p := &ReferralErasePayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Erase, out.CustomerRef = p, p.CustomerRef
	case ReferralOpExport:
		p := &ReferralExportPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Export, out.CustomerRef, out.Test = p, p.CustomerRef, p.Test
	case ReferralOpPartner:
		p := &ReferralPartnerPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Partner, out.CustomerRef = p, p.CustomerRef
	case ReferralOpSignal:
		p := &ReferralSignalPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Signal, out.CustomerRef = p, p.CustomerRef
	case ReferralOpAlias:
		p := &ReferralAliasPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Alias, out.CustomerRef = p, p.CustomerRef
	case ReferralOpUser:
		p := &ReferralUserPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.User, out.CustomerRef = p, p.CustomerRef
	case ReferralOpPing:
		p := &ReferralPingPayload{}
		if err := decode(p); err != nil {
			return nil, err
		}
		out.Ping, out.CustomerRef = p, p.CustomerRef
	}
	return out, nil
}

// ReferralEventUpdated is the type of the event a platform sends to an Atlas
// instance's inbound URL when a referral changed after sign-up.
const ReferralEventUpdated = "referral.updated"

// ReferralUpdatedEvent is the body of a referral.updated event (two-way sync).
// CustomerRef or ReferralID names the referral; empty fields are omitted and
// stay unchanged on the Atlas side.
type ReferralUpdatedEvent struct {
	// Type is always referral.updated (set by SignReferralUpdatedEvent).
	Type string `json:"type"`
	// OccurredAt is ISO 8601: when the change happened. Atlas ignores an event
	// older than the last one applied. Default: the signing time.
	OccurredAt string `json:"occurredAt"`
	// CustomerRef is the user's customerRef, as Atlas sent it on sign-up.
	CustomerRef string `json:"customerRef,omitempty"`
	// ReferralID is the platform's referral id.
	ReferralID string `json:"referralId,omitempty"`
	ProgramID  string `json:"programId,omitempty"`
	// Status is the referral's status on the platform (e.g. qualified).
	Status    string `json:"status,omitempty"`
	PartnerID string `json:"partnerId,omitempty"`
	// ReferrerExternalRef is the referrer's customerRef, when the referrer is an Atlas user.
	ReferrerExternalRef string `json:"referrerExternalRef,omitempty"`
	MatchedVia          string `json:"matchedVia,omitempty"`
}

// ReferralEventOptions tunes SignReferralUpdatedEvent. The zero value uses a
// random event id and the current time.
type ReferralEventOptions struct {
	// EventID is the atlas-id, the same on every retry of one event.
	EventID string
	// Now is the signing time (atlas-timestamp).
	Now time.Time
}

// SignedReferralEvent is a ready-to-send signed event.
type SignedReferralEvent struct {
	URL    string
	Header http.Header
	// Body is the exact signed body.
	Body []byte
}

// Request builds the POST to send.
func (e *SignedReferralEvent) Request(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, bytes.NewReader(e.Body))
	if err != nil {
		return nil, err
	}
	req.Header = e.Header.Clone()
	return req, nil
}

// ErrReferralEventNoReference: the event has neither CustomerRef nor ReferralID.
var ErrReferralEventNoReference = errors.New("atlas referral: the event needs CustomerRef or ReferralID")

// SignReferralUpdatedEvent builds a referral.updated event for an Atlas
// instance's inbound URL (Inbound.URL on the referral settings), signed like
// an Atlas webhook: atlas-id, atlas-timestamp (ms) and atlas-signature
// "v1,<base64 HMAC-SHA256 of {id}.{timestamp}.{body}>". secret is the inbound
// secret, or the connection's signing secret when no inbound secret is set.
//
//	e, err := atlas.SignReferralUpdatedEvent(inboundURL, secret, atlas.ReferralUpdatedEvent{CustomerRef: "user_1", Status: "qualified"}, nil)
//	req, _ := e.Request(ctx)
//	resp, err := http.DefaultClient.Do(req)
func SignReferralUpdatedEvent(inboundURL, secret string, event ReferralUpdatedEvent, opts *ReferralEventOptions) (*SignedReferralEvent, error) {
	if event.CustomerRef == "" && event.ReferralID == "" {
		return nil, ErrReferralEventNoReference
	}
	var o ReferralEventOptions
	if opts != nil {
		o = *opts
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.EventID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		o.EventID = "rfe_" + hex.EncodeToString(b)
	}
	event.Type = ReferralEventUpdated
	if event.OccurredAt == "" {
		event.OccurredAt = o.Now.UTC().Format("2006-01-02T15:04:05.000Z07:00")
	}
	body, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(o.Now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(o.EventID + "." + ts + "." + string(body)))
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Atlas-Id", o.EventID)
	h.Set("Atlas-Timestamp", ts)
	h.Set("Atlas-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	h.Set("User-Agent", ReferralProtocolUserAgent)
	h.Set(ReferralProtocolVersionHeader, ReferralProtocolVersion)
	return &SignedReferralEvent{URL: inboundURL, Header: h, Body: body}, nil
}

// Install starts a one-click connection to a referral platform (referalli, or
// any id in OneClickPresets). 422 REFERRALS_NOT_CONFIGURED when the deployment
// does not offer it; connect with a key or signing secret then.
// POST /v1/instance/referrals/:preset/install.
func (s *ReferralsService) Install(ctx context.Context, preset string, params InstallReferralParams, opts ...RequestOption) (*ReferralInstall, error) {
	out := &ReferralInstall{}
	return out, s.client.post(ctx, "/v1/instance/referrals/"+url.PathEscape(preset)+"/install", params, out, opts...)
}
