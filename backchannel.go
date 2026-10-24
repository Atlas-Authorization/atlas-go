package atlas

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// ── Back-channel logout delivery logs and tests ─────────────────────────────

// BackchannelLogoutDelivery is one back-channel logout attempt to an OAuth
// client's or Sign in with Atlas app's backchannel_logout_uri. Atlas never
// follows redirects: a 3xx fails with Error backchannel_redirect_not_followed
// and the Location it pointed at.
type BackchannelLogoutDelivery struct {
	Object        string  `json:"object"`
	ID            string  `json:"id"`
	OAuthClientID *string `json:"oauth_client_id"`
	// Sid is the ended session (sid_test_… for a test); nil for "sign out
	// everywhere".
	Sid *string `json:"sid"`
	// Test is true for a delivery sent by the test call (never retried).
	Test bool `json:"test"`
	// Status is pending, success or failed.
	Status        string `json:"status"`
	AttemptNumber int    `json:"attempt_number"`
	MaxAttempts   int    `json:"max_attempts"`
	HTTPStatus    *int   `json:"http_status"`
	LatencyMS     *int   `json:"latency_ms"`
	// Error is backchannel_redirect_not_followed, backchannel_http_error,
	// backchannel_timeout, backchannel_network_error or
	// backchannel_url_blocked; nil on success or while pending.
	Error           *string `json:"error"`
	Location        *string `json:"location"`
	ResponseSnippet *string `json:"response_snippet"`
	NextRetryAt     *int64  `json:"next_retry_at"`
	AttemptedAt     *int64  `json:"attempted_at"`
	DeliveredAt     *int64  `json:"delivered_at"`
	CreatedAt       int64   `json:"created_at"`
}

// BackchannelLogoutTest is the result of a test back-channel logout: a
// correctly signed logout_token for a synthetic session, POSTed now.
type BackchannelLogoutTest struct {
	Object     string `json:"object"`
	DeliveryID string `json:"delivery_id"`
	// OK is true when the receiver answered 2xx.
	OK  bool   `json:"ok"`
	Sid string `json:"sid"`
	// Status is the HTTP status the receiver answered; nil when none came back.
	Status    *int    `json:"status"`
	LatencyMS *int    `json:"latency_ms"`
	Error     *string `json:"error"`
	Location  *string `json:"location"`
	// BlockedReason is set when nothing was sent (private, loopback or
	// non-https address).
	BlockedReason *string `json:"blocked_reason"`
	BodyExcerpt   *string `json:"body_excerpt"`
}

// ListBackchannelDeliveries returns a client's back-channel logout delivery
// log, newest first. GET /v1/oauth_clients/:id/backchannel_deliveries.
func (s *OAuthClientsService) ListBackchannelDeliveries(ctx context.Context, id string, params ListParams) (*CursorPage[BackchannelLogoutDelivery], error) {
	out := &CursorPage[BackchannelLogoutDelivery]{}
	return out, s.client.get(ctx, "/v1/oauth_clients/"+url.PathEscape(id)+"/backchannel_deliveries", params.values(), out)
}

// TestBackchannelLogout sends a test back-channel logout to the client now.
// POST /v1/oauth_clients/:id/backchannel_logout/test.
func (s *OAuthClientsService) TestBackchannelLogout(ctx context.Context, id string, opts ...RequestOption) (*BackchannelLogoutTest, error) {
	out := &BackchannelLogoutTest{}
	return out, s.client.post(ctx, "/v1/oauth_clients/"+url.PathEscape(id)+"/backchannel_logout/test", nil, out, opts...)
}

// ── Sign in with Atlas apps: delivery log, preflight, users, origin moves ───

// ListBackchannelDeliveries returns the app's back-channel logout delivery
// log, newest first. GET /v1/platform/atlas_id_apps/:id/backchannel_deliveries.
func (s *AtlasIDAppsService) ListBackchannelDeliveries(ctx context.Context, id string, params ListParams) (*CursorPage[BackchannelLogoutDelivery], error) {
	out := &CursorPage[BackchannelLogoutDelivery]{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/backchannel_deliveries", params.values(), out)
}

// TestBackchannelLogout sends a test back-channel logout to the app now.
// POST /v1/platform/atlas_id_apps/:id/backchannel_logout/test.
func (s *AtlasIDAppsService) TestBackchannelLogout(ctx context.Context, id string, opts ...RequestOption) (*BackchannelLogoutTest, error) {
	out := &BackchannelLogoutTest{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/backchannel_logout/test", nil, out, opts...)
}

// AtlasIDAppPreflight is one app's setup check, in the instance preflight's
// finding shape.
type AtlasIDAppPreflight struct {
	Object    string `json:"object"`
	AppID     string `json:"app_id"`
	OK        bool   `json:"ok"`
	CheckedAt int64  `json:"checked_at"`
	// UserCount is the number of people who approved the app.
	UserCount int                `json:"user_count"`
	Findings  []PreflightFinding `json:"findings"`
	// ButtonRenderedOrigins are the page origins the Sign in with Atlas button
	// script ran on in the last 7 days.
	ButtonRenderedOrigins []AtlasIDOriginSeen `json:"button_rendered_origins,omitempty"`
	// AuthorizeRequests7d counts how the last 7 days' sign-ins started.
	AuthorizeRequests7d *AtlasIDAuthorizeSources `json:"authorize_requests_7d,omitempty"`
	// FallbackOrigins are origins of sign-ins that came through the no-script
	// fallback link (?atlasid_fallback=1).
	FallbackOrigins []AtlasIDOriginSeen `json:"fallback_origins,omitempty"`
	// HomepageIncludesScript is whether the app's homepage references the
	// button script (nil = could not check).
	HomepageIncludesScript *bool `json:"homepage_includes_script,omitempty"`
}

// SetManagedByResult is an app after SetManagedBy, with whether anything changed.
type SetManagedByResult struct {
	AtlasIDApp
	Changed bool `json:"changed"`
}

// SetManagedBy hands the app's grant management to an instance of the same
// account (managed_via "adopted"), or takes it back when instanceID is nil. That
// instance's secret key, scoped to privacy:grants:revoke or atlas_id_apps:*, then
// lists and revokes the app's grants, so a data-rights tool never needs the
// platform key. The app stays yours to edit.
// PUT /v1/platform/atlas_id_apps/:id/managed_by.
func (s *AtlasIDAppsService) SetManagedBy(ctx context.Context, id string, instanceID *string, opts ...RequestOption) (*SetManagedByResult, error) {
	out := &SetManagedByResult{}
	body := struct {
		InstanceID *string `json:"instance_id"`
	}{instanceID}
	return out, s.client.platPut(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/managed_by", body, out, opts...)
}

// Preflight checks one app's setup. GET /v1/platform/atlas_id_apps/:id/preflight.
func (s *AtlasIDAppsService) Preflight(ctx context.Context, id string) (*AtlasIDAppPreflight, error) {
	out := &AtlasIDAppPreflight{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/preflight", nil, out)
}

// AtlasIDAppUser is a person who has approved a Sign in with Atlas app.
type AtlasIDAppUser struct {
	Object      string `json:"object"`
	AtlasIDUser bool   `json:"atlas_id_user"`
	// Sub is the user id as this app sees it (the id_token sub).
	Sub       string   `json:"sub"`
	GrantID   string   `json:"grant_id"`
	Scopes    []string `json:"scopes"`
	GrantedAt int64    `json:"granted_at"`
}

// FindUsers answers a privacy request: is this person one of the app's users?
// Exact match on a verified email; anyone else gets the same empty list.
// GET /v1/platform/atlas_id_apps/:id/users?email=.
func (s *AtlasIDAppsService) FindUsers(ctx context.Context, id, email string) (*ListPage[AtlasIDAppUser], error) {
	out := &ListPage[AtlasIDAppUser]{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/users", url.Values{"email": {email}}, out)
}

// AtlasIDGrantRevocation acknowledges revoking one user's grant to an app.
type AtlasIDGrantRevocation struct {
	Object             string `json:"object"`
	ID                 string `json:"id"`
	Sub                string `json:"sub"`
	Revoked            bool   `json:"revoked"`
	TokensRevoked      int    `json:"tokens_revoked,omitempty"`
	BackchannelLogouts int    `json:"backchannel_logouts,omitempty"`
}

// RevokeGrant revokes one user's grant (GrantID from FindUsers): the next
// sign-in shows the consent screen again.
// DELETE /v1/platform/atlas_id_apps/:id/grants/:grantId.
func (s *AtlasIDAppsService) RevokeGrant(ctx context.Context, id, grantID string, opts ...RequestOption) (*AtlasIDGrantRevocation, error) {
	out := &AtlasIDGrantRevocation{}
	return out, s.client.platDel(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/grants/"+url.PathEscape(grantID), out, opts...)
}

// MoveOrigin moves the app's URLs from one origin to another; DryRun writes
// nothing. POST /v1/platform/atlas_id_apps/:id/move_origin.
func (s *AtlasIDAppsService) MoveOrigin(ctx context.Context, id string, params OriginMoveParams, opts ...RequestOption) (*OriginMove, error) {
	out := &OriginMove{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/move_origin", params, out, opts...)
}

// RotateWebhookSecret rotates the app's webhook signing secret; the new one is
// in WebhookSecret, returned once.
// POST /v1/platform/atlas_id_apps/:id/webhook/rotate_secret.
func (s *AtlasIDAppsService) RotateWebhookSecret(ctx context.Context, id string, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/webhook/rotate_secret", nil, out, opts...)
}

// RotateWebhookSecretWithParams rotates the webhook signing secret with a
// chosen overlap: the previous secret signs each delivery too until
// WebhookPreviousSecretExpiresAt. POST /v1/platform/atlas_id_apps/:id/webhook/rotate_secret.
func (s *AtlasIDAppsService) RotateWebhookSecretWithParams(ctx context.Context, id string, params RotateAtlasIDAppSecretParams, opts ...RequestOption) (*AtlasIDApp, error) {
	out := &AtlasIDApp{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_apps/"+url.PathEscape(id)+"/webhook/rotate_secret", params, out, opts...)
}

// ── Sign in with Atlas publisher + platform config changelog ────────────────

// AtlasIDPublisherService is /v1/platform/atlas_id_publisher.
type AtlasIDPublisherService struct{ client *Client }

// AtlasIDPublisher is the account's Sign in with Atlas publisher.
type AtlasIDPublisher struct {
	Object string `json:"object"`
	// Configured is false when the singleton has never been set (the GET
	// answers 200, no longer 404).
	Configured *bool  `json:"configured,omitempty"`
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	Verified   bool   `json:"verified"`
	VerifiedAt *int64 `json:"verified_at"`
	// SkipConsent is publisher-wide consent for verified apps (openid / email
	// / profile only).
	SkipConsent  bool `json:"skip_consent"`
	Verification struct {
		RecordName  string `json:"record_name"`
		RecordType  string `json:"record_type"`
		RecordValue string `json:"record_value"`
	} `json:"verification"`
	LastCheckedAt *int64 `json:"last_checked_at"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	// RecordFound is set by Verify: whether the TXT record matched.
	RecordFound *bool `json:"record_found,omitempty"`
}

// SetAtlasIDPublisherParams is the body of PUT /v1/platform/atlas_id_publisher.
type SetAtlasIDPublisherParams struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	// SkipConsent defaults to false.
	SkipConsent *bool `json:"skip_consent,omitempty"`
}

// Get reads the publisher (404 until claimed). GET /v1/platform/atlas_id_publisher.
func (s *AtlasIDPublisherService) Get(ctx context.Context) (*AtlasIDPublisher, error) {
	out := &AtlasIDPublisher{}
	return out, s.client.platGet(ctx, "/v1/platform/atlas_id_publisher", nil, out)
}

// Set claims a publisher name and domain and returns the TXT record to
// publish. PUT /v1/platform/atlas_id_publisher.
func (s *AtlasIDPublisherService) Set(ctx context.Context, params SetAtlasIDPublisherParams, opts ...RequestOption) (*AtlasIDPublisher, error) {
	out := &AtlasIDPublisher{}
	return out, s.client.platPut(ctx, "/v1/platform/atlas_id_publisher", params, out, opts...)
}

// SetSkipConsent turns publisher-wide consent on or off.
// PATCH /v1/platform/atlas_id_publisher.
func (s *AtlasIDPublisherService) SetSkipConsent(ctx context.Context, skipConsent bool, opts ...RequestOption) (*AtlasIDPublisher, error) {
	out := &AtlasIDPublisher{}
	body := map[string]bool{"skip_consent": skipConsent}
	return out, s.client.platPatch(ctx, "/v1/platform/atlas_id_publisher", body, out, opts...)
}

// Delete removes the publisher claim. DELETE /v1/platform/atlas_id_publisher.
func (s *AtlasIDPublisherService) Delete(ctx context.Context, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.platDel(ctx, "/v1/platform/atlas_id_publisher", out, opts...)
}

// Verify looks up the TXT record now. POST /v1/platform/atlas_id_publisher/verify.
func (s *AtlasIDPublisherService) Verify(ctx context.Context, opts ...RequestOption) (*AtlasIDPublisher, error) {
	out := &AtlasIDPublisher{}
	return out, s.client.platPost(ctx, "/v1/platform/atlas_id_publisher/verify", nil, out, opts...)
}

// ConfigChangelog lists config changes to the account's Sign in with Atlas
// apps, newest first. GET /v1/platform/config_changelog.
func (s *PlatformService) ConfigChangelog(ctx context.Context, params ConfigChangelogParams) (*CursorPage[ConfigChange], error) {
	q := params.ListParams.values()
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	if !params.Since.IsZero() {
		q.Set("since", params.Since.UTC().Format(time.RFC3339))
	}
	if params.IncludeNoOp != nil {
		q.Set("include_no_op", strconv.FormatBool(*params.IncludeNoOp))
	}
	out := &CursorPage[ConfigChange]{}
	return out, s.client.platGet(ctx, "/v1/platform/config_changelog", q, out)
}
