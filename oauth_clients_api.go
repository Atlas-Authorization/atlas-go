package atlas

import (
	"context"
	"net/url"
)

// GetExchangePolicy: Read the token-exchange policy of an OAuth client (the defaults, with
// configured=false, when none is set).
// GET /v1/oauth_clients/{id}/exchange_policy.
func (s *OAuthClientsService) GetExchangePolicy(ctx context.Context, id string) (*OAuthClientsGetExchangePolicyResult, error) {
	out := &OAuthClientsGetExchangePolicyResult{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_clients/"+url.PathEscape(id)+"/exchange_policy", nil, nil, out)
}

// SetExchangePolicy: Set the token-exchange policy of an OAuth client: allowed audiences and
// scopes, whether it may impersonate (no actor_token), whether delegation needs may_act, and the
// maximum act-chain depth. Audited as oauth_exchange_policy.updated.
// PUT /v1/oauth_clients/{id}/exchange_policy.
func (s *OAuthClientsService) SetExchangePolicy(ctx context.Context, id string, params OAuthClientsSetExchangePolicyParams, opts ...RequestOption) (*OAuthClientsGetExchangePolicyResult, error) {
	out := &OAuthClientsGetExchangePolicyResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_clients/"+url.PathEscape(id)+"/exchange_policy", nil, params, out, opts...)
}

// DeleteExchangePolicy: Remove the token-exchange policy of an OAuth client, restoring the
// defaults.
// DELETE /v1/oauth_clients/{id}/exchange_policy.
func (s *OAuthClientsService) DeleteExchangePolicy(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/oauth_clients/"+url.PathEscape(id)+"/exchange_policy", nil, nil, out, opts...)
}

// SetProfile: Assign a policy profile to an OAuth client (profile null clears it). The client must
// already conform (auth method, redirect URIs); the profile is then enforced at /oauth2/authorize,
// /oauth2/par and /oauth2/token.
// PUT /v1/oauth_clients/{id}/profile.
func (s *OAuthClientsService) SetProfile(ctx context.Context, id string, params OAuthClientsSetProfileParams, opts ...RequestOption) (*OAuthClientsSetProfileResult, error) {
	out := &OAuthClientsSetProfileResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_clients/"+url.PathEscape(id)+"/profile", nil, params, out, opts...)
}

// SetDelegatedUI: Set (or clear, with null) the URLs of your own sign-in and consent pages for an
// OAuth client. /oauth2/authorize then sends the browser there with a login_challenge /
// consent_challenge instead of Atlas’s pages. A client URL overrides the instance-wide
// oauthProvider.loginUrl / consentUrl.
// PUT /v1/oauth_clients/{id}/delegated_ui.
func (s *OAuthClientsService) SetDelegatedUI(ctx context.Context, id string, params OAuthClientsSetDelegatedUIParams, opts ...RequestOption) (*OAuthClientsSetDelegatedUIResult, error) {
	out := &OAuthClientsSetDelegatedUIResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_clients/"+url.PathEscape(id)+"/delegated_ui", nil, params, out, opts...)
}

// OAuthClientsAppSettingsService is the oauthClients appSettings group of OAuthClientsService.
type OAuthClientsAppSettingsService struct {
	client *Client
}

// Get: The per-application settings of an OAuth client: allowed sign-in methods, hosted-page
// branding, the user-claim allow-list for ID tokens and userinfo, and the traits a session from
// this app may write. Null = no restriction.
// GET /v1/oauth_clients/{id}/app_settings.
func (s *OAuthClientsAppSettingsService) Get(ctx context.Context, id string) (*OAuthClientsAppSettingsGetResult, error) {
	out := &OAuthClientsAppSettingsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_clients/"+url.PathEscape(id)+"/app_settings", nil, nil, out)
}

// Update: Change the per-application settings. Each field sent replaces the stored one and null
// clears it; fields left out keep their value. Unknown fields and malformed values are refused.
// PATCH /v1/oauth_clients/{id}/app_settings.
func (s *OAuthClientsAppSettingsService) Update(ctx context.Context, id string, params OAuthClientsAppSettingsUpdateParams, opts ...RequestOption) (*OAuthClientsAppSettingsGetResult, error) {
	out := &OAuthClientsAppSettingsGetResult{}
	return out, s.client.do(ctx, "PATCH", "/v1/oauth_clients/"+url.PathEscape(id)+"/app_settings", nil, params, out, opts...)
}

// OAuthClientsWorkloadIdentityService is the oauthClients workloadIdentity group of OAuthClientsService.
type OAuthClientsWorkloadIdentityService struct {
	client *Client
}

// Presets: List the workload platforms Atlas knows defaults for (SPIFFE, Kubernetes, GitHub
// Actions, GCP, Azure): issuer, JWKS URL and the shape of the token subject.
// GET /v1/workload_identity/presets.
func (s *OAuthClientsWorkloadIdentityService) Presets(ctx context.Context, params ListParams) (*CursorPage[OAuthClientsWorkloadIdentityPresetsItem], error) {
	out := &CursorPage[OAuthClientsWorkloadIdentityPresetsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/workload_identity/presets", params.values(), nil, out)
}

// OAuthClientsWorkloadIdentityCloudTrustQuery holds the query parameters of OAuthClientsWorkloadIdentityService.CloudTrust.
type OAuthClientsWorkloadIdentityCloudTrustQuery struct {
	// Target cloud.
	Provider string
	// The audience (resource server identifier) the token will carry.
	Audience string
	// The token subject (the OAuth client id) the cloud should trust.
	Subject string
	// Entra tenant, for azure.
	TenantID string
}

func (q OAuthClientsWorkloadIdentityCloudTrustQuery) values() url.Values {
	v := url.Values{}
	v.Set("provider", q.Provider)
	v.Set("audience", q.Audience)
	v.Set("subject", q.Subject)
	if q.TenantID != "" {
		v.Set("tenant_id", q.TenantID)
	}
	return v
}

// CloudTrust: Trust-policy snippets that make AWS (AssumeRoleWithWebIdentity), GCP (workload
// identity federation) or Azure (federated credentials) accept an access token issued by this
// instance. Nothing is changed in the cloud.
// GET /v1/workload_identity/cloud_trust.
func (s *OAuthClientsWorkloadIdentityService) CloudTrust(ctx context.Context, query OAuthClientsWorkloadIdentityCloudTrustQuery) (*OAuthClientsWorkloadIdentityCloudTrustResult, error) {
	out := &OAuthClientsWorkloadIdentityCloudTrustResult{}
	return out, s.client.do(ctx, "GET", "/v1/workload_identity/cloud_trust", query.values(), nil, out)
}

// OAuthClientsTrustedIssuersService is the oauthClients trustedIssuers group of OAuthClientsService.
type OAuthClientsTrustedIssuersService struct {
	client *Client
}

// List: List the external issuers this OAuth client trusts to assert users through the RFC 7523
// jwt-bearer grant.
// GET /v1/oauth_clients/{id}/trusted_issuers.
func (s *OAuthClientsTrustedIssuersService) List(ctx context.Context, id string, params ListParams) (*CursorPage[OAuthClientsTrustedIssuersListItem], error) {
	out := &CursorPage[OAuthClientsTrustedIssuersListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_clients/"+url.PathEscape(id)+"/trusted_issuers", params.values(), nil, out)
}

// Create: Trust an external issuer for this client. With purpose user_assertion (default) its
// signed JWTs (verified against the inline jwks or the https jwks_uri) can then be presented to
// POST /oauth2/token with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer. subject_mapping
// says how the JWT sub names an Atlas user. With purpose client_auth or both (PRO-06 workload
// identity) a client registered with token_endpoint_auth_method workload_jwt authenticates by
// presenting a token from this issuer as its client_assertion; subject_pattern is then required
// and must name the workload. workload_kind github_actions, gcp and azure fill in the issuer and
// JWKS URL. Audited as oauth_trusted_issuer.created.
// POST /v1/oauth_clients/{id}/trusted_issuers.
func (s *OAuthClientsTrustedIssuersService) Create(ctx context.Context, id string, params OAuthClientsTrustedIssuersCreateParams, opts ...RequestOption) (*OAuthClientsTrustedIssuersListItem, error) {
	out := &OAuthClientsTrustedIssuersListItem{}
	return out, s.client.do(ctx, "POST", "/v1/oauth_clients/"+url.PathEscape(id)+"/trusted_issuers", nil, params, out, opts...)
}

// Delete: Stop trusting an issuer: its assertions are refused at once. Audited as
// oauth_trusted_issuer.deleted.
// DELETE /v1/oauth_clients/{id}/trusted_issuers/{issuerId}.
func (s *OAuthClientsTrustedIssuersService) Delete(ctx context.Context, id string, issuerID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/oauth_clients/"+url.PathEscape(id)+"/trusted_issuers/"+url.PathEscape(issuerID), nil, nil, out, opts...)
}

// OAuthClientsLoginRequestsService is the oauthClients loginRequests group of OAuthClientsService.
type OAuthClientsLoginRequestsService struct {
	client *Client
}

// OAuthClientsLoginRequestsGetQuery holds the query parameters of OAuthClientsLoginRequestsService.Get.
type OAuthClientsLoginRequestsGetQuery struct {
	// The login_challenge your sign-in page received from /oauth2/authorize.
	LoginChallenge string
}

func (q OAuthClientsLoginRequestsGetQuery) values() url.Values {
	v := url.Values{}
	v.Set("login_challenge", q.LoginChallenge)
	return v
}

// Get: Read a login challenge: which application is signing a user in, with what scopes, and who
// (if anyone) is already signed in on this browser.
// GET /v1/oauth_login_requests.
func (s *OAuthClientsLoginRequestsService) Get(ctx context.Context, query OAuthClientsLoginRequestsGetQuery) (*OAuthClientsLoginRequestsGetResult, error) {
	out := &OAuthClientsLoginRequestsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_login_requests", query.values(), nil, out)
}

// OAuthClientsLoginRequestsAcceptQuery holds the query parameters of OAuthClientsLoginRequestsService.Accept.
type OAuthClientsLoginRequestsAcceptQuery struct {
	// The login_challenge your sign-in page received from /oauth2/authorize.
	LoginChallenge string
}

func (q OAuthClientsLoginRequestsAcceptQuery) values() url.Values {
	v := url.Values{}
	v.Set("login_challenge", q.LoginChallenge)
	return v
}

// Accept: Accept a login challenge: the visitor authenticated as `subject` (an Atlas user id).
// Returns redirect_to; when the browser follows it Atlas signs the user in and continues the
// authorization. The returned link is single-use and valid for five minutes.
// PUT /v1/oauth_login_requests/accept.
func (s *OAuthClientsLoginRequestsService) Accept(ctx context.Context, query OAuthClientsLoginRequestsAcceptQuery, params OAuthClientsLoginRequestsAcceptParams, opts ...RequestOption) (*OAuthClientsLoginRequestsAcceptResult, error) {
	out := &OAuthClientsLoginRequestsAcceptResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_login_requests/accept", query.values(), params, out, opts...)
}

// OAuthClientsLoginRequestsRejectQuery holds the query parameters of OAuthClientsLoginRequestsService.Reject.
type OAuthClientsLoginRequestsRejectQuery struct {
	// The login_challenge your sign-in page received from /oauth2/authorize.
	LoginChallenge string
}

func (q OAuthClientsLoginRequestsRejectQuery) values() url.Values {
	v := url.Values{}
	v.Set("login_challenge", q.LoginChallenge)
	return v
}

// Reject: Reject a login challenge. Following redirect_to returns the application to its
// redirect_uri with the OAuth error.
// PUT /v1/oauth_login_requests/reject.
func (s *OAuthClientsLoginRequestsService) Reject(ctx context.Context, query OAuthClientsLoginRequestsRejectQuery, params OAuthClientsLoginRequestsRejectParams, opts ...RequestOption) (*OAuthClientsLoginRequestsAcceptResult, error) {
	out := &OAuthClientsLoginRequestsAcceptResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_login_requests/reject", query.values(), params, out, opts...)
}

// OAuthClientsConsentRequestsService is the oauthClients consentRequests group of OAuthClientsService.
type OAuthClientsConsentRequestsService struct {
	client *Client
}

// OAuthClientsConsentRequestsGetQuery holds the query parameters of OAuthClientsConsentRequestsService.Get.
type OAuthClientsConsentRequestsGetQuery struct {
	// The consent_challenge your consent page received from /oauth2/authorize.
	ConsentChallenge string
}

func (q OAuthClientsConsentRequestsGetQuery) values() url.Values {
	v := url.Values{}
	v.Set("consent_challenge", q.ConsentChallenge)
	return v
}

// Get: Read a consent challenge: the signed-in user, the application and the scopes, audience,
// authorization details and organization it asks for.
// GET /v1/oauth_consent_requests.
func (s *OAuthClientsConsentRequestsService) Get(ctx context.Context, query OAuthClientsConsentRequestsGetQuery) (*OAuthClientsConsentRequestsGetResult, error) {
	out := &OAuthClientsConsentRequestsGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_consent_requests", query.values(), nil, out)
}

// OAuthClientsConsentRequestsAcceptQuery holds the query parameters of OAuthClientsConsentRequestsService.Accept.
type OAuthClientsConsentRequestsAcceptQuery struct {
	// The consent_challenge your consent page received from /oauth2/authorize.
	ConsentChallenge string
}

func (q OAuthClientsConsentRequestsAcceptQuery) values() url.Values {
	v := url.Values{}
	v.Set("consent_challenge", q.ConsentChallenge)
	return v
}

// Accept: Accept a consent challenge, optionally narrowing the granted scopes. Following
// redirect_to (in the same browser that started the flow) records the consent unless remember is
// false, and returns the application to its redirect_uri with a code.
// PUT /v1/oauth_consent_requests/accept.
func (s *OAuthClientsConsentRequestsService) Accept(ctx context.Context, query OAuthClientsConsentRequestsAcceptQuery, params OAuthClientsConsentRequestsAcceptParams, opts ...RequestOption) (*OAuthClientsLoginRequestsAcceptResult, error) {
	out := &OAuthClientsLoginRequestsAcceptResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_consent_requests/accept", query.values(), params, out, opts...)
}

// OAuthClientsConsentRequestsRejectQuery holds the query parameters of OAuthClientsConsentRequestsService.Reject.
type OAuthClientsConsentRequestsRejectQuery struct {
	// The consent_challenge your consent page received from /oauth2/authorize.
	ConsentChallenge string
}

func (q OAuthClientsConsentRequestsRejectQuery) values() url.Values {
	v := url.Values{}
	v.Set("consent_challenge", q.ConsentChallenge)
	return v
}

// Reject: Reject a consent challenge. Following redirect_to returns the application to its
// redirect_uri with the OAuth error.
// PUT /v1/oauth_consent_requests/reject.
func (s *OAuthClientsConsentRequestsService) Reject(ctx context.Context, query OAuthClientsConsentRequestsRejectQuery, params OAuthClientsLoginRequestsRejectParams, opts ...RequestOption) (*OAuthClientsLoginRequestsAcceptResult, error) {
	out := &OAuthClientsLoginRequestsAcceptResult{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_consent_requests/reject", query.values(), params, out, opts...)
}
