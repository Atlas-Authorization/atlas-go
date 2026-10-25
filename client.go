// Package atlas is the official Go backend SDK for the Atlas auth platform — an
// idiomatic, typed client over the secret-key ("sk_") Backend API (BAPI).
//
// It is the peer of the TypeScript SDK in packages/backend/src/client: the same
// namespaces (users, organizations, sessions, invitations, roles, domains,
// webhooks, oauth clients, resource servers, sso connections, scim tokens, jwt
// templates, actor tokens, sign-in tokens, attack protection, restrictions,
// waitlist, audit logs), the same snake_case wire types, and the same §9.1
// error envelope
//
//	{ "errors": [ { "code", "message", "param?", "meta?" } ] }
//
// mapped onto an *APIError callers branch on with errors.As.
//
// The client depends on nothing but the standard library (net/http +
// encoding/json). Every request is authenticated with
// `Authorization: Bearer sk_...`, sends and accepts JSON, and reads the BAPI
// origin from BaseURL (default https://api.atlasauth.net, overridable per client).
//
// Usage:
//
//	c := atlas.New("sk_live_...")
//	u, err := c.Users.Create(ctx, atlas.CreateUserParams{EmailAddress: "a@b.com"})
//	var apiErr *atlas.APIError
//	if errors.As(err, &apiErr) && apiErr.Code() == "FORM_IDENTIFIER_EXISTS" { ... }
package atlas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DefaultBaseURL is the Atlas Backend API origin (BAPI_ORIGIN), overridable per
// client with WithBaseURL.
const DefaultBaseURL = "https://api.atlasauth.net"

// userAgent identifies this SDK build to the API.
const userAgent = "atlas-go"

// Client is the typed management client for the Atlas Backend API. Construct it
// with New; then reach for a namespace field (Client.Users, Client.Organizations,
// …). It is safe for concurrent use by multiple goroutines.
type Client struct {
	baseURL         string
	secretKey       string
	platformKey     string
	httpClient      *http.Client
	strict          *bool
	onUnknownFields UnknownFieldsHandler
	secretRecipient string

	// Namespaces — one per BAPI area, mirroring the TypeScript SDK.
	Users           *UsersService
	Sessions        *SessionsService
	Organizations   *OrganizationsService
	Invitations     *InvitationsService
	Roles           *RolesService
	Permissions     *PermissionsService
	OAuthClients    *OAuthClientsService
	ResourceServers *ResourceServersService
	// AppRoles is /v1/app_roles: instance-wide user roles.
	AppRoles *AppRolesService
	// OAuthInitialAccessTokens is /v1/oauth_initial_access_tokens (DCR gating).
	OAuthInitialAccessTokens *OAuthInitialAccessTokensService
	SSOConnections           *SSOConnectionsService
	SCIMTokens               *SCIMTokensService
	Domains                  *DomainsService
	Webhooks                 *WebhooksService
	Waitlist                 *WaitlistService
	Allowlist                *AllowlistService
	Blocklist                *BlocklistService
	AttackProtection         *AttackProtectionService
	ActorTokens              *ActorTokensService
	SignInTokens             *SignInTokensService
	AuditLogs                *AuditLogsService
	JWTTemplates             *JWTTemplatesService
	APIKeys                  *APIKeysService

	OAuthProviders *OAuthProvidersService
	// CustomOAuthProviders are your own upstream OAuth / OIDC login providers.
	CustomOAuthProviders *CustomOAuthProvidersService
	SSOOnboarding        *SSOOnboardingService
	SCIMProvisioning     *SCIMProvisioningService
	FGA                  *FGAService
	RateLimitPolicy      *RateLimitPolicyService
	RiskBasedMFA         *RiskBasedMFAService
	BotSignals           *BotSignalsService
	NetworkACLs          *NetworkACLsService
	ManagedWAF           *ManagedWAFService
	LogStreams           *LogStreamsService
	// LogoutNotifyEndpoints is /v1/logout_notify_endpoints — logout fan-out.
	LogoutNotifyEndpoints *LogoutNotifyEndpointsService
	Branding              *BrandingService
	EmailTemplates        *EmailTemplatesService
	SMSTemplates          *SMSTemplatesService
	Localizations         *LocalizationsService
	Actions               *ActionsService
	// ActionGallery browses and installs Action templates; ActionTemplates
	// publishes your own.
	ActionGallery   *ActionGalleryService
	ActionTemplates *ActionTemplatesService
	Billing         *BillingService
	// Policies is policy acceptance (terms, privacy, any key); PolicySource
	// connects an external system that serves the policy documents.
	Policies            *PoliciesService
	PolicySource        *PolicySourceService
	Messaging           *MessagingService
	ImportExport        *ImportExportService
	DataSubjectRequests *DataSubjectRequestsService
	RadiusClients       *RadiusClientsService
	LTIPlatforms        *LTIPlatformsService
	Instance            *InstanceService
	InstanceSecurity    *InstanceSecurityService
	Referrals           *ReferralsService
	UserHooks           *UserHooksService
	Tokens              *TokensService

	EmailAddresses             *EmailAddressesService
	OrganizationSettingsSchema *OrganizationSettingsSchemaService
	Machines                   *MachinesService
	SessionExchangeApps        *SessionExchangeAppsService
	RedirectURLs               *RedirectURLsService
	Tickets                    *TicketsService
	Notifications              *NotificationsService
	OpenFGA                    *OpenFGAService
	Connectors                 *ConnectorsService
	AuditEvents                *AuditEventsService
	Diagnostics                *DiagnosticsService
	Analytics                  *AnalyticsService
	Captcha                    *CaptchaService
	Testing                    *TestingService
	MCP                        *MCPService
	LegacyAuth                 *LegacyAuthService
	// BetterAuthImports imports a sealed Better Auth bundle (/v1/better_auth_imports).
	BetterAuthImports *BetterAuthImportsService
	// BetterAuthBridge manages the Better Auth session bridge (/v1/migrations/better_auth/*).
	BetterAuthBridge     *BetterAuthBridgeService
	OrgLDAPConnections   *OrgLDAPConnectionsService
	PCA                  *PCAService
	Design               *DesignService
	EntitlementOverrides *EntitlementOverridesService
	// Platform is the platform-key surface (/v1/platform/*); see WithPlatformKey.
	Platform *PlatformService

	// SecretKeys is /v1/secret_keys: scoped, expiring, rotatable secret keys.
	SecretKeys *SecretKeysService
	// Keys is /v1/keys: every credential on the instance in one standard shape.
	Keys *KeysService
	// PartnerLinks is /v1/partner_links: credentials granted to (and held for)
	// an integrated partner service.
	PartnerLinks *PartnerLinksService
	// PartnerPlatforms is /v1/partner_platforms: this instance as the partner
	// platform of another product (signed deliveries in, partner token stored
	// once and never returned).
	PartnerPlatforms *PartnerPlatformsService
	// AtlasIDGrants manages the Sign in with Atlas apps the instance owns and
	// their per-user grants (/v1/atlas_id_apps).
	AtlasIDGrants *AtlasIDGrantsService
	// Privacy is the data-rights executor protocol (/v1/privacy) and the
	// instance's own orchestrator connection.
	Privacy *PrivacyService
	// Integrations is the integration-facing surface (/v1/integrations/*).
	Integrations *IntegrationsService
	// Entitlements is /v1/entitlements: the standard entitlements document.
	Entitlements *EntitlementsService
	// Notices is /v1/instance/notices: behaviour changes that affect this instance.
	Notices *NoticesService
	// SecurityAdvisories is /v1/security_advisories.
	SecurityAdvisories *SecurityAdvisoriesService
	// SubProcessors is /v1/instance/sub_processors.
	SubProcessors *SubProcessorsService
	// AuditExports is /v1/audit_exports: continuous audit-log forwarding.
	AuditExports *AuditExportsService
	// Status is the service status, the instance's incident subscription and
	// its status dependencies.
	Status *StatusService
	// Delivery is outbound delivery health (/v1/delivery_health) and the
	// fixed egress addresses (/v1/meta/egress_ips).
	Delivery *DeliveryService
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithBaseURL overrides the BAPI origin (default https://api.atlasauth.net). A
// trailing slash is tolerated.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithHTTPClient injects a custom *http.Client — for timeouts, proxies, or a
// mock transport in tests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithStrict sets the strict-bodies default for every write (POST, PUT,
// PATCH): WithStrict(true) sends `Atlas-Strict: true`, so a body field the
// endpoint does not accept is refused with 422 UNKNOWN_FIELD instead of being
// ignored. WithStrict(false) sends `Atlas-Strict: false`, opting out of an
// instance that is strict by default. Override per call with StrictBody.
func WithStrict(on bool) Option {
	return func(c *Client) { c.strict = &on }
}

// WithUnknownFieldsHandler registers a callback for the `Atlas-Unknown-Fields`
// response header: the body fields an endpoint ignored on a non-strict write.
// Use it to log typos without turning on strict mode.
func WithUnknownFieldsHandler(fn UnknownFieldsHandler) Option {
	return func(c *Client) { c.onUnknownFields = fn }
}

// WithPlatformKey sets the platform key ("psk_...") used for the platform
// surface (Client.Platform: apps, Sign in with Atlas apps, account design
// images). Without it, platform calls are signed with the key given to New.
func WithPlatformKey(platformKey string) Option {
	return func(c *Client) { c.platformKey = platformKey }
}

// NewPlatform builds a Client for the platform surface only, signed with a
// platform key ("psk_..."). Equivalent to New("", WithPlatformKey(key), ...).
func NewPlatform(platformKey string, opts ...Option) *Client {
	return New("", append([]Option{WithPlatformKey(platformKey)}, opts...)...)
}

// New builds a Client bound to the given instance secret key ("sk_..."). The
// key is sent as `Authorization: Bearer <key>` on every request and never
// placed in a URL. Options tune the base URL and HTTP client.
func New(secretKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:    DefaultBaseURL,
		secretKey:  secretKey,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}

	c.Users = &UsersService{client: c}
	c.Sessions = &SessionsService{client: c}
	c.Organizations = &OrganizationsService{
		client:      c,
		Memberships: &OrgMembershipsService{client: c},
		Invitations: &OrgInvitationsService{client: c},
		Domains:     &OrgDomainsService{client: c},
		GroupRoles:  &OrgGroupRolesService{client: c},
		Teams:       &OrgTeamsService{client: c},
		Roles:       &OrgRolesService{client: c},
	}
	c.Invitations = &InvitationsService{client: c}
	c.Roles = &RolesService{client: c}
	c.Permissions = &PermissionsService{client: c}
	c.OAuthClients = &OAuthClientsService{client: c, Grants: &OAuthClientGrantsService{client: c}}
	c.ResourceServers = &ResourceServersService{client: c}
	c.AppRoles = &AppRolesService{client: c}
	c.OAuthInitialAccessTokens = &OAuthInitialAccessTokensService{client: c}
	c.SSOConnections = &SSOConnectionsService{client: c}
	c.SCIMTokens = &SCIMTokensService{client: c}
	c.Domains = &DomainsService{client: c}
	c.Webhooks = &WebhooksService{client: c, Endpoints: &WebhookEndpointsService{client: c}}
	c.Waitlist = &WaitlistService{client: c}
	c.Allowlist = &AllowlistService{client: c}
	c.Blocklist = &BlocklistService{client: c}
	c.AttackProtection = &AttackProtectionService{client: c}
	c.ActorTokens = &ActorTokensService{client: c}
	c.SignInTokens = &SignInTokensService{client: c}
	c.AuditLogs = &AuditLogsService{client: c}
	c.JWTTemplates = &JWTTemplatesService{client: c}
	c.APIKeys = &APIKeysService{client: c}

	c.OAuthProviders = &OAuthProvidersService{client: c}
	c.CustomOAuthProviders = &CustomOAuthProvidersService{client: c}
	c.SSOOnboarding = &SSOOnboardingService{client: c}
	c.SCIMProvisioning = &SCIMProvisioningService{client: c}
	c.FGA = &FGAService{
		client: c,
		Stores: &FGAStoresService{client: c},
		Models: &FGAModelsService{client: c},
	}
	c.RateLimitPolicy = &RateLimitPolicyService{client: c}
	c.RiskBasedMFA = &RiskBasedMFAService{client: c}
	c.BotSignals = &BotSignalsService{client: c}
	c.NetworkACLs = &NetworkACLsService{client: c}
	c.ManagedWAF = &ManagedWAFService{client: c}
	c.LogStreams = &LogStreamsService{client: c}
	c.LogoutNotifyEndpoints = &LogoutNotifyEndpointsService{client: c}
	c.Branding = &BrandingService{client: c}
	c.EmailTemplates = &EmailTemplatesService{client: c}
	c.SMSTemplates = &SMSTemplatesService{client: c}
	c.Localizations = &LocalizationsService{client: c}
	c.Actions = &ActionsService{client: c}
	c.ActionGallery = &ActionGalleryService{client: c}
	c.ActionTemplates = &ActionTemplatesService{client: c}
	c.Billing = &BillingService{client: c}
	c.Policies = &PoliciesService{
		client:   c,
		Versions: &PolicyVersionsService{client: c},
		Settings: &PolicySettingsService{client: c},
	}
	c.PolicySource = &PolicySourceService{client: c}
	c.Messaging = &MessagingService{client: c}
	c.ImportExport = &ImportExportService{client: c}
	c.DataSubjectRequests = &DataSubjectRequestsService{client: c}
	c.RadiusClients = &RadiusClientsService{client: c}
	c.LTIPlatforms = &LTIPlatformsService{client: c}
	c.Instance = &InstanceService{client: c}
	c.InstanceSecurity = &InstanceSecurityService{client: c}
	c.Referrals = &ReferralsService{client: c}
	c.UserHooks = &UserHooksService{client: c}
	c.Tokens = &TokensService{client: c}

	c.EmailAddresses = &EmailAddressesService{client: c}
	c.OrganizationSettingsSchema = &OrganizationSettingsSchemaService{client: c}
	c.Machines = &MachinesService{client: c, EnrolmentTokens: &MachineEnrolmentTokensService{client: c}}
	c.SessionExchangeApps = &SessionExchangeAppsService{client: c}
	c.RedirectURLs = &RedirectURLsService{client: c}
	c.Tickets = &TicketsService{client: c}
	c.Notifications = &NotificationsService{
		client:     c,
		Categories: &NotificationCategoriesService{client: c},
		Templates:  &NotificationTemplatesService{client: c},
	}
	c.OpenFGA = &OpenFGAService{client: c}
	c.Connectors = &ConnectorsService{client: c}
	c.AuditEvents = &AuditEventsService{client: c}
	c.Diagnostics = &DiagnosticsService{client: c}
	c.Analytics = &AnalyticsService{client: c}
	c.Captcha = &CaptchaService{client: c}
	c.Testing = &TestingService{client: c}
	c.MCP = &MCPService{client: c}
	c.LegacyAuth = &LegacyAuthService{client: c}
	c.BetterAuthImports = &BetterAuthImportsService{client: c}
	c.BetterAuthBridge = &BetterAuthBridgeService{client: c}
	c.OrgLDAPConnections = &OrgLDAPConnectionsService{client: c}
	c.PCA = &PCAService{client: c}
	c.Design = &DesignService{client: c, Assets: &DesignAssetsService{client: c}}
	c.EntitlementOverrides = &EntitlementOverridesService{client: c}
	c.Platform = &PlatformService{
		client:           c,
		Apps:             &PlatformAppsService{client: c},
		AtlasIDApps:      &AtlasIDAppsService{client: c},
		DesignAssets:     &PlatformDesignAssetsService{client: c},
		AtlasIDPublisher: &AtlasIDPublisherService{client: c},
		Keys:             &PlatformKeysService{client: c},
		Audit:            &PlatformAuditService{client: c, Streams: &PlatformAuditStreamsService{client: c}},
	}
	c.SecretKeys = &SecretKeysService{client: c}
	c.Keys = &KeysService{client: c}
	c.PartnerLinks = &PartnerLinksService{client: c, Outbound: &OutboundPartnerLinksService{client: c}, Requests: &PartnerLinkRequestsService{client: c}}
	c.PartnerPlatforms = &PartnerPlatformsService{client: c}
	c.AtlasIDGrants = &AtlasIDGrantsService{client: c}
	c.Privacy = &PrivacyService{client: c, Orchestrator: &PrivacyOrchestratorService{client: c}}
	c.Integrations = &IntegrationsService{client: c}
	c.Entitlements = &EntitlementsService{client: c}
	c.Notices = &NoticesService{client: c}
	c.SecurityAdvisories = &SecurityAdvisoriesService{client: c}
	c.SubProcessors = &SubProcessorsService{client: c}
	c.AuditExports = &AuditExportsService{client: c}
	c.Status = &StatusService{client: c}
	c.Delivery = &DeliveryService{client: c}
	return c
}

// requestConfig accumulates per-call options.
type requestConfig struct {
	idempotencyKey string
	strict         *bool
	headers        map[string]string
	dryRun         bool
	traceparent    string
}

// RequestOption tunes a single request: WithIdempotencyKey on creates, and
// StrictBody on any write to override the client's strict-bodies setting.
type RequestOption func(*requestConfig)

// WithIdempotencyKey sets the Idempotency-Key header (§9.1) so a retried create
// is de-duplicated server-side.
func WithIdempotencyKey(key string) RequestOption {
	return func(rc *requestConfig) { rc.idempotencyKey = key }
}

// StrictBody overrides the client-level strict setting (see WithStrict) for one
// write. StrictBody(true) sends `Atlas-Strict: true`, so an unknown body field is
// refused with 422 UNKNOWN_FIELD before anything is written; StrictBody(false)
// sends `Atlas-Strict: false`, opting this call out of an instance that rejects
// unknown fields by default.
func StrictBody(on bool) RequestOption {
	return func(rc *requestConfig) { rc.strict = &on }
}

// WithHeader sets an extra request header on one call (for example a header a
// newer API version accepts before this SDK models it).
func WithHeader(name, value string) RequestOption {
	return func(rc *requestConfig) {
		if rc.headers == nil {
			rc.headers = map[string]string{}
		}
		rc.headers[name] = value
	}
}

// UnknownFieldsHandler receives the body fields an endpoint ignored, as reported
// by the `Atlas-Unknown-Fields` response header (dotted paths for nested
// fields). It is called only when the header is present and non-empty.
type UnknownFieldsHandler func(method, path string, fields []string)

// authKind selects which credential a request is signed with.
type authKind int

const (
	authSecret   authKind = iota // sk_ — the Backend API
	authPlatform                 // psk_ — /v1/platform/*
)

// do performs a single BAPI request. body is JSON-encoded when non-nil; a 2xx
// body is decoded into out when out is non-nil. A non-2xx becomes an *APIError.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out interface{}, opts ...RequestOption) error {
	return c.doAuth(ctx, authSecret, method, path, query, body, out, opts...)
}

// doAuth is do with an explicit credential choice.
func (c *Client) doAuth(ctx context.Context, auth authKind, method, path string, query url.Values, body, out interface{}, opts ...RequestOption) error {
	var payload []byte
	contentType := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("atlas: encoding request body: %w", err)
		}
		payload = encoded
		contentType = "application/json"
	}
	_, err := c.send(ctx, auth, method, path, query, contentType, payload, body != nil, out, opts...)
	return err
}

// doRaw sends raw request bytes (an image upload, say) with the given
// content type, decoding a JSON 2xx response into out.
func (c *Client) doRaw(ctx context.Context, auth authKind, method, path string, query url.Values, contentType string, payload []byte, out interface{}, opts ...RequestOption) error {
	_, err := c.send(ctx, auth, method, path, query, contentType, payload, true, out, opts...)
	return err
}

// doBytes performs a request and returns the raw 2xx body without decoding it
// (streamed exports such as JSONL / CSV).
func (c *Client) doBytes(ctx context.Context, method, path string, query url.Values) ([]byte, error) {
	return c.send(ctx, authSecret, method, path, query, "", nil, false, nil)
}

func (c *Client) send(ctx context.Context, auth authKind, method, path string, query url.Values, contentType string, payload []byte, hasBody bool, out interface{}, opts ...RequestOption) ([]byte, error) {
	var cfg requestConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	var reader io.Reader
	if hasBody {
		reader = bytes.NewReader(payload)
	}

	if cfg.dryRun && method != http.MethodGet {
		q := url.Values{}
		for k, vs := range query {
			q[k] = append([]string(nil), vs...)
		}
		q.Set("dry_run", "true")
		query = q
	}

	fullURL := c.baseURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, fmt.Errorf("atlas: building request: %w", err)
	}
	key := c.secretKey
	if auth == authPlatform && c.platformKey != "" {
		key = c.platformKey
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if hasBody && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if cfg.idempotencyKey != "" && !(cfg.dryRun && method != http.MethodGet) {
		req.Header.Set("Idempotency-Key", cfg.idempotencyKey)
	}
	if cfg.traceparent != "" {
		req.Header.Set("traceparent", cfg.traceparent)
	}
	if c.secretRecipient != "" {
		req.Header.Set("X-Secret-Recipient", c.secretRecipient)
	}
	if isWrite(method) {
		strict := c.strict
		if cfg.strict != nil {
			strict = cfg.strict
		}
		if strict != nil {
			if *strict {
				req.Header.Set("Atlas-Strict", "true")
			} else {
				req.Header.Set("Atlas-Strict", "false")
			}
		}
	}
	for name, value := range cfg.headers {
		req.Header.Set(name, value)
	}

	hc := c.httpClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("atlas: performing request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("atlas: reading response body: %w", err)
	}

	if c.onUnknownFields != nil {
		if fields := parseUnknownFields(resp.Header.Get("Atlas-Unknown-Fields")); len(fields) > 0 {
			c.onUnknownFields(method, path, fields)
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp.StatusCode, raw)
	}

	if out == nil || len(raw) == 0 {
		return raw, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return raw, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return raw, nil
}

func isWrite(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

// parseUnknownFields splits the comma-separated Atlas-Unknown-Fields header.
func parseUnknownFields(header string) []string {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	var fields []string
	for _, f := range strings.Split(header, ",") {
		if f = strings.TrimSpace(f); f != "" {
			fields = append(fields, f)
		}
	}
	return fields
}

// get/post/patch/put/del are thin verb helpers over do, keeping namespace
// methods to a single readable line.
func (c *Client) get(ctx context.Context, path string, query url.Values, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, query, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodPost, path, nil, body, out, opts...)
}

func (c *Client) patch(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodPatch, path, nil, body, out, opts...)
}

func (c *Client) put(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodPut, path, nil, body, out, opts...)
}

func (c *Client) del(ctx context.Context, path string, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, out, opts...)
}

// delQ is del with a query string.
func (c *Client) delQ(ctx context.Context, path string, query url.Values, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodDelete, path, query, nil, out, opts...)
}

// postQ is post with a query string.
func (c *Client) postQ(ctx context.Context, path string, query url.Values, body, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodPost, path, query, body, out, opts...)
}

// platGet/platPost/platPatch/platPut/platDel sign with the platform key
// (psk_) — the /v1/platform/* surface.
func (c *Client) platGet(ctx context.Context, path string, query url.Values, out interface{}) error {
	return c.doAuth(ctx, authPlatform, http.MethodGet, path, query, nil, out)
}

func (c *Client) platPost(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.doAuth(ctx, authPlatform, http.MethodPost, path, nil, body, out, opts...)
}

func (c *Client) platPatch(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.doAuth(ctx, authPlatform, http.MethodPatch, path, nil, body, out, opts...)
}

func (c *Client) platPut(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.doAuth(ctx, authPlatform, http.MethodPut, path, nil, body, out, opts...)
}

func (c *Client) platDel(ctx context.Context, path string, out interface{}, opts ...RequestOption) error {
	return c.doAuth(ctx, authPlatform, http.MethodDelete, path, nil, nil, out, opts...)
}
