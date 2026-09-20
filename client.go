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
	baseURL    string
	secretKey  string
	httpClient *http.Client

	// Namespaces — one per BAPI area, mirroring the TypeScript SDK.
	Users            *UsersService
	Sessions         *SessionsService
	Organizations    *OrganizationsService
	Invitations      *InvitationsService
	Roles            *RolesService
	Permissions      *PermissionsService
	OAuthClients     *OAuthClientsService
	ResourceServers  *ResourceServersService
	SSOConnections   *SSOConnectionsService
	SCIMTokens       *SCIMTokensService
	Domains          *DomainsService
	Webhooks         *WebhooksService
	Waitlist         *WaitlistService
	Allowlist        *AllowlistService
	Blocklist        *BlocklistService
	AttackProtection *AttackProtectionService
	ActorTokens      *ActorTokensService
	SignInTokens     *SignInTokensService
	AuditLogs        *AuditLogsService
	JWTTemplates     *JWTTemplatesService
	APIKeys          *APIKeysService

	OAuthProviders      *OAuthProvidersService
	SSOOnboarding       *SSOOnboardingService
	SCIMProvisioning    *SCIMProvisioningService
	FGA                 *FGAService
	RateLimitPolicy     *RateLimitPolicyService
	RiskBasedMFA        *RiskBasedMFAService
	BotSignals          *BotSignalsService
	NetworkACLs         *NetworkACLsService
	ManagedWAF          *ManagedWAFService
	LogStreams          *LogStreamsService
	Branding            *BrandingService
	EmailTemplates      *EmailTemplatesService
	SMSTemplates        *SMSTemplatesService
	Localizations       *LocalizationsService
	Actions             *ActionsService
	Billing             *BillingService
	Messaging           *MessagingService
	ImportExport        *ImportExportService
	DataSubjectRequests *DataSubjectRequestsService
	RadiusClients       *RadiusClientsService
	LTIPlatforms        *LTIPlatformsService
	Instance            *InstanceService
	InstanceSecurity    *InstanceSecurityService
	Tokens              *TokensService
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
	}
	c.Invitations = &InvitationsService{client: c}
	c.Roles = &RolesService{client: c}
	c.Permissions = &PermissionsService{client: c}
	c.OAuthClients = &OAuthClientsService{client: c, Grants: &OAuthClientGrantsService{client: c}}
	c.ResourceServers = &ResourceServersService{client: c}
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
	c.Branding = &BrandingService{client: c}
	c.EmailTemplates = &EmailTemplatesService{client: c}
	c.SMSTemplates = &SMSTemplatesService{client: c}
	c.Localizations = &LocalizationsService{client: c}
	c.Actions = &ActionsService{client: c}
	c.Billing = &BillingService{client: c}
	c.Messaging = &MessagingService{client: c}
	c.ImportExport = &ImportExportService{client: c}
	c.DataSubjectRequests = &DataSubjectRequestsService{client: c}
	c.RadiusClients = &RadiusClientsService{client: c}
	c.LTIPlatforms = &LTIPlatformsService{client: c}
	c.Instance = &InstanceService{client: c}
	c.InstanceSecurity = &InstanceSecurityService{client: c}
	c.Tokens = &TokensService{client: c}
	return c
}

// requestConfig accumulates per-call options (currently the Idempotency-Key).
type requestConfig struct {
	idempotencyKey string
}

// RequestOption tunes a single request. The only one today is
// WithIdempotencyKey, accepted on create/mutation methods.
type RequestOption func(*requestConfig)

// WithIdempotencyKey sets the Idempotency-Key header (§9.1) so a retried create
// is de-duplicated server-side.
func WithIdempotencyKey(key string) RequestOption {
	return func(rc *requestConfig) { rc.idempotencyKey = key }
}

// do performs a single BAPI request. body is JSON-encoded when non-nil; a 2xx
// body is decoded into out when out is non-nil. A non-2xx becomes an *APIError.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out interface{}, opts ...RequestOption) error {
	var cfg requestConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("atlas: encoding request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	fullURL := c.baseURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return fmt.Errorf("atlas: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", cfg.idempotencyKey)
	}

	hc := c.httpClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("atlas: performing request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("atlas: reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseError(resp.StatusCode, raw)
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return nil
}

// get/post/patch/put/del are thin verb helpers over do, keeping namespace
// methods to a single readable line.
func (c *Client) get(ctx context.Context, path string, query url.Values, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, query, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out interface{}, opts ...RequestOption) error {
	return c.do(ctx, http.MethodPost, path, nil, body, out, opts...)
}

func (c *Client) patch(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPatch, path, nil, body, out)
}

func (c *Client) put(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPut, path, nil, body, out)
}

func (c *Client) del(ctx context.Context, path string, out interface{}) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, out)
}
