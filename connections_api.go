package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ConnectionsService is the connections resource.
type ConnectionsService struct {
	client       *Client
	OAuthClients *ConnectionsOAuthClientsService
	Webhooks     *ConnectionsWebhooksService
}

// Create: Define a connection: an owner (an organization or a user) and a third-party API. `kind`
// is oauth (rides a linked provider account; for an organization, the account of the member who
// shared it), api_key or client_credentials (a credential the owner enters). `allowed_hosts` lists
// the only hosts the relay may call. An owner may hold several connections of one provider (one
// per provider account): create one per account, then call `POST /v1/connections/{id}/connect`. A
// connection is never a sign-in method.
// POST /v1/connections.
func (s *ConnectionsService) Create(ctx context.Context, params ConnectionsCreateParams, opts ...RequestOption) (*ConnectionsCreateResult, error) {
	out := &ConnectionsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections", nil, params, out, opts...)
}

// ConnectionsListQuery holds the query parameters of ConnectionsService.List.
type ConnectionsListQuery struct {
	// Owner type to filter by.
	OwnerType string
	// Restrict to one owner.
	OwnerID string
	// Restrict to one provider.
	Provider string
	// Restrict to one environment.
	Environment string
	// Restrict to one status.
	Status string
	// Cursor: the id of the last connection of the previous page.
	StartingAfter string
	// Page size. Defaults to 50; values above 200 are capped at 200.
	Limit int64
}

func (q ConnectionsListQuery) values() url.Values {
	v := url.Values{}
	if q.OwnerType != "" {
		v.Set("owner_type", q.OwnerType)
	}
	if q.OwnerID != "" {
		v.Set("owner_id", q.OwnerID)
	}
	if q.Provider != "" {
		v.Set("provider", q.Provider)
	}
	if q.Environment != "" {
		v.Set("environment", q.Environment)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	return v
}

// List: List connections, newest first, with each one's live status. Filter by owner or provider.
// GET /v1/connections.
func (s *ConnectionsService) List(ctx context.Context, query ConnectionsListQuery) (*CursorPage[ConnectionsCreateResult], error) {
	out := &CursorPage[ConnectionsCreateResult]{}
	return out, s.client.do(ctx, "GET", "/v1/connections", query.values(), nil, out)
}

// Get: Read one connection with its current status.
// GET /v1/connections/{id}.
func (s *ConnectionsService) Get(ctx context.Context, id string) (*ConnectionsCreateResult, error) {
	out := &ConnectionsCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/connections/"+url.PathEscape(id), nil, nil, out)
}

// Update: Rename a connection, change its allowed hosts or settings, transfer it to another owner
// with `owner` (the stored tokens move with it, no reconnect), change `environment` or
// `host_params` (an oauth connection that already holds a token becomes needs_reauth, because the
// token belongs to the old host), or (organization-owned oauth) set `shared_by_user_id` to copy
// that member's linked account into the connection.
// PATCH /v1/connections/{id}.
func (s *ConnectionsService) Update(ctx context.Context, id string, params ConnectionsUpdateParams, opts ...RequestOption) (*ConnectionsCreateResult, error) {
	out := &ConnectionsCreateResult{}
	return out, s.client.do(ctx, "PATCH", "/v1/connections/"+url.PathEscape(id), nil, params, out, opts...)
}

// ConnectionsDeleteQuery holds the query parameters of ConnectionsService.Delete.
type ConnectionsDeleteQuery struct {
	// Revoke the token at the provider before deleting, and return the outcome.
	Revoke *bool
}

func (q ConnectionsDeleteQuery) values() url.Values {
	v := url.Values{}
	if q.Revoke != nil {
		v.Set("revoke", strconv.FormatBool(*q.Revoke))
	}
	return v
}

// Delete: Delete a connection and its stored credential (204). With `revoke=true` the token is
// first revoked at the provider and the answer is 200 with what the provider said
// (provider_revoked true, false or "unsupported", provider_error, local_cleared); the connection
// is deleted either way.
// DELETE /v1/connections/{id}.
func (s *ConnectionsService) Delete(ctx context.Context, id string, query ConnectionsDeleteQuery, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/connections/"+url.PathEscape(id), query.values(), nil, nil, opts...)
}

// SetCredentials: Enter the credential for a non-OAuth connection (api_key, bearer, basic,
// custom_header, hmac_secret, client_credentials, jwt_bearer, oauth1, github_app_installation).
// Write-only: it is sealed in the vault and never returned. Replaces the earlier credential as a
// new vault version; use POST .../credentials/rotate to keep the old version valid for an overlap
// window.
// PUT /v1/connections/{id}/credentials.
func (s *ConnectionsService) SetCredentials(ctx context.Context, id string, params ConnectionsSetCredentialsParams, opts ...RequestOption) (*ConnectionsCreateResult, error) {
	out := &ConnectionsCreateResult{}
	return out, s.client.do(ctx, "PUT", "/v1/connections/"+url.PathEscape(id)+"/credentials", nil, params, out, opts...)
}

// Connect: Start the provider authorization for this connection and return the URL to send the
// owner to. The tokens are stored on the connection itself, never on a user: no external account
// is created, no sign-in method is added, no email is proven and no step-up is needed.
// `host_params` fill the provider's host templates for this connection (validated against a
// per-provider allowlist; 400 `host_params.<key>` otherwise). Reconnecting the same provider
// account updates the same connection; a different account answers 409 unless `create_if_new` is
// true. An owner OAuth client (`PUT /v1/connections/oauth_clients`) overrides the instance client.
// POST /v1/connections/{id}/connect.
func (s *ConnectionsService) Connect(ctx context.Context, id string, params ConnectionsConnectParams, opts ...RequestOption) (*ConnectionsConnectResult, error) {
	out := &ConnectionsConnectResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/connect", nil, params, out, opts...)
}

// Revoke: Revoke the stored token at the provider, delete it from the vault and mark the
// connection revoked (connection.revoked is sent once). The response is the connection plus what
// the provider said: provider_revoked is true only when it confirmed, "unsupported" when it has no
// revoke endpoint, false when it refused or was unreachable (provider_error says why). The local
// token is cleared in every case. Connect again to use it.
// POST /v1/connections/{id}/revoke.
func (s *ConnectionsService) Revoke(ctx context.Context, id string, params map[string]interface{}, opts ...RequestOption) (interface{}, error) {
	var out interface{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/revoke", nil, params, &out, opts...)
}

// Oauth1Sign: Have Atlas sign a request with an oauth1 connection (NetSuite token-based
// authentication: HMAC-SHA256 with the realm; X Ads and other three-legged providers: HMAC-SHA1)
// and return the `Authorization: OAuth ...` header. The consumer and token secrets never leave
// Atlas. The URL must be https on an allowed host; a form-encoded body is part of the signature.
// Needs connections:sign.
// POST /v1/connections/{id}/oauth1/sign.
func (s *ConnectionsService) Oauth1Sign(ctx context.Context, id string, params ConnectionsOauth1SignParams, opts ...RequestOption) (*ConnectionsOauth1SignResult, error) {
	out := &ConnectionsOauth1SignResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/oauth1/sign", nil, params, out, opts...)
}

// Relay: Make a provider API call server-side with this connection's credential, so the credential
// never reaches your code: Atlas injects an api_key (header or query), bearer, basic or custom
// header, signs with an hmac_secret or OAuth 1.0a, or sends a minted client_credentials /
// jwt_bearer / GitHub App installation / admin consent token. Only https calls to the connection's
// allowed_hosts are made, with the verbs in allowed_methods (default GET, HEAD, POST). When the
// connection is not connected, or the provider rejects the credential, the answer is 402
// CONNECTION_REQUIRED with `meta.reason` (not_connected or needs_reauth) and, for a user-owned
// OAuth connection when you pass `redirect_url`, `meta.authorize_url`. The audit log records the
// method, host and status only.
// POST /v1/connections/{id}/relay.
func (s *ConnectionsService) Relay(ctx context.Context, id string, params ConnectionsRelayParams, opts ...RequestOption) (*ConnectionsRelayResult, error) {
	out := &ConnectionsRelayResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/relay", nil, params, out, opts...)
}

// ConnectionsTokenQuery holds the query parameters of ConnectionsService.Token.
type ConnectionsTokenQuery struct {
	// Refresh first unless at least this many seconds of validity remain (0 to 3600). Default 0: the
	// usual one-minute margin.
	MinTTLSeconds int64
	// jwt_bearer only: act as this user (Google domain-wide delegation). The token is cached per
	// subject.
	Subject string
	// Set to true to force a refresh even if the token is still valid (never cached). Prefer POST
	// .../token/refresh with the stale token hash, which does not refresh again when a peer already
	// did.
	Refresh string
}

func (q ConnectionsTokenQuery) values() url.Values {
	v := url.Values{}
	if q.MinTTLSeconds != 0 {
		v.Set("min_ttl_seconds", strconv.FormatInt(q.MinTTLSeconds, 10))
	}
	if q.Subject != "" {
		v.Set("subject", q.Subject)
	}
	if q.Refresh != "" {
		v.Set("refresh", q.Refresh)
	}
	return v
}

// Token: The connection's live token for your backend. An oauth connection's token is refreshed
// first when it is expired or about to be (single-flight across processes, using the client that
// issued it and the connection's host_params). Built for sync workers: the response carries an
// `ETag` and `Cache-Control: private, max-age=<seconds until just before expires_at>`, so cache it
// until then; send `If-None-Match` and an unchanged, still-valid token answers 304 with no body
// and no vault read; `min_ttl_seconds` refreshes first when less than that much validity remains.
// A grant connection (client_credentials, jwt_bearer, github_app_installation, admin_consent) has
// its token minted from the credential Atlas holds instead, answered with `Cache-Control:
// no-store` (no ETag); pass `subject` to a jwt_bearer connection to act as that user (Google
// domain-wide delegation). Includes the captured handles (`metadata`, `token_response`) and any
// further named credentials. 402 CONNECTION_REQUIRED with `meta.reason` not_connected,
// needs_reauth, revoked or refresh_failed when there is no usable token. When the provider answers
// 401 to the token, call `POST /v1/connections/{id}/token/refresh` instead of re-reading. Rate
// limit: 6,000 reads per minute per secret key and 300 per minute per connection (RateLimit-*
// headers on every response, 429 with Retry-After beyond them). Reads are audited as
// connection.token_read once per connection per minute with the read count (a read that refreshed
// is always audited); the token itself is never logged.
// GET /v1/connections/{id}/token.
func (s *ConnectionsService) Token(ctx context.Context, id string, query ConnectionsTokenQuery) (*ConnectionsTokenResult, error) {
	out := &ConnectionsTokenResult{}
	return out, s.client.do(ctx, "GET", "/v1/connections/"+url.PathEscape(id)+"/token", query.values(), nil, out)
}

// RefreshToken: Force a refresh after the provider refused the access token (401). Single-flight:
// however many callers saw the same 401, the provider is called once. Send `stale_token_hash`
// (lowercase hex SHA-256 of the access token you were refused with); if the stored token is
// already a different one, a peer has refreshed and the current token is returned without calling
// the provider (`refreshed: false`). Same body, ETag and 402 behaviour as the token read; the
// response is never cached. Counts against the same rate limit as the token read.
// POST /v1/connections/{id}/token/refresh.
func (s *ConnectionsService) RefreshToken(ctx context.Context, id string, params ConnectionsRefreshTokenParams, opts ...RequestOption) (*ConnectionsTokenResult, error) {
	out := &ConnectionsTokenResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/token/refresh", nil, params, out, opts...)
}

// Tokens: Read the tokens of up to 100 connections in one call (min_ttl_seconds applies to each).
// Each id gets its own result: status ok with the token, or status error with a code and reason
// (not_connected, needs_reauth, revoked, refresh_failed, unknown_connection), so one dead
// connection never fails the batch. The response is never cached. Counts once against the
// token-read rate limit.
// POST /v1/connections/tokens/batch.
func (s *ConnectionsService) Tokens(ctx context.Context, params ConnectionsTokensParams, opts ...RequestOption) (*CursorPage[ConnectionsTokensItem], error) {
	out := &CursorPage[ConnectionsTokensItem]{}
	return out, s.client.do(ctx, "POST", "/v1/connections/tokens/batch", nil, params, out, opts...)
}

// ImportConnections: Bulk-import existing provider refresh tokens as connections, up to 500 rows,
// so nobody reconnects. Each row: provider, owner, external_id (the provider-side account: how a
// re-import finds the same connection), refresh_token (or access_token), and optionally scopes,
// metadata, environment, host_params, name, allowed_hosts. By default (validate true) each refresh
// token is spent once against the provider with the OAuth client that will own the connection, and
// the tokens the provider issues are stored, so the imported copy stops being current on a
// rotating provider. A failing row creates and changes nothing. dry_run checks shapes only and
// never calls the provider. Idempotent on Idempotency-Key. Tokens go straight to the vault and
// never appear in the answer or the audit log.
// POST /v1/connections/import.
func (s *ConnectionsService) ImportConnections(ctx context.Context, params ConnectionsImportConnectionsParams, opts ...RequestOption) (*ConnectionsImportConnectionsResult, error) {
	out := &ConnectionsImportConnectionsResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/import", nil, params, out, opts...)
}

// ExportConnections: Export connections. Without include_secrets: metadata only (provider, owner,
// account, environment, scopes, status), scope connections:export. With include_secrets: needs
// scope connections:export_secrets, the header X-Atlas-Confirm: export-secrets and
// recipient_public_key (a public JWK: RSA of 3072 bits or more, or EC P-256/384/521). The tokens
// come back as one compact JWE sealed to that key that only its holder can open; Atlas keeps no
// plaintext. Pages hold up to 200 connections with secrets (500 without); follow next_cursor with
// starting_after. Every export is audited with its count, never the secrets. Opened, each
// connection is a valid import row.
// POST /v1/connections/export.
func (s *ConnectionsService) ExportConnections(ctx context.Context, params ConnectionsExportConnectionsParams, opts ...RequestOption) (*ConnectionsExportConnectionsResult, error) {
	out := &ConnectionsExportConnectionsResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/export", nil, params, out, opts...)
}

// ConnectionsSecretQuery holds the query parameters of ConnectionsService.Secret.
type ConnectionsSecretQuery struct {
	// current (default), previous, or a version number.
	Version string
}

func (q ConnectionsSecretQuery) values() url.Values {
	v := url.Values{}
	if q.Version != "" {
		v.Set("version", q.Version)
	}
	return v
}

// Secret: Read the credential an api_key, bearer, basic, custom_header or hmac_secret connection
// stores, for your backend. Needs the dedicated connections:secret_read scope; every read is
// audited as connection.secret.read with the caller, connection and version (never the value) and
// the response is `Cache-Control: no-store`. `version` is current (default), previous (only while
// a rotation's overlap window is open) or a version number. A signing grant's private key is never
// readable: 409 `not_readable`. There is no browser or session route that reads a credential.
// GET /v1/connections/{id}/secret.
func (s *ConnectionsService) Secret(ctx context.Context, id string, query ConnectionsSecretQuery) (*OrganizationsGetConnectionSecretResult, error) {
	out := &OrganizationsGetConnectionSecretResult{}
	return out, s.client.do(ctx, "GET", "/v1/connections/"+url.PathEscape(id)+"/secret", query.values(), nil, out)
}

// SecretVersions: The vault versions of a connection's entered credential (numbers and times only,
// never values) and the open rotation window.
// GET /v1/connections/{id}/credentials/versions.
func (s *ConnectionsService) SecretVersions(ctx context.Context, id string, params ListParams) (*ConnectionsSecretVersionsResult, error) {
	out := &ConnectionsSecretVersionsResult{}
	return out, s.client.do(ctx, "GET", "/v1/connections/"+url.PathEscape(id)+"/credentials/versions", params.values(), nil, out)
}

// RotateCredentials: Rotate the credential: the body is the new credential (the same fields as PUT
// credentials). It becomes the current vault version; the replaced one stays valid for
// `overlap_seconds` (default 3600, up to 30 days): the relay falls back to it when the provider
// refuses the new one, and GET secret?version=previous returns it. `expires_at` sets the new
// credential's expiry. The secret never reaches the audit log.
// POST /v1/connections/{id}/credentials/rotate.
func (s *ConnectionsService) RotateCredentials(ctx context.Context, id string, params ConnectionsRotateCredentialsParams, opts ...RequestOption) (*ConnectionsCreateResult, error) {
	out := &ConnectionsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/credentials/rotate", nil, params, out, opts...)
}

// ConnectionsOAuthClientsService is the connections oauthClients group of ConnectionsService.
type ConnectionsOAuthClientsService struct {
	client *Client
}

// Set: Set an owner's own OAuth client (their registered app) for a provider and environment. It
// overrides the instance client for that owner's connections to connect and to refresh. Write-only
// secret, sealed in the vault. Creates the client or replaces it.
// PUT /v1/connections/oauth_clients.
func (s *ConnectionsOAuthClientsService) Set(ctx context.Context, params ConnectionsOAuthClientsSetParams, opts ...RequestOption) (*ConnectionsOAuthClientsSetResult, error) {
	out := &ConnectionsOAuthClientsSetResult{}
	return out, s.client.do(ctx, "PUT", "/v1/connections/oauth_clients", nil, params, out, opts...)
}

// ConnectionsOAuthClientsListQuery holds the query parameters of ConnectionsOAuthClientsService.List.
type ConnectionsOAuthClientsListQuery struct {
	// Owner type to filter by.
	OwnerType string
	// Restrict to one owner.
	OwnerID string
	// Restrict to one provider.
	Provider string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q ConnectionsOAuthClientsListQuery) values() url.Values {
	v := url.Values{}
	if q.OwnerType != "" {
		v.Set("owner_type", q.OwnerType)
	}
	if q.OwnerID != "" {
		v.Set("owner_id", q.OwnerID)
	}
	if q.Provider != "" {
		v.Set("provider", q.Provider)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List owner OAuth clients. The secret is never returned.
// GET /v1/connections/oauth_clients.
func (s *ConnectionsOAuthClientsService) List(ctx context.Context, query ConnectionsOAuthClientsListQuery) (*CursorPage[ConnectionsOAuthClientsSetResult], error) {
	out := &CursorPage[ConnectionsOAuthClientsSetResult]{}
	return out, s.client.do(ctx, "GET", "/v1/connections/oauth_clients", query.values(), nil, out)
}

// Get: Read one owner OAuth client.
// GET /v1/connections/oauth_clients/{id}.
func (s *ConnectionsOAuthClientsService) Get(ctx context.Context, id string) (*ConnectionsOAuthClientsSetResult, error) {
	out := &ConnectionsOAuthClientsSetResult{}
	return out, s.client.do(ctx, "GET", "/v1/connections/oauth_clients/"+url.PathEscape(id), nil, nil, out)
}

// Delete: Delete an owner OAuth client and its sealed secret. 409 while connections still hold
// tokens it issued (they could no longer refresh).
// DELETE /v1/connections/oauth_clients/{id}.
func (s *ConnectionsOAuthClientsService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/connections/oauth_clients/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// ConnectionsWebhooksService is the connections webhooks group of ConnectionsService.
type ConnectionsWebhooksService struct {
	client *Client
}

// Verify: Verify a provider webhook signature with the connection's secret (the endpoint's own
// signing secret, else the connection's hmac_secret, else its OAuth client secret). Schemes:
// hubspot_v3 (needs method and url), shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
// generic_hmac_sha256. Constant-time comparison; a signed timestamp must be within the tolerance
// (5 minutes, Calendly 3); a delivery id or signature already seen on the connection answers
// `replayed`. Send the body exactly as received (`raw_body`, or base64 with raw_body_encoding).
// Zoom and Slack handshakes come back in `handshake`. Needs connections:webhook_verify.
// POST /v1/connections/{id}/webhooks/verify.
func (s *ConnectionsWebhooksService) Verify(ctx context.Context, id string, params ConnectionsWebhooksVerifyParams, opts ...RequestOption) (*ConnectionsWebhooksVerifyResult, error) {
	out := &ConnectionsWebhooksVerifyResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/webhooks/verify", nil, params, out, opts...)
}

// CreateEndpoint: Create a webhook ingress endpoint on a connection. Point the provider at
// `ingress_url`; Atlas verifies each delivery, refuses forged, stale and replayed ones, answers
// Zoom and Slack handshakes, and forwards only genuine deliveries to `forward_url` as Atlas-signed
// webhooks (atlas-id, atlas-timestamp, atlas-signature with `forward_secret`, returned once).
// Bodies over 1 MiB are refused; the ingress is rate limited.
// POST /v1/connections/{id}/webhook_endpoints.
func (s *ConnectionsWebhooksService) CreateEndpoint(ctx context.Context, id string, params ConnectionsWebhooksCreateEndpointParams, opts ...RequestOption) (*ConnectionsWebhooksCreateEndpointResult, error) {
	out := &ConnectionsWebhooksCreateEndpointResult{}
	return out, s.client.do(ctx, "POST", "/v1/connections/"+url.PathEscape(id)+"/webhook_endpoints", nil, params, out, opts...)
}

// ListEndpoints: List a connection's webhook ingress endpoints.
// GET /v1/connections/{id}/webhook_endpoints.
func (s *ConnectionsWebhooksService) ListEndpoints(ctx context.Context, id string, params ListParams) (*CursorPage[ConnectionsWebhooksCreateEndpointResult], error) {
	out := &CursorPage[ConnectionsWebhooksCreateEndpointResult]{}
	return out, s.client.do(ctx, "GET", "/v1/connections/"+url.PathEscape(id)+"/webhook_endpoints", params.values(), nil, out)
}

// UpdateEndpoint: Change an endpoint's forward_url, enabled flag or signing secret.
// PATCH /v1/connections/{id}/webhook_endpoints/{endpointId}.
func (s *ConnectionsWebhooksService) UpdateEndpoint(ctx context.Context, id string, endpointID string, params ConnectionsWebhooksUpdateEndpointParams, opts ...RequestOption) (*ConnectionsWebhooksCreateEndpointResult, error) {
	out := &ConnectionsWebhooksCreateEndpointResult{}
	return out, s.client.do(ctx, "PATCH", "/v1/connections/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID), nil, params, out, opts...)
}

// DeleteEndpoint: Delete a webhook ingress endpoint and its secrets.
// DELETE /v1/connections/{id}/webhook_endpoints/{endpointId}.
func (s *ConnectionsWebhooksService) DeleteEndpoint(ctx context.Context, id string, endpointID string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/connections/"+url.PathEscape(id)+"/webhook_endpoints/"+url.PathEscape(endpointID), nil, nil, nil, opts...)
}
