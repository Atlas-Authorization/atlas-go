package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// --- Instance signing keys ---------------------------------------------------

// SigningKey is one published token-signing key. Status is "current" (signs
// every new token) or "previous" (still in the JWKS until RetiresAt, epoch ms,
// after a rotation). Role is "main" or "secondary" (the key of the other
// algorithm, for APIs set to it).
type SigningKey struct {
	Object    string `json:"object"`
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	Status    string `json:"status"`
	Role      string `json:"role,omitempty"`
	RetiresAt *int64 `json:"retires_at"`
	// Provider is, on the current main key, "local" or the KMS holding its
	// private half (aws_kms, gcp_kms, azure_key_vault).
	Provider string `json:"provider,omitempty"`
}

// SigningKeyList is GET /v1/instance/signing_keys.
type SigningKeyList struct {
	Object string       `json:"object"`
	Data   []SigningKey `json:"data"`
}

// RotateSigningKeyParams is the body of POST /v1/instance/signing_keys/rotate.
// Alg switches the instance key's algorithm ("RS256" or "ES256");
// GracePeriodSeconds keeps the previous key published (default 86400, at most
// 2592000); Emergency publishes ONLY the new key (old tokens stop verifying at
// once) and is required for a second rotation inside a grace window.
type RotateSigningKeyParams struct {
	Alg                string `json:"alg,omitempty"`
	GracePeriodSeconds *int64 `json:"grace_period_seconds,omitempty"`
	Emergency          bool   `json:"emergency,omitempty"`
}

// SigningKeyRotation is the result of a rotation.
type SigningKeyRotation struct {
	Object            string  `json:"object"`
	Kid               string  `json:"kid"`
	Alg               string  `json:"alg"`
	PreviousKid       *string `json:"previous_kid"`
	PreviousRetiresAt *int64  `json:"previous_retires_at"`
	Emergency         bool    `json:"emergency"`
}

// ListSigningKeys lists the published signing keys, newest first.
// GET /v1/instance/signing_keys.
func (s *InstanceSecurityService) ListSigningKeys(ctx context.Context) (*SigningKeyList, error) {
	out := &SigningKeyList{}
	return out, s.client.get(ctx, "/v1/instance/signing_keys", nil, out)
}

// RotateSigningKey rotates the instance signing key, optionally switching its
// algorithm. POST /v1/instance/signing_keys/rotate.
func (s *InstanceSecurityService) RotateSigningKey(ctx context.Context, params RotateSigningKeyParams, opts ...RequestOption) (*SigningKeyRotation, error) {
	out := &SigningKeyRotation{}
	return out, s.client.post(ctx, "/v1/instance/signing_keys/rotate", params, out, opts...)
}

// --- Signing keys held in your own KMS --------------------------------------

// Key management services a signing key can live in.
const (
	SigningKeyProviderLocal         = "local"
	SigningKeyProviderAWSKMS        = "aws_kms"
	SigningKeyProviderGCPKMS        = "gcp_kms"
	SigningKeyProviderAzureKeyVault = "azure_key_vault"
)

// SigningKeyProviderSettings is GET /v1/instance/signing_key_provider. It never
// carries credentials. Config holds the non-secret settings (region, key / key
// ring / vault, algorithm), nil for "local"; Active is true when the current
// main key is in this KMS; KeyVersion is the KMS key version tokens are signed
// with (ARN, resource name or key id).
type SigningKeyProviderSettings struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id,omitempty"`
	Provider       string                 `json:"provider"`
	Config         map[string]interface{} `json:"config"`
	Active         bool                   `json:"active"`
	KeyVersion     *string                `json:"key_version"`
	LastVerifiedAt *int64                 `json:"last_verified_at,omitempty"`
	CreatedAt      int64                  `json:"created_at,omitempty"`
	UpdatedAt      int64                  `json:"updated_at,omitempty"`
	// Rotation is set on a PUT: the rotation onto the KMS key.
	Rotation *SigningKeyRotation `json:"rotation,omitempty"`
}

// SetSigningKeyProviderParams switches signing to a key in your own KMS.
//   - aws_kms: Config {region, key_id?, alg?}, Credentials {access_key_id, secret_access_key, session_token?}
//   - gcp_kms: Config {crypto_key, key_version?}, Credentials {service_account_json}
//   - azure_key_vault: Config {vault_url, key_name, key_version?, alg?}, Credentials {tenant_id, client_id, client_secret}
//
// Without a key id / version Atlas creates a new key version in the KMS.
// GracePeriodSeconds keeps the previous key published (default 86400, at most
// 2592000); Emergency publishes only the new key now.
type SetSigningKeyProviderParams struct {
	Provider           string                 `json:"provider"`
	Config             map[string]interface{} `json:"config"`
	Credentials        map[string]interface{} `json:"credentials"`
	GracePeriodSeconds *int64                 `json:"grace_period_seconds,omitempty"`
	Emergency          bool                   `json:"emergency,omitempty"`
}

// SigningKeyProviderRemoved acknowledges DELETE /v1/instance/signing_key_provider.
type SigningKeyProviderRemoved struct {
	Object   string              `json:"object"`
	Provider string              `json:"provider"`
	Deleted  bool                `json:"deleted"`
	Rotation *SigningKeyRotation `json:"rotation"`
}

// GetSigningKeyProvider reads where the signing key lives ("local" when no
// KMS is set). GET /v1/instance/signing_key_provider.
func (s *InstanceSecurityService) GetSigningKeyProvider(ctx context.Context) (*SigningKeyProviderSettings, error) {
	out := &SigningKeyProviderSettings{}
	return out, s.client.get(ctx, "/v1/instance/signing_key_provider", nil, out)
}

// SetSigningKeyProvider signs every token with a key in your AWS KMS, Google
// Cloud KMS or Azure Key Vault. PUT /v1/instance/signing_key_provider.
func (s *InstanceSecurityService) SetSigningKeyProvider(ctx context.Context, params SetSigningKeyProviderParams, opts ...RequestOption) (*SigningKeyProviderSettings, error) {
	out := &SigningKeyProviderSettings{}
	return out, s.client.put(ctx, "/v1/instance/signing_key_provider", params, out, opts...)
}

// RemoveSigningKeyProvider stops using the KMS: it rotates back to a key Atlas
// holds and forgets the credentials. params may set the grace period or
// Emergency. DELETE /v1/instance/signing_key_provider.
func (s *InstanceSecurityService) RemoveSigningKeyProvider(ctx context.Context, params RotateSigningKeyParams, opts ...RequestOption) (*SigningKeyProviderRemoved, error) {
	out := &SigningKeyProviderRemoved{}
	return out, s.client.do(ctx, "DELETE", "/v1/instance/signing_key_provider", nil, params, out, opts...)
}

// WalletRPCSecretResult acknowledges PUT /v1/instance/wallet_rpc_secret.
type WalletRPCSecretResult struct {
	Object  string `json:"object"`
	ChainID int64  `json:"chain_id"`
	Set     bool   `json:"set"`
}

// SetWalletRPCSecret stores (write-only, encrypted) the wallet RPC endpoint for
// an EIP-155 chain, used by wallet token gating and the Sign in with Ethereum
// ENS lookup. An empty url removes it; the URL is never returned.
// PUT /v1/instance/wallet_rpc_secret.
func (s *InstanceSecurityService) SetWalletRPCSecret(ctx context.Context, chainID int64, rpcURL string, opts ...RequestOption) (*WalletRPCSecretResult, error) {
	out := &WalletRPCSecretResult{}
	body := map[string]interface{}{"chain_id": chainID, "url": rpcURL}
	return out, s.client.put(ctx, "/v1/instance/wallet_rpc_secret", body, out, opts...)
}

// --- OAuth initial access tokens (RFC 7591 §3) -------------------------------

// OAuthInitialAccessTokensService is /v1/oauth_initial_access_tokens: tokens
// that gate dynamic client registration once
// oauthProvider.requireInitialAccessToken is on.
type OAuthInitialAccessTokensService struct{ client *Client }

// InitialAccessToken is a DCR initial access token. Token is set only on
// create (shown once, stored hashed). Status is active, expired, used_up or
// revoked.
type InitialAccessToken struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	TokenPrefix string  `json:"token_prefix"`
	Description *string `json:"description"`
	Status      string  `json:"status"`
	MaxUses     *int64  `json:"max_uses"`
	UseCount    int64   `json:"use_count"`
	ExpiresAt   *int64  `json:"expires_at"`
	RevokedAt   *int64  `json:"revoked_at"`
	LastUsedAt  *int64  `json:"last_used_at"`
	CreatedAt   int64   `json:"created_at"`
	Token       string  `json:"token,omitempty"`
}

// CreateInitialAccessTokenParams is the body of
// POST /v1/oauth_initial_access_tokens.
type CreateInitialAccessTokenParams struct {
	Description      string `json:"description,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
	MaxUses          int64  `json:"max_uses,omitempty"`
}

// List lists the tokens, newest first (the tokens themselves never).
// GET /v1/oauth_initial_access_tokens.
func (s *OAuthInitialAccessTokensService) List(ctx context.Context) (*CursorPage[InitialAccessToken], error) {
	out := &CursorPage[InitialAccessToken]{}
	return out, s.client.get(ctx, "/v1/oauth_initial_access_tokens", nil, out)
}

// Create mints a token; Token is returned exactly once.
// POST /v1/oauth_initial_access_tokens.
func (s *OAuthInitialAccessTokensService) Create(ctx context.Context, params CreateInitialAccessTokenParams, opts ...RequestOption) (*InitialAccessToken, error) {
	out := &InitialAccessToken{}
	return out, s.client.post(ctx, "/v1/oauth_initial_access_tokens", params, out, opts...)
}

// Revoke revokes a token at once. DELETE /v1/oauth_initial_access_tokens/:id.
func (s *OAuthInitialAccessTokensService) Revoke(ctx context.Context, id string, opts ...RequestOption) (*InitialAccessToken, error) {
	out := &InitialAccessToken{}
	return out, s.client.del(ctx, "/v1/oauth_initial_access_tokens/"+url.PathEscape(id), out, opts...)
}

// --- Delivery logs -------------------------------------------------------------

// BeforeUserCreateHookCall is one entry of the hook's delivery log.
type BeforeUserCreateHookCall struct {
	Object     string                 `json:"object"`
	ID         string                 `json:"id"`
	UserID     *string                `json:"user_id"`
	Test       bool                   `json:"test"`
	Status     string                 `json:"status"`
	HTTPStatus *int                   `json:"http_status"`
	LatencyMS  *int                   `json:"latency_ms"`
	Error      *string                `json:"error"`
	Answer     map[string]interface{} `json:"answer"`
	CreatedAt  int64                  `json:"created_at"`
}

// ListBeforeUserCreateCallsParams filters the hook's delivery log. Status is
// ok, failed, timeout, error or invalid_response; Test filters test calls.
type ListBeforeUserCreateCallsParams struct {
	Limit         int
	Status        string
	Test          *bool
	StartingAfter string
}

// ListBeforeUserCreateCalls returns the hook's delivery log, newest first
// (kept 30 days). GET /v1/instance/hooks/before_user_create/calls.
func (s *UserHooksService) ListBeforeUserCreateCalls(ctx context.Context, params ListBeforeUserCreateCallsParams) (*CursorPage[BeforeUserCreateHookCall], error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	if params.Test != nil {
		q.Set("test", strconv.FormatBool(*params.Test))
	}
	if params.StartingAfter != "" {
		q.Set("starting_after", params.StartingAfter)
	}
	out := &CursorPage[BeforeUserCreateHookCall]{}
	return out, s.client.get(ctx, "/v1/instance/hooks/before_user_create/calls", q, out)
}

// GetCall fetches one call of the referral delivery log, by its id or by the
// platform's request id. GET /v1/instance/referrals/calls/:id.
func (s *ReferralsService) GetCall(ctx context.Context, id string) (*ReferralCall, error) {
	out := &ReferralCall{}
	return out, s.client.get(ctx, "/v1/instance/referrals/calls/"+url.PathEscape(id), nil, out)
}
