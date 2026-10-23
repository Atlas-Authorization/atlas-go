package atlas

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── Migrate from Better Auth: sealed-bundle imports (/v1/better_auth_imports) ─

// BetterAuthImportsService imports a sealed bundle made by the Better Auth
// exporter (`npx atlas-better-auth-export`):
//
//  1. GetPublicKey: the key the exporter seals the bundle to.
//  2. Upload (or Create, UploadPart per part and Finalize): Atlas opens the
//     bundle and runs the dry run.
//  3. Read the import's Report, then Apply. Applying again after a failure
//     resumes where it stopped; every record is an idempotent upsert.
type BetterAuthImportsService struct{ client *Client }

// Better Auth import statuses: uploading → analyzing → ready | invalid →
// queued → applying → completed | failed.
const (
	BetterAuthImportUploading = "uploading"
	BetterAuthImportAnalyzing = "analyzing"
	BetterAuthImportReady     = "ready"
	BetterAuthImportInvalid   = "invalid"
	BetterAuthImportQueued    = "queued"
	BetterAuthImportApplying  = "applying"
	BetterAuthImportCompleted = "completed"
	BetterAuthImportFailed    = "failed"
)

// BetterAuthImportPartBytes is the default upload part size (the API takes at
// most 10 MiB per part). Parts always end on a line boundary.
const BetterAuthImportPartBytes = 8 * 1024 * 1024

// BetterAuthImportKey is the X25519 key the exporter seals a bundle to.
type BetterAuthImportKey struct {
	Object string `json:"object"`
	Kid    string `json:"kid"`
	// PublicKey is the base64url raw X25519 public key.
	PublicKey string `json:"public_key"`
	Alg       string `json:"alg"`
	// Status is active or retired.
	Status string `json:"status"`
	// Fingerprint is the SHA-256 of the raw key, first 16 bytes as hex pairs.
	Fingerprint string `json:"fingerprint"`
	// Compact is "kid:public_key", the form the exporter's --public-key takes.
	Compact   string `json:"compact"`
	CreatedAt int64  `json:"created_at"`
	RetiredAt *int64 `json:"retired_at"`
}

// BetterAuthImportOptions tunes what an import moves and how. Unknown or
// mistyped options are refused with 400.
type BetterAuthImportOptions struct {
	Models []string `json:"models,omitempty"`
	// OnEmailConflict is skip or link.
	OnEmailConflict   string `json:"on_email_conflict,omitempty"`
	DefaultRole       string `json:"default_role,omitempty"`
	CreateAppRoles    *bool  `json:"create_app_roles,omitempty"`
	ImportOAuthTokens *bool  `json:"import_oauth_tokens,omitempty"`
	// PasskeysOnRPMismatch is skip or import.
	PasskeysOnRPMismatch string            `json:"passkeys_on_rp_mismatch,omitempty"`
	ImportSubscriptions  *bool             `json:"import_subscriptions,omitempty"`
	PlanMap              map[string]string `json:"plan_map,omitempty"`
	ImportJWKS           *bool             `json:"import_jwks,omitempty"`
	// JWKSCutoverDays is 1–365 (default 30).
	JWKSCutoverDays int   `json:"jwks_cutover_days,omitempty"`
	ImportSessions  *bool `json:"import_sessions,omitempty"`
	RetainBundle    *bool `json:"retain_bundle,omitempty"`
}

// BetterAuthImportProgress reports an apply's progress.
type BetterAuthImportProgress struct {
	Total     int `json:"total"`
	Processed int `json:"processed"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Percent   int `json:"percent"`
}

// BetterAuthImportActionItem is something to fix before (or after) applying.
// Only severity "required" should block: those rows stay out until fixed and
// re-run.
type BetterAuthImportActionItem struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Count    int      `json:"count"`
	Items    []string `json:"items"`
}

// BetterAuthImportReport is the dry run (Models carry found / will_create /
// will_update / will_skip) or, as an import's Result, the apply outcome
// (created / updated / unchanged / skipped / failed).
type BetterAuthImportReport struct {
	Models         []map[string]interface{}     `json:"models"`
	Skipped        []map[string]interface{}     `json:"skipped"`
	SkippedTotal   int                          `json:"skipped_total"`
	SkippedByCode  map[string]int               `json:"skipped_by_code"`
	Conflicts      []map[string]interface{}     `json:"conflicts"`
	ConflictsTotal int                          `json:"conflicts_total"`
	ActionItems    []BetterAuthImportActionItem `json:"action_items"`
	Warnings       []string                     `json:"warnings"`
	Notes          map[string]interface{}       `json:"notes"`
	CompletedAt    *int64                       `json:"completed_at,omitempty"`
}

// BetterAuthImport is one bundle import.
type BetterAuthImport struct {
	Object         string                    `json:"object"`
	ID             string                    `json:"id"`
	Status         string                    `json:"status"`
	KeyID          *string                   `json:"key_id"`
	Parts          int                       `json:"parts"`
	Bytes          int64                     `json:"bytes"`
	BundleSHA256   *string                   `json:"bundle_sha256"`
	BundlePurged   bool                      `json:"bundle_purged"`
	Options        BetterAuthImportOptions   `json:"options"`
	Source         map[string]interface{}    `json:"source"`
	Total          int                       `json:"total"`
	Progress       *BetterAuthImportProgress `json:"progress"`
	Report         *BetterAuthImportReport   `json:"report"`
	Result         *BetterAuthImportReport   `json:"result"`
	Error          *ErrorItem                `json:"error"`
	CreatedAt      int64                     `json:"created_at"`
	UpdatedAt      int64                     `json:"updated_at"`
	AnalyzedAt     *int64                    `json:"analyzed_at"`
	ApplyStartedAt *int64                    `json:"apply_started_at"`
	CompletedAt    *int64                    `json:"completed_at"`
	Deleted        bool                      `json:"deleted,omitempty"`
}

// InFlight reports whether Atlas is still working on the import (analyzing,
// queued or applying).
func (i *BetterAuthImport) InFlight() bool {
	switch i.Status {
	case BetterAuthImportAnalyzing, BetterAuthImportQueued, BetterAuthImportApplying:
		return true
	}
	return false
}

// BetterAuthImportPart acknowledges one uploaded part.
type BetterAuthImportPart struct {
	Object   string `json:"object"`
	ImportID string `json:"import_id"`
	Part     int    `json:"part"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
}

// ImportedJWK is a Better Auth JWT key Atlas publishes in the instance JWKS for
// the cutover.
type ImportedJWK struct {
	Object    string                 `json:"object"`
	Kid       string                 `json:"kid"`
	Source    string                 `json:"source"`
	JWK       map[string]interface{} `json:"jwk"`
	ImportID  *string                `json:"import_id"`
	ExpiresAt *int64                 `json:"expires_at"`
	CreatedAt int64                  `json:"created_at"`
	Deleted   bool                   `json:"deleted,omitempty"`
}

// CreateBetterAuthImportParams starts (or, with new Options, re-runs the dry run of) an import.
type CreateBetterAuthImportParams struct {
	Options *BetterAuthImportOptions `json:"options,omitempty"`
}

// ApplyBetterAuthImportParams applies an import. ConfirmConflicts is required
// when the dry run reported conflicts (otherwise 409).
type ApplyBetterAuthImportParams struct {
	ConfirmConflicts bool `json:"confirm_conflicts,omitempty"`
}

const betterAuthImportsPath = "/v1/better_auth_imports"

// GetPublicKey reads the import key (created on first read).
// GET /v1/better_auth_imports/public_key.
func (s *BetterAuthImportsService) GetPublicKey(ctx context.Context) (*BetterAuthImportKey, error) {
	out := &BetterAuthImportKey{}
	return out, s.client.get(ctx, betterAuthImportsPath+"/public_key", nil, out)
}

// RotatePublicKey replaces the import key; bundles sealed to the old one no
// longer finalize (import_key_retired). POST /v1/better_auth_imports/public_key/rotate.
func (s *BetterAuthImportsService) RotatePublicKey(ctx context.Context, opts ...RequestOption) (*BetterAuthImportKey, error) {
	out := &BetterAuthImportKey{}
	return out, s.client.post(ctx, betterAuthImportsPath+"/public_key/rotate", nil, out, opts...)
}

// Create starts an import (status uploading). POST /v1/better_auth_imports.
func (s *BetterAuthImportsService) Create(ctx context.Context, params CreateBetterAuthImportParams, opts ...RequestOption) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.post(ctx, betterAuthImportsPath, params, out, opts...)
}

// List lists imports, newest first. GET /v1/better_auth_imports.
func (s *BetterAuthImportsService) List(ctx context.Context, params ListParams) (*CursorPage[BetterAuthImport], error) {
	out := &CursorPage[BetterAuthImport]{}
	return out, s.client.get(ctx, betterAuthImportsPath, params.values(), out)
}

// Get fetches an import: status, progress, report and result.
// GET /v1/better_auth_imports/{id}.
func (s *BetterAuthImportsService) Get(ctx context.Context, id string) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.get(ctx, betterAuthImportsPath+"/"+url.PathEscape(id), nil, out)
}

// UploadPart uploads part (1-based) of the sealed bundle: whole lines, at most
// 10 MiB, sent as text/plain. Re-sending a part replaces it.
// PUT /v1/better_auth_imports/{id}/parts/{part}.
func (s *BetterAuthImportsService) UploadPart(ctx context.Context, id string, part int, data []byte) (*BetterAuthImportPart, error) {
	out := &BetterAuthImportPart{}
	path := fmt.Sprintf("%s/%s/parts/%d", betterAuthImportsPath, url.PathEscape(id), part)
	return out, s.client.doRaw(ctx, authSecret, http.MethodPut, path, nil, "text/plain; charset=utf-8", data, out)
}

// Finalize closes the upload: Atlas checks the parts and the key, then runs the
// dry run (inline up to 4 MiB; larger bundles come back analyzing).
// POST /v1/better_auth_imports/{id}/finalize.
func (s *BetterAuthImportsService) Finalize(ctx context.Context, id string, opts ...RequestOption) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.post(ctx, betterAuthImportsPath+"/"+url.PathEscape(id)+"/finalize", nil, out, opts...)
}

// DryRun runs the dry run again; new Options replace the stored ones.
// POST /v1/better_auth_imports/{id}/dry_run.
func (s *BetterAuthImportsService) DryRun(ctx context.Context, id string, params CreateBetterAuthImportParams, opts ...RequestOption) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.post(ctx, betterAuthImportsPath+"/"+url.PathEscape(id)+"/dry_run", params, out, opts...)
}

// Apply imports (or resumes a failed import from its cursor).
// POST /v1/better_auth_imports/{id}/apply.
func (s *BetterAuthImportsService) Apply(ctx context.Context, id string, params ApplyBetterAuthImportParams, opts ...RequestOption) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.post(ctx, betterAuthImportsPath+"/"+url.PathEscape(id)+"/apply", params, out, opts...)
}

// Delete removes the import and its stored bundle; imported data stays.
// DELETE /v1/better_auth_imports/{id}.
func (s *BetterAuthImportsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*BetterAuthImport, error) {
	out := &BetterAuthImport{}
	return out, s.client.del(ctx, betterAuthImportsPath+"/"+url.PathEscape(id), out, opts...)
}

// ListJWKS lists the imported Better Auth JWT keys. GET /v1/better_auth_imports/jwks.
func (s *BetterAuthImportsService) ListJWKS(ctx context.Context) (*CursorPage[ImportedJWK], error) {
	out := &CursorPage[ImportedJWK]{}
	return out, s.client.get(ctx, betterAuthImportsPath+"/jwks", nil, out)
}

// DeleteJWK stops publishing one imported key. DELETE /v1/better_auth_imports/jwks/{kid}.
func (s *BetterAuthImportsService) DeleteJWK(ctx context.Context, kid string, opts ...RequestOption) (*ImportedJWK, error) {
	out := &ImportedJWK{}
	return out, s.client.del(ctx, betterAuthImportsPath+"/jwks/"+url.PathEscape(kid), out, opts...)
}

// SplitBundleParts splits a sealed bundle into upload parts of at most maxBytes
// (BetterAuthImportPartBytes when maxBytes <= 0), each ending on a line
// boundary. Empty lines are dropped; a single line longer than maxBytes becomes
// a part of its own.
func SplitBundleParts(bundle []byte, maxBytes int) [][]byte {
	if maxBytes <= 0 {
		maxBytes = BetterAuthImportPartBytes
	}
	var parts [][]byte
	var cur []byte
	for _, line := range strings.Split(string(bundle), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		n := len(line) + 1
		if len(cur) > 0 && len(cur)+n > maxBytes {
			parts = append(parts, cur)
			cur = nil
		}
		cur = append(cur, line...)
		cur = append(cur, '\n')
	}
	if len(cur) > 0 {
		parts = append(parts, cur)
	}
	return parts
}

// UploadBetterAuthBundleOptions tunes Upload.
type UploadBetterAuthBundleOptions struct {
	Options *BetterAuthImportOptions
	// PartBytes caps each part (default BetterAuthImportPartBytes).
	PartBytes int
	// OnPart is called after each part is uploaded.
	OnPart func(n, of int)
}

// Upload creates an import, uploads the sealed bundle in line-aligned parts of
// at most 8 MiB and finalizes it. The result is ready / invalid, or analyzing
// for a large bundle (see WaitFor).
func (s *BetterAuthImportsService) Upload(ctx context.Context, bundle []byte, opts UploadBetterAuthBundleOptions) (*BetterAuthImport, error) {
	parts := SplitBundleParts(bundle, opts.PartBytes)
	if len(parts) == 0 {
		return nil, errors.New("atlas: the bundle is empty")
	}
	created, err := s.Create(ctx, CreateBetterAuthImportParams{Options: opts.Options})
	if err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("atlas: Atlas did not return an import id")
	}
	for i, part := range parts {
		if _, err := s.UploadPart(ctx, created.ID, i+1, part); err != nil {
			return nil, err
		}
		if opts.OnPart != nil {
			opts.OnPart(i+1, len(parts))
		}
	}
	return s.Finalize(ctx, created.ID)
}

// WaitForBetterAuthImportOptions tunes WaitFor.
type WaitForBetterAuthImportOptions struct {
	// Interval between polls (default 2s).
	Interval time.Duration
	// Timeout overall (default 6h); the context's deadline also applies.
	Timeout time.Duration
	// OnProgress sees every polled import.
	OnProgress func(*BetterAuthImport)
}

// WaitFor polls until the import leaves analyzing / queued / applying and
// returns it (ready, invalid, completed or failed).
func (s *BetterAuthImportsService) WaitFor(ctx context.Context, id string, opts WaitForBetterAuthImportOptions) (*BetterAuthImport, error) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Hour
	}
	deadline := time.Now().Add(timeout)
	for {
		imp, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if opts.OnProgress != nil {
			opts.OnProgress(imp)
		}
		if !imp.InFlight() {
			return imp, nil
		}
		if time.Now().After(deadline) {
			return imp, fmt.Errorf("atlas: timed out waiting for Better Auth import %s (status %s)", id, imp.Status)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return imp, ctx.Err()
		case <-timer.C:
		}
	}
}

// ── Better Auth session bridge (/v1/migrations/better_auth/*) ───────────────

// BetterAuthBridgeService manages the session bridge: during a migration
// window a returning user's Better Auth session is exchanged, once, for an Atlas
// session, so nobody is signed out by the switch.
type BetterAuthBridgeService struct{ client *Client }

// BetterAuthBridgeSettings is the bridge as read back (never the secret).
type BetterAuthBridgeSettings struct {
	Object       string `json:"object"`
	Enabled      bool   `json:"enabled"`
	EndsAt       *int64 `json:"ends_at"`
	CookiePrefix string `json:"cookie_prefix"`
	LiveFallback struct {
		Enabled   bool    `json:"enabled"`
		BaseURL   *string `json:"base_url"`
		HasSecret bool    `json:"has_secret"`
	} `json:"live_fallback"`
	ExchangePath string `json:"exchange_path"`
	Stats        struct {
		Exchanged  int `json:"exchanged"`
		FromImport int `json:"from_import"`
		FromLive   int `json:"from_live"`
	} `json:"stats"`
	CreatedAt *int64 `json:"created_at"`
	UpdatedAt *int64 `json:"updated_at"`
	Deleted   bool   `json:"deleted,omitempty"`
}

// BetterAuthLiveFallbackParams configures the live check of sessions missing
// from the import. Secret (the old app's BETTER_AUTH_SECRET) is write-only:
// leave it nil to keep the stored one, set ClearSecret to remove it.
type BetterAuthLiveFallbackParams struct {
	Enabled      *bool
	BaseURL      *string
	ClearBaseURL bool
	Secret       *string
	ClearSecret  bool
}

// UpdateBetterAuthBridgeParams is merged onto the stored settings.
type UpdateBetterAuthBridgeParams struct {
	Enabled *bool
	// EndsAt ends the migration window; ClearEndsAt leaves it open until disabled.
	EndsAt       *time.Time
	ClearEndsAt  bool
	CookiePrefix string
	LiveFallback *BetterAuthLiveFallbackParams
}

func (p UpdateBetterAuthBridgeParams) body() map[string]interface{} {
	out := map[string]interface{}{}
	if p.Enabled != nil {
		out["enabled"] = *p.Enabled
	}
	if p.ClearEndsAt {
		out["ends_at"] = nil
	} else if p.EndsAt != nil {
		out["ends_at"] = p.EndsAt.UTC().Format(time.RFC3339)
	}
	if p.CookiePrefix != "" {
		out["cookie_prefix"] = p.CookiePrefix
	}
	if lf := p.LiveFallback; lf != nil {
		m := map[string]interface{}{}
		if lf.Enabled != nil {
			m["enabled"] = *lf.Enabled
		}
		if lf.ClearBaseURL {
			m["base_url"] = nil
		} else if lf.BaseURL != nil {
			m["base_url"] = *lf.BaseURL
		}
		if lf.ClearSecret {
			m["secret"] = nil
		} else if lf.Secret != nil {
			m["secret"] = *lf.Secret
		}
		out["live_fallback"] = m
	}
	return out
}

const betterAuthBridgePath = "/v1/migrations/better_auth/bridge"

// BetterAuthExchangePath is the Backend API path of the secret-key exchange.
const BetterAuthExchangePath = "/v1/migrations/better_auth/exchange"

// Get reads the settings and exchange counts. GET /v1/migrations/better_auth/bridge.
func (s *BetterAuthBridgeService) Get(ctx context.Context) (*BetterAuthBridgeSettings, error) {
	out := &BetterAuthBridgeSettings{}
	return out, s.client.get(ctx, betterAuthBridgePath, nil, out)
}

// Update creates or updates the settings. PUT /v1/migrations/better_auth/bridge.
func (s *BetterAuthBridgeService) Update(ctx context.Context, params UpdateBetterAuthBridgeParams, opts ...RequestOption) (*BetterAuthBridgeSettings, error) {
	out := &BetterAuthBridgeSettings{}
	return out, s.client.put(ctx, betterAuthBridgePath, params.body(), out, opts...)
}

// Delete removes the settings (the bridge is off, the stored secret deleted).
// DELETE /v1/migrations/better_auth/bridge.
func (s *BetterAuthBridgeService) Delete(ctx context.Context, opts ...RequestOption) (*BetterAuthBridgeSettings, error) {
	out := &BetterAuthBridgeSettings{}
	return out, s.client.del(ctx, betterAuthBridgePath, out, opts...)
}

// BetterAuthExchangeParams is one exchange. ClientIP and UserAgent are the END
// USER's, forwarded (X-Atlas-Client-IP / X-Atlas-Client-User-Agent) so Atlas's
// guards, risk and geo checks and the device record see the user, not your server.
type BetterAuthExchangeParams struct {
	// Token is the raw Better Auth session cookie value or the bare token.
	Token     string
	ClientIP  string
	UserAgent string
	// NotRemembered records a browser-session (non-persistent) session.
	NotRemembered bool
}

// BetterAuthExchangeResponse is session_tokens, or sign_in_attempt when a
// second factor is still owed.
type BetterAuthExchangeResponse struct {
	Object       string `json:"object"`
	ID           string `json:"id,omitempty"`
	Status       string `json:"status,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	JWT          string `json:"jwt,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// Exchange exchanges a Better Auth session for an Atlas session, once
// (POST /v1/migrations/better_auth/exchange, secret key). A refusal is an
// *APIError (meta.bridge_outcome); ExchangeBetterAuthSession classifies it.
func (s *BetterAuthBridgeService) Exchange(ctx context.Context, params BetterAuthExchangeParams) (*BetterAuthExchangeResponse, error) {
	body := map[string]interface{}{"token": params.Token}
	if params.NotRemembered {
		body["remember"] = false
	}
	var opts []RequestOption
	if params.ClientIP != "" {
		opts = append(opts, WithHeader("X-Atlas-Client-IP", params.ClientIP))
	}
	if params.UserAgent != "" {
		opts = append(opts, WithHeader("X-Atlas-Client-User-Agent", params.UserAgent))
	}
	out := &BetterAuthExchangeResponse{}
	return out, s.client.post(ctx, BetterAuthExchangePath, body, out, opts...)
}

// Better Auth exchange outcomes (BetterAuthExchangeResult.Kind).
const (
	BetterAuthExchangeSession  = "session"
	BetterAuthExchangeNeedsMFA = "needs_mfa"
	BetterAuthExchangeRefused  = "refused"
)

// BetterAuthExchangeResult classifies an exchange. Kind session carries the
// tokens; needs_mfa the AttemptID and Status (the Better Auth session is spent,
// the user finishes the second factor); refused an Outcome: closed, invalid,
// signature_invalid, expired, reused, user_unavailable, rate_limited or
// unavailable (HTTPStatus 0 for a transport failure).
type BetterAuthExchangeResult struct {
	Kind         string
	JWT          string
	RefreshToken string
	SessionID    string
	UserID       string
	ExpiresIn    int
	AttemptID    string
	Status       string
	Outcome      string
	HTTPStatus   int
}

var knownBridgeOutcomes = map[string]bool{
	"closed": true, "invalid": true, "signature_invalid": true, "expired": true,
	"reused": true, "user_unavailable": true, "rate_limited": true,
}

// finalBridgeOutcomes say the Better Auth session will never exchange: its
// cookies are cleared.
var finalBridgeOutcomes = map[string]bool{
	"invalid": true, "signature_invalid": true, "expired": true, "reused": true, "user_unavailable": true,
}

// ExchangeBetterAuthSession runs Exchange and classifies the outcome. It never
// returns an error: anything that is not a verdict on the Better Auth session
// (a 5xx, a transport failure, an unexpected body) is refused/unavailable, so
// the caller keeps the cookie and retries on a later request.
func (c *Client) ExchangeBetterAuthSession(ctx context.Context, params BetterAuthExchangeParams) BetterAuthExchangeResult {
	res, err := c.BetterAuthBridge.Exchange(ctx, params)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return BetterAuthExchangeResult{Kind: BetterAuthExchangeRefused, Outcome: "unavailable"}
		}
		if apiErr.Status == http.StatusTooManyRequests {
			return BetterAuthExchangeResult{Kind: BetterAuthExchangeRefused, Outcome: "rate_limited", HTTPStatus: 429}
		}
		if len(apiErr.Errors) > 0 {
			if o, _ := apiErr.Errors[0].Meta["bridge_outcome"].(string); knownBridgeOutcomes[o] {
				return BetterAuthExchangeResult{Kind: BetterAuthExchangeRefused, Outcome: o, HTTPStatus: apiErr.Status}
			}
		}
		return BetterAuthExchangeResult{Kind: BetterAuthExchangeRefused, Outcome: "unavailable", HTTPStatus: apiErr.Status}
	}
	if res.Object == "session_tokens" && res.JWT != "" && res.RefreshToken != "" {
		return BetterAuthExchangeResult{
			Kind: BetterAuthExchangeSession, JWT: res.JWT, RefreshToken: res.RefreshToken,
			SessionID: res.SessionID, UserID: res.UserID, ExpiresIn: res.ExpiresIn, HTTPStatus: 200,
		}
	}
	if res.Object == "sign_in_attempt" && res.ID != "" && (res.Status == "needs_second_factor" || res.Status == "needs_mfa_enrollment") {
		return BetterAuthExchangeResult{Kind: BetterAuthExchangeNeedsMFA, AttemptID: res.ID, Status: res.Status, HTTPStatus: 200}
	}
	return BetterAuthExchangeResult{Kind: BetterAuthExchangeRefused, Outcome: "unavailable", HTTPStatus: 200}
}

// ── The framework-neutral bridge ─────────────────────────────────────────────

// BetterAuthCookiePrefix is Better Auth's default advanced.cookiePrefix.
const BetterAuthCookiePrefix = "better-auth"

// BetterAuthCookieNames returns the session cookie names the bridge reads (the
// __Secure- name first) and every Better Auth cookie it clears.
func BetterAuthCookieNames(prefix string) (sessionToken, all []string) {
	if prefix == "" {
		prefix = BetterAuthCookiePrefix
	}
	base := []string{prefix + ".session_token", prefix + ".session_data", prefix + ".account_data", prefix + ".dont_remember"}
	for _, n := range base {
		all = append(all, "__Secure-"+n)
	}
	all = append(all, base...)
	return []string{"__Secure-" + prefix + ".session_token", prefix + ".session_token"}, all
}

// ReadBetterAuthSessionCookie returns the raw Better Auth session cookie value
// on r (the __Secure- name first), or "". cookieName overrides the name when the
// old app set advanced.cookies.session_token.name.
func ReadBetterAuthSessionCookie(r *http.Request, cookiePrefix, cookieName string) string {
	names, _ := BetterAuthCookieNames(cookiePrefix)
	if cookieName != "" {
		names = []string{"__Secure-" + cookieName, cookieName}
	}
	for _, n := range names {
		if ck, err := r.Cookie(n); err == nil && ck.Value != "" {
			return ck.Value
		}
	}
	return ""
}

// BetterAuthBridgeOptions configure a BetterAuthBridge.
type BetterAuthBridgeOptions struct {
	// Client is an Atlas client on the instance secret key. Required.
	Client *Client
	// CookiePrefix is Better Auth's advanced.cookiePrefix (default better-auth).
	CookiePrefix string
	// CookieName is the session cookie's full name, when the old app overrode it.
	CookieName string
	// BetterAuthCookieDomain is the domain the Better Auth cookies were set on
	// (crossSubDomainCookies.domain), so they clear.
	BetterAuthCookieDomain string
	// Insecure drops Secure from the Atlas cookies (plain-http local development only).
	Insecure bool
	// SignInURL is where a user who still owes a second factor is sent (with
	// __atlas_attempt / __atlas_status); default the requested URL.
	SignInURL string
	// ClientIP resolves the end user's IP; default the first X-Forwarded-For hop,
	// then X-Real-IP, then RemoteAddr.
	ClientIP func(*http.Request) string
}

// BetterAuthBridge exchanges a request's Better Auth session cookie for an Atlas
// session. Build it with NewBetterAuthBridge.
type BetterAuthBridge struct{ opts BetterAuthBridgeOptions }

// NewBetterAuthBridge builds a bridge; Client is required.
func NewBetterAuthBridge(opts BetterAuthBridgeOptions) (*BetterAuthBridge, error) {
	if opts.Client == nil {
		return nil, errors.New("atlas: NewBetterAuthBridge requires Client (on the instance secret key)")
	}
	return &BetterAuthBridge{opts: opts}, nil
}

// Better Auth bridge actions (BridgeDecision.Action).
const (
	BridgeNone     = "none"
	BridgeSignedIn = "signed_in"
	BridgeNeedsMFA = "needs_mfa"
	BridgeRefused  = "refused"
)

// BridgeDecision is what the bridge decided for one request: none (no Better
// Auth cookie, or an Atlas session already present), signed_in (set Cookies and
// re-enter the same URL), needs_mfa (set Cookies and redirect to
// ContinuationURL) or refused (set Cookies — they clear the Better Auth cookies
// only on a final refusal — and carry on).
type BridgeDecision struct {
	Action    string
	Cookies   []*http.Cookie
	Session   *BetterAuthExchangeResult
	AttemptID string
	Status    string
	Outcome   string
}

// ContinuationURL returns target with __atlas_attempt / __atlas_status set.
func (d *BridgeDecision) ContinuationURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set("__atlas_attempt", d.AttemptID)
	q.Set("__atlas_status", d.Status)
	u.RawQuery = q.Encode()
	return u.String()
}

func (b *BetterAuthBridge) clearCookies() []*http.Cookie {
	_, names := BetterAuthCookieNames(b.opts.CookiePrefix)
	if b.opts.CookieName != "" {
		names = append(names, b.opts.CookieName, "__Secure-"+b.opts.CookieName)
	}
	out := make([]*http.Cookie, 0, len(names))
	for _, n := range names {
		out = append(out, &http.Cookie{
			Name: n, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
			Domain: b.opts.BetterAuthCookieDomain,
			// A __Secure- cookie can only be overwritten by a Secure Set-Cookie.
			Secure: strings.HasPrefix(n, "__Secure-"),
		})
	}
	return out
}

// ClientIPFromRequest is the default end-user IP: the first X-Forwarded-For
// hop, then X-Real-IP, then the connection's RemoteAddr. It is only as
// trustworthy as the proxy in front of your server.
func ClientIPFromRequest(r *http.Request) string {
	if xff := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); xff != "" {
		return xff
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		return real
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// Decide runs the bridge for one request. It makes no network call for a
// request without a Better Auth cookie or with an Atlas session (__session /
// __atlas_rt) already present.
func (b *BetterAuthBridge) Decide(ctx context.Context, r *http.Request) BridgeDecision {
	token := ReadBetterAuthSessionCookie(r, b.opts.CookiePrefix, b.opts.CookieName)
	if token == "" {
		return BridgeDecision{Action: BridgeNone}
	}
	for _, n := range []string{"__session", "__atlas_rt"} {
		if ck, err := r.Cookie(n); err == nil && ck.Value != "" {
			return BridgeDecision{Action: BridgeNone}
		}
	}
	ipOf := b.opts.ClientIP
	if ipOf == nil {
		ipOf = ClientIPFromRequest
	}
	res := b.opts.Client.ExchangeBetterAuthSession(ctx, BetterAuthExchangeParams{
		Token: token, ClientIP: ipOf(r), UserAgent: r.Header.Get("User-Agent"),
	})
	switch res.Kind {
	case BetterAuthExchangeSession:
		secure := !b.opts.Insecure
		cookies := []*http.Cookie{
			{Name: "__session", Value: res.JWT, Path: "/", SameSite: http.SameSiteLaxMode, Secure: secure},
			{Name: "__atlas_rt", Value: res.RefreshToken, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure},
		}
		return BridgeDecision{Action: BridgeSignedIn, Session: &res, Cookies: append(cookies, b.clearCookies()...)}
	case BetterAuthExchangeNeedsMFA:
		return BridgeDecision{Action: BridgeNeedsMFA, AttemptID: res.AttemptID, Status: res.Status, Cookies: b.clearCookies()}
	}
	d := BridgeDecision{Action: BridgeRefused, Outcome: res.Outcome}
	if finalBridgeOutcomes[res.Outcome] {
		d.Cookies = b.clearCookies()
	}
	return d
}

// Handle runs the bridge in a net/http handler chain and reports whether it
// already wrote the response (a redirect). Only GET and HEAD are bridged.
func (b *BetterAuthBridge) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	d := b.Decide(r.Context(), r)
	for _, ck := range d.Cookies {
		http.SetCookie(w, ck)
	}
	switch d.Action {
	case BridgeSignedIn:
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
		return true
	case BridgeNeedsMFA:
		target := b.opts.SignInURL
		if target == "" {
			target = requestURL(r)
		}
		http.Redirect(w, r, d.ContinuationURL(target), http.StatusFound)
		return true
	}
	return false
}

// Middleware wraps next: a GET/HEAD carrying a Better Auth session cookie and no
// Atlas session is exchanged once and redirected to the same URL signed in (or
// to SignInURL when a second factor is owed); everything else passes through.
func (b *BetterAuthBridge) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.Handle(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
