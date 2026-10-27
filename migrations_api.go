package atlas

import (
	"context"
	"net/url"
)

// MigrationsService is the migrations resource.
type MigrationsService struct {
	client  *Client
	Imports *MigrationsImportsService
}

// Exchange: Server-to-server exchange of an old `source` session for an Atlas session, once (what
// migrationBridge({ source }) calls with the secret key). The token is verified (vendor JWT
// against the bridge's issuer and keys, or sha256 matched against imported sessions), mapped to
// the imported user, spent in the single-use ledger and then takes the normal sign-in path
// (guards, MFA policy, post_login Actions, audit). Returns tokens in the body, or a
// sign_in_attempt when a second factor is owed. Limited per instance (6000/min), per end-user IP
// (60/min) and per user (10/min). Send the end user's IP / user agent in X-Atlas-Client-IP /
// X-Atlas-Client-User-Agent.
// POST /v1/migrations/{source}/exchange.
func (s *MigrationsService) Exchange(ctx context.Context, source string, params MigrationsExchangeParams, opts ...RequestOption) (*MigrationsExchangeResult, error) {
	out := &MigrationsExchangeResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/exchange", nil, params, out, opts...)
}

// Sources: Every migration source: what it exports, whether passwords move (or need lazy
// migration), its bridge preset and variables, and its lazy-migration preset.
// GET /v1/migrations/sources.
func (s *MigrationsService) Sources(ctx context.Context, params ListParams) (*CursorPage[MigrationsSourcesItem], error) {
	out := &CursorPage[MigrationsSourcesItem]{}
	return out, s.client.do(ctx, "GET", "/v1/migrations/sources", params.values(), nil, out)
}

// GetBridge: Read the zero-logout bridge settings for `source` (window, JWT preset / issuer /
// keys, claims, cookie names) and exchange counts. Never returns a shared secret.
// GET /v1/migrations/{source}/bridge.
func (s *MigrationsService) GetBridge(ctx context.Context, source string) (*MigrationsGetBridgeResult, error) {
	out := &MigrationsGetBridgeResult{}
	return out, s.client.do(ctx, "GET", "/v1/migrations/"+url.PathEscape(source)+"/bridge", nil, nil, out)
}

// SetBridge: Create or update the bridge settings for `source`. Every field is optional and merged
// onto the stored ones; a preset fills the JWT settings from its variables, explicit fields
// override it. The keys URL must be public https on a production instance. `better_auth` takes the
// Better Auth bridge body (see /v1/migrations/better_auth/bridge).
// PUT /v1/migrations/{source}/bridge.
func (s *MigrationsService) SetBridge(ctx context.Context, source string, params MigrationsSetBridgeParams, opts ...RequestOption) (*MigrationsGetBridgeResult, error) {
	out := &MigrationsGetBridgeResult{}
	return out, s.client.do(ctx, "PUT", "/v1/migrations/"+url.PathEscape(source)+"/bridge", nil, params, out, opts...)
}

// DeleteBridge: Remove the bridge settings for `source` (the bridge is off and any stored secret
// deleted).
// DELETE /v1/migrations/{source}/bridge.
func (s *MigrationsService) DeleteBridge(ctx context.Context, source string, opts ...RequestOption) (*MigrationsDeleteBridgeResult, error) {
	out := &MigrationsDeleteBridgeResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/migrations/"+url.PathEscape(source)+"/bridge", nil, nil, out, opts...)
}

// MigrationsImportsService is the migrations imports group of MigrationsService.
type MigrationsImportsService struct {
	client *Client
}

// GetPublicKey: The instance's import public key (created on first read). Seal the export to it;
// only this instance can open the bundle. One key serves every source. A key with jobs:write may
// read it too.
// GET /v1/migrations/{source}/imports/public_key.
func (s *MigrationsImportsService) GetPublicKey(ctx context.Context, source string) (*MigrationsImportsGetPublicKeyResult, error) {
	out := &MigrationsImportsGetPublicKeyResult{}
	return out, s.client.do(ctx, "GET", "/v1/migrations/"+url.PathEscape(source)+"/imports/public_key", nil, nil, out)
}

// RotatePublicKey: Replace the import key. A bundle sealed to the old key no longer finalizes;
// export again with the new key.
// POST /v1/migrations/{source}/imports/public_key/rotate.
func (s *MigrationsImportsService) RotatePublicKey(ctx context.Context, source string, opts ...RequestOption) (*MigrationsImportsGetPublicKeyResult, error) {
	out := &MigrationsImportsGetPublicKeyResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/imports/public_key/rotate", nil, nil, out, opts...)
}

// Create: Start an import from `source` (status `uploading`). Then upload the sealed bundle with
// PUT …/parts/{part} and call …/finalize. Nothing is written to users until apply.
// POST /v1/migrations/{source}/imports.
func (s *MigrationsImportsService) Create(ctx context.Context, source string, params MigrationsImportsCreateParams, opts ...RequestOption) (*MigrationsImportsCreateResult, error) {
	out := &MigrationsImportsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/imports", nil, params, out, opts...)
}

// List: List the imports from `source`, newest first (cursor pagination).
// GET /v1/migrations/{source}/imports.
func (s *MigrationsImportsService) List(ctx context.Context, source string, params ListParams) (*CursorPage[MigrationsImportsCreateResult], error) {
	out := &CursorPage[MigrationsImportsCreateResult]{}
	return out, s.client.do(ctx, "GET", "/v1/migrations/"+url.PathEscape(source)+"/imports", params.values(), nil, out)
}

// Get: Fetch one import: status, the dry-run report, live progress and the apply result.
// GET /v1/migrations/{source}/imports/{id}.
func (s *MigrationsImportsService) Get(ctx context.Context, source string, id string) (*MigrationsImportsCreateResult, error) {
	out := &MigrationsImportsCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id), nil, nil, out)
}

// Delete: Delete an import and its stored bundle. Data it already imported stays. Refused (409)
// while analyzing or applying.
// DELETE /v1/migrations/{source}/imports/{id}.
func (s *MigrationsImportsService) Delete(ctx context.Context, source string, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id), nil, nil, out, opts...)
}

// PutPart: Upload part `part` (1, 2, …) of the sealed bundle: whole lines, at most 10 MiB, as `{
// "data": "…" }` or a text/plain body. Re-sending a part replaces it. Only while `uploading`.
// PUT /v1/migrations/{source}/imports/{id}/parts/{part}.
func (s *MigrationsImportsService) PutPart(ctx context.Context, source string, id string, part string, params MigrationsImportsPutPartParams, opts ...RequestOption) (*MigrationsImportsPutPartResult, error) {
	out := &MigrationsImportsPutPartResult{}
	return out, s.client.do(ctx, "PUT", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id)+"/parts/"+url.PathEscape(part), nil, params, out, opts...)
}

// Finalize: Close the upload: every part 1..n present, the bundle sealed to the active import key
// and in a format `source` reads (else 400 or status `invalid`). The dry run follows: inline up to
// 4 MiB (200, `ready`), else in the background (202, `analyzing`; poll GET).
// POST /v1/migrations/{source}/imports/{id}/finalize.
func (s *MigrationsImportsService) Finalize(ctx context.Context, source string, id string, opts ...RequestOption) (*MigrationsImportsCreateResult, error) {
	out := &MigrationsImportsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id)+"/finalize", nil, nil, out, opts...)
}

// DryRun: Run the dry run again, optionally with new options (they replace the stored ones). Reads
// only.
// POST /v1/migrations/{source}/imports/{id}/dry_run.
func (s *MigrationsImportsService) DryRun(ctx context.Context, source string, id string, params MigrationsImportsCreateParams, opts ...RequestOption) (*MigrationsImportsCreateResult, error) {
	out := &MigrationsImportsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id)+"/dry_run", nil, params, out, opts...)
}

// Apply: Import the bundle. Every record is an idempotent upsert keyed by its source id, so
// applying a failed import again resumes where it stopped. Up to 1,000 remaining records run
// inline (200), more are queued (202). With conflicts in the dry run, send confirm_conflicts:
// true.
// POST /v1/migrations/{source}/imports/{id}/apply.
func (s *MigrationsImportsService) Apply(ctx context.Context, source string, id string, params MigrationsImportsApplyParams, opts ...RequestOption) (*MigrationsImportsCreateResult, error) {
	out := &MigrationsImportsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/migrations/"+url.PathEscape(source)+"/imports/"+url.PathEscape(id)+"/apply", nil, params, out, opts...)
}
