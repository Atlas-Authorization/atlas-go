package atlas

import (
	"context"
	"net/url"
)

// PolicyBundlesService is the policyBundles resource.
type PolicyBundlesService struct {
	client *Client
}

// Current: The bundle revision the instance policy is at right now. Compare it with a deployed
// bundle’s revision to detect drift.
// GET /v1/policy_bundles/current.
func (s *PolicyBundlesService) Current(ctx context.Context) (*PolicyBundlesCurrentResult, error) {
	out := &PolicyBundlesCurrentResult{}
	return out, s.client.do(ctx, "GET", "/v1/policy_bundles/current", nil, nil, out)
}

// List: List the signed policy bundles exported or imported on this instance, newest first
// (without the archives).
// GET /v1/policy_bundles.
func (s *PolicyBundlesService) List(ctx context.Context, params ListParams) (*PolicyBundlesListResult, error) {
	out := &PolicyBundlesListResult{}
	return out, s.client.do(ctx, "GET", "/v1/policy_bundles", params.values(), nil, out)
}

// Export: Export the instance policy — every ABAC policy (current version), the ABAC entity
// schema, templates and template links, and every FGA store’s latest authorization model — as a
// versioned tar.gz with a manifest of file digests, signed with the instance signing key (detached
// JWS). The same policy always has the same revision.
// POST /v1/policy_bundles.
func (s *PolicyBundlesService) Export(ctx context.Context, opts ...RequestOption) (*PolicyBundlesListResultDataItem, error) {
	out := &PolicyBundlesListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/policy_bundles", nil, nil, out, opts...)
}

// Get: Read a stored bundle by revision, with the base64 archive and its signature.
// GET /v1/policy_bundles/{revision}.
func (s *PolicyBundlesService) Get(ctx context.Context, revision string) (*PolicyBundlesListResultDataItem, error) {
	out := &PolicyBundlesListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/policy_bundles/"+url.PathEscape(revision), nil, nil, out)
}

// Archive: Download a stored bundle as the raw tar.gz (`application/gzip`). The detached signature
// is in the `Atlas-Bundle-Signature` header, with `Atlas-Bundle-Revision` and
// `Atlas-Bundle-Key-Id`.
// The result is the raw response bytes.
// GET /v1/policy_bundles/{revision}/archive.
func (s *PolicyBundlesService) Archive(ctx context.Context, revision string) ([]byte, error) {
	return s.client.doBytes(ctx, "GET", "/v1/policy_bundles/"+url.PathEscape(revision)+"/archive", nil)
}

// Verify: Check a bundle without importing it: the detached signature against this instance's
// signing keys (plus any `trusted_jwks` you supply) and the archive's integrity. The SDK can do
// the same check offline.
// POST /v1/policy_bundles/verify.
func (s *PolicyBundlesService) Verify(ctx context.Context, params PolicyBundlesVerifyParams, opts ...RequestOption) (*PolicyBundlesVerifyResult, error) {
	out := &PolicyBundlesVerifyResult{}
	return out, s.client.do(ctx, "POST", "/v1/policy_bundles/verify", nil, params, out, opts...)
}

// Import: Import a signed bundle. The signature and the archive integrity must both check out or
// nothing is touched (422). With `dry_run: true` it returns the diff of what would change and
// applies nothing (needs only policy_bundles:read). Otherwise it applies everything in one
// transaction: stores and models first, then the ABAC schema, templates, links and policies; a
// changed policy appends a version. `prune` also deletes ABAC policies, templates and links the
// bundle does not name (and the schema when it has none); FGA stores are never deleted.
// POST /v1/policy_bundles/import.
func (s *PolicyBundlesService) Import(ctx context.Context, params PolicyBundlesImportParams, opts ...RequestOption) (*PolicyBundlesImportResult, error) {
	out := &PolicyBundlesImportResult{}
	return out, s.client.do(ctx, "POST", "/v1/policy_bundles/import", nil, params, out, opts...)
}
