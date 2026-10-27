package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// VaultService is the vault resource.
type VaultService struct {
	client      *Client
	KeyProvider *VaultKeyProviderService
}

// Create: Store a secret. `key_context` (1–10 string labels) is mandatory and is authenticated
// into the encryption: the value can only be opened with the context it was written under. The
// value (up to 64 KiB) is sealed under a fresh data key wrapped by the instance key, or by your
// own cloud KMS key when one is configured. 409 when the name is taken.
// POST /v1/vault/objects.
func (s *VaultService) Create(ctx context.Context, params VaultCreateParams, opts ...RequestOption) (*VaultCreateResult, error) {
	out := &VaultCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/vault/objects", nil, params, out, opts...)
}

// VaultListQuery holds the query parameters of VaultService.List.
type VaultListQuery struct {
	// Only objects whose name starts with this prefix.
	NamePrefix string
	// A JSON object of labels; matches objects whose key_context contains all of them.
	KeyContext string
	// Cursor: the id of the last object of the previous page.
	StartingAfter string
	// Page size. Defaults to 20; values above 100 are capped at 100.
	Limit int64
}

func (q VaultListQuery) values() url.Values {
	v := url.Values{}
	if q.NamePrefix != "" {
		v.Set("name_prefix", q.NamePrefix)
	}
	if q.KeyContext != "" {
		v.Set("key_context", q.KeyContext)
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	return v
}

// List: List vault objects (metadata only, never values), newest first. Filter by `name_prefix` or
// by `key_context` (a JSON object; objects whose context contains every given label).
// GET /v1/vault/objects.
func (s *VaultService) List(ctx context.Context, query VaultListQuery) (*CursorPage[VaultCreateResult], error) {
	out := &CursorPage[VaultCreateResult]{}
	return out, s.client.do(ctx, "GET", "/v1/vault/objects", query.values(), nil, out)
}

// Metadata: Read a vault object's metadata without its value.
// GET /v1/vault/objects/{id}/metadata.
func (s *VaultService) Metadata(ctx context.Context, id string) (*VaultCreateResult, error) {
	out := &VaultCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/vault/objects/"+url.PathEscape(id)+"/metadata", nil, nil, out)
}

// Versions: List the versions of a vault object (number, which key protects it, when written) —
// never values.
// GET /v1/vault/objects/{id}/versions.
func (s *VaultService) Versions(ctx context.Context, id string, params ListParams) (*CursorPage[VaultVersionsItem], error) {
	out := &CursorPage[VaultVersionsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/vault/objects/"+url.PathEscape(id)+"/versions", params.values(), nil, out)
}

// VaultReadQuery holds the query parameters of VaultService.Read.
type VaultReadQuery struct {
	// A specific version; defaults to the current one.
	Version int64
}

func (q VaultReadQuery) values() url.Values {
	v := url.Values{}
	if q.Version != 0 {
		v.Set("version", strconv.FormatInt(q.Version, 10))
	}
	return v
}

// Read: Read a vault object with its decrypted value (the current version, or `version`). Every
// read is audited. 409 if the version's wrapping key provider is no longer configured; 502
// VAULT_KMS_ERROR when your KMS refuses.
// GET /v1/vault/objects/{id}.
func (s *VaultService) Read(ctx context.Context, id string, query VaultReadQuery) (*VaultReadResult, error) {
	out := &VaultReadResult{}
	return out, s.client.do(ctx, "GET", "/v1/vault/objects/"+url.PathEscape(id), query.values(), nil, out)
}

// Update: Append a new version with a new value. Earlier versions stay readable. Pass
// `version_check` (the version you last read) for optimistic concurrency: 409 if another update
// landed since.
// PUT /v1/vault/objects/{id}.
func (s *VaultService) Update(ctx context.Context, id string, params VaultUpdateParams, opts ...RequestOption) (*VaultCreateResult, error) {
	out := &VaultCreateResult{}
	return out, s.client.do(ctx, "PUT", "/v1/vault/objects/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a vault object and every version of it. Irreversible.
// DELETE /v1/vault/objects/{id}.
func (s *VaultService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/vault/objects/"+url.PathEscape(id), nil, nil, out, opts...)
}

// VaultKeyProviderService is the vault keyProvider group of VaultService.
type VaultKeyProviderService struct {
	client *Client
}

// Get: The customer-managed key that wraps new vault data keys. 404 when none is configured (the
// instance key is used).
// GET /v1/vault/key_provider.
func (s *VaultKeyProviderService) Get(ctx context.Context) (*VaultKeyProviderGetResult, error) {
	out := &VaultKeyProviderGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/vault/key_provider", nil, nil, out)
}

// Set: Bring your own key: wrap new vault data keys with your AWS KMS (`config.region`,
// `config.key_id`; symmetric key), Google Cloud KMS (`config.crypto_key`; symmetric key) or Azure
// Key Vault (`config.vault_url`, `config.key_name`; RSA key with wrap/unwrap) key. Atlas proves
// access with a wrap/unwrap round trip before saving (422 or 502 on refusal). Credentials are
// write-only. Existing versions stay on the key that wrapped them; switching provider type is a
// 409 while versions remain on the old one.
// PUT /v1/vault/key_provider.
func (s *VaultKeyProviderService) Set(ctx context.Context, params VaultKeyProviderSetParams, opts ...RequestOption) (*VaultKeyProviderGetResult, error) {
	out := &VaultKeyProviderGetResult{}
	return out, s.client.do(ctx, "PUT", "/v1/vault/key_provider", nil, params, out, opts...)
}

// Remove: Stop using your own key for new versions. 409 while any version is still wrapped by it.
// DELETE /v1/vault/key_provider.
func (s *VaultKeyProviderService) Remove(ctx context.Context, opts ...RequestOption) (*MFAFactorsRemoveYubicoSecretResult, error) {
	out := &MFAFactorsRemoveYubicoSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/vault/key_provider", nil, nil, out, opts...)
}
