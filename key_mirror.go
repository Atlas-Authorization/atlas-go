package atlas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A local, authoritative mirror of end-user API keys, with Atlas as the minting
// and revocation backstop.
//
// Your request path verifies a presented key against the LOCAL row (sha256 hash,
// scopes, expiry, revocation) with no network call. Atlas mints and imports keys
// and is told about every revoke; a revoke made anywhere else (the dashboard, the
// user's own key list, another service) reaches the mirror through Sync, which
// consumes the revocation feed, or ApplyWebhook for the api_key.* webhooks.
// Revoking locally happens FIRST, so a failed Atlas call never leaves a key usable.

// MirroredAPIKey is what the mirror keeps per key. Never the secret: only its sha256 (hex).
type MirroredAPIKey struct {
	// ID is the Atlas key id.
	ID string `json:"id"`
	// Hash is the sha256 of the full secret, lowercase hex.
	Hash string `json:"hash"`
	// Prefix is the public head, for listings.
	Prefix      string  `json:"prefix"`
	SubjectType string  `json:"subject_type"`
	SubjectID   string  `json:"subject_id"`
	Name        *string `json:"name"`
	// Scopes is nil when the key carries none.
	Scopes []string `json:"scopes"`
	// AllowedIPs is a CIDR allowlist; empty = any caller.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// ExpiresAt is epoch ms; nil = never.
	ExpiresAt *int64 `json:"expires_at"`
	// RevokedAt is epoch ms; nil = live.
	RevokedAt *int64 `json:"revoked_at"`
	// OrganizationID is the organization a user key is bound to; nil = unbound.
	OrganizationID *string `json:"organization_id,omitempty"`
	// RevokedReason says why it was revoked, when Atlas said (membership_ended,
	// creator_departed, organization_deleted, user_banned, rotated).
	RevokedReason *string `json:"revoked_reason,omitempty"`
	// Enabled is false for a disabled key (refused like an unknown one); nil = enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Credential is "secret" or "key_pair". A key-pair row has no secret hash (Hash is a placeholder
	// nothing matches); its assertions verify against PublicKeyPEM.
	Credential string `json:"credential,omitempty"`
	// PublicKeyPEM is the SPKI PEM a key-pair key's assertions are verified against.
	PublicKeyPEM *string `json:"public_key_pem,omitempty"`
	// Audience is the aud an assertion must carry.
	Audience *string `json:"audience,omitempty"`
	// MaxTokenLifetimeSeconds is the longest assertion lifetime; nil = 3600.
	MaxTokenLifetimeSeconds *int64 `json:"max_token_lifetime_seconds,omitempty"`
}

// KeyMirrorJTIStore is optional on a KeyMirrorStore: record an assertion jti as used until
// expiresAtMS and report false when it was already used (a replay). Without it the mirror
// keeps used ids in process memory, which a restart or a second instance does not share.
type KeyMirrorJTIStore interface {
	ClaimAssertionJTI(ctx context.Context, keyID, jti string, expiresAtMS int64) (bool, error)
}

// KeyMirrorStore is the smallest store that works. Get and GetByHash return
// (nil, nil) for an unknown key. Back it with a table in production;
// MemoryKeyMirrorStore is for tests and single-process apps. A store may also
// implement KeyMirrorMembershipStore and KeyMirrorSyncClock.
type KeyMirrorStore interface {
	Put(ctx context.Context, key MirroredAPIKey) error
	Get(ctx context.Context, id string) (*MirroredAPIKey, error)
	GetByHash(ctx context.Context, hash string) (*MirroredAPIKey, error)
	// MarkRevoked stamps a live key revoked (reason "" = none given). A no-op for an unknown or already revoked key.
	MarkRevoked(ctx context.Context, id string, revokedAt int64, reason string) error
	// Cursor is the revocation-feed cursor last consumed ("" = from the start).
	Cursor(ctx context.Context) (string, error)
	SetCursor(ctx context.Context, cursor string) error
}

// KeyMirrorMembershipStore is optional: stamp every live key of userID bound to
// organizationID revoked (reason membership_ended). A store without it still drops
// those keys through the revocation feed.
type KeyMirrorMembershipStore interface {
	MarkMembershipEnded(ctx context.Context, userID, organizationID string, revokedAt int64) error
}

// KeyMirrorSyncClock is optional: persist the time of the last completed Sync. Without
// it the mirror keeps it in memory, so a restart reads as never synced.
type KeyMirrorSyncClock interface {
	// LastSyncAt returns epoch ms; ok is false when never synced.
	LastSyncAt(ctx context.Context) (at int64, ok bool, err error)
	SetLastSyncAt(ctx context.Context, at int64) error
}

// MemoryKeyMirrorStore is an in-memory store implementing every optional interface.
type MemoryKeyMirrorStore struct {
	mu         sync.Mutex
	keys       map[string]MirroredAPIKey
	cursor     string
	lastSyncAt int64
	synced     bool
}

// NewMemoryKeyMirrorStore returns an empty store.
func NewMemoryKeyMirrorStore() *MemoryKeyMirrorStore {
	return &MemoryKeyMirrorStore{keys: map[string]MirroredAPIKey{}}
}

// Put implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) Put(_ context.Context, key MirroredAPIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.ID] = key
	return nil
}

// Get implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) Get(_ context.Context, id string) (*MirroredAPIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, nil
	}
	return &k, nil
}

// GetByHash implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) GetByHash(_ context.Context, hash string) (*MirroredAPIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.Hash == hash {
			c := k
			return &c, nil
		}
	}
	return nil, nil
}

// MarkRevoked implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) MarkRevoked(_ context.Context, id string, revokedAt int64, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if ok && k.RevokedAt == nil {
		k.RevokedAt = &revokedAt
		if reason != "" {
			r := reason
			k.RevokedReason = &r
		}
		s.keys[id] = k
	}
	return nil
}

// MarkMembershipEnded implements KeyMirrorMembershipStore.
func (s *MemoryKeyMirrorStore) MarkMembershipEnded(_ context.Context, userID, organizationID string, revokedAt int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.keys {
		if k.RevokedAt == nil && k.SubjectType == "user" && k.SubjectID == userID && k.OrganizationID != nil && *k.OrganizationID == organizationID {
			at := revokedAt
			reason := "membership_ended"
			k.RevokedAt = &at
			k.RevokedReason = &reason
			s.keys[id] = k
		}
	}
	return nil
}

// Cursor implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) Cursor(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor, nil
}

// SetCursor implements KeyMirrorStore.
func (s *MemoryKeyMirrorStore) SetCursor(_ context.Context, cursor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = cursor
	return nil
}

// LastSyncAt implements KeyMirrorSyncClock.
func (s *MemoryKeyMirrorStore) LastSyncAt(_ context.Context) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSyncAt, s.synced, nil
}

// SetLastSyncAt implements KeyMirrorSyncClock.
func (s *MemoryKeyMirrorStore) SetLastSyncAt(_ context.Context, at int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSyncAt, s.synced = at, true
	return nil
}

// KeyMirrorMembership is a user's current membership of an organization, as the
// key's scopes are narrowed by it.
type KeyMirrorMembership struct {
	ID          string   `json:"id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// KeyMirrorKeyRecord is a key as Atlas answers a create or get: the mirrored
// fields, plus the one-time Secret on a mint and Outcome on an import.
type KeyMirrorKeyRecord struct {
	ID             string   `json:"id"`
	Prefix         string   `json:"prefix"`
	SubjectType    string   `json:"subject_type"`
	SubjectID      string   `json:"subject_id"`
	Name           *string  `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedIPs     []string `json:"allowed_ips"`
	ExpiresAt      *int64   `json:"expires_at"`
	RevokedAt      *int64   `json:"revoked_at"`
	OrganizationID *string  `json:"organization_id"`
	RevokedReason  *string  `json:"revoked_reason"`
	// Secret is set on a mint only. Show it once; the mirror stores only its hash.
	Secret string `json:"secret,omitempty"`
	// Outcome is created or already_present on an import.
	Outcome string `json:"outcome,omitempty"`
	// Credential, PublicKey, Audience and MaxTokenLifetimeSeconds describe a key-pair key
	// (Secret is empty for one).
	Enabled                 *bool   `json:"enabled,omitempty"`
	Credential              string  `json:"credential,omitempty"`
	PublicKey               *string `json:"public_key,omitempty"`
	Audience                *string `json:"audience,omitempty"`
	MaxTokenLifetimeSeconds *int64  `json:"max_token_lifetime_seconds,omitempty"`
}

// KeyMirrorRevokedKey is one entry of the revocation feed.
type KeyMirrorRevokedKey struct {
	ID            string  `json:"id"`
	RevokedAt     *int64  `json:"revoked_at"`
	RevokedReason *string `json:"revoked_reason"`
}

// KeyMirrorRevokedPage is one page of the revocation feed.
type KeyMirrorRevokedPage struct {
	Data       []KeyMirrorRevokedKey `json:"data"`
	HasMore    bool                  `json:"has_more"`
	NextCursor string                `json:"next_cursor"`
}

// KeyMirrorRemoteVerdict is Atlas's own answer to a verify.
type KeyMirrorRemoteVerdict struct {
	Valid           bool                 `json:"valid"`
	ID              string               `json:"id"`
	EffectiveScopes []string             `json:"effective_scopes"`
	Organization    *KeyMirrorMembership `json:"organization"`
}

// KeyMirrorUpstream is the part of the Backend API the mirror talks to.
// NewKeyMirrorUpstream returns the real one for a Client; tests pass a fake.
type KeyMirrorUpstream interface {
	CreateKey(ctx context.Context, params CreateAPIKeyParams, opts ...RequestOption) (*KeyMirrorKeyRecord, error)
	DeleteKey(ctx context.Context, id string) error
	ListRevoked(ctx context.Context, since string, limit int) (*KeyMirrorRevokedPage, error)
}

// KeyMirrorRemoteVerifier is optional on a KeyMirrorUpstream: ask Atlas to verify a
// secret (needed for imported bcrypt/argon2id keys and for org-bound keys without a
// Membership callback).
type KeyMirrorRemoteVerifier interface {
	VerifyKey(ctx context.Context, secret, clientIP string) (*KeyMirrorRemoteVerdict, error)
	GetKey(ctx context.Context, id string) (*KeyMirrorKeyRecord, error)
}

type clientKeyMirrorUpstream struct{ c *Client }

// NewKeyMirrorUpstream returns the KeyMirrorUpstream (and KeyMirrorRemoteVerifier) backed by c.
func NewKeyMirrorUpstream(c *Client) KeyMirrorUpstream { return &clientKeyMirrorUpstream{c: c} }

func (u *clientKeyMirrorUpstream) CreateKey(ctx context.Context, params CreateAPIKeyParams, opts ...RequestOption) (*KeyMirrorKeyRecord, error) {
	out := &KeyMirrorKeyRecord{}
	if err := u.c.do(ctx, "POST", "/v1/api_keys", nil, params, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *clientKeyMirrorUpstream) DeleteKey(ctx context.Context, id string) error {
	return u.c.do(ctx, "DELETE", "/v1/api_keys/"+url.PathEscape(id), nil, nil, nil)
}

func (u *clientKeyMirrorUpstream) ListRevoked(ctx context.Context, since string, limit int) (*KeyMirrorRevokedPage, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	out := &KeyMirrorRevokedPage{}
	if err := u.c.do(ctx, "GET", "/v1/api_keys/revoked", q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *clientKeyMirrorUpstream) VerifyKey(ctx context.Context, secret, clientIP string) (*KeyMirrorRemoteVerdict, error) {
	body := map[string]interface{}{"secret": secret}
	if clientIP != "" {
		body["client_ip"] = clientIP
	}
	out := &KeyMirrorRemoteVerdict{}
	if err := u.c.do(ctx, "POST", "/v1/api_keys/verify", nil, body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *clientKeyMirrorUpstream) GetKey(ctx context.Context, id string) (*KeyMirrorKeyRecord, error) {
	out := &KeyMirrorKeyRecord{}
	if err := u.c.do(ctx, "GET", "/v1/api_keys/"+url.PathEscape(id), nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// KeyMirrorRotateParams is the body of POST /v1/api_keys/{id}/rotate.
type KeyMirrorRotateParams struct {
	// OverlapSeconds is how long the old key keeps working (server default 86400; 0 revokes it at once).
	OverlapSeconds *int64 `json:"overlap_seconds,omitempty"`
	// Name is a new name for the successor (default: the old key's name).
	Name *string `json:"name,omitempty"`
	// ExpiresAt is the epoch ms the successor expires; not with ExpiresInSeconds.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	// ExpiresInSeconds is the successor's relative lifetime; not with ExpiresAt.
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// KeyMirrorRotation is the rotation answer: the successor with its one-time Secret,
// and what became of the old key.
type KeyMirrorRotation struct {
	KeyMirrorKeyRecord
	PreviousKey struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
		// ExpiresAt is when the old key stops working (epoch ms); nil when it was revoked at once.
		ExpiresAt *int64 `json:"expires_at"`
		Revoked   bool   `json:"revoked"`
	} `json:"previous_key"`
	OverlapSeconds int64 `json:"overlap_seconds"`
}

// KeyMirrorRotator is optional on a KeyMirrorUpstream: rotate a key at Atlas.
// NewKeyMirrorUpstream's upstream implements it.
type KeyMirrorRotator interface {
	RotateKey(ctx context.Context, id string, params KeyMirrorRotateParams, opts ...RequestOption) (*KeyMirrorRotation, error)
}

func (u *clientKeyMirrorUpstream) RotateKey(ctx context.Context, id string, params KeyMirrorRotateParams, opts ...RequestOption) (*KeyMirrorRotation, error) {
	out := &KeyMirrorRotation{}
	if err := u.c.do(ctx, "POST", "/v1/api_keys/"+url.PathEscape(id)+"/rotate", nil, params, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// Codes of a refused KeyMirrorVerification (empty for a plain unknown / revoked / expired key).
const (
	KeyMirrorCodeInsufficientScope   = "insufficient_scope"
	KeyMirrorCodeIPNotAllowed        = "ip_not_allowed"
	KeyMirrorCodeClientIPRequired    = "client_ip_required"
	KeyMirrorCodeMembershipUnresolve = "membership_unresolved"
	// KeyMirrorCodeStale: the mirror is not fresh enough to answer (never synced, or the last Sync is older than MaxStaleness). Retry after Sync.
	KeyMirrorCodeStale = "stale"

	// Refusals of a key-pair assertion, the same strings Atlas verify answers.
	KeyMirrorCodeInvalidAssertion         = "invalid_assertion"
	KeyMirrorCodeAssertionExpired         = "assertion_expired"
	KeyMirrorCodeAssertionNotYetValid     = "assertion_not_yet_valid"
	KeyMirrorCodeWrongAudience            = "wrong_audience"
	KeyMirrorCodeAssertionLifetimeTooLong = "assertion_lifetime_too_long"
	KeyMirrorCodeAssertionReplayed        = "assertion_replayed"
	KeyMirrorCodeScopeNotGranted          = "scope_not_granted"
)

// KeyMirrorOptions configures a KeyMirror.
type KeyMirrorOptions struct {
	Store    KeyMirrorStore
	Upstream KeyMirrorUpstream
	// ScopeImplications are the instance scope implications, so a local required-scopes
	// check matches Atlas verify. "*" = every scope in AllowedScopes plus both sides of the map.
	ScopeImplications map[string][]string
	AllowedScopes     []string
	// VerifyAtAtlas asks Atlas to verify the secret on a local miss (needs the Upstream to
	// implement KeyMirrorRemoteVerifier). Required for keys imported with a bcrypt or
	// argon2id hash; once Atlas accepts one, the mirror stores its sha256 and verifies it
	// locally from then on.
	VerifyAtAtlas bool
	// MaxStaleness bounds the freshness of the revocation feed. When set, Verify answers
	// KeyMirrorCodeStale if the mirror has never completed a Sync or the last one finished
	// longer ago. Zero turns the check off (webhook-only mirrors).
	MaxStaleness time.Duration
	// ServeStaleFor keeps answering from the last synced data for this long after
	// MaxStaleness (the answer carries Stale), instead of refusing at once.
	ServeStaleFor time.Duration
	// OnServeStale is called each time an answer is served inside the ServeStaleFor grace.
	OnServeStale func(lastSyncAt time.Time, staleFor time.Duration)
	// Membership returns the user's CURRENT membership for a key bound to an organization
	// (nil when no longer a member). The key's scopes are narrowed to what its permissions
	// cover. Without it a bound key is verified at Atlas; with neither it answers
	// KeyMirrorCodeMembershipUnresolve.
	Membership func(ctx context.Context, userID, organizationID string) (*KeyMirrorMembership, error)
	// Now overrides the clock (tests).
	Now func() time.Time
}

// KeyMirror verifies API keys locally. Build one with NewKeyMirror. Safe for concurrent use.
type KeyMirror struct {
	opts       KeyMirrorOptions
	mu         sync.Mutex
	memSyncAt  int64
	memSynced  bool
	usedJTIs   map[string]int64
	clock      KeyMirrorSyncClock
	membership KeyMirrorMembershipStore
}

// NewKeyMirror builds a KeyMirror.
func NewKeyMirror(opts KeyMirrorOptions) (*KeyMirror, error) {
	if opts.Store == nil || opts.Upstream == nil {
		return nil, errors.New("atlas: KeyMirror needs a Store and an Upstream")
	}
	m := &KeyMirror{opts: opts}
	m.clock, _ = opts.Store.(KeyMirrorSyncClock)
	m.membership, _ = opts.Store.(KeyMirrorMembershipStore)
	return m, nil
}

func (m *KeyMirror) nowMS() int64 {
	if m.opts.Now != nil {
		return m.opts.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// HashAPIKeySecret is the sha256 (lowercase hex) the mirror stores and Atlas imports as sha256_hex.
func HashAPIKeySecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// LastSyncAt returns epoch ms of the last completed Sync; ok is false when never synced.
func (m *KeyMirror) LastSyncAt(ctx context.Context) (int64, bool, error) {
	if m.clock != nil {
		return m.clock.LastSyncAt(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.memSyncAt, m.memSynced, nil
}

func keyRecordToMirrored(r *KeyMirrorKeyRecord, hash string) MirroredAPIKey {
	return MirroredAPIKey{
		ID: r.ID, Hash: hash, Prefix: r.Prefix, SubjectType: r.SubjectType, SubjectID: r.SubjectID, Name: r.Name,
		Scopes: r.Scopes, AllowedIPs: r.AllowedIPs, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
		OrganizationID: r.OrganizationID, RevokedReason: r.RevokedReason,
		Enabled: r.Enabled, Credential: r.Credential, PublicKeyPEM: r.PublicKey, Audience: r.Audience, MaxTokenLifetimeSeconds: r.MaxTokenLifetimeSeconds,
	}
}

// keyRecordHash is the secret's sha256; a key-pair key has no secret, so its row carries a placeholder nothing can match.
func keyRecordHash(r *KeyMirrorKeyRecord) string {
	if r.Secret == "" && r.Credential == "key_pair" {
		return "key_pair:" + r.ID
	}
	return HashAPIKeySecret(r.Secret)
}

// Mint creates a key at Atlas, then mirrors it. The returned record carries the one-time Secret.
func (m *KeyMirror) Mint(ctx context.Context, params CreateAPIKeyParams, opts ...RequestOption) (*KeyMirrorKeyRecord, error) {
	params.Import = nil
	created, err := m.opts.Upstream.CreateKey(ctx, params, opts...)
	if err != nil {
		return nil, err
	}
	if err := m.opts.Store.Put(ctx, keyRecordToMirrored(created, keyRecordHash(created))); err != nil {
		return nil, err
	}
	return created, nil
}

var keyMirrorHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// KeyMirrorImport describes an existing key to import so its holders keep their secret.
// Give exactly one of Secret, SecretHash (sha256 hex), BcryptHash or Argon2idHash.
type KeyMirrorImport struct {
	Secret       string
	SecretHash   string
	BcryptHash   string
	Argon2idHash string
	// Prefix is the public head shown in listings, e.g. the first 16 characters.
	Prefix string
	// Params carries the subject, name, scopes, expiry and so on (Import is set for you).
	Params CreateAPIKeyParams
}

// Import registers an existing key at Atlas by its hash and mirrors it. Atlas stores
// the hash, the mirror stores the same hash. A bcrypt/argon2id import has no local
// sha256 yet: Verify (with VerifyAtAtlas) learns it on first use.
func (m *KeyMirror) Import(ctx context.Context, in KeyMirrorImport, opts ...RequestOption) (*KeyMirrorKeyRecord, error) {
	params := in.Params
	legacy, algo := in.BcryptHash, "bcrypt"
	if legacy == "" {
		legacy, algo = in.Argon2idHash, "argon2id"
	}
	if legacy != "" {
		params.Import = &APIKeyImport{SecretHash: legacy, HashAlgorithm: algo, Prefix: in.Prefix}
		rec, err := m.opts.Upstream.CreateKey(ctx, params, opts...)
		if err != nil {
			return nil, err
		}
		held, err := m.opts.Store.Get(ctx, rec.ID)
		if err != nil {
			return nil, err
		}
		// A retry that answered already_present keeps a sha256 the mirror already learned.
		if rec.Outcome != "already_present" || held == nil {
			if err := m.opts.Store.Put(ctx, keyRecordToMirrored(rec, "legacy:"+rec.ID)); err != nil {
				return nil, err
			}
		}
		if rec.Outcome == "" {
			rec.Outcome = "created"
		}
		return rec, nil
	}
	hash := strings.ToLower(in.SecretHash)
	if hash == "" && in.Secret != "" {
		hash = HashAPIKeySecret(in.Secret)
	}
	if !keyMirrorHex64.MatchString(hash) {
		return nil, errors.New("atlas: Import needs the full Secret or its SecretHash (64 lowercase hex characters of sha256)")
	}
	params.Import = &APIKeyImport{SecretHash: hash, HashAlgorithm: "sha256_hex", Prefix: in.Prefix}
	rec, err := m.opts.Upstream.CreateKey(ctx, params, opts...)
	if err != nil {
		return nil, err
	}
	if err := m.opts.Store.Put(ctx, keyRecordToMirrored(rec, hash)); err != nil {
		return nil, err
	}
	if rec.Outcome == "" {
		rec.Outcome = "created"
	}
	return rec, nil
}

// Revoke revokes LOCALLY first (the key stops working here at once), then at Atlas.
// A key Atlas already revoked or no longer knows (404/409) counts as revoked; any
// other Atlas error is returned after the local revoke, so retry it.
func (m *KeyMirror) Revoke(ctx context.Context, id string) error {
	if err := m.opts.Store.MarkRevoked(ctx, id, m.nowMS(), ""); err != nil {
		return err
	}
	if err := m.opts.Upstream.DeleteKey(ctx, id); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 409) {
			return nil
		}
		return err
	}
	return nil
}

// Rotate rotates a key at Atlas, then mirrors both sides: the successor is added,
// and the old key now ends at the end of the overlap (or is revoked at once when
// the overlap is 0). The returned rotation carries the successor's one-time Secret.
// The upstream must implement KeyMirrorRotator (NewKeyMirrorUpstream does).
func (m *KeyMirror) Rotate(ctx context.Context, id string, params KeyMirrorRotateParams, opts ...RequestOption) (*KeyMirrorRotation, error) {
	rotator, ok := m.opts.Upstream.(KeyMirrorRotator)
	if !ok {
		return nil, errors.New("atlas: KeyMirror.Rotate needs an upstream that implements KeyMirrorRotator")
	}
	rotated, err := rotator.RotateKey(ctx, id, params, opts...)
	if err != nil {
		return nil, err
	}
	if err := m.opts.Store.Put(ctx, keyRecordToMirrored(&rotated.KeyMirrorKeyRecord, keyRecordHash(&rotated.KeyMirrorKeyRecord))); err != nil {
		return nil, err
	}
	old, err := m.opts.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if old != nil {
		if rotated.PreviousKey.Revoked {
			if err := m.opts.Store.MarkRevoked(ctx, id, m.nowMS(), "rotated"); err != nil {
				return nil, err
			}
		} else {
			updated := *old
			if rotated.PreviousKey.ExpiresAt != nil {
				updated.ExpiresAt = rotated.PreviousKey.ExpiresAt
			}
			if err := m.opts.Store.Put(ctx, updated); err != nil {
				return nil, err
			}
		}
	}
	return rotated, nil
}

// KeyVerifyOptions are the per-call inputs of KeyMirror.Verify.
type KeyVerifyOptions struct {
	// RequiredScopes must all be held (after scope implications).
	RequiredScopes []string
	// ClientIP is the end caller's address, checked against a key's allowlist. A key
	// with an allowlist fails closed without it.
	ClientIP string
}

// KeyMirrorVerification is the answer of KeyMirror.Verify.
type KeyMirrorVerification struct {
	Valid bool
	// Code explains a refusal (see the KeyMirrorCode constants); empty for a plain unknown, revoked or expired key.
	Code          string
	MissingScopes []string
	// Key and EffectiveScopes are set when Valid.
	Key             *MirroredAPIKey
	EffectiveScopes []string
	// Stale is true when the mirror was past MaxStaleness and this answer came from its last synced data.
	Stale bool
	// Organization is the membership a bound key's scopes were narrowed by.
	Organization *KeyMirrorMembership
	// LastSyncAt is set with KeyMirrorCodeStale: epoch ms of the last completed sync (nil = never).
	LastSyncAt *int64
	// Credential is "key_pair" after VerifyAssertion; JTI and Exp (epoch seconds) are the assertion's.
	Credential string
	JTI        string
	Exp        int64
}

func keyMirrorExpand(held []string, implications map[string][]string, allowed []string) []string {
	vocab := map[string]bool{}
	for _, a := range allowed {
		vocab[a] = true
	}
	for from, tos := range implications {
		vocab[from] = true
		for _, t := range tos {
			if t != "*" {
				vocab[t] = true
			}
		}
	}
	out := map[string]bool{}
	queue := []string{}
	for _, h := range held {
		out[h] = true
		queue = append(queue, h)
	}
	for len(queue) > 0 {
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, to := range implications[cur] {
			targets := []string{to}
			if to == "*" {
				targets = targets[:0]
				for v := range vocab {
					targets = append(targets, v)
				}
			}
			for _, t := range targets {
				if !out[t] {
					out[t] = true
					queue = append(queue, t)
				}
			}
		}
	}
	res := make([]string, 0, len(out))
	for s := range out {
		res = append(res, s)
	}
	sort.Strings(res)
	return res
}

// IPInAllowlist reports whether ip is inside one of the addresses / CIDR ranges.
// Unparseable input is never inside; an IPv4-mapped IPv6 address never matches an IPv4 range.
func IPInAllowlist(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.Zone() != "" {
		return false
	}
	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			p, perr := netip.ParsePrefix(entry)
			if perr == nil && p.Contains(addr) {
				return true
			}
			continue
		}
		if a, aerr := netip.ParseAddr(entry); aerr == nil && a == addr {
			return true
		}
	}
	return false
}

// KeyMirrorPermissionCoversScope reports whether a permission covers a key scope:
// the same name, "*", or "<prefix>:*". Mirrors Atlas verify.
func KeyMirrorPermissionCoversScope(permission, scope string) bool {
	if permission == scope || permission == "*" {
		return true
	}
	return strings.HasSuffix(permission, ":*") && strings.HasPrefix(scope, permission[:len(permission)-1])
}

// IntersectScopesWithPermissions returns the key scopes a membership's permissions
// cover: what Atlas returns as effective_scopes for a key bound to an organization. Sorted.
func IntersectScopesWithPermissions(scopes, permissions []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range scopes {
		if seen[s] {
			continue
		}
		for _, p := range permissions {
			if KeyMirrorPermissionCoversScope(p, s) {
				seen[s] = true
				out = append(out, s)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// freshness returns a refusal when the mirror is too stale to answer, and whether the answer is served stale.
func (m *KeyMirror) freshness(ctx context.Context) (*KeyMirrorVerification, bool, error) {
	if m.opts.MaxStaleness <= 0 {
		return nil, false, nil
	}
	at, ok, err := m.LastSyncAt(ctx)
	if err != nil {
		return nil, false, err
	}
	var behind int64
	if ok {
		behind = m.nowMS() - at - m.opts.MaxStaleness.Milliseconds()
	}
	if ok && behind <= 0 {
		return nil, false, nil
	}
	if !ok || behind > m.opts.ServeStaleFor.Milliseconds() {
		v := &KeyMirrorVerification{Code: KeyMirrorCodeStale}
		if ok {
			v.LastSyncAt = &at
		}
		return v, false, nil
	}
	if m.opts.OnServeStale != nil {
		m.opts.OnServeStale(time.UnixMilli(at), time.Duration(behind)*time.Millisecond)
	}
	return nil, true, nil
}

// Verify checks a presented secret against the mirror, with no network call
// (except VerifyAtAtlas on a local miss, and an org-bound key without Membership).
// Unknown, revoked and expired keys all answer Valid=false; a mirror that is not
// fresh (MaxStaleness) answers KeyMirrorCodeStale. An error means the store or
// Atlas failed, not that the key is bad.
func (m *KeyMirror) Verify(ctx context.Context, secret string, opts KeyVerifyOptions) (*KeyMirrorVerification, error) {
	if secret == "" {
		return &KeyMirrorVerification{}, nil
	}
	refuse, servedStale, err := m.freshness(ctx)
	if err != nil || refuse != nil {
		return refuse, err
	}
	hash := HashAPIKeySecret(secret)
	key, err := m.opts.Store.GetByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	remote, _ := m.opts.Upstream.(KeyMirrorRemoteVerifier)
	if key == nil && m.opts.VerifyAtAtlas && remote != nil {
		verdict, verr := remote.VerifyKey(ctx, secret, opts.ClientIP)
		if verr != nil {
			return nil, verr
		}
		if verdict.Valid {
			rec, gerr := remote.GetKey(ctx, verdict.ID)
			if gerr != nil {
				return nil, gerr
			}
			mk := keyRecordToMirrored(rec, hash)
			if perr := m.opts.Store.Put(ctx, mk); perr != nil {
				return nil, perr
			}
			key = &mk
		}
	}
	if key == nil || key.RevokedAt != nil || (key.Enabled != nil && !*key.Enabled) {
		return &KeyMirrorVerification{}, nil
	}
	if key.ExpiresAt != nil && *key.ExpiresAt <= m.nowMS() {
		return &KeyMirrorVerification{}, nil
	}
	// A key with an allowlist needs the end caller's address; no address fails closed.
	if len(key.AllowedIPs) > 0 {
		if opts.ClientIP == "" {
			return &KeyMirrorVerification{Code: KeyMirrorCodeClientIPRequired}, nil
		}
		if !IPInAllowlist(opts.ClientIP, key.AllowedIPs) {
			return &KeyMirrorVerification{Code: KeyMirrorCodeIPNotAllowed}, nil
		}
	}
	effective := keyMirrorExpand(key.Scopes, m.opts.ScopeImplications, m.opts.AllowedScopes)
	var organization *KeyMirrorMembership
	if key.SubjectType == "user" && key.OrganizationID != nil && *key.OrganizationID != "" {
		// A bound key stands for the user's CURRENT membership; never answer from the key's own scopes.
		switch {
		case m.opts.Membership != nil:
			held, merr := m.opts.Membership(ctx, key.SubjectID, *key.OrganizationID)
			if merr != nil {
				return nil, merr
			}
			if held == nil {
				return &KeyMirrorVerification{}, nil
			}
			organization = held
			effective = IntersectScopesWithPermissions(effective, held.Permissions)
		case remote != nil:
			verdict, verr := remote.VerifyKey(ctx, secret, opts.ClientIP)
			if verr != nil {
				return nil, verr
			}
			if !verdict.Valid || verdict.Organization == nil {
				return &KeyMirrorVerification{}, nil
			}
			organization = verdict.Organization
			effective = verdict.EffectiveScopes
		default:
			return &KeyMirrorVerification{Code: KeyMirrorCodeMembershipUnresolve}, nil
		}
	}
	held := map[string]bool{}
	for _, s := range effective {
		held[s] = true
	}
	var missing []string
	for _, s := range opts.RequiredScopes {
		if !held[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return &KeyMirrorVerification{Code: KeyMirrorCodeInsufficientScope, MissingScopes: missing}, nil
	}
	return &KeyMirrorVerification{Valid: true, Key: key, EffectiveScopes: effective, Organization: organization, Stale: servedStale}, nil
}

// VerifyAssertion verifies a key-pair assertion (SignAPIKeyAssertion) locally with the checks Atlas
// verify makes: the signature with the stored public key (alg must fit its type), iss = kid, aud, iat,
// exp and the lifetime cap, nbf, scope (a subset of the key's, narrows the result), revocation, expiry,
// the IP allowlist, then the single-use jti. A refusal carries the server's Code; a key the mirror does
// not hold answers Valid=false with no code. The jti is claimed through the store's optional
// KeyMirrorJTIStore, else in this process's memory, and only after every other check passed.
func (m *KeyMirror) VerifyAssertion(ctx context.Context, token string, opts KeyVerifyOptions) (*KeyMirrorVerification, error) {
	refuse, servedStale, err := m.freshness(ctx)
	if err != nil || refuse != nil {
		return refuse, err
	}
	refused := func(code string) (*KeyMirrorVerification, error) { return &KeyMirrorVerification{Code: code}, nil }
	parsed := parseAPIKeyAssertion(token)
	if parsed == nil || parsed.kid == "" {
		return refused(KeyMirrorCodeInvalidAssertion)
	}
	key, err := m.opts.Store.Get(ctx, parsed.kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return &KeyMirrorVerification{}, nil
	}
	if key.Credential != "key_pair" || key.PublicKeyPEM == nil || *key.PublicKeyPEM == "" {
		return refused(KeyMirrorCodeInvalidAssertion)
	}
	if !parsed.verifySignature(*key.PublicKeyPEM) || parsed.claimString("iss") != parsed.kid {
		return refused(KeyMirrorCodeInvalidAssertion)
	}
	if key.Enabled != nil && !*key.Enabled {
		return refused(KeyMirrorCodeInvalidAssertion)
	}
	if key.RevokedAt != nil {
		return &KeyMirrorVerification{}, nil
	}
	nowMS := m.nowMS()
	if key.ExpiresAt != nil && *key.ExpiresAt <= nowMS {
		return &KeyMirrorVerification{}, nil
	}
	nowS := nowMS / 1000
	audOK := false
	switch aud := parsed.claims["aud"].(type) {
	case string:
		audOK = key.Audience != nil && aud == *key.Audience
	case []interface{}:
		for _, a := range aud {
			if as, ok := a.(string); ok && key.Audience != nil && as == *key.Audience {
				audOK = true
			}
		}
	}
	if !audOK {
		return refused(KeyMirrorCodeWrongAudience)
	}
	iat, iatOK := parsed.claimInt("iat")
	exp, expOK := parsed.claimInt("exp")
	nbf, nbfOK := parsed.claimInt("nbf")
	_, hasNbf := parsed.claims["nbf"]
	jti, hasJti := parsed.claims["jti"]
	jtiStr, jtiIsStr := jti.(string)
	scopeClaim, hasScope := parsed.claims["scope"]
	scopeStr, scopeIsStr := scopeClaim.(string)
	if !iatOK || !expOK || (hasNbf && !nbfOK) || (hasJti && (!jtiIsStr || jtiStr == "")) || (hasScope && !scopeIsStr) {
		return refused(KeyMirrorCodeInvalidAssertion)
	}
	if iat > nowS+60 || (hasNbf && nbf > nowS+60) {
		return refused(KeyMirrorCodeAssertionNotYetValid)
	}
	if exp <= nowS-30 {
		return refused(KeyMirrorCodeAssertionExpired)
	}
	maxLife := int64(3600)
	if key.MaxTokenLifetimeSeconds != nil {
		maxLife = *key.MaxTokenLifetimeSeconds
	}
	if maxLife > 86400 {
		maxLife = 86400
	}
	if exp-iat > maxLife {
		return refused(KeyMirrorCodeAssertionLifetimeTooLong)
	}
	if len(key.AllowedIPs) > 0 {
		if opts.ClientIP == "" {
			return refused(KeyMirrorCodeClientIPRequired)
		}
		if !IPInAllowlist(opts.ClientIP, key.AllowedIPs) {
			return refused(KeyMirrorCodeIPNotAllowed)
		}
	}
	effective := keyMirrorExpand(key.Scopes, m.opts.ScopeImplications, m.opts.AllowedScopes)
	var organization *KeyMirrorMembership
	if key.SubjectType == "user" && key.OrganizationID != nil && *key.OrganizationID != "" {
		if m.opts.Membership == nil {
			return refused(KeyMirrorCodeMembershipUnresolve)
		}
		held, merr := m.opts.Membership(ctx, key.SubjectID, *key.OrganizationID)
		if merr != nil {
			return nil, merr
		}
		if held == nil {
			return &KeyMirrorVerification{}, nil
		}
		organization = held
		effective = IntersectScopesWithPermissions(effective, held.Permissions)
	}
	if asked := strings.Fields(scopeStr); len(asked) > 0 {
		has := map[string]bool{}
		for _, s := range effective {
			has[s] = true
		}
		var notGranted []string
		for _, s := range asked {
			if !has[s] {
				notGranted = append(notGranted, s)
			}
		}
		if len(notGranted) > 0 {
			return &KeyMirrorVerification{Code: KeyMirrorCodeScopeNotGranted, MissingScopes: notGranted}, nil
		}
		narrowed := []string{}
		for _, s := range effective {
			for _, a := range asked {
				if s == a {
					narrowed = append(narrowed, s)
					break
				}
			}
		}
		effective = narrowed
	}
	held := map[string]bool{}
	for _, s := range effective {
		held[s] = true
	}
	var missing []string
	for _, s := range opts.RequiredScopes {
		if !held[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return &KeyMirrorVerification{Code: KeyMirrorCodeInsufficientScope, MissingScopes: missing}, nil
	}
	// Last, so a refused assertion never burns its jti.
	if hasJti {
		first, cerr := m.claimJTI(ctx, key.ID, jtiStr, exp*1000, nowMS)
		if cerr != nil {
			return nil, cerr
		}
		if !first {
			return refused(KeyMirrorCodeAssertionReplayed)
		}
	}
	return &KeyMirrorVerification{Valid: true, Key: key, EffectiveScopes: effective, Organization: organization, Stale: servedStale,
		Credential: "key_pair", JTI: jtiStr, Exp: exp}, nil
}

func (m *KeyMirror) claimJTI(ctx context.Context, keyID, jti string, untilMS, nowMS int64) (bool, error) {
	if s, ok := m.opts.Store.(KeyMirrorJTIStore); ok {
		return s.ClaimAssertionJTI(ctx, keyID, jti, untilMS)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.usedJTIs == nil {
		m.usedJTIs = map[string]int64{}
	}
	for k, t := range m.usedJTIs {
		if t <= nowMS {
			delete(m.usedJTIs, k)
		}
	}
	id := keyID + "\n" + jti
	if _, seen := m.usedJTIs[id]; seen {
		return false, nil
	}
	m.usedJTIs[id] = untilMS
	return true, nil
}

// Sync consumes the revocation feed from the stored cursor, revoking each listed key
// locally. Call it on a timer (every few seconds to a minute): a key revoked at Atlas
// is rejected here within one tick. It returns how many ids it applied.
func (m *KeyMirror) Sync(ctx context.Context) (int, error) {
	since, err := m.opts.Store.Cursor(ctx)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for {
		page, err := m.opts.Upstream.ListRevoked(ctx, since, 100)
		if err != nil {
			return revoked, err
		}
		for _, ref := range page.Data {
			at := m.nowMS()
			if ref.RevokedAt != nil {
				at = *ref.RevokedAt
			}
			reason := ""
			if ref.RevokedReason != nil {
				reason = *ref.RevokedReason
			}
			if err := m.opts.Store.MarkRevoked(ctx, ref.ID, at, reason); err != nil {
				return revoked, err
			}
			revoked++
		}
		if page.NextCursor != "" {
			since = page.NextCursor
			if err := m.opts.Store.SetCursor(ctx, since); err != nil {
				return revoked, err
			}
		}
		if !page.HasMore || page.NextCursor == "" {
			now := m.nowMS()
			m.mu.Lock()
			m.memSyncAt, m.memSynced = now, true
			m.mu.Unlock()
			if m.clock != nil {
				if err := m.clock.SetLastSyncAt(ctx, now); err != nil {
					return revoked, err
				}
			}
			return revoked, nil
		}
	}
}

// ApplyWebhook applies a VERIFIED api_key.* webhook (check the signature first, e.g.
// with VerifyWebhook): api_key.revoked revokes locally, api_key.restored lifts a
// revocation a ban caused, api_key.updated refreshes name, scopes, allowlist and
// expiry of a key the mirror holds. organization_membership.deleted drops the keys
// bound to that membership (when the store supports it). The hash never changes, so a
// key the mirror does not hold is ignored (Mint or Import adds it). It returns whether
// the event changed the mirror.
func (m *KeyMirror) ApplyWebhook(ctx context.Context, eventType string, data json.RawMessage) (bool, error) {
	if eventType == "organization_membership.deleted" || eventType == "organizationMembership.deleted" {
		var d struct {
			UserID         string `json:"user_id"`
			OrganizationID string `json:"organization_id"`
		}
		if json.Unmarshal(data, &d) != nil || d.UserID == "" || d.OrganizationID == "" || m.membership == nil {
			return false, nil
		}
		return true, m.membership.MarkMembershipEnded(ctx, d.UserID, d.OrganizationID, m.nowMS())
	}
	if !strings.HasPrefix(eventType, "api_key.") {
		return false, nil
	}
	var d struct {
		ID            string          `json:"id"`
		Name          json.RawMessage `json:"name"`
		Scopes        json.RawMessage `json:"scopes"`
		AllowedIPs    json.RawMessage `json:"allowed_ips"`
		Enabled       *bool           `json:"enabled"`
		ExpiresAt     json.RawMessage `json:"expires_at"`
		RevokedAt     *int64          `json:"revoked_at"`
		RevokedReason *string         `json:"revoked_reason"`
	}
	if json.Unmarshal(data, &d) != nil || d.ID == "" {
		return false, nil
	}
	held, err := m.opts.Store.Get(ctx, d.ID)
	if err != nil || held == nil {
		return false, err
	}
	updated := *held
	if len(d.ExpiresAt) > 0 {
		var v *int64
		_ = json.Unmarshal(d.ExpiresAt, &v)
		updated.ExpiresAt = v
	}
	// A key a ban had suspended works again: lift the local revocation.
	if eventType == "api_key.restored" {
		if held.RevokedAt == nil {
			return false, nil
		}
		updated.RevokedAt, updated.RevokedReason = nil, nil
		return true, m.opts.Store.Put(ctx, updated)
	}
	if eventType == "api_key.revoked" || (d.RevokedAt != nil && held.RevokedAt == nil) {
		at := m.nowMS()
		if d.RevokedAt != nil {
			at = *d.RevokedAt
		}
		reason := ""
		if d.RevokedReason != nil {
			reason = *d.RevokedReason
		}
		return true, m.opts.Store.MarkRevoked(ctx, held.ID, at, reason)
	}
	if eventType == "api_key.updated" || eventType == "api_key.created" {
		if len(d.Name) > 0 {
			var v *string
			_ = json.Unmarshal(d.Name, &v)
			updated.Name = v
		}
		if len(d.Scopes) > 0 {
			var v []string
			_ = json.Unmarshal(d.Scopes, &v)
			updated.Scopes = v
		}
		if len(d.AllowedIPs) > 0 {
			var v []string
			_ = json.Unmarshal(d.AllowedIPs, &v)
			updated.AllowedIPs = v
		}
		if d.Enabled != nil {
			updated.Enabled = d.Enabled
		}
		return true, m.opts.Store.Put(ctx, updated)
	}
	return false, nil
}
