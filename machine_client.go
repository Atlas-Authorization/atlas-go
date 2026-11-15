package atlas

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The device side of machine enrolment, for a service or device of your own:
// generate an Ed25519 key, enrol with a token or a short code, then trade a signed
// challenge for short-lived machine tokens, cached until shortly before they
// expire. Everything is three JSON POSTs to your issuer URL (see the machine
// identities guide for the wire spec).

// MachineClientIdentity is what a machine keeps between runs. The private key never leaves it.
// The JSON form is shared with the other SDKs' machine clients.
type MachineClientIdentity struct {
	Issuer    string `json:"issuer"`
	MachineID string `json:"machine_id"`
	// PrivateKeyPEM is the PKCS#8 PEM of the Ed25519 private key.
	PrivateKeyPEM string `json:"private_key_pem"`
	// PublicKeyPEM is the SPKI PEM of the matching public key (what enrolment registered).
	PublicKeyPEM string `json:"public_key_pem"`
	// EnrolledAt is epoch ms.
	EnrolledAt int64 `json:"enrolled_at"`
}

// MachineClientStore is where the identity lives; pass your own to use a keychain
// or secret manager. Load returns (nil, nil) before enrolment.
type MachineClientStore interface {
	Load(ctx context.Context) (*MachineClientIdentity, error)
	Save(ctx context.Context, identity MachineClientIdentity) error
	Clear(ctx context.Context) error
}

type fileMachineClientStore struct{ path string }

// FileMachineClientStore keeps the identity in one file, written 0600 in a 0700 directory.
func FileMachineClientStore(path string) MachineClientStore {
	return &fileMachineClientStore{path: path}
}

func (s *fileMachineClientStore) Load(_ context.Context) (*MachineClientIdentity, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	id := &MachineClientIdentity{}
	if json.Unmarshal(raw, id) != nil {
		return nil, nil
	}
	return id, nil
}

func (s *fileMachineClientStore) Save(_ context.Context, identity MachineClientIdentity) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *fileMachineClientStore) Clear(_ context.Context) error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// MemoryMachineClientStore forgets on exit (tests, short-lived jobs that enrol every run).
type MemoryMachineClientStore struct {
	mu sync.Mutex
	id *MachineClientIdentity
}

// NewMemoryMachineClientStore returns an empty store, optionally holding initial.
func NewMemoryMachineClientStore(initial *MachineClientIdentity) *MemoryMachineClientStore {
	return &MemoryMachineClientStore{id: initial}
}

// Load implements MachineClientStore.
func (s *MemoryMachineClientStore) Load(_ context.Context) (*MachineClientIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
		return nil, nil
	}
	c := *s.id
	return &c, nil
}

// Save implements MachineClientStore.
func (s *MemoryMachineClientStore) Save(_ context.Context, identity MachineClientIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = &identity
	return nil
}

// Clear implements MachineClientStore.
func (s *MemoryMachineClientStore) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = nil
	return nil
}

// MachineClientError is Atlas refusing a request. Code is the machine-readable
// error code when the response had one ("" otherwise).
type MachineClientError struct {
	Status  int
	Code    string
	Message string
}

func (e *MachineClientError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("atlas: machine client: %s: %s (status %d)", e.Code, e.Message, e.Status)
	}
	return fmt.Sprintf("atlas: machine client: %s (status %d)", e.Message, e.Status)
}

// MachineClientOptions configures a MachineClient.
type MachineClientOptions struct {
	// Issuer is your instance's issuer URL: the iss of its tokens. Required.
	Issuer string
	// Store keeps the identity between runs. Required.
	Store MachineClientStore
	// HTTPClient performs the requests (nil = http.DefaultClient).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
	// RefreshSkew fetches a new token this long before the cached one expires. Default 60s.
	RefreshSkew time.Duration
	// DPoPKeyPEM binds every token to a DPoP key (RFC 9449): a PKCS#8 PEM, Ed25519 or
	// P-256. Needed when the machine's token_binding is dpop. Send DPoPProof() with each
	// call to your API. GenerateDPoPKey makes one in memory instead.
	DPoPKeyPEM      string
	GenerateDPoPKey bool
}

// MachineTokenRequest says what a token is for.
type MachineTokenRequest struct {
	// Audience is the resource server (API) the token is for; becomes its aud.
	Audience string
	// Scopes within the grant. Needs Audience.
	Scopes []string
	// ScopePresets are scope preset names of the resource server. Needs Audience.
	ScopePresets []string
	// OrganizationID is the organization context; defaults to the machine's own.
	OrganizationID string
}

// MachineClientToken is a minted machine token.
type MachineClientToken struct {
	Token string
	// TokenType is "DPoP" when bound to this client's key (send Authorization: DPoP <token> with a DPoPProof) else "Bearer".
	TokenType string
	// ExpiresAt is epoch ms.
	ExpiresAt int64
	Audience  string
	Scope     string
	// Constraints are the grant's constraints, as the token carries them. Your API enforces them.
	Constraints    map[string]interface{}
	OrganizationID string
}

// MachineEnrolOptions is the input of Enroll.
type MachineEnrolOptions struct {
	// Credential is a met_ enrolment token, or a short user code (XXXX-XXXX).
	Credential string
	Name       string
	Metadata   map[string]interface{}
	// DeviceKey is a stable device identifier, so re-enrolling replaces this device's earlier machine.
	DeviceKey string
}

// MachineEnrolResult is the outcome of Enroll.
type MachineEnrolResult struct {
	MachineID string
	Status    string
	// ApprovalRequired is true when an administrator must approve the machine before it can get tokens.
	ApprovalRequired bool
}

func pemEncode(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func parseMachinePrivateKey(privateKeyPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("atlas: not a PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("atlas: parsing PKCS#8 private key: %w", err)
	}
	return key, nil
}

// SignMachineChallenge is base64url(sign(privateKey, nonce)): pure Ed25519 over the
// nonce's UTF-8 bytes, no padding.
func SignMachineChallenge(privateKeyPEM, nonce string) (string, error) {
	key, err := parseMachinePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("atlas: a machine key must be Ed25519")
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed, []byte(nonce))), nil
}

// MachinePublicKeyPEMOf re-derives the SPKI PEM of a private key: the public half the
// server holds. Useful to check a store was not swapped.
func MachinePublicKeyPEMOf(privateKeyPEM string) (string, error) {
	key, err := parseMachinePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	var pub interface{}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		pub = k.Public()
	case *ecdsa.PrivateKey:
		pub = k.Public()
	default:
		return "", errors.New("atlas: unsupported key type")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return pemEncode("PUBLIC KEY", der), nil
}

// GenerateDPoPKeyPEM makes a new Ed25519 key for DPoP, as a PKCS#8 PEM. Keep it as
// safely as the machine's own key.
func GenerateDPoPKeyPEM() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return pemEncode("PRIVATE KEY", der), nil
}

func machinePublicJWK(key interface{}) (map[string]interface{}, string, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		pub, _ := k.Public().(ed25519.PublicKey)
		return map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}, "EdDSA", nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, "", errors.New("atlas: a DPoP key must be Ed25519 or P-256")
		}
		x := k.PublicKey.X.FillBytes(make([]byte, 32))
		y := k.PublicKey.Y.FillBytes(make([]byte, 32))
		return map[string]interface{}{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}, "ES256", nil
	}
	return nil, "", errors.New("atlas: a DPoP key must be Ed25519 or P-256")
}

// DPoPKeyThumbprint is the RFC 7638 thumbprint of a DPoP key: the cnf.jkt a token
// minted with its proofs carries.
func DPoPKeyThumbprint(privateKeyPEM string) (string, error) {
	key, err := parseMachinePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	jwk, _, err := machinePublicJWK(key)
	if err != nil {
		return "", err
	}
	return JWKThumbprint(jwk)
}

// DPoPProofInput is what CreateDPoPProof signs.
type DPoPProofInput struct {
	PrivateKeyPEM string
	Method        string
	// URL is the full request URL (query and fragment are dropped, as the standard requires).
	URL string
	// AccessToken is set when calling a resource server so the proof names the token.
	AccessToken string
	// Nonce is set when the server answered use_dpop_nonce.
	Nonce string
	// Now overrides the clock (tests); zero means time.Now.
	Now time.Time
}

// CreateDPoPProof signs one DPoP proof (RFC 9449) for one request.
func CreateDPoPProof(in DPoPProofInput) (string, error) {
	key, err := parseMachinePrivateKey(in.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	jwk, alg, err := machinePublicJWK(key)
	if err != nil {
		return "", err
	}
	htu, ok := NormalizeHTU(in.URL)
	if !ok {
		return "", errors.New("atlas: DPoP proof needs an absolute http(s) URL")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	payload := map[string]interface{}{
		"jti": hex.EncodeToString(jti),
		"htm": strings.ToUpper(in.Method),
		"htu": htu,
		"iat": now.Unix(),
	}
	if in.AccessToken != "" {
		payload["ath"] = DPoPAccessTokenHash(in.AccessToken)
	}
	if in.Nonce != "" {
		payload["nonce"] = in.Nonce
	}
	header, _ := json.Marshal(map[string]interface{}{"typ": "dpop+jwt", "alg": alg, "jwk": jwk})
	body, _ := json.Marshal(payload)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	var sig []byte
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256([]byte(input))
		r, s, serr := ecdsa.Sign(rand.Reader, k, digest[:])
		if serr != nil {
			return "", serr
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type machineMintCall struct {
	done chan struct{}
	tok  *MachineClientToken
	err  error
}

// MachineClient enrols a machine and mints its tokens. Safe for concurrent use.
type MachineClient struct {
	issuer   string
	store    MachineClientStore
	hc       *http.Client
	now      func() time.Time
	skew     time.Duration
	dpopKey  string
	mu       sync.Mutex
	cache    map[string]*MachineClientToken
	inflight map[string]*machineMintCall
}

// NewMachineClient builds a MachineClient.
func NewMachineClient(opts MachineClientOptions) (*MachineClient, error) {
	if opts.Issuer == "" || opts.Store == nil {
		return nil, errors.New("atlas: MachineClient needs an Issuer and a Store")
	}
	c := &MachineClient{
		issuer:   strings.TrimRight(opts.Issuer, "/"),
		store:    opts.Store,
		hc:       opts.HTTPClient,
		now:      opts.Now,
		skew:     opts.RefreshSkew,
		dpopKey:  opts.DPoPKeyPEM,
		cache:    map[string]*MachineClientToken{},
		inflight: map[string]*machineMintCall{},
	}
	if c.hc == nil {
		c.hc = http.DefaultClient
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.skew <= 0 {
		c.skew = 60 * time.Second
	}
	if c.dpopKey == "" && opts.GenerateDPoPKey {
		k, err := GenerateDPoPKeyPEM()
		if err != nil {
			return nil, err
		}
		c.dpopKey = k
	}
	if c.dpopKey != "" {
		if _, err := DPoPKeyThumbprint(c.dpopKey); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *MachineClient) post(ctx context.Context, path string, body map[string]interface{}, proof bool, out interface{}) error {
	target := c.issuer + path
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if proof && c.dpopKey != "" {
		p, perr := CreateDPoPProof(DPoPProofInput{PrivateKeyPEM: c.dpopKey, Method: "POST", URL: target, Now: c.now()})
		if perr != nil {
			return perr
		}
		req.Header.Set("DPoP", p)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	parsed := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed) // a non-JSON error page falls through to the status
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, msg := "", fmt.Sprintf("Request failed with status %d.", resp.StatusCode)
		if errs, ok := parsed["errors"].([]interface{}); ok && len(errs) > 0 {
			if first, ok := errs[0].(map[string]interface{}); ok {
				if v, ok := first["code"].(string); ok {
					code = v
				}
				if v, ok := first["message"].(string); ok {
					msg = v
				}
			}
		} else {
			if v, ok := parsed["code"].(string); ok {
				code = v
			}
			if v, ok := parsed["message"].(string); ok {
				msg = v
			}
		}
		return &MachineClientError{Status: resp.StatusCode, Code: code, Message: msg}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// identity returns the stored identity, or nil before enrolment (or when it belongs to another issuer).
func (c *MachineClient) identity(ctx context.Context) (*MachineClientIdentity, error) {
	id, err := c.store.Load(ctx)
	if err != nil || id == nil || id.Issuer != c.issuer {
		return nil, err
	}
	return id, nil
}

// Enroll generates a key, enrols with a token or short code, and stores the
// identity. The private key is created here and only its public half is sent.
func (c *MachineClient) Enroll(ctx context.Context, opts MachineEnrolOptions) (*MachineEnrolResult, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	publicPEM, privatePEM := pemEncode("PUBLIC KEY", pubDER), pemEncode("PRIVATE KEY", privDER)
	body := map[string]interface{}{
		"enrolment_token": strings.TrimSpace(opts.Credential),
		"name":            opts.Name,
		"public_key_pem":  publicPEM,
	}
	if opts.Metadata != nil {
		body["metadata"] = opts.Metadata
	}
	if opts.DeviceKey != "" {
		body["device_key"] = opts.DeviceKey
	}
	var res struct {
		ID               string `json:"id"`
		Status           string `json:"status"`
		ApprovalRequired bool   `json:"approval_required"`
		EnrolledAt       *int64 `json:"enrolled_at"`
	}
	if err := c.post(ctx, "/v1/machines/enroll", body, false, &res); err != nil {
		return nil, err
	}
	enrolledAt := c.now().UnixMilli()
	if res.EnrolledAt != nil {
		enrolledAt = *res.EnrolledAt
	}
	if err := c.store.Save(ctx, MachineClientIdentity{Issuer: c.issuer, MachineID: res.ID, PrivateKeyPEM: privatePEM, PublicKeyPEM: publicPEM, EnrolledAt: enrolledAt}); err != nil {
		return nil, err
	}
	c.ClearTokens()
	return &MachineEnrolResult{MachineID: res.ID, Status: res.Status, ApprovalRequired: res.ApprovalRequired}, nil
}

// IsEnrolled reports whether an identity for this issuer is stored.
func (c *MachineClient) IsEnrolled(ctx context.Context) (bool, error) {
	id, err := c.identity(ctx)
	return id != nil, err
}

// MachineID returns the stored machine id ("" before enrolment).
func (c *MachineClient) MachineID(ctx context.Context) (string, error) {
	id, err := c.identity(ctx)
	if id == nil {
		return "", err
	}
	return id.MachineID, nil
}

func machineCacheKey(r MachineTokenRequest) string {
	scopes := append([]string(nil), r.Scopes...)
	presets := append([]string(nil), r.ScopePresets...)
	sort.Strings(scopes)
	sort.Strings(presets)
	raw, _ := json.Marshal([]interface{}{r.Audience, scopes, presets, r.OrganizationID})
	return string(raw)
}

func (c *MachineClient) mint(ctx context.Context, req MachineTokenRequest) (*MachineClientToken, error) {
	id, err := c.identity(ctx)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, &MachineClientError{Code: "not_enrolled", Message: "This machine is not enrolled. Call Enroll first."}
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := c.post(ctx, "/v1/machines/challenge", map[string]interface{}{"machine_id": id.MachineID}, false, &challenge); err != nil {
		return nil, err
	}
	sig, err := SignMachineChallenge(id.PrivateKeyPEM, challenge.Nonce)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{"machine_id": id.MachineID, "nonce": challenge.Nonce, "signature": sig}
	if req.Audience != "" {
		body["audience"] = req.Audience
	}
	if req.Scopes != nil {
		body["scopes"] = req.Scopes
	}
	if req.ScopePresets != nil {
		body["scope_presets"] = req.ScopePresets
	}
	if req.OrganizationID != "" {
		body["organization_id"] = req.OrganizationID
	}
	var res struct {
		Token          string                 `json:"token"`
		TokenType      string                 `json:"token_type"`
		ExpiresIn      int64                  `json:"expires_in"`
		Audience       string                 `json:"audience"`
		Scope          string                 `json:"scope"`
		Constraints    map[string]interface{} `json:"constraints"`
		OrganizationID string                 `json:"organization_id"`
	}
	if err := c.post(ctx, "/v1/machines/token", body, true, &res); err != nil {
		return nil, err
	}
	tokenType := "Bearer"
	if res.TokenType == "DPoP" {
		tokenType = "DPoP"
	}
	return &MachineClientToken{
		Token: res.Token, TokenType: tokenType, ExpiresAt: c.now().UnixMilli() + res.ExpiresIn*1000,
		Audience: res.Audience, Scope: res.Scope, Constraints: res.Constraints, OrganizationID: res.OrganizationID,
	}, nil
}

// GetToken returns a machine token for req, from the cache while it has more than
// the refresh skew left. Concurrent callers asking for the same thing share one mint.
func (c *MachineClient) GetToken(ctx context.Context, req MachineTokenRequest) (*MachineClientToken, error) {
	key := machineCacheKey(req)
	c.mu.Lock()
	if hit, ok := c.cache[key]; ok && hit.ExpiresAt-c.skew.Milliseconds() > c.now().UnixMilli() {
		c.mu.Unlock()
		return hit, nil
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done
		return call.tok, call.err
	}
	call := &machineMintCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	call.tok, call.err = c.mint(ctx, req)

	c.mu.Lock()
	if call.err == nil {
		c.cache[key] = call.tok
	}
	delete(c.inflight, key)
	c.mu.Unlock()
	close(call.done)
	return call.tok, call.err
}

// DPoPProof signs a DPoP proof for one call to your API with a token this client
// minted: send Authorization: DPoP <token> plus DPoP: <proof>. Pass nonce when the
// API answered use_dpop_nonce. Needs a DPoP key.
func (c *MachineClient) DPoPProof(token, method, targetURL, nonce string) (string, error) {
	if c.dpopKey == "" {
		return "", &MachineClientError{Code: "dpop_not_configured", Message: "Create the client with DPoPKeyPEM or GenerateDPoPKey to sign DPoP proofs."}
	}
	return CreateDPoPProof(DPoPProofInput{PrivateKeyPEM: c.dpopKey, Method: method, URL: targetURL, AccessToken: token, Nonce: nonce, Now: c.now()})
}

// DPoPThumbprint is the cnf.jkt tokens minted by this client carry ("" without a DPoP key).
func (c *MachineClient) DPoPThumbprint() string {
	if c.dpopKey == "" {
		return ""
	}
	t, _ := DPoPKeyThumbprint(c.dpopKey)
	return t
}

// ClearTokens forgets cached tokens (the stored identity stays).
func (c *MachineClient) ClearTokens() {
	c.mu.Lock()
	c.cache = map[string]*MachineClientToken{}
	c.mu.Unlock()
}

// Reset forgets the identity too: the machine must enrol again.
func (c *MachineClient) Reset(ctx context.Context) error {
	c.ClearTokens()
	return c.store.Clear(ctx)
}
