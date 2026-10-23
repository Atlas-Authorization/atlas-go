package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Access-token verification for your own API (an OAuth 2.0 resource server).
//
// Atlas, acting as your authorization server, issues access tokens for the APIs
// you register as resource servers. AccessTokenVerifier checks one locally
// against the instance JWKS (RS256 or ES256, nothing else): the issuer, expiry,
// that it IS an access token, that its aud names your API (RFC 8707), and the
// scopes the route needs. A failure comes back with the RFC 6750 / RFC 9728
// WWW-Authenticate challenge to answer with, so an OAuth or MCP client can
// discover Atlas from the 401 (resource_metadata) or ask for the missing scope.
//
// Sender-constrained tokens (RFC 9449 DPoP) are enforced: a token bound to a
// key (cnf.jkt) is only accepted with the DPoP scheme and a valid DPoP proof
// from that key, never as a plain Bearer token. Set RequireDPoP to refuse
// unbound tokens altogether, and DPoPNonces to demand a server nonce.

// AccessTokenErrorCode is the RFC 6750 error of a refusal ("" when no token
// was sent at all).
type AccessTokenErrorCode string

const (
	AccessTokenInvalidRequest    AccessTokenErrorCode = "invalid_request"
	AccessTokenInvalidToken      AccessTokenErrorCode = "invalid_token"
	AccessTokenInsufficientScope AccessTokenErrorCode = "insufficient_scope"
	// AccessTokenInvalidDPoPProof: the DPoP proof is missing or fails a check.
	AccessTokenInvalidDPoPProof AccessTokenErrorCode = "invalid_dpop_proof"
	// AccessTokenUseDPoPNonce: retry with the nonce in the DPoP-Nonce header.
	AccessTokenUseDPoPNonce AccessTokenErrorCode = "use_dpop_nonce"
)

// AccessTokenVerifierOptions configure an AccessTokenVerifier.
type AccessTokenVerifierOptions struct {
	// Issuer is your instance's issuer (frontend API origin). Required.
	Issuer string
	// Audiences are your API's identifiers (the resource server identifier);
	// the token's aud must contain one. Empty accepts only tokens with no
	// audience check — set AllowAnyAudience to make that explicit.
	Audiences []string
	// AllowAnyAudience skips the aud check (userinfo-style tokens). Off by
	// default: an empty Audiences without it is a configuration error.
	AllowAnyAudience bool
	// RequiredScopes must all be granted on every request.
	RequiredScopes []string
	// JWKSURL defaults to Issuer + "/.well-known/jwks.json".
	JWKSURL string
	// ResourceMetadataURL is advertised in every challenge as
	// resource_metadata (RFC 9728), e.g.
	// https://api.example.com/.well-known/oauth-protected-resource.
	ResourceMetadataURL string
	// RequireDPoP refuses every token that is not DPoP-bound (never accepts a
	// plain Bearer token) and challenges with the DPoP scheme.
	RequireDPoP bool
	// PublicOrigin is this API's public origin (https://api.example.com), used
	// to build the DPoP htu when the request URL is a path. Set it behind a
	// proxy or load balancer; without it VerifyRequest uses the request's Host
	// and TLS state.
	PublicOrigin string
	// DPoPReplayStore records DPoP proof jtis; default an in-memory store
	// (one process). Share one store when the API runs on several.
	DPoPReplayStore DPoPReplayStore
	// DPoPNonces, when set, requires every DPoP proof to carry a nonce it
	// issued (RFC 9449 §9): a proof without a current one is refused with
	// use_dpop_nonce, and every result carries DPoPNonce for the DPoP-Nonce
	// response header.
	DPoPNonces DPoPNonceSource
	// Introspection validates opaque access tokens (and, with IntrospectJWTs,
	// JWTs too) at Atlas's RFC 7662 introspection endpoint, with a short cache.
	// The client must be a confidential client your API lists in its
	// introspection_client_ids (or the client the tokens are issued to).
	Introspection *IntrospectionOptions
	// Realm is the WWW-Authenticate realm (optional).
	Realm      string
	HTTPClient *http.Client
	Now        func() time.Time
}

// AccessTokenResult is the verdict. On success OK is true and Claims, Scopes,
// Subject, ClientID and DPoPBound are set. Otherwise Status (400, 401 or
// 403), Error, Description and WWWAuthenticate (set it as the response header
// verbatim) describe the refusal. DPoPNonce, when not empty, goes in the
// DPoP-Nonce response header (on success and refusal alike).
type AccessTokenResult struct {
	OK              bool
	Claims          map[string]interface{}
	Scopes          []string
	Subject         string
	ClientID        string
	DPoPBound       bool
	DPoPNonce       string
	Status          int
	Error           AccessTokenErrorCode
	Description     string
	WWWAuthenticate string
}

// AccessTokenVerifier verifies access tokens for one API. Build it once (it
// holds the JWKS cache) and call VerifyRequest per request.
type AccessTokenVerifier struct {
	opts   AccessTokenVerifierOptions
	issuer string
	jwks   *JWKSCache
	replay DPoPReplayStore
	// introspector is set when Introspection is configured.
	introspector *Introspector
}

// NewAccessTokenVerifier builds a verifier.
func NewAccessTokenVerifier(opts AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	if opts.Issuer == "" {
		return nil, errors.New("atlas: AccessTokenVerifier needs Issuer")
	}
	if len(opts.Audiences) == 0 && !opts.AllowAnyAudience {
		return nil, errors.New("atlas: AccessTokenVerifier needs Audiences (or AllowAnyAudience)")
	}
	issuer := strings.TrimRight(opts.Issuer, "/")
	u := opts.JWKSURL
	if u == "" {
		u = issuer + "/.well-known/jwks.json"
	}
	replay := opts.DPoPReplayStore
	if replay == nil {
		mem := NewMemoryDPoPReplayStore(0)
		if opts.Now != nil {
			mem.now = opts.Now
		}
		replay = mem
	}
	var introspector *Introspector
	if opts.Introspection != nil {
		var err error
		introspector, err = NewIntrospector(issuer, *opts.Introspection, opts.HTTPClient, opts.Now)
		if err != nil {
			return nil, err
		}
	}
	return &AccessTokenVerifier{
		opts:         opts,
		issuer:       issuer,
		jwks:         NewJWKSCache(JWKSCacheOptions{URL: u, HTTPClient: opts.HTTPClient, Now: opts.Now}),
		replay:       replay,
		introspector: introspector,
	}, nil
}

var bearerRE = regexp.MustCompile(`^(?i:(Bearer|DPoP))\s+([A-Za-z0-9\-._~+/]+=*)$`)

// ResourceRequest is what verification reads from an HTTP request.
type ResourceRequest struct {
	// Method is the HTTP method (GET when empty).
	Method string
	// URL is the absolute request URL, or a path resolved against
	// PublicOrigin, for the DPoP htu check.
	URL string
	// Authorization is the Authorization header value.
	Authorization string
	// DPoP is the DPoP header value (the proof), if any.
	DPoP string
}

// VerifyRequest verifies the request's Authorization header (Bearer or DPoP
// scheme) and DPoP proof, requiring the configured scopes plus extraScopes.
// It never returns an error for a bad token: the refusal is in the result.
func (v *AccessTokenVerifier) VerifyRequest(ctx context.Context, r *http.Request, extraScopes ...string) *AccessTokenResult {
	return v.VerifyResource(ctx, ResourceRequest{
		Method:        r.Method,
		URL:           v.requestURL(r),
		Authorization: r.Header.Get("Authorization"),
		DPoP:          dpopHeader(r.Header),
	}, extraScopes...)
}

// requestURL is the URL the DPoP htu must name: the path against
// PublicOrigin when it is set, otherwise rebuilt from Host and TLS.
func (v *AccessTokenVerifier) requestURL(r *http.Request) string {
	if r.URL != nil && r.URL.IsAbs() {
		return r.URL.String()
	}
	path := "/"
	if r.URL != nil {
		path = r.URL.RequestURI()
	}
	if v.opts.PublicOrigin != "" {
		return path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

// dpopHeader reads the single DPoP header; more than one is no proof at all.
func dpopHeader(h http.Header) string {
	vals := h.Values("DPoP")
	if len(vals) != 1 {
		return ""
	}
	return vals[0]
}

// Verify verifies an Authorization header value ("Bearer <token>") with no
// DPoP proof: a DPoP-bound token is refused. Use VerifyRequest or
// VerifyResource for DPoP.
func (v *AccessTokenVerifier) Verify(ctx context.Context, authorization string, extraScopes ...string) *AccessTokenResult {
	return v.VerifyResource(ctx, ResourceRequest{Method: "GET", Authorization: authorization}, extraScopes...)
}

// VerifyResource verifies a request described by req.
func (v *AccessTokenVerifier) VerifyResource(ctx context.Context, req ResourceRequest, extraScopes ...string) *AccessTokenResult {
	authorization := req.Authorization
	required := append(append([]string{}, v.opts.RequiredScopes...), extraScopes...)
	scheme := "Bearer"
	if v.opts.RequireDPoP {
		scheme = "DPoP"
	}
	nonce := ""
	if v.opts.DPoPNonces != nil {
		nonce = v.opts.DPoPNonces.Current()
	}
	failAs := func(challenge string, status int, code AccessTokenErrorCode, desc string) *AccessTokenResult {
		var scope []string
		if code == AccessTokenInsufficientScope || code == "" {
			scope = required
		}
		return &AccessTokenResult{
			Status:      status,
			Error:       code,
			Description: desc,
			DPoPNonce:   nonce,
			WWWAuthenticate: BuildWWWAuthenticate(WWWAuthenticateParams{
				Scheme: challenge, Realm: v.opts.Realm, Error: code, Description: desc, Scope: scope,
				ResourceMetadataURL: v.opts.ResourceMetadataURL,
			}),
		}
	}
	fail := func(status int, code AccessTokenErrorCode, desc string) *AccessTokenResult {
		return failAs(scheme, status, code, desc)
	}

	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return fail(401, "", "Authentication required.")
	}
	m := bearerRE.FindStringSubmatch(authorization)
	if m == nil {
		return fail(400, AccessTokenInvalidRequest, "Malformed Authorization header.")
	}
	presentedDPoP := strings.EqualFold(m[1], "DPoP")
	token := m[2]
	now := time.Now()
	if v.opts.Now != nil {
		now = v.opts.Now()
	}
	invalid := func() *AccessTokenResult {
		return fail(401, AccessTokenInvalidToken, "The access token is invalid or expired.")
	}
	isJWT := len(strings.Split(token, ".")) == 3
	var claims map[string]interface{}
	if !isJWT || (v.introspector != nil && v.opts.Introspection.IntrospectJWTs) {
		// An opaque token (or a JWT the caller wants checked live) is validated
		// by Atlas itself, at its introspection endpoint.
		if v.introspector == nil {
			return fail(401, AccessTokenInvalidToken, "The access token is not a JWT; configure Introspection to accept opaque tokens.")
		}
		active, err := v.introspector.Introspect(ctx, token)
		if err != nil {
			return fail(401, AccessTokenInvalidToken, "The access token could not be validated right now.")
		}
		if active == nil {
			return invalid()
		}
		if iss, ok := active["iss"]; ok {
			if s, _ := iss.(string); strings.TrimRight(s, "/") != v.issuer {
				return fail(401, AccessTokenInvalidToken, "The access token was issued by another authorization server.")
			}
		}
		if exp, ok := active["exp"].(float64); ok && exp+ClockSkewSeconds <= float64(now.Unix()) {
			return invalid()
		}
		claims = active
	} else {
		var refused bool
		claims, refused = v.verifyJWT(ctx, token, now)
		if refused {
			return invalid()
		}
		if claims == nil {
			return fail(401, AccessTokenInvalidToken, "No signing keys are available to verify the token.")
		}
	}
	if tu, ok := claims["token_use"]; ok {
		if s, _ := tu.(string); s != "access_token" {
			return fail(401, AccessTokenInvalidToken, "The token is not an access token.")
		}
	}
	if !v.opts.AllowAnyAudience {
		if !audienceMatches(claims["aud"], v.opts.Audiences) {
			return fail(401, AccessTokenInvalidToken, "The access token was not issued for this resource.")
		}
	}
	// Sender constraint (RFC 9449). A bound token is only ever a DPoP token.
	jkt := ""
	cnf, hasCnf := claims["cnf"].(map[string]interface{})
	if hasCnf {
		if raw, bound := cnf["jkt"]; bound {
			jkt, _ = raw.(string)
			if jkt == "" {
				return fail(401, AccessTokenInvalidToken, "The access token is invalid or expired.")
			}
		}
	}
	if jkt != "" || v.opts.RequireDPoP || presentedDPoP {
		if jkt == "" {
			return failAs("DPoP", 401, AccessTokenInvalidToken, "This resource requires a DPoP-bound access token.")
		}
		if !presentedDPoP {
			return failAs("DPoP", 401, AccessTokenInvalidToken, "A DPoP-bound access token must be sent with the DPoP scheme.")
		}
		if req.DPoP == "" {
			return failAs("DPoP", 401, AccessTokenInvalidDPoPProof, "A DPoP proof is required.")
		}
		method := strings.ToUpper(req.Method)
		if method == "" {
			method = "GET"
		}
		if refusal := checkDPoPProof(strings.TrimSpace(req.DPoP), dpopCheck{
			token: token, jkt: jkt, method: method, url: req.URL, publicOrigin: v.opts.PublicOrigin,
			now: now, replay: v.replay, nonces: v.opts.DPoPNonces,
		}); refusal != nil {
			return failAs("DPoP", 401, refusal.code, refusal.desc)
		}
	}

	scopeStr, _ := claims["scope"].(string)
	scopes := strings.Fields(scopeStr)
	granted := map[string]bool{}
	for _, s := range scopes {
		granted[s] = true
	}
	if perms, ok := claims["permissions"].([]interface{}); ok {
		for _, p := range perms {
			if s, ok := p.(string); ok {
				granted[s] = true
			}
		}
	}
	var missing []string
	for _, s := range required {
		if !granted[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return fail(403, AccessTokenInsufficientScope, "The access token is missing the required scope(s): "+strings.Join(missing, " ")+".")
	}
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		clientID, _ = claims["azp"].(string)
	}
	return &AccessTokenResult{OK: true, Status: 200, Claims: claims, Scopes: scopes, Subject: sub, ClientID: clientID,
		DPoPBound: jkt != "", DPoPNonce: nonce}
}

// verifyJWT checks a JWT access token's signature, issuer and lifetime. It
// returns (nil, false) when no signing key is available and (nil, true) for a
// token that is refused.
func (v *AccessTokenVerifier) verifyJWT(ctx context.Context, token string, now time.Time) (map[string]interface{}, bool) {
	parts := strings.Split(token, ".")
	set := v.jwks.get(ctx, readKID(token))
	if set == nil || len(set.Keys) == 0 {
		return nil, false
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, true
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || !contains(SigningAlgs, header.Alg) {
		return nil, true
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil || !verifyJWSSignature(set, header.Alg, header.Kid, parts[0]+"."+parts[1], sig) {
		return nil, true
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, true
	}
	var claims map[string]interface{}
	if json.Unmarshal(payloadRaw, &claims) != nil {
		return nil, true
	}
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, true
	}
	nowSec := float64(now.Unix())
	exp, hasExp := claims["exp"].(float64)
	if !hasExp || nowSec > exp+ClockSkewSeconds {
		return nil, true
	}
	if nbf, ok := claims["nbf"].(float64); ok && nowSec+ClockSkewSeconds < nbf {
		return nil, true
	}
	return claims, false
}

func audienceMatches(aud interface{}, want []string) bool {
	switch a := aud.(type) {
	case string:
		return contains(want, a)
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok && contains(want, s) {
				return true
			}
		}
	}
	return false
}

// WWWAuthenticateParams build a challenge with BuildWWWAuthenticate.
type WWWAuthenticateParams struct {
	// Scheme is "Bearer" (default) or "DPoP"; a DPoP challenge also lists
	// the accepted proof algorithms (algs).
	Scheme              string
	Realm               string
	Error               AccessTokenErrorCode
	Description         string
	Scope               []string
	ResourceMetadataURL string
}

// BuildWWWAuthenticate renders an RFC 6750 / RFC 9449 / RFC 9728 challenge.
// Without an Error it is the bare "authentication required" challenge (no
// token was sent), as RFC 6750 §3.1 asks.
func BuildWWWAuthenticate(p WWWAuthenticateParams) string {
	quote := func(v string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
	}
	var parts []string
	if p.Realm != "" {
		parts = append(parts, "realm="+quote(p.Realm))
	}
	if p.Error != "" {
		parts = append(parts, "error="+quote(string(p.Error)))
		if p.Description != "" {
			parts = append(parts, "error_description="+quote(p.Description))
		}
	}
	if len(p.Scope) > 0 {
		parts = append(parts, "scope="+quote(strings.Join(p.Scope, " ")))
	}
	if p.ResourceMetadataURL != "" {
		parts = append(parts, "resource_metadata="+quote(p.ResourceMetadataURL))
	}
	scheme := "Bearer"
	if p.Scheme == "DPoP" {
		scheme = "DPoP"
		parts = append(parts, "algs="+quote(strings.Join(DPoPAlgs, " ")))
	}
	if len(parts) == 0 {
		return scheme
	}
	return scheme + " " + strings.Join(parts, ", ")
}

// ProtectedResourceMetadata is the RFC 9728 document for your API. Serve it as
// JSON at ProtectedResourceMetadataPath(resource) and point
// ResourceMetadataURL at it.
func ProtectedResourceMetadata(resource, issuer string, scopesSupported []string) map[string]interface{} {
	doc := map[string]interface{}{
		"resource":                 resource,
		"authorization_servers":    []string{strings.TrimRight(issuer, "/")},
		"bearer_methods_supported": []string{"header"},
	}
	if len(scopesSupported) > 0 {
		doc["scopes_supported"] = scopesSupported
	}
	doc["dpop_signing_alg_values_supported"] = DPoPAlgs
	return doc
}

// ProtectedResourceMetadataRequiringDPoP is ProtectedResourceMetadata that
// also advertises dpop_bound_access_tokens_required (pair it with
// RequireDPoP).
func ProtectedResourceMetadataRequiringDPoP(resource, issuer string, scopesSupported []string) map[string]interface{} {
	doc := ProtectedResourceMetadata(resource, issuer, scopesSupported)
	doc["dpop_bound_access_tokens_required"] = true
	return doc
}

// ProtectedResourceMetadataPath is the RFC 9728 well-known path for a
// resource identifier (path-inserted form).
func ProtectedResourceMetadataPath(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(u.Path, "/")
	return "/.well-known/oauth-protected-resource" + path, nil
}
