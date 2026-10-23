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
// DPoP-bound tokens (cnf.jkt) are refused: this verifier checks Bearer tokens
// only. Use the TypeScript @atlasauth/backend verifier for DPoP.

// AccessTokenErrorCode is the RFC 6750 error of a refusal ("" when no token
// was sent at all).
type AccessTokenErrorCode string

const (
	AccessTokenInvalidRequest    AccessTokenErrorCode = "invalid_request"
	AccessTokenInvalidToken      AccessTokenErrorCode = "invalid_token"
	AccessTokenInsufficientScope AccessTokenErrorCode = "insufficient_scope"
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
	// Realm is the WWW-Authenticate realm (optional).
	Realm      string
	HTTPClient *http.Client
	Now        func() time.Time
}

// AccessTokenResult is the verdict. On success OK is true and Claims, Scopes,
// Subject and ClientID are set. Otherwise Status (400, 401 or 403), Error,
// Description and WWWAuthenticate (set it as the response header verbatim)
// describe the refusal.
type AccessTokenResult struct {
	OK              bool
	Claims          map[string]interface{}
	Scopes          []string
	Subject         string
	ClientID        string
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
	return &AccessTokenVerifier{
		opts:   opts,
		issuer: issuer,
		jwks:   NewJWKSCache(JWKSCacheOptions{URL: u, HTTPClient: opts.HTTPClient, Now: opts.Now}),
	}, nil
}

var bearerRE = regexp.MustCompile(`^(?i:(Bearer|DPoP))\s+([A-Za-z0-9\-._~+/]+=*)$`)

// VerifyRequest verifies the request's Authorization: Bearer token, requiring
// the configured scopes plus extraScopes. It never returns an error for a bad
// token: the refusal is in the result.
func (v *AccessTokenVerifier) VerifyRequest(ctx context.Context, r *http.Request, extraScopes ...string) *AccessTokenResult {
	return v.Verify(ctx, r.Header.Get("Authorization"), extraScopes...)
}

// Verify verifies an Authorization header value ("Bearer <token>").
func (v *AccessTokenVerifier) Verify(ctx context.Context, authorization string, extraScopes ...string) *AccessTokenResult {
	required := append(append([]string{}, v.opts.RequiredScopes...), extraScopes...)
	fail := func(status int, code AccessTokenErrorCode, desc string) *AccessTokenResult {
		var scope []string
		if code == AccessTokenInsufficientScope || code == "" {
			scope = required
		}
		return &AccessTokenResult{
			Status:      status,
			Error:       code,
			Description: desc,
			WWWAuthenticate: BuildWWWAuthenticate(WWWAuthenticateParams{
				Realm: v.opts.Realm, Error: code, Description: desc, Scope: scope,
				ResourceMetadataURL: v.opts.ResourceMetadataURL,
			}),
		}
	}

	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return fail(401, "", "Authentication required.")
	}
	m := bearerRE.FindStringSubmatch(authorization)
	if m == nil {
		return fail(400, AccessTokenInvalidRequest, "Malformed Authorization header.")
	}
	if strings.EqualFold(m[1], "DPoP") {
		return fail(401, AccessTokenInvalidToken, "DPoP-bound access tokens are not accepted here.")
	}
	token := m[2]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fail(401, AccessTokenInvalidToken, "The access token is malformed.")
	}
	set := v.jwks.get(ctx, readKID(token))
	if set == nil || len(set.Keys) == 0 {
		return fail(401, AccessTokenInvalidToken, "No signing keys are available to verify the token.")
	}
	invalid := func() *AccessTokenResult {
		return fail(401, AccessTokenInvalidToken, "The access token is invalid or expired.")
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return invalid()
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || !contains(SigningAlgs, header.Alg) {
		return invalid()
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil || !verifyJWSSignature(set, header.Alg, header.Kid, parts[0]+"."+parts[1], sig) {
		return invalid()
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return invalid()
	}
	var claims map[string]interface{}
	if json.Unmarshal(payloadRaw, &claims) != nil {
		return invalid()
	}
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return invalid()
	}
	now := time.Now()
	if v.opts.Now != nil {
		now = v.opts.Now()
	}
	nowSec := float64(now.Unix())
	exp, hasExp := claims["exp"].(float64)
	if !hasExp || nowSec > exp+ClockSkewSeconds {
		return invalid()
	}
	if nbf, ok := claims["nbf"].(float64); ok && nowSec+ClockSkewSeconds < nbf {
		return invalid()
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
	if cnf, ok := claims["cnf"].(map[string]interface{}); ok {
		if _, bound := cnf["jkt"]; bound {
			return fail(401, AccessTokenInvalidToken, "DPoP-bound access tokens are not accepted here.")
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
	return &AccessTokenResult{OK: true, Status: 200, Claims: claims, Scopes: scopes, Subject: sub, ClientID: clientID}
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
	Realm               string
	Error               AccessTokenErrorCode
	Description         string
	Scope               []string
	ResourceMetadataURL string
}

// BuildWWWAuthenticate renders an RFC 6750 / RFC 9728 Bearer challenge.
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
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
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
