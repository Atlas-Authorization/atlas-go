package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Transaction tokens (draft-ietf-oauth-transaction-tokens): a short-lived JWT a
// service passes to the services it calls, carrying who is acting and what for.
// VerifyTransactionToken checks one a service received: typ txntoken+jwt, signed
// by the issuer's keys, for THIS trust domain, unexpired, with the required claims.

// ErrTxnTokenInvalid is returned for a token that is malformed, badly signed,
// expired, for another trust domain, or missing a required claim.
var ErrTxnTokenInvalid = errors.New("atlas: the transaction token is invalid, expired, or for another trust domain")

// TxnTokenClaims are the claims of a verified transaction token.
type TxnTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Txn   string `json:"txn"`
	Scope string `json:"scope"`
	ReqWL string `json:"req_wl"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	// Aud is the trust domain the token was issued for (the one you verified against).
	Aud string `json:"aud"`
	// Tctx is the transaction context; Rctx the requester context.
	Tctx map[string]interface{} `json:"tctx,omitempty"`
	Rctx map[string]interface{} `json:"rctx,omitempty"`
	// Raw holds every claim, including ones not modelled above.
	Raw map[string]interface{} `json:"-"`
}

// TxnTokenResult is a verified transaction token.
type TxnTokenResult struct {
	Claims *TxnTokenClaims
	// Scopes is Claims.Scope split on spaces.
	Scopes []string
}

// TxnTokenOptions configures VerifyTransactionToken.
type TxnTokenOptions struct {
	// Issuer is the expected iss (trailing slashes ignored). Required.
	Issuer string
	// TrustDomain is the expected aud: your own trust domain. Required.
	TrustDomain string
	// JWKS is a cache to verify against (share one across calls). Without it,
	// JWKSJSON is used, else the issuer's /.well-known/jwks.json is fetched.
	JWKS *JWKSCache
	// JWKSJSON is a static JWK Set document.
	JWKSJSON []byte
	// JWKSURL overrides <issuer>/.well-known/jwks.json when fetching.
	JWKSURL string
	// HTTPClient fetches the JWKS (nil = http.DefaultClient).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now time.Time
}

// VerifyTransactionToken verifies token. It never panics on bad input; every
// failure is ErrTxnTokenInvalid except a missing required claim, which names the claim.
func VerifyTransactionToken(ctx context.Context, token string, opts TxnTokenOptions) (*TxnTokenResult, error) {
	issuer := strings.TrimRight(opts.Issuer, "/")
	if issuer == "" || opts.TrustDomain == "" {
		return nil, errors.New("atlas: VerifyTransactionToken needs Issuer and TrustDomain")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTxnTokenInvalid
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, ErrTxnTokenInvalid
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || !contains(SigningAlgs, header.Alg) || !strings.EqualFold(header.Typ, "txntoken+jwt") {
		return nil, ErrTxnTokenInvalid
	}
	sig, err := base64urlDecode(parts[2])
	if err != nil {
		return nil, ErrTxnTokenInvalid
	}

	var set *jwks
	switch {
	case opts.JWKS != nil:
		set = opts.JWKS.get(ctx, header.Kid)
	case len(opts.JWKSJSON) > 0:
		set = &jwks{}
		if json.Unmarshal(opts.JWKSJSON, set) != nil {
			return nil, ErrTxnTokenInvalid
		}
	default:
		url := opts.JWKSURL
		if url == "" {
			url = issuer + "/.well-known/jwks.json"
		}
		set = NewJWKSCache(JWKSCacheOptions{URL: url, HTTPClient: opts.HTTPClient}).get(ctx, header.Kid)
	}
	if set == nil || len(set.Keys) == 0 || !verifyJWSSignature(set, header.Alg, header.Kid, parts[0]+"."+parts[1], sig) {
		return nil, ErrTxnTokenInvalid
	}

	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, ErrTxnTokenInvalid
	}
	raw := map[string]interface{}{}
	if json.Unmarshal(payloadRaw, &raw) != nil {
		return nil, ErrTxnTokenInvalid
	}
	if iss, _ := raw["iss"].(string); strings.TrimRight(iss, "/") != issuer {
		return nil, ErrTxnTokenInvalid
	}
	if !txnAudienceMatches(raw["aud"], opts.TrustDomain) {
		return nil, ErrTxnTokenInvalid
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := now.Unix()
	if exp, ok := raw["exp"].(float64); !ok || nowSec > int64(exp)+ClockSkewSeconds {
		return nil, ErrTxnTokenInvalid
	}
	if nbf, ok := raw["nbf"].(float64); ok && nowSec+ClockSkewSeconds < int64(nbf) {
		return nil, ErrTxnTokenInvalid
	}
	for _, c := range []string{"txn", "sub", "scope", "req_wl", "iat", "exp"} {
		if raw[c] == nil {
			return nil, errors.New("atlas: the transaction token has no " + c)
		}
	}
	claims := &TxnTokenClaims{Raw: raw, Aud: opts.TrustDomain}
	claims.Iss, _ = raw["iss"].(string)
	claims.Sub, _ = raw["sub"].(string)
	claims.Txn, _ = raw["txn"].(string)
	claims.Scope, _ = raw["scope"].(string)
	claims.ReqWL, _ = raw["req_wl"].(string)
	if v, ok := raw["iat"].(float64); ok {
		claims.Iat = int64(v)
	}
	if v, ok := raw["exp"].(float64); ok {
		claims.Exp = int64(v)
	}
	claims.Tctx, _ = raw["tctx"].(map[string]interface{})
	claims.Rctx, _ = raw["rctx"].(map[string]interface{})
	return &TxnTokenResult{Claims: claims, Scopes: strings.Fields(claims.Scope)}, nil
}

// txnAudienceMatches reports whether aud (a string or an array of strings) names domain.
func txnAudienceMatches(aud interface{}, domain string) bool {
	switch v := aud.(type) {
	case string:
		return v == domain
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == domain {
				return true
			}
		}
	}
	return false
}
