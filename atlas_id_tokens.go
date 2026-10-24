package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AtlasIDIntegrationToken is an integration token for a Sign in with Atlas
// user.
type AtlasIDIntegrationToken struct {
	JWT         string `json:"jwt"`
	ExpiresIn   int    `json:"expires_in"`
	Integration string `json:"integration"`
	Audience    string `json:"audience"`
	// Issuer is the Sign in with Atlas issuer: the token's iss.
	Issuer string `json:"issuer"`
	// JWKSURI is where the receiving service fetches the keys to verify it.
	JWKSURI string `json:"jwks_uri"`
}

// AtlasIDTokensOptions tunes AtlasIDIntegrationTokenFor.
type AtlasIDTokensOptions struct {
	// DPoPProof is a DPoP proof (RFC 9449) for this exact request (htm POST,
	// htu the URL without the query, ath the access token's hash). Required
	// when the access token is DPoP-bound; the token is then sent as "DPoP".
	DPoPProof string
	// Origin is sent as the Origin header. Atlas checks it against the Sign in
	// with Atlas app's web origins, so set it when calling server-side.
	Origin string
	// HTTPClient overrides the default client (10 s timeout).
	HTTPClient *http.Client
}

// AtlasIDIntegrationTokenFor is the browser route for integration tokens of
// Sign in with Atlas users: POST /v1/client/integrations/:id/atlas_id_tokens.
// An app with no server of its own gets a token for a service from a user's
// Sign in with Atlas access token. It is normally called from browser code;
// this is the same call for a backend-for-frontend. No cookies are sent.
//
// It returns nil, nil when the integration is not enabled for Sign in with
// Atlas users, the token is not accepted or the origin is not the app's.
func AtlasIDIntegrationTokenFor(ctx context.Context, frontendAPI, publishableKey, integration, accessToken string, opts *AtlasIDTokensOptions) (*AtlasIDIntegrationToken, error) {
	if accessToken == "" {
		return nil, nil
	}
	client := (*http.Client)(nil)
	if opts != nil {
		client = opts.HTTPClient
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// The publishable key also rides in the query, so a CORS preflight (which
	// carries no custom headers) can name the instance.
	target := strings.TrimRight(frontendAPI, "/") + "/v1/client/integrations/" + url.PathEscape(integration) +
		"/atlas_id_tokens?publishable_key=" + url.QueryEscape(publishableKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if opts != nil && opts.DPoPProof != "" {
		req.Header.Set("Authorization", "DPoP "+accessToken)
		req.Header.Set("DPoP", opts.DPoPProof)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if opts != nil && opts.Origin != "" {
		req.Header.Set("Origin", opts.Origin)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, nil
	}
	out := &AtlasIDIntegrationToken{}
	if err := json.Unmarshal(raw, out); err != nil || out.JWT == "" {
		return nil, nil
	}
	return out, nil
}
