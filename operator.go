package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Operator sign-in (`atlas login`) and token exchange, without a long-lived
// key, for CLIs written in Go.
//
//  1. StartOperatorLogin runs the RFC 8628 device flow against Atlas's own
//     sign-in with the public atlas-cli client: show the person
//     VerificationURIComplete / UserCode, then
//  2. PollOperatorLogin until it returns the operator access token, then
//  3. ExchangeOperatorToken swaps it (RFC 8693) for a ONE-HOUR Atlas token
//     bound to one instance (ins_…, Backend API) or app/account (app_… /
//     acct_…, Platform API), with only the scopes you ask for.
//
// Root actions (create an app or instance, mint a key) need a multi-factor
// sign-in within 5 minutes; otherwise the API answers 403 STEP_UP_REQUIRED.

// OperatorOptions tunes the operator helpers. The zero value (or nil) uses
// DefaultBaseURL and http.DefaultClient.
type OperatorOptions struct {
	// APIURL is the Atlas API origin (default DefaultBaseURL).
	APIURL     string
	HTTPClient *http.Client
	// Sleep replaces the wait between polls (tests).
	Sleep func(ctx context.Context, d time.Duration) error
	// Now replaces time.Now (tests).
	Now func() time.Time
}

func (o *OperatorOptions) apiURL() string {
	if o != nil && o.APIURL != "" {
		return strings.TrimRight(o.APIURL, "/")
	}
	return DefaultBaseURL
}

func (o *OperatorOptions) httpClient() *http.Client {
	if o != nil && o.HTTPClient != nil {
		return o.HTTPClient
	}
	return http.DefaultClient
}

func (o *OperatorOptions) now() time.Time {
	if o != nil && o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OperatorOptions) sleep(ctx context.Context, d time.Duration) error {
	if o != nil && o.Sleep != nil {
		return o.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// OperatorConfiguration is GET /v1/operator: where the device flow and token
// exchange live.
type OperatorConfiguration struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	ClientID                    string `json:"client_id"`
	Scope                       string `json:"scope"`
	TokenExchangeEndpoint       string `json:"token_exchange_endpoint"`
	TokenExchangeAudience       string `json:"token_exchange_audience"`
	RootActionMaxMFAAgeSeconds  int    `json:"root_action_max_mfa_age_seconds"`
}

// OperatorDeviceAuthorization is the RFC 8628 device authorization response.
type OperatorDeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	// Config is the operator configuration the flow runs against.
	Config OperatorConfiguration `json:"-"`
}

// OAuthTokenResponse is a token endpoint answer.
type OAuthTokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// Resource is the resource a token exchange bound the token to.
	Resource string `json:"resource,omitempty"`
}

// OAuthFlowError is a failed device-flow, token-exchange or token request.
// Err is the OAuth error code (access_denied, expired_token, invalid_grant,
// STEP_UP_REQUIRED, …).
type OAuthFlowError struct {
	Err         string
	Description string
	Status      int
}

// Error implements error.
func (e *OAuthFlowError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("atlas: %s: %s (HTTP %d)", e.Err, e.Description, e.Status)
	}
	return fmt.Sprintf("atlas: %s (HTTP %d)", e.Err, e.Status)
}

func (o *OperatorOptions) postForm(ctx context.Context, endpoint string, form url.Values) (map[string]interface{}, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("atlas: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("atlas: performing request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("atlas: reading response body: %w", err)
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode, nil
}

// flowError builds an OAuthFlowError from a token-endpoint answer, accepting
// both the OAuth shape and the Atlas error envelope.
func flowError(body map[string]interface{}, status int, fallback string) *OAuthFlowError {
	code, _ := body["error"].(string)
	desc, _ := body["error_description"].(string)
	if code == "" {
		if errs, ok := body["errors"].([]interface{}); ok && len(errs) > 0 {
			if first, ok := errs[0].(map[string]interface{}); ok {
				code, _ = first["code"].(string)
				if desc == "" {
					desc, _ = first["message"].(string)
				}
			}
		}
	}
	if code == "" {
		code = "error"
	}
	if desc == "" {
		desc = fallback
	}
	return &OAuthFlowError{Err: code, Description: desc, Status: status}
}

func decodeInto(body map[string]interface{}, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// GetOperatorConfiguration reads GET /v1/operator (no key needed).
func GetOperatorConfiguration(ctx context.Context, opts *OperatorOptions) (*OperatorConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.apiURL()+"/v1/operator", nil)
	if err != nil {
		return nil, fmt.Errorf("atlas: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := opts.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("atlas: performing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &OAuthFlowError{Err: "not_configured", Description: "The operator issuer is not configured on this deployment.", Status: resp.StatusCode}
	}
	out := &OperatorConfiguration{}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return out, nil
}

// StartOperatorLogin begins the device flow. config may be nil to read it
// from GET /v1/operator.
func StartOperatorLogin(ctx context.Context, config *OperatorConfiguration, opts *OperatorOptions) (*OperatorDeviceAuthorization, error) {
	if config == nil {
		c, err := GetOperatorConfiguration(ctx, opts)
		if err != nil {
			return nil, err
		}
		config = c
	}
	body, status, err := opts.postForm(ctx, config.DeviceAuthorizationEndpoint, url.Values{"client_id": {config.ClientID}, "scope": {config.Scope}})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, flowError(body, status, "Device authorization failed.")
	}
	out := &OperatorDeviceAuthorization{}
	if err := decodeInto(body, out); err != nil {
		return nil, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	out.Config = *config
	return out, nil
}

// PollOperatorLogin polls until the person approves (returning the operator
// token), denies or the code expires (an *OAuthFlowError). It honours the
// interval and slow_down, and the context.
func PollOperatorLogin(ctx context.Context, start *OperatorDeviceAuthorization, opts *OperatorOptions) (*OAuthTokenResponse, error) {
	interval := start.Interval
	if interval < 1 {
		interval = 1
	}
	wait := time.Duration(interval) * time.Second
	deadline := opts.now().Add(time.Duration(start.ExpiresIn) * time.Second)
	for opts.now().Before(deadline) {
		if err := opts.sleep(ctx, wait); err != nil {
			return nil, err
		}
		body, status, err := opts.postForm(ctx, start.Config.TokenEndpoint, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {start.DeviceCode},
			"client_id":   {start.Config.ClientID},
		})
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			out := &OAuthTokenResponse{}
			if err := decodeInto(body, out); err != nil {
				return nil, fmt.Errorf("atlas: decoding response body: %w", err)
			}
			return out, nil
		}
		code, _ := body["error"].(string)
		switch code {
		case "authorization_pending":
			continue
		case "slow_down":
			wait += 5 * time.Second
			continue
		}
		return nil, flowError(body, status, "Sign-in failed.")
	}
	return nil, &OAuthFlowError{Err: "expired_token", Description: "The sign-in code expired. Run the login again.", Status: http.StatusBadRequest}
}

// ExchangeOperatorToken swaps an operator token (RFC 8693) for a one-hour,
// resource-bound Atlas token. resource is an ins_… / app_… / acct_… id;
// scopes are the scopes to keep.
func ExchangeOperatorToken(ctx context.Context, subjectToken, resource string, scopes []string, opts *OperatorOptions) (*OAuthTokenResponse, error) {
	body, status, err := opts.postForm(ctx, opts.apiURL()+"/v1/oauth/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {"atlas"},
		"resource":           {resource},
		"scope":              {strings.Join(scopes, " ")},
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, flowError(body, status, "Token exchange failed.")
	}
	out := &OAuthTokenResponse{}
	if err := decodeInto(body, out); err != nil {
		return nil, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return out, nil
}

// PartnerLinkToken runs client_credentials with a partner link's credentials
// (a partner service calling an instance). scope may be empty.
func PartnerLinkToken(ctx context.Context, clientID, clientSecret, scope string, opts *OperatorOptions) (*OAuthTokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {clientSecret}}
	if scope != "" {
		form.Set("scope", scope)
	}
	body, status, err := opts.postForm(ctx, opts.apiURL()+"/v1/oauth/token", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, flowError(body, status, "Token request failed.")
	}
	out := &OAuthTokenResponse{}
	if err := decodeInto(body, out); err != nil {
		return nil, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return out, nil
}

// LeakedKeyResult is one outcome of RevokeLeakedKeys.
type LeakedKeyResult struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
	// Outcome is revoked, already_revoked or not_found.
	Outcome string `json:"outcome"`
}

// RevokeLeakedKeys revokes leaked Atlas credentials (POST
// /v1/keys/revoke_leaked, no key needed). sourceURL optionally says where the
// secret was found.
func RevokeLeakedKeys(ctx context.Context, secrets []string, sourceURL string, opts *OperatorOptions) ([]LeakedKeyResult, error) {
	payload := map[string]interface{}{"secrets": secrets}
	if sourceURL != "" {
		payload["url"] = sourceURL
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.apiURL()+"/v1/keys/revoke_leaked", strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("atlas: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := opts.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("atlas: performing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &OAuthFlowError{Err: "request_failed", Description: fmt.Sprintf("revoke_leaked failed (%d).", resp.StatusCode), Status: resp.StatusCode}
	}
	var out struct {
		Results []LeakedKeyResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("atlas: decoding response body: %w", err)
	}
	return out.Results, nil
}

// ErrAccessTokenMissing is returned by NewClientFromAccessToken for an empty token.
var ErrAccessTokenMissing = errors.New("atlas: empty access token")

// NewClientFromAccessToken builds a Client signed with a one-hour Atlas access
// token from ExchangeOperatorToken. An ins_… token drives the Backend API
// (Client.Users, …); an app_… / acct_… token drives Client.Platform.
func NewClientFromAccessToken(token string, opts ...Option) (*Client, error) {
	if token == "" {
		return nil, ErrAccessTokenMissing
	}
	return New(token, append([]Option{WithPlatformKey(token)}, opts...)...), nil
}
