package atlas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device sign-in approval (OAuth 2.0 Device Authorization Grant, RFC 8628)
// from your own app: the signed-in user types — or scans — the code a TV,
// console or CLI shows, and your app approves it instead of sending them to
// Atlas's hosted /oauth2/device page.
//
// These calls run on the Frontend API as the signed-in USER: they need the
// user's session token (a native app's session JWT), never a secret key, PAT
// or OAuth token. Use them from a backend-for-frontend that holds the user's
// session token.
//
//	d := atlas.NewDeviceAuthorizations("https://clerk.example.com", sessionToken, nil)
//	auth, err := d.Lookup(ctx, typedCode)
//	// show auth.Client.Name and auth.Scopes, then
//	_, err = d.Approve(ctx, auth) // or d.Deny(ctx, auth)
//
// When the application requires a recent re-authentication to approve a
// device, a stale session gets a *DeviceAuthorizationError whose
// NeedsReverification() is true.

// DeviceAuthorizationScope is one requested scope with a human description.
type DeviceAuthorizationScope struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// DeviceAuthorization is a pending device sign-in. UserCode is the code as
// the device shows it (XXXX-XXXX); Status is pending, approved or denied.
type DeviceAuthorization struct {
	Object   string `json:"object"`
	ID       string `json:"id"`
	UserCode string `json:"user_code"`
	Status   string `json:"status"`
	Client   struct {
		ClientID    string  `json:"client_id"`
		Name        string  `json:"name"`
		LogoURL     *string `json:"logo_url"`
		HomepageURL *string `json:"homepage_url"`
		FirstParty  bool    `json:"first_party"`
	} `json:"client"`
	Scopes []DeviceAuthorizationScope `json:"scopes"`
	// Audience is the API the device asked a token for, if any.
	Audience *string `json:"audience"`
	// RequiresStepUp: approving needs a recent re-authentication.
	RequiresStepUp bool  `json:"requires_step_up"`
	CreatedAt      int64 `json:"created_at"`
	ExpiresAt      int64 `json:"expires_at"`
}

// DeviceAuthorizationError is a refused request. Code is the server's stable
// error code (NOT_FOUND, RATE_LIMITED, STEP_UP_REQUIRED, …).
type DeviceAuthorizationError struct {
	Status  int
	Code    string
	Message string
	Param   string
	Reason  string
}

func (e *DeviceAuthorizationError) Error() string {
	return fmt.Sprintf("atlas: device authorization %d %s: %s", e.Status, e.Code, e.Message)
}

// NeedsReverification is true when approving needs a fresh re-authentication.
func (e *DeviceAuthorizationError) NeedsReverification() bool { return e.Code == "STEP_UP_REQUIRED" }

// IsInvalidCode is true when the code is unknown, expired or already used.
func (e *DeviceAuthorizationError) IsInvalidCode() bool { return e.Status == 404 || e.Status == 409 }

// DeviceAuthorizations calls the Frontend API's device-approval routes with a
// user's session token.
type DeviceAuthorizations struct {
	frontendAPI    string
	sessionToken   string
	publishableKey string
	httpClient     *http.Client
}

// DeviceAuthorizationsOptions: PublishableKey is sent as x-publishable-key
// when set; HTTPClient defaults to a 10 s client.
type DeviceAuthorizationsOptions struct {
	PublishableKey string
	HTTPClient     *http.Client
}

// NewDeviceAuthorizations builds the helper for one user's session.
// frontendAPI is the instance's Frontend API origin (https://…).
func NewDeviceAuthorizations(frontendAPI, sessionToken string, opts *DeviceAuthorizationsOptions) *DeviceAuthorizations {
	d := &DeviceAuthorizations{frontendAPI: strings.TrimRight(frontendAPI, "/"), sessionToken: sessionToken}
	if opts != nil {
		d.publishableKey = opts.PublishableKey
		d.httpClient = opts.HTTPClient
	}
	if d.httpClient == nil {
		d.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return d
}

const deviceAuthorizationsBase = "/v1/client/me/device_authorizations"

// FormatUserCode normalises what a person typed into the XXXX-XXXX form
// devices show: uppercase, spaces and dashes ignored. It returns the trimmed
// input unchanged when it is not 8 letters or digits, so the server answers
// "not valid".
func FormatUserCode(input string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(input) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	c := b.String()
	if len(c) == 8 {
		return c[:4] + "-" + c[4:]
	}
	return strings.TrimSpace(input)
}

// UserCodeFromURL reads a user_code from a verification URL the device
// displayed (?user_code=), formatted; "" when there is none.
func UserCodeFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return ""
	}
	v := u.Query().Get("user_code")
	if v == "" {
		return ""
	}
	return FormatUserCode(v)
}

func (d *DeviceAuthorizations) call(ctx context.Context, path string, body map[string]string) (*DeviceAuthorization, error) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.frontendAPI+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.sessionToken)
	if d.publishableKey != "" {
		req.Header.Set("x-publishable-key", d.publishableKey)
	}
	res, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var raw json.RawMessage
	_ = json.NewDecoder(res.Body).Decode(&raw)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var env struct {
			Errors []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Param   string `json:"param"`
				Reason  string `json:"reason"`
			} `json:"errors"`
		}
		_ = json.Unmarshal(raw, &env)
		e := &DeviceAuthorizationError{Status: res.StatusCode, Code: "UNKNOWN", Message: "The request failed."}
		if len(env.Errors) > 0 {
			first := env.Errors[0]
			if first.Code != "" {
				e.Code = first.Code
			}
			if first.Message != "" {
				e.Message = first.Message
			}
			e.Param, e.Reason = first.Param, first.Reason
		}
		return nil, e
	}
	out := &DeviceAuthorization{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Lookup finds a pending device sign-in by the code the device shows.
// POST /v1/client/me/device_authorizations/lookup.
func (d *DeviceAuthorizations) Lookup(ctx context.Context, userCode string) (*DeviceAuthorization, error) {
	return d.call(ctx, deviceAuthorizationsBase+"/lookup", map[string]string{"user_code": FormatUserCode(userCode)})
}

// Approve approves the device sign-in for the signed-in user; the device's
// next poll receives its tokens. POST /v1/client/me/device_authorizations/:id/approve.
func (d *DeviceAuthorizations) Approve(ctx context.Context, auth *DeviceAuthorization) (*DeviceAuthorization, error) {
	return d.call(ctx, deviceAuthorizationsBase+"/"+url.PathEscape(auth.ID)+"/approve", map[string]string{"user_code": auth.UserCode})
}

// Deny denies the device sign-in; the device's next poll is told
// access_denied. POST /v1/client/me/device_authorizations/:id/deny.
func (d *DeviceAuthorizations) Deny(ctx context.Context, auth *DeviceAuthorization) (*DeviceAuthorization, error) {
	return d.call(ctx, deviceAuthorizationsBase+"/"+url.PathEscape(auth.ID)+"/deny", map[string]string{"user_code": auth.UserCode})
}
