package atlas

import "context"

// CookieConsent is the cookie-consent banner (CMP) injected into the hosted
// sign-in, sign-up and account pages. Enabled is false when none is set.
type CookieConsent struct {
	Object  string `json:"object"`
	Enabled bool   `json:"enabled"`
	// ScriptURL is the CMP script URL (https).
	ScriptURL string `json:"script_url,omitempty"`
	// ScriptID is the <script id> some CMPs need.
	ScriptID *string `json:"script_id,omitempty"`
	// SiteID is the CMP site id (sent as data-cbid).
	SiteID *string `json:"site_id,omitempty"`
	// BlockingMode is the CMP prior-blocking mode (sent as data-blockingmode).
	BlockingMode *string `json:"blocking_mode,omitempty"`
	// ExtraOrigins are other https URLs the CMP loads from or calls.
	ExtraOrigins []string `json:"extra_origins,omitempty"`
}

// SetCookieConsentParams is the body of PUT /v1/instance/cookie_consent. It
// replaces the whole setting. ScriptURL and every ExtraOrigins entry must be
// https; only their exact origins are added to the page CSP.
type SetCookieConsentParams struct {
	ScriptURL    string   `json:"script_url"`
	ScriptID     string   `json:"script_id,omitempty"`
	SiteID       string   `json:"site_id,omitempty"`
	BlockingMode string   `json:"blocking_mode,omitempty"`
	ExtraOrigins []string `json:"extra_origins,omitempty"`
}

// CookieConsent reads the hosted pages' cookie-consent setting.
// GET /v1/instance/cookie_consent.
func (s *InstanceService) CookieConsent(ctx context.Context) (*CookieConsent, error) {
	out := &CookieConsent{}
	return out, s.client.get(ctx, "/v1/instance/cookie_consent", nil, out)
}

// SetCookieConsent sets the cookie-consent CMP for the hosted pages (any
// provider). PUT /v1/instance/cookie_consent.
func (s *InstanceService) SetCookieConsent(ctx context.Context, params SetCookieConsentParams, opts ...RequestOption) (*CookieConsent, error) {
	out := &CookieConsent{}
	return out, s.client.put(ctx, "/v1/instance/cookie_consent", params, out, opts...)
}

// DeleteCookieConsent turns the cookie-consent CMP off.
// DELETE /v1/instance/cookie_consent.
func (s *InstanceService) DeleteCookieConsent(ctx context.Context, opts ...RequestOption) (*CookieConsent, error) {
	out := &CookieConsent{}
	return out, s.client.del(ctx, "/v1/instance/cookie_consent", out, opts...)
}
