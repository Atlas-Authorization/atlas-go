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
	// SettingsLink is the "cookie settings" link rendered on the hosted pages;
	// nil when none is set.
	SettingsLink *CookieSettingsLink `json:"settings_link,omitempty"`
	// Culture is page (the CMP tag carries the page language) or browser.
	Culture string `json:"culture,omitempty"`
	// DeclaredCookies is every cookie and browser-storage key Atlas writes for
	// this instance, for your cookie policy (all strictly necessary).
	DeclaredCookies []DeclaredCookie `json:"declared_cookies,omitempty"`
}

// DeclaredCookie is one cookie or browser-storage key Atlas writes.
type DeclaredCookie struct {
	// Name is the exact name, or nil when Pattern describes a family of keys.
	Name *string `json:"name"`
	// Pattern is a * wildcard for keys with an id suffix, e.g. atlasid:*.
	Pattern *string `json:"pattern"`
	// Store is cookie, localStorage, sessionStorage or indexedDB.
	Store  string `json:"store"`
	Domain string `json:"domain"`
	// LifetimeSeconds is nil for a browser session (cookie) or until cleared.
	LifetimeSeconds *int64 `json:"lifetime_seconds"`
	Lifetime        string `json:"lifetime"`
	HTTPOnly        bool   `json:"http_only"`
	Category        string `json:"category"`
	Purpose         string `json:"purpose"`
	WrittenWhen     string `json:"written_when"`
	// SetBy is atlas_frontend_api or atlas_sdk.
	SetBy string `json:"set_by"`
	// Purposes is Purpose per locale (locale -> text), when translated.
	Purposes map[string]string `json:"purposes,omitempty"`
	// LifetimeRange is, for a cookie whose lifetime follows a setting, the
	// setting and its bounds.
	LifetimeRange *DeclaredCookieLifetimeRange `json:"lifetime_range,omitempty"`
}

// DeclaredCookieLifetimeRange is the configurable lifetime of a declared cookie.
type DeclaredCookieLifetimeRange struct {
	// Setting is the instance setting that decides the lifetime.
	Setting        string `json:"setting"`
	MinSeconds     int64  `json:"min_seconds"`
	MaxSeconds     int64  `json:"max_seconds"`
	DefaultSeconds int64  `json:"default_seconds"`
}

// Cookie settings link presets: the CMP whose preferences dialog the link
// opens. CookieSettingsLink.Preset is a plain string so a preset added later
// still decodes.
const (
	CookieSettingsLinkPresetCookiemunch = "cookiemunch"
	CookieSettingsLinkPresetCookiebot   = "cookiebot"
	CookieSettingsLinkPresetOneTrust    = "onetrust"
	CookieSettingsLinkPresetCustom      = "custom"
)

// CookieSettingsLink is the "cookie settings" link as the API returns it.
type CookieSettingsLink struct {
	Label string `json:"label"`
	// Preset is one of the CookieSettingsLinkPreset* values, or nil.
	Preset *string `json:"preset"`
	// Attributes are the attributes you set on the link.
	Attributes map[string]string `json:"attributes"`
	// RenderedAttributes are the attributes the rendered link carries: yours
	// plus the preset's trigger.
	RenderedAttributes map[string]string `json:"rendered_attributes"`
}

// CookieSettingsLinkInput is the "cookie settings" link to render on the
// hosted pages. It needs a Preset or at least one attribute (400 otherwise).
type CookieSettingsLinkInput struct {
	// Label is the link text (required, 1-60 characters).
	Label string `json:"label"`
	// Preset is one of the CookieSettingsLinkPreset* values; empty for none.
	Preset string `json:"preset,omitempty"`
	// Attributes are extra link attributes: data-*, aria-*, id, class and
	// href (https or a #fragment). At most 10; each value at most 200
	// characters.
	Attributes map[string]string `json:"attributes,omitempty"`
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
	// SettingsLink renders a "cookie settings" link on the hosted pages; nil
	// for no link.
	SettingsLink *CookieSettingsLinkInput `json:"settings_link,omitempty"`
	// Culture is page (default: the CMP tag carries the page language) or
	// browser (no attribute; the CMP picks its own language).
	Culture string `json:"culture,omitempty"`
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
