package atlas

import "context"

// BrandingService is the /v1/branding namespace — the hosted-page / email
// appearance bag. Every field is optional and customer-authored; the render
// paths only ever use the sanitized Resolved shape.
type BrandingService struct{ client *Client }

// HostedBackground is the hosted-page background config.
type HostedBackground struct {
	Type     string `json:"type"`
	Color    string `json:"color,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Angle    *int   `json:"angle,omitempty"`
	ImageURL string `json:"imageUrl,omitempty"`
}

// Branding is the appearance bag. The flat colour/logo fields feed both email and
// the hosted page; the deeper composite fields shape the hosted page only and are
// carried as free-form maps to mirror the fully-optional wire shape.
type Branding struct {
	ApplicationName string `json:"applicationName,omitempty"`
	LogoURL         string `json:"logoUrl,omitempty"`
	ColorPrimary    string `json:"colorPrimary,omitempty"`
	ColorBackground string `json:"colorBackground,omitempty"`
	ColorText       string `json:"colorText,omitempty"`
	SupportEmail    string `json:"supportEmail,omitempty"`

	ColorAccent  string `json:"colorAccent,omitempty"`
	ColorCard    string `json:"colorCard,omitempty"`
	ColorBorder  string `json:"colorBorder,omitempty"`
	BorderRadius string `json:"borderRadius,omitempty"`
	Theme        string `json:"theme,omitempty"`
	FontFamily   string `json:"fontFamily,omitempty"`
	FontURL      string `json:"fontUrl,omitempty"`
	Layout       string `json:"layout,omitempty"`

	Background        *HostedBackground        `json:"background,omitempty"`
	Providers         map[string]interface{}   `json:"providers,omitempty"`
	Copy              map[string]interface{}   `json:"copy,omitempty"`
	SocialButtons     map[string]interface{}   `json:"socialButtons,omitempty"`
	CodeInput         string                   `json:"codeInput,omitempty"`
	Card              map[string]interface{}   `json:"card,omitempty"`
	Typography        map[string]interface{}   `json:"typography,omitempty"`
	ButtonShape       string                   `json:"buttonShape,omitempty"`
	CardBorder        string                   `json:"cardBorder,omitempty"`
	InputSize         string                   `json:"inputSize,omitempty"`
	Interaction       map[string]interface{}   `json:"interaction,omitempty"`
	BackgroundPattern string                   `json:"backgroundPattern,omitempty"`
	CardStyle         string                   `json:"cardStyle,omitempty"`
	TextScale         string                   `json:"textScale,omitempty"`
	SocialPlacement   string                   `json:"socialPlacement,omitempty"`
	SectionOrder      []string                 `json:"sectionOrder,omitempty"`
	Legal             map[string]interface{}   `json:"legal,omitempty"`
	SignUpFields      []map[string]interface{} `json:"signUpFields,omitempty"`
	// Audiences is per-audience hosted-page branding keyed by audience hint
	// ([a-z0-9_-]{1,32}, at most 20). A sign-in started with
	// audience_hint=<hint> uses that entry. An update merges per hint; a nil
	// entry deletes that hint.
	Audiences        map[string]*BrandingAudience `json:"audiences,omitempty"`
	CustomCSS        string                       `json:"customCss,omitempty"`
	CustomHTMLHeader string                       `json:"customHtmlHeader,omitempty"`
	CustomHTMLFooter string                       `json:"customHtmlFooter,omitempty"`
}

// ResolvedBranding is what the renderers actually use — everything already
// escaped or dropped.
type ResolvedBranding struct {
	ApplicationName string  `json:"applicationName"`
	EscapedName     string  `json:"escapedName"`
	LogoURL         *string `json:"logoUrl"`
	ColorPrimary    string  `json:"colorPrimary"`
	ColorBackground string  `json:"colorBackground"`
	ColorText       string  `json:"colorText"`
	SupportEmail    *string `json:"supportEmail"`
	// Audiences is every audience the hosted page can theme for, as it reads
	// them (invalid values dropped).
	Audiences map[string]BrandingAudience `json:"audiences,omitempty"`
}

// BrandingAudience is the hosted-page branding for one audience hint.
type BrandingAudience struct {
	// Heading replaces the card heading (up to 120 characters).
	Heading string `json:"heading,omitempty"`
	// Subheading replaces the line under the heading (up to 240 characters).
	Subheading string `json:"subheading,omitempty"`
	// LogoURL replaces the logo (https).
	LogoURL string `json:"logoUrl,omitempty"`
	// PrimaryColor replaces the primary colour (hex, rgb() or a CSS colour name).
	PrimaryColor string `json:"primaryColor,omitempty"`
}

// BrandingResponse echoes the stored branding plus the sanitized Resolved shape.
type BrandingResponse struct {
	Branding
	Object   string           `json:"object"`
	Resolved ResolvedBranding `json:"resolved"`
}

// HostedPagePreview is a draft rendered through the real hosted-page renderer.
type HostedPagePreview struct {
	Object string `json:"object"`
	HTML   string `json:"html"`
}

// Get reads the stored branding + resolved shape. GET /v1/branding.
func (s *BrandingService) Get(ctx context.Context) (*BrandingResponse, error) {
	out := &BrandingResponse{}
	return out, s.client.get(ctx, "/v1/branding", nil, out)
}

// Update partially merges branding — one field changes, the rest is preserved.
// PATCH /v1/branding.
func (s *BrandingService) Update(ctx context.Context, params Branding, opts ...RequestOption) (*BrandingResponse, error) {
	out := &BrandingResponse{}
	return out, s.client.patch(ctx, "/v1/branding", params, out, opts...)
}

// Preview renders a draft through the live sign-in renderer without saving it.
// POST /v1/branding/preview.
func (s *BrandingService) Preview(ctx context.Context, params Branding, opts ...RequestOption) (*HostedPagePreview, error) {
	out := &HostedPagePreview{}
	return out, s.client.post(ctx, "/v1/branding/preview", params, out, opts...)
}
