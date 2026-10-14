package atlas

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// DesignService is the sign-in page design namespace: the instance design
// (/v1/instance/design), per-organization design overrides
// (/v1/organizations/:id/design), uploaded design images (/v1/design/assets)
// and the public design catalog (/v1/design/catalog).
//
// The full design (Design) is typed section by section. Partial updates use
// DesignPatch, an open map, because a patch needs to send JSON null to remove
// a setting — something a typed Go struct cannot tell apart from "not set".
type DesignService struct {
	client *Client

	// Assets is /v1/design/assets — this instance's uploaded images.
	Assets *DesignAssetsService
}

// Design is a sign-in page design (the AtlasDesign object). Every section is
// optional; anything unset falls back to the preset, then to Atlas defaults.
type Design struct {
	// Version is the design format version (always 1).
	Version int `json:"version,omitempty"`
	// Preset is a starting look: minimal, atlas, glass, midnight, editorial,
	// terminal, sunrise, forest, grape, slate, split-photo or bold.
	Preset string `json:"preset,omitempty"`
	// ColorScheme is auto, light or dark.
	ColorScheme    string            `json:"colorScheme,omitempty"`
	Palette        *DesignPalette    `json:"palette,omitempty"`
	PaletteDark    *DesignPalette    `json:"paletteDark,omitempty"`
	Typography     *DesignTypography `json:"typography,omitempty"`
	Shape          *DesignShape      `json:"shape,omitempty"`
	Elevation      *DesignElevation  `json:"elevation,omitempty"`
	Spacing        *DesignSpacing    `json:"spacing,omitempty"`
	Card           *DesignCard       `json:"card,omitempty"`
	Layout         *DesignLayout     `json:"layout,omitempty"`
	Buttons        *DesignButtons    `json:"buttons,omitempty"`
	Inputs         *DesignInputs     `json:"inputs,omitempty"`
	Background     *DesignBackground `json:"background,omitempty"`
	BackgroundDark *DesignBackground `json:"backgroundDark,omitempty"`
	Logo           *DesignLogo       `json:"logo,omitempty"`
}

// DesignPalette is a set of colour slots, each #rrggbb.
type DesignPalette struct {
	Primary         string `json:"primary,omitempty"`
	PrimaryInk      string `json:"primaryInk,omitempty"`
	Accent          string `json:"accent,omitempty"`
	Background      string `json:"background,omitempty"`
	Surface         string `json:"surface,omitempty"`
	Text            string `json:"text,omitempty"`
	Muted           string `json:"muted,omitempty"`
	Border          string `json:"border,omitempty"`
	Danger          string `json:"danger,omitempty"`
	Success         string `json:"success,omitempty"`
	InputBackground string `json:"inputBackground,omitempty"`
	InputText       string `json:"inputText,omitempty"`
}

// DesignTypography sets fonts and the type scale. Font and HeadingFont are ids
// from the design catalog (system, inter, roboto, …).
type DesignTypography struct {
	Font          string `json:"font,omitempty"`
	HeadingFont   string `json:"headingFont,omitempty"`
	BaseSize      *int   `json:"baseSize,omitempty"`
	HeadingWeight *int   `json:"headingWeight,omitempty"`
	BodyWeight    *int   `json:"bodyWeight,omitempty"`
	// LetterCase is none or uppercase.
	LetterCase string `json:"letterCase,omitempty"`
	// Scale is a modular scale name (minor-second … octave).
	Scale string `json:"scale,omitempty"`
}

// DesignShape sets corner radii and border width, in pixels.
type DesignShape struct {
	Radius        *int `json:"radius,omitempty"`
	ControlRadius *int `json:"controlRadius,omitempty"`
	BorderWidth   *int `json:"borderWidth,omitempty"`
}

// DesignElevation sets the card shadow: none, sm, md, lg or xl.
type DesignElevation struct {
	CardShadow string `json:"cardShadow,omitempty"`
}

// DesignSpacing sets the density: compact, comfortable or spacious.
type DesignSpacing struct {
	Density string `json:"density,omitempty"`
}

// DesignCard styles the sign-in card.
type DesignCard struct {
	// Style is solid, glass, outline or none.
	Style string `json:"style,omitempty"`
	Blur  *int   `json:"blur,omitempty"`
	// Width is narrow, normal or wide.
	Width string `json:"width,omitempty"`
}

// DesignLayout places the card and logo.
type DesignLayout struct {
	// Position is center, left, right or split.
	Position string `json:"position,omitempty"`
	// SplitImageSide is left or right.
	SplitImageSide string `json:"splitImageSide,omitempty"`
	// LogoPlacement is card, page or hidden.
	LogoPlacement string `json:"logoPlacement,omitempty"`
	// LogoSize is sm, md or lg.
	LogoSize string `json:"logoSize,omitempty"`
}

// DesignButtons styles buttons.
type DesignButtons struct {
	// Style is solid, outline, soft or gradient.
	Style string `json:"style,omitempty"`
	// SocialLayout is list, grid or icons.
	SocialLayout string `json:"socialLayout,omitempty"`
}

// DesignInputs styles inputs: outline, filled or underline.
type DesignInputs struct {
	Style string `json:"style,omitempty"`
}

// DesignBackground is the page background: a colour, gradient, image and/or
// pattern.
type DesignBackground struct {
	Color    string                    `json:"color,omitempty"`
	Gradient *DesignBackgroundGradient `json:"gradient,omitempty"`
	Image    *DesignBackgroundImage    `json:"image,omitempty"`
	// Pattern is none, dots, grid or noise.
	Pattern string `json:"pattern,omitempty"`
}

// DesignBackgroundGradient is a linear or radial gradient.
type DesignBackgroundGradient struct {
	// Type is linear or radial.
	Type  string               `json:"type"`
	Angle *int                 `json:"angle,omitempty"`
	Stops []DesignGradientStop `json:"stops"`
}

// DesignGradientStop is one colour stop; At is a position from 0 to 1.
type DesignGradientStop struct {
	Color string  `json:"color"`
	At    float64 `json:"at"`
}

// DesignBackgroundImage is an uploaded background image (a design asset id).
type DesignBackgroundImage struct {
	AssetID string `json:"assetId"`
	// Fit is cover or contain.
	Fit string `json:"fit,omitempty"`
	// Position is top-left, top, top-right, left, center, right, bottom-left,
	// bottom or bottom-right.
	Position string                   `json:"position,omitempty"`
	Overlay  *DesignBackgroundOverlay `json:"overlay,omitempty"`
	Blur     *int                     `json:"blur,omitempty"`
}

// DesignBackgroundOverlay tints a background image.
type DesignBackgroundOverlay struct {
	Color   string  `json:"color"`
	Opacity float64 `json:"opacity"`
}

// DesignLogo names uploaded logo images (design asset ids).
type DesignLogo struct {
	AssetID     string `json:"assetId,omitempty"`
	DarkAssetID string `json:"darkAssetId,omitempty"`
}

// DesignPatch is a partial design for PATCH: nested sections merge with what is
// stored and a nil value (JSON null) removes a setting. Keys and nesting are the
// same as Design's JSON form, e.g.
//
//	atlas.DesignPatch{"palette": map[string]interface{}{"primary": "#0a7cff"}, "logo": nil}
type DesignPatch map[string]interface{}

// ResolvedDesign is the design the page actually renders with: every setting
// filled in. Palettes are typed; the other sections are open maps keyed like
// Design's JSON form.
type ResolvedDesign struct {
	Version        int                    `json:"version"`
	Preset         string                 `json:"preset"`
	ColorScheme    string                 `json:"colorScheme"`
	Palette        map[string]string      `json:"palette"`
	PaletteDark    map[string]string      `json:"paletteDark"`
	Typography     map[string]interface{} `json:"typography"`
	Shape          map[string]interface{} `json:"shape"`
	Elevation      map[string]interface{} `json:"elevation"`
	Spacing        map[string]interface{} `json:"spacing"`
	Card           map[string]interface{} `json:"card"`
	Layout         map[string]interface{} `json:"layout"`
	Buttons        map[string]interface{} `json:"buttons"`
	Inputs         map[string]interface{} `json:"inputs"`
	Background     map[string]interface{} `json:"background"`
	BackgroundDark map[string]interface{} `json:"backgroundDark"`
	Logo           map[string]interface{} `json:"logo"`
}

// DesignWarning is a contrast warning: a colour pair below the required ratio.
type DesignWarning struct {
	Code     string   `json:"code"`
	Mode     string   `json:"mode"`
	Pair     []string `json:"pair"`
	Ratio    float64  `json:"ratio"`
	Required float64  `json:"required"`
	// Path is the setting to change, e.g. palette.primaryInk.
	Path    string `json:"path"`
	Message string `json:"message"`
}

// DesignSettings is a stored design (instance or organization) with what it
// resolves to.
type DesignSettings struct {
	// Object is "design" or "organization_design".
	Object string `json:"object"`
	// OrganizationID is set on organization designs only.
	OrganizationID string          `json:"organization_id,omitempty"`
	Design         Design          `json:"design"`
	Resolved       ResolvedDesign  `json:"resolved"`
	Warnings       []DesignWarning `json:"warnings"`
	// Legacy is true when nothing is stored and the page is drawn from the
	// older branding settings; LegacyDesign is then the equivalent design.
	Legacy       bool    `json:"legacy"`
	LegacyDesign *Design `json:"legacy_design,omitempty"`
}

// DesignPreview is a compiled, unsaved design.
type DesignPreview struct {
	Object string `json:"object"`
	// Scope is the CSS selector the variables are scoped to (".atlas-root").
	Scope           string            `json:"scope"`
	CSS             string            `json:"css"`
	DataAttributes  map[string]string `json:"data_attributes"`
	FontStylesheets []string          `json:"font_stylesheets"`
	Resolved        ResolvedDesign    `json:"resolved"`
	Warnings        []DesignWarning   `json:"warnings"`
	// HTML is the sign-in page rendered with the draft design (inert markup for
	// a sandboxed preview frame).
	HTML string `json:"html"`
}

// DesignAsset is an uploaded design image.
type DesignAsset struct {
	Object string `json:"object"`
	// AssetID is the dasset_... id referenced from a design.
	AssetID string `json:"asset_id"`
	// Kind is background or logo.
	Kind   string `json:"kind"`
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	// DominantColor is #rrggbb for an opaque image, else nil.
	DominantColor *string `json:"dominant_color"`
	Bytes         int64   `json:"bytes"`
	CreatedAt     string  `json:"created_at"`
}

// DesignAssetList is the list of uploaded design images, newest first.
type DesignAssetList struct {
	Object string        `json:"object"`
	Data   []DesignAsset `json:"data"`
}

// DesignAssetDeleted acknowledges a deleted design image.
type DesignAssetDeleted struct {
	Object  string `json:"object"`
	AssetID string `json:"asset_id"`
	Deleted bool   `json:"deleted"`
}

// DesignCatalog is the public design catalog: presets (fully resolved), the
// curated font list and the documented --atlas-* CSS variables.
type DesignCatalog struct {
	Object       string                `json:"object"`
	Version      int                   `json:"version"`
	Presets      []DesignCatalogPreset `json:"presets"`
	Fonts        []DesignCatalogFont   `json:"fonts"`
	CSSVariables []DesignCSSVariable   `json:"css_variables"`
}

// DesignCatalogPreset is one preset and the design it resolves to.
type DesignCatalogPreset struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Resolved    ResolvedDesign `json:"resolved"`
}

// DesignCatalogFont is one curated font.
type DesignCatalogFont struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Family   string `json:"family"`
	Category string `json:"category"`
	WebFont  bool   `json:"web_font"`
	// Stylesheet is the font's stylesheet path, or nil for a system font.
	Stylesheet *string `json:"stylesheet"`
}

// DesignCSSVariable is one documented --atlas-* CSS custom property.
type DesignCSSVariable struct {
	Name string `json:"name"`
	// Type is color, length, number, font-family, font-weight, shadow, image or
	// keyword.
	Type string `json:"type"`
	// PerMode is true when the value differs between light and dark mode.
	PerMode     bool   `json:"perMode"`
	Description string `json:"description"`
}

type designBody struct {
	Design interface{} `json:"design"`
}

// Get reads the instance design: stored overrides, the resolved design,
// contrast warnings and the legacy flag. GET /v1/instance/design.
func (s *DesignService) Get(ctx context.Context) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.get(ctx, "/v1/instance/design", nil, out)
}

// Replace replaces the instance design. Unknown keys are refused; image ids
// must be design assets uploaded to this instance. PUT /v1/instance/design.
func (s *DesignService) Replace(ctx context.Context, design Design, opts ...RequestOption) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.put(ctx, "/v1/instance/design", designBody{design}, out, opts...)
}

// Update changes part of the instance design: nested settings merge and a nil
// value removes a setting. PATCH /v1/instance/design.
func (s *DesignService) Update(ctx context.Context, patch DesignPatch, opts ...RequestOption) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.patch(ctx, "/v1/instance/design", designBody{patch}, out, opts...)
}

// Preview compiles an unsaved design (CSS variables, data attributes, font
// stylesheets, warnings, the resolved design and the rendered sign-in page).
// Nothing is saved. POST /v1/instance/design/preview.
func (s *DesignService) Preview(ctx context.Context, design Design, opts ...RequestOption) (*DesignPreview, error) {
	out := &DesignPreview{}
	return out, s.client.post(ctx, "/v1/instance/design/preview", designBody{design}, out, opts...)
}

// GetOrganization reads an organization's design override and the result of
// layering it over the instance design. GET /v1/organizations/:id/design.
func (s *DesignService) GetOrganization(ctx context.Context, organizationID string) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.get(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/design", nil, out)
}

// ReplaceOrganization replaces an organization's design override; an empty
// Design{} removes it. PUT /v1/organizations/:id/design.
func (s *DesignService) ReplaceOrganization(ctx context.Context, organizationID string, design Design, opts ...RequestOption) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.put(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/design", designBody{design}, out, opts...)
}

// UpdateOrganization changes part of an organization's design override; a nil
// value removes a setting. PATCH /v1/organizations/:id/design.
func (s *DesignService) UpdateOrganization(ctx context.Context, organizationID string, patch DesignPatch, opts ...RequestOption) (*DesignSettings, error) {
	out := &DesignSettings{}
	return out, s.client.patch(ctx, "/v1/organizations/"+url.PathEscape(organizationID)+"/design", designBody{patch}, out, opts...)
}

// Catalog returns the public design catalog: presets, fonts and the CSS
// variable set. GET /v1/design/catalog.
func (s *DesignService) Catalog(ctx context.Context) (*DesignCatalog, error) {
	out := &DesignCatalog{}
	return out, s.client.get(ctx, "/v1/design/catalog", nil, out)
}

// DesignAssetsService is /v1/design/assets — this instance's design images.
type DesignAssetsService struct{ client *Client }

// Upload stores a design image: the raw bytes of a PNG, JPEG, GIF or WebP (up
// to 8 MB / 40 megapixels). kind is "background" (the default when empty) or
// "logo". contentType is the image's MIME type; when empty it is detected from
// the bytes. POST /v1/design/assets.
func (s *DesignAssetsService) Upload(ctx context.Context, image []byte, contentType, kind string, opts ...RequestOption) (*DesignAsset, error) {
	return uploadDesignAsset(ctx, s.client, authSecret, "/v1/design/assets", image, contentType, kind, opts...)
}

// List returns this instance's design images, newest first.
// GET /v1/design/assets.
func (s *DesignAssetsService) List(ctx context.Context) (*DesignAssetList, error) {
	out := &DesignAssetList{}
	return out, s.client.get(ctx, "/v1/design/assets", nil, out)
}

// Delete removes a design image. Refused with 409 while a saved design still
// uses it. DELETE /v1/design/assets/:id.
func (s *DesignAssetsService) Delete(ctx context.Context, assetID string, opts ...RequestOption) (*DesignAssetDeleted, error) {
	out := &DesignAssetDeleted{}
	return out, s.client.del(ctx, "/v1/design/assets/"+url.PathEscape(assetID), out, opts...)
}

func uploadDesignAsset(ctx context.Context, c *Client, auth authKind, path string, image []byte, contentType, kind string, opts ...RequestOption) (*DesignAsset, error) {
	if len(image) == 0 {
		return nil, errors.New("atlas: design asset upload needs the image bytes")
	}
	if contentType == "" {
		contentType = http.DetectContentType(image)
	}
	var query url.Values
	if kind != "" {
		query = url.Values{"kind": {kind}}
	}
	out := &DesignAsset{}
	return out, c.doRaw(ctx, auth, http.MethodPost, path, query, contentType, image, out, opts...)
}
