package atlas

import "encoding/json"

// Origin integrations: how an allowed origin signs in.
const (
	// OriginIntegrationRedirect is hosted-redirect OIDC: the app sends users to
	// /oauth2/authorize and never runs the embedded components, so the CORS and
	// session-cookie checks do not apply to it.
	OriginIntegrationRedirect = "redirect"
	// OriginIntegrationEmbedded means the sign-in components run on the origin.
	OriginIntegrationEmbedded = "embedded"
	// OriginIntegrationAuto clears a declared integration; Atlas infers it.
	OriginIntegrationAuto = "auto"
)

// AllowedOriginEntry is one allowed_origins entry that may also declare how the
// origin signs in. With an empty Integration it is sent as the plain origin
// string, which keeps the hint the origin already had; otherwise as
// {"origin", "integration"}.
type AllowedOriginEntry struct {
	Origin string
	// Integration is OriginIntegrationRedirect, OriginIntegrationEmbedded,
	// OriginIntegrationAuto (clear the hint) or empty (keep it).
	Integration string
}

// MarshalJSON renders the entry as a string or an {origin, integration} object.
func (e AllowedOriginEntry) MarshalJSON() ([]byte, error) {
	if e.Integration == "" {
		return json.Marshal(e.Origin)
	}
	return json.Marshal(struct {
		Origin      string `json:"origin"`
		Integration string `json:"integration"`
	}{e.Origin, e.Integration})
}

// originEntriesExtra overlays allowed_origins with entries when they are set.
func originEntriesExtra(entries []AllowedOriginEntry) map[string]interface{} {
	if entries == nil {
		return nil
	}
	return map[string]interface{}{"allowed_origins": entries}
}
