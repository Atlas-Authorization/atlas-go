package atlas

import "strings"

// Atlas keys come in two formats. The suite format is
// `atlas_<live|test>_<kind>_<random><checksum>` (sk, psk, dsk, whsec, pl, at);
// the legacy format is `sk_live_…`, `sk_test_…`, `pk_…`, `psk_…`, `whsec_…`
// and `dsk_…`. Any prefix check in your code must accept both, which is what
// these helpers do.

// KeyKind names what a credential is.
type KeyKind string

// Credential kinds.
const (
	KeyKindSecret        KeyKind = "sk"
	KeyKindPlatform      KeyKind = "psk"
	KeyKindPublishable   KeyKind = "pk"
	KeyKindDeploy        KeyKind = "dsk"
	KeyKindWebhookSecret KeyKind = "whsec"
	KeyKindPartnerLink   KeyKind = "pl"
	KeyKindAccessToken   KeyKind = "at"
)

const (
	suiteKeyPrefix = "atlas_"
	keyEnvLive     = "live"
	keyEnvTest     = "test"
)

// ParsedKey is what ParseKeyPrefix learned from a credential's prefix.
type ParsedKey struct {
	Kind KeyKind
	// Environment is "live", "test" or "" when the key carries none.
	Environment string
	// Suite is true for the `atlas_<env>_<kind>_…` format, false for legacy.
	Suite bool
}

func isKeyEnv(s string) bool { return s == keyEnvLive || s == keyEnvTest }

// ParseKeyPrefix classifies a credential by its prefix, accepting the suite
// format (`atlas_live_sk_…`) and the legacy one (`sk_live_…`, `pk_test_…`,
// `psk_…`, `whsec_…`). It does not validate the checksum or contact Atlas.
// ok is false for anything else.
func ParseKeyPrefix(key string) (ParsedKey, bool) {
	if strings.HasPrefix(key, suiteKeyPrefix) {
		parts := strings.SplitN(key[len(suiteKeyPrefix):], "_", 3)
		if len(parts) == 3 && isKeyEnv(parts[0]) {
			switch KeyKind(parts[1]) {
			case KeyKindSecret, KeyKindPlatform, KeyKindDeploy, KeyKindWebhookSecret, KeyKindPartnerLink, KeyKindAccessToken:
				return ParsedKey{Kind: KeyKind(parts[1]), Environment: parts[0], Suite: true}, true
			}
		}
		return ParsedKey{}, false
	}
	parts := strings.SplitN(key, "_", 3)
	if len(parts) < 2 {
		return ParsedKey{}, false
	}
	kind := KeyKind(parts[0])
	switch kind {
	case KeyKindSecret, KeyKindPublishable:
		if len(parts) == 3 && isKeyEnv(parts[1]) {
			return ParsedKey{Kind: kind, Environment: parts[1]}, true
		}
		return ParsedKey{}, false
	case KeyKindPlatform, KeyKindDeploy, KeyKindWebhookSecret:
		env := ""
		if len(parts) == 3 && isKeyEnv(parts[1]) {
			env = parts[1]
		}
		return ParsedKey{Kind: kind, Environment: env}, true
	}
	return ParsedKey{}, false
}

func keyIsKind(key string, kind KeyKind) bool {
	p, ok := ParseKeyPrefix(key)
	return ok && p.Kind == kind
}

// IsSecretKey reports whether key is an instance secret key in either format
// (`atlas_live_sk_…` or `sk_live_…`).
func IsSecretKey(key string) bool { return keyIsKind(key, KeyKindSecret) }

// IsPlatformKey reports whether key is a platform key in either format
// (`atlas_live_psk_…` or `psk_…`).
func IsPlatformKey(key string) bool { return keyIsKind(key, KeyKindPlatform) }

// IsPublishableKey reports whether key is a publishable key (`pk_live_…` /
// `pk_test_…`). Publishable keys are not secrets and have no suite form.
func IsPublishableKey(key string) bool { return keyIsKind(key, KeyKindPublishable) }

// IsWebhookSecret reports whether key is a webhook signing secret in either
// format (`atlas_live_whsec_…` or `whsec_…`). Webhook verification is
// unchanged: the whole string is the HMAC key.
func IsWebhookSecret(key string) bool { return keyIsKind(key, KeyKindWebhookSecret) }

// IsPartnerLinkSecret reports whether key is a partner-link secret
// (`atlas_live_pl_…`).
func IsPartnerLinkSecret(key string) bool { return keyIsKind(key, KeyKindPartnerLink) }

// IsAccessToken reports whether key is a one-hour Atlas access token from an
// operator token exchange (`atlas_live_at_…`).
func IsAccessToken(key string) bool { return keyIsKind(key, KeyKindAccessToken) }
