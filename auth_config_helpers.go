package atlas

import "context"

// Captcha providers an instance can configure (auth_config.captcha.provider).
// Captcha is bring-your-own-keys: store the provider secret with
// InstanceSecurity.SetCaptchaSecretWithParams before turning it on.
// CaptchaProviderVercelBotID is secret-only (no site key): set
// AttestationURL to your BotID attestation route instead.
const (
	CaptchaProviderNone                = "none"
	CaptchaProviderAtlas               = "atlas"
	CaptchaProviderHCaptcha            = "hcaptcha"
	CaptchaProviderTurnstile           = "turnstile"
	CaptchaProviderRecaptcha           = "recaptcha"
	CaptchaProviderRecaptchaV3         = "recaptcha_v3"
	CaptchaProviderRecaptchaEnterprise = "recaptcha_enterprise"
	CaptchaProviderFunCaptcha          = "funcaptcha"
	CaptchaProviderFriendly            = "friendly"
	CaptchaProviderYandex              = "yandex"
	CaptchaProviderGeeTest             = "geetest"
	CaptchaProviderMCaptcha            = "mcaptcha"
	CaptchaProviderCapy                = "capy"
	CaptchaProviderSEON                = "seon"
	CaptchaProviderAWSWAF              = "awswaf"
	CaptchaProviderPerimeterX          = "perimeterx"
	CaptchaProviderAkamai              = "akamai"
	CaptchaProviderKasada              = "kasada"
	CaptchaProviderIncapsula           = "incapsula"
	CaptchaProviderCaptchaFox          = "captchafox"
	CaptchaProviderVercelBotID         = "vercel_botid"
)

// CaptchaConfig is the auth_config.captcha block (or one per-flow / per-action
// override). Widget is "invisible", "managed" or "visible". AttestationURL
// (Vercel BotID) is where the browser fetches a signed verdict: an https URL
// or a root-relative path.
type CaptchaConfig struct {
	Enabled        *bool    `json:"enabled,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	SiteKey        string   `json:"siteKey,omitempty"`
	MinScore       *float64 `json:"minScore,omitempty"`
	VerifyURL      string   `json:"verifyUrl,omitempty"`
	ProjectID      string   `json:"projectId,omitempty"`
	Widget         string   `json:"widget,omitempty"`
	AttestationURL string   `json:"attestationUrl,omitempty"`
}

// SetCaptchaConfig merges a captcha block into the instance's auth config.
// PATCH /v1/instance.
func (s *InstanceService) SetCaptchaConfig(ctx context.Context, captcha CaptchaConfig, opts ...RequestOption) (*InstanceUpdateResult, error) {
	return s.Update(ctx, UpdateInstanceParams{AuthConfig: map[string]interface{}{"captcha": captcha}}, opts...)
}

// Account-linking trust levels: whether a provider's email is trusted to link
// a sign-in to an existing account with that email. "always" vouches for the
// provider's email (for linking only), "verified" trusts it only when the
// provider says it is verified, "never" refuses to link (409
// IDENTITY_ALREADY_LINKED, reason provider_not_trusted_for_linking).
const (
	LinkingTrustAlways   = "always"
	LinkingTrustVerified = "verified"
	LinkingTrustNever    = "never"
)

// SetAccountLinkingTrust writes auth_config.accountLinkingTrust: keys are an
// exact provider key, a "prefix*" or "*"; values are LinkingTrust*. An
// account that never proved its email is never linked. PATCH /v1/instance.
func (s *InstanceService) SetAccountLinkingTrust(ctx context.Context, trust map[string]string, opts ...RequestOption) (*InstanceUpdateResult, error) {
	return s.Update(ctx, UpdateInstanceParams{AuthConfig: map[string]interface{}{"accountLinkingTrust": trust}}, opts...)
}

// EmailTemplateAccountReactivated is the security notice sent when a dormant
// account signs in again.
const EmailTemplateAccountReactivated = "account_reactivated"

// Webhook event types for session custom data and dormant-account reactivation.
const (
	// WebhookEventSessionUpdated: a session's custom data changed.
	WebhookEventSessionUpdated = "session.updated"
	// WebhookEventUserReactivated: a dormant account signed in again.
	WebhookEventUserReactivated = "user.reactivated"
)
