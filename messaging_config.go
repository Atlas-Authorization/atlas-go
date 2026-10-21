package atlas

import "context"

// Typed per-transport messaging provider config. Each struct has exactly the
// config keys the API accepts for its transport; the API refuses any other key.
//
// "Required on first setup" fields must be sent the first time you configure a
// transport (or switch the channel to it). On an update of the SAME transport,
// an empty field is omitted from the request and its stored value is kept —
// including a stored secret. "Write-only" fields are never returned; a response
// reports only whether they are set (MessagingProvider.SecretsSet).

// EmailProviderConfig is the config for one email transport. Implemented only
// by ResendConfig, SESConfig, SMTPConfig, BrevoConfig and MailgunConfig.
type EmailProviderConfig interface {
	emailTransport() string
}

// SMSProviderConfig is the config for one SMS transport. Implemented only by
// TwilioConfig, VonageConfig, MessageBirdConfig, PlivoConfig, TelnyxConfig,
// SinchConfig, InfobipConfig, ClickSendConfig, BandwidthConfig and AWSSNSConfig.
type SMSProviderConfig interface {
	smsTransport() string
}

// ResendConfig configures the "resend" email transport.
type ResendConfig struct {
	// APIKey is the Resend API key (re_…). Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
}

// BrevoConfig configures the "brevo" email transport.
type BrevoConfig struct {
	// APIKey is the Brevo API key (xkeysib-…). Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
}

// MailgunConfig configures the "mailgun" email transport.
type MailgunConfig struct {
	// APIKey is the Mailgun private API key. Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
	// Domain is your Mailgun sending domain, e.g. mg.example.com. Required on first setup.
	Domain string `json:"domain,omitempty"`
	// Region is "us" or "eu". Default us.
	Region string `json:"region,omitempty"`
}

// SESConfig configures the "ses" (Amazon SES) email transport.
type SESConfig struct {
	// Region is the AWS region, e.g. us-east-1. Required on first setup.
	Region string `json:"region,omitempty"`
	// AccessKeyID is the IAM access key ID. Required on first setup. Write-only.
	AccessKeyID string `json:"access_key_id,omitempty"`
	// SecretAccessKey is the IAM secret access key. Required on first setup. Write-only.
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	// SessionToken is an STS session token, only for temporary credentials. Write-only.
	SessionToken string `json:"session_token,omitempty"`
}

// SMTPConfig configures the "smtp" email transport.
type SMTPConfig struct {
	// Host is the SMTP server hostname, e.g. smtp.example.com. Required on first setup.
	Host string `json:"host,omitempty"`
	// Port is the SMTP port (1-65535). Default 587.
	Port *int `json:"port,omitempty"`
	// Secure selects implicit TLS. Default: true on port 465, otherwise STARTTLS.
	Secure *bool `json:"secure,omitempty"`
	// Username is the SMTP username, if the server requires authentication.
	Username string `json:"username,omitempty"`
	// Password is the SMTP password or app password. Write-only.
	Password string `json:"password,omitempty"`
}

// TwilioConfig configures the "twilio" SMS transport.
type TwilioConfig struct {
	// AccountSID is the Twilio Account SID (AC…). Required on first setup.
	AccountSID string `json:"account_sid,omitempty"`
	// AuthToken is the Twilio auth token. Required on first setup. Write-only.
	AuthToken string `json:"auth_token,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
	// WhatsAppFrom is a WhatsApp-enabled sender number, for the WhatsApp channel.
	WhatsAppFrom string `json:"whatsapp_from,omitempty"`
	// VoiceFrom is a voice-capable number, for the voice channel.
	VoiceFrom string `json:"voice_from,omitempty"`
}

// VonageConfig configures the "vonage" SMS transport.
type VonageConfig struct {
	// APIKey is the Vonage API key. Required on first setup.
	APIKey string `json:"api_key,omitempty"`
	// APISecret is the Vonage API secret. Required on first setup. Write-only.
	APISecret string `json:"api_secret,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// MessageBirdConfig configures the "messagebird" SMS transport.
type MessageBirdConfig struct {
	// AccessKey is the MessageBird (Bird) access key. Required on first setup. Write-only.
	AccessKey string `json:"access_key,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// PlivoConfig configures the "plivo" SMS transport.
type PlivoConfig struct {
	// AuthID is the Plivo Auth ID. Required on first setup.
	AuthID string `json:"auth_id,omitempty"`
	// AuthToken is the Plivo auth token. Required on first setup. Write-only.
	AuthToken string `json:"auth_token,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// TelnyxConfig configures the "telnyx" SMS transport.
type TelnyxConfig struct {
	// APIKey is the Telnyx API key. Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// SinchConfig configures the "sinch" SMS transport.
type SinchConfig struct {
	// ServicePlanID is the Sinch service plan ID. Required on first setup.
	ServicePlanID string `json:"service_plan_id,omitempty"`
	// APIToken is the Sinch API token. Required on first setup. Write-only.
	APIToken string `json:"api_token,omitempty"`
	// Region is a short lowercase region code such as us or eu. Default us.
	Region string `json:"region,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// InfobipConfig configures the "infobip" SMS transport.
type InfobipConfig struct {
	// BaseURL is your Infobip https base URL, e.g. https://xxxxx.api.infobip.com. Required on first setup.
	BaseURL string `json:"base_url,omitempty"`
	// APIKey is the Infobip API key. Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// ClickSendConfig configures the "clicksend" SMS transport.
type ClickSendConfig struct {
	// Username is your ClickSend username (your login email). Required on first setup.
	Username string `json:"username,omitempty"`
	// APIKey is the ClickSend API key. Required on first setup. Write-only.
	APIKey string `json:"api_key,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// BandwidthConfig configures the "bandwidth" SMS transport.
type BandwidthConfig struct {
	// AccountID is the Bandwidth account ID. Required on first setup.
	AccountID string `json:"account_id,omitempty"`
	// ApplicationID is the Bandwidth messaging application ID. Required on first setup.
	ApplicationID string `json:"application_id,omitempty"`
	// Username is the Bandwidth API username. Required on first setup.
	Username string `json:"username,omitempty"`
	// Password is the Bandwidth API password. Required on first setup. Write-only.
	Password string `json:"password,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

// AWSSNSConfig configures the "aws_sns" (Amazon SNS) SMS transport.
type AWSSNSConfig struct {
	// Region is the AWS region, e.g. us-east-1. Required on first setup.
	Region string `json:"region,omitempty"`
	// AccessKeyID is the IAM access key ID. Required on first setup.
	AccessKeyID string `json:"access_key_id,omitempty"`
	// SecretAccessKey is the IAM secret access key. Required on first setup. Write-only.
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	// SessionToken is an STS session token, only for temporary credentials. Write-only.
	SessionToken string `json:"session_token,omitempty"`
	// From is the sender number or ID. The request's from address takes precedence.
	From string `json:"from,omitempty"`
}

func (ResendConfig) emailTransport() string  { return "resend" }
func (BrevoConfig) emailTransport() string   { return "brevo" }
func (MailgunConfig) emailTransport() string { return "mailgun" }
func (SESConfig) emailTransport() string     { return "ses" }
func (SMTPConfig) emailTransport() string    { return "smtp" }

func (TwilioConfig) smsTransport() string      { return "twilio" }
func (VonageConfig) smsTransport() string      { return "vonage" }
func (MessageBirdConfig) smsTransport() string { return "messagebird" }
func (PlivoConfig) smsTransport() string       { return "plivo" }
func (TelnyxConfig) smsTransport() string      { return "telnyx" }
func (SinchConfig) smsTransport() string       { return "sinch" }
func (InfobipConfig) smsTransport() string     { return "infobip" }
func (ClickSendConfig) smsTransport() string   { return "clicksend" }
func (BandwidthConfig) smsTransport() string   { return "bandwidth" }
func (AWSSNSConfig) smsTransport() string      { return "aws_sns" }

// typedProviderBody is the PUT body built from a typed config.
type typedProviderBody struct {
	Transport   string      `json:"transport"`
	FromAddress string      `json:"from_address,omitempty"`
	Mode        string      `json:"mode,omitempty"`
	Config      interface{} `json:"config"`
}

// Email provider modes.
const (
	// ProviderModeStandard is a provider sending normally.
	ProviderModeStandard = "standard"
	// ProviderModeDevelopment lets a development instance send Atlas's sign-in
	// emails without a verified domain ("[Atlas test] " subjects, capped).
	ProviderModeDevelopment = "development"
	// ProviderModeManagedDomain is the provider that holds managed email's key.
	ProviderModeManagedDomain = "managed_domain"
)

// EmailProviderParams is the typed body of SetEmailProviderWithParams.
type EmailProviderParams struct {
	// FromAddress may be empty; otherwise the From address.
	FromAddress string
	// Mode is ProviderModeStandard or ProviderModeDevelopment; empty keeps the
	// stored mode. Development is refused with 409 on a production instance.
	Mode   string
	Config EmailProviderConfig
}

// SetEmailProvider configures (or updates) the email provider from a typed
// per-transport config; the transport is taken from the config's type.
// fromAddress may be empty; otherwise it is the From address, e.g.
// "Acme <no-reply@acme.com>". PUT /v1/messaging_providers/email.
func (s *MessagingService) SetEmailProvider(ctx context.Context, fromAddress string, cfg EmailProviderConfig, opts ...RequestOption) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	body := typedProviderBody{Transport: cfg.emailTransport(), FromAddress: fromAddress, Config: cfg}
	return out, s.client.put(ctx, "/v1/messaging_providers/email", body, out, opts...)
}

// SetEmailProviderWithParams is SetEmailProvider with a provider mode.
// PUT /v1/messaging_providers/email.
func (s *MessagingService) SetEmailProviderWithParams(ctx context.Context, params EmailProviderParams, opts ...RequestOption) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	body := typedProviderBody{Transport: params.Config.emailTransport(), FromAddress: params.FromAddress, Mode: params.Mode, Config: params.Config}
	return out, s.client.put(ctx, "/v1/messaging_providers/email", body, out, opts...)
}

// SetSMSProvider configures (or updates) the SMS provider from a typed
// per-transport config; the transport is taken from the config's type.
// fromAddress may be empty; otherwise it is the sender number in E.164 format,
// e.g. +15551234567. PUT /v1/messaging_providers/sms.
func (s *MessagingService) SetSMSProvider(ctx context.Context, fromAddress string, cfg SMSProviderConfig, opts ...RequestOption) (*MessagingProvider, error) {
	out := &MessagingProvider{}
	body := typedProviderBody{Transport: cfg.smsTransport(), FromAddress: fromAddress, Config: cfg}
	return out, s.client.put(ctx, "/v1/messaging_providers/sms", body, out, opts...)
}
