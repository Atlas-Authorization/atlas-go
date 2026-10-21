package atlas

import (
	"context"
	"encoding/json"
	"testing"
)

// TestRotateSecretWithOverlap sends overlap_seconds (0 included) and decodes
// the previous secret's expiry.
func TestRotateSecretWithOverlap(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"oauth_client","id":"oc_1","client_secret":"cs_new","overlap_seconds":0,"previous_secret_expires_at":null}`)
	zero := 0
	out, err := c.OAuthClients.RotateSecretWithParams(ctx, "oc_1", RotateOAuthClientSecretParams{OverlapSeconds: &zero})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/oauth_clients/oc_1/rotate_secret")
	if rec.RawBody != `{"overlap_seconds":0}` || out.ClientSecret != "cs_new" || out.PreviousSecretExpiresAt != nil {
		t.Errorf("body=%s out=%+v", rec.RawBody, out)
	}

	c, rec = recordingClient(t, `{"object":"oauth_client","id":"oc_1","client_secret":"cs_new","overlap_seconds":86400,"previous_secret_expires_at":1800000000000}`)
	out, _ = c.OAuthClients.RotateSecret(ctx, "oc_1")
	if rec.RawBody != "" || out.OverlapSeconds != 86400 || out.PreviousSecretExpiresAt == nil || *out.PreviousSecretExpiresAt != 1800000000000 {
		t.Errorf("body=%q out=%+v", rec.RawBody, out)
	}
}

// TestDevelopmentEmail covers get / enable / disable.
func TestDevelopmentEmail(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"development_email","provider_id":"mp_1","enabled":true,"active":true,"transport":"resend","from_address":"onboarding@resend.dev","subject_prefix":"[Atlas test] ","footer":"f","templates":["magic_link"],"limits":{"daily":100,"per_recipient_hourly":10},"updated_at":5,"deleted":true,"mode":"standard"}`)
	dev, err := c.Messaging.DevelopmentEmail(ctx)
	if err != nil || dev.Limits.PerRecipientHourly != 10 || dev.SubjectPrefix != "[Atlas test] " {
		t.Fatalf("get = %+v, %v", dev, err)
	}
	rec.expect(t, "GET", "/v1/messaging_providers/email/development")

	if _, err := c.Messaging.EnableDevelopmentEmail(ctx, EnableDevelopmentEmailParams{ProviderID: "mp_1"}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/messaging_providers/email/development")
	if rec.RawBody != `{"provider_id":"mp_1"}` {
		t.Errorf("enable body = %s", rec.RawBody)
	}

	gone, _ := c.Messaging.DisableDevelopmentEmail(ctx)
	rec.expect(t, "DELETE", "/v1/messaging_providers/email/development")
	if !gone.Deleted || gone.Mode != "standard" {
		t.Errorf("disable = %+v", gone)
	}
}

// TestManagedEmailOwnAccountAndProviderMode sends transport + api_key and
// decodes the new fields; SetEmailProviderWithParams sends mode.
func TestManagedEmailOwnAccountAndProviderMode(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"managed_email","backend":"brevo","provider_id":"mp_2","limits":null,"reputation":"your_provider_account","feedback_webhook":"registered","records":[{"purpose":"ownership","type":"TXT","name":"acme.test","value":"v"}],"id":"mp_1","mode":"development","channel":"email"}`)
	me, err := c.Messaging.CreateManagedEmail(ctx, CreateManagedEmailParams{FromAddress: "hi@acme.test", Transport: "brevo", Config: &ManagedEmailProviderKey{APIKey: "xkeysib-x"}})
	if err != nil {
		t.Fatal(err)
	}
	if rec.RawBody != `{"from_address":"hi@acme.test","transport":"brevo","config":{"api_key":"xkeysib-x"}}` {
		t.Errorf("body = %s", rec.RawBody)
	}
	if me.ProviderID == nil || *me.ProviderID != "mp_2" || me.Backend != "brevo" || me.FeedbackWebhook != "registered" || me.Limits.Daily != 0 {
		t.Errorf("managed = %+v", me)
	}

	p, err := c.Messaging.SetEmailProviderWithParams(ctx, EmailProviderParams{Mode: ProviderModeDevelopment, Config: ResendConfig{APIKey: "re_x"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "PUT", "/v1/messaging_providers/email")
	if rec.Body["mode"] != "development" || rec.Body["transport"] != "resend" || p.ID != "mp_1" || p.Mode != "development" {
		t.Errorf("body=%v provider=%+v", rec.Body, p)
	}
}

// TestAllowedOriginEntriesAndIssuerFields marshals origin entries as strings or
// objects and decodes the issuer fields.
func TestAllowedOriginEntriesAndIssuerFields(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"instance","issuer":"https://auth.acme.test","discovery_url":"https://auth.acme.test/.well-known/openid-configuration","jwks_uri":"https://auth.acme.test/.well-known/jwks.json","allowed_origins":["https://app.acme.test"],"allowed_origin_integrations":{"https://app.acme.test":"redirect"}}`)
	got, err := c.Instance.Get(ctx)
	if err != nil || got.Issuer != "https://auth.acme.test" || got.JWKSURI == "" || got.AllowedOriginIntegrations["https://app.acme.test"] != "redirect" {
		t.Fatalf("instance = %+v, %v", got, err)
	}
	_, _ = c.Instance.Update(ctx, UpdateInstanceParams{AllowedOriginEntries: []AllowedOriginEntry{
		{Origin: "https://a.acme.test"},
		{Origin: "https://app.acme.test", Integration: OriginIntegrationRedirect},
	}})
	if rec.RawBody != `{"allowed_origins":["https://a.acme.test",{"origin":"https://app.acme.test","integration":"redirect"}]}` {
		t.Errorf("update body = %s", rec.RawBody)
	}
	// Plain AllowedOrigins still work.
	_, _ = c.Instance.Update(ctx, UpdateInstanceParams{AllowedOrigins: []string{"https://a.acme.test"}})
	if rec.RawBody != `{"allowed_origins":["https://a.acme.test"]}` {
		t.Errorf("plain body = %s", rec.RawBody)
	}

	b, _ := json.Marshal(UpdatePlatformAppParams{Name: "x", AllowedOriginEntries: []AllowedOriginEntry{{Origin: "https://a.acme.test", Integration: OriginIntegrationAuto}}})
	if string(b) != `{"allowed_origins":[{"origin":"https://a.acme.test","integration":"auto"}],"name":"x"}` {
		t.Errorf("platform body = %s", b)
	}
	var app PlatformApp
	_ = json.Unmarshal([]byte(`{"frontend_api_host":"auth.acme.test","issuer":"https://i","discovery_url":"https://d","jwks_uri":"https://j","allowed_origin_integrations":{"https://a":"embedded"}}`), &app)
	if app.FrontendAPIHost == nil || app.Issuer != "https://i" || app.AllowedOriginIntegrations["https://a"] != "embedded" {
		t.Errorf("platform app = %+v", app)
	}
}

// TestLoginReadinessIntegrationAndVerification decodes the new report and
// email-address fields, and the new error codes are named.
func TestLoginReadinessIntegrationAndVerification(t *testing.T) {
	var lr LoginReadiness
	_ = json.Unmarshal([]byte(`{"object":"login_readiness","ready":true,"integration":{"assumed":"redirect","source":"declared","reason":"r"},"checks":[{"name":"cors","pass":false,"applies":false}]}`), &lr)
	if lr.Integration == nil || lr.Integration.Assumed != "redirect" || lr.Checks[0].Applies == nil || *lr.Checks[0].Applies {
		t.Errorf("login readiness = %+v", lr)
	}
	var ea EmailAddress
	_ = json.Unmarshal([]byte(`{"verified":false,"verification":{"status":"unverified","strategy":"skipped"}}`), &ea)
	if ea.Verification == nil || ea.Verification.Status != "unverified" || ea.Verification.Strategy == nil || *ea.Verification.Strategy != "skipped" {
		t.Errorf("email address = %+v", ea)
	}
	for _, code := range []string{ErrCodeReadOnlyField, ErrCodeDevelopmentEmailNotAllowed, ErrCodeDevelopmentEmailUnavailable, ErrCodeDevelopmentEmailLimitReached, ErrCodeDevelopmentEmailTemplateNotAllowed} {
		if code == "" {
			t.Error("empty code")
		}
	}
	b, _ := json.Marshal(Branding{Audiences: map[string]*BrandingAudience{"partners": {Heading: "Partners"}, "old": nil}})
	if string(b) != `{"audiences":{"old":null,"partners":{"heading":"Partners"}}}` {
		t.Errorf("branding = %s", b)
	}
}
