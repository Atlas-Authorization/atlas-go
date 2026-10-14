package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// captureMessaging records the method, path and decoded JSON body of each request.
func captureMessaging(t *testing.T) (*Client, *[]map[string]interface{}, *[]string) {
	t.Helper()
	var bodies []map[string]interface{}
	var paths []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"messaging_provider","channel":"email","transport":"smtp","from_address":null,"status":"active","config":{"host":"smtp.acme.test"},"secrets_set":{"password":true},"updated_at":1}`))
	})
	return c, &bodies, &paths
}

func TestMessagingSetEmailProviderTyped(t *testing.T) {
	c, bodies, paths := captureMessaging(t)
	port, secure := 465, true
	p, err := c.Messaging.SetEmailProvider(context.Background(), "Acme <no-reply@acme.test>", SMTPConfig{
		Host: "smtp.acme.test", Port: &port, Secure: &secure, Password: "p",
	})
	if err != nil {
		t.Fatalf("SetEmailProvider: %v", err)
	}
	if (*paths)[0] != "PUT /v1/messaging_providers/email" {
		t.Errorf("hit %s", (*paths)[0])
	}
	want := map[string]interface{}{
		"transport":    "smtp",
		"from_address": "Acme <no-reply@acme.test>",
		// username omitted (empty) — keeps any stored value.
		"config": map[string]interface{}{"host": "smtp.acme.test", "port": float64(465), "secure": true, "password": "p"},
	}
	if !reflect.DeepEqual((*bodies)[0], want) {
		t.Errorf("body = %#v\nwant %#v", (*bodies)[0], want)
	}
	if !p.SecretsSet["password"] || p.Config["host"] != "smtp.acme.test" {
		t.Errorf("decoded provider = %+v", p)
	}
}

func TestMessagingSetEmailProviderUpdateOmitsSecret(t *testing.T) {
	c, bodies, _ := captureMessaging(t)
	if _, err := c.Messaging.SetEmailProvider(context.Background(), "new@acme.test", ResendConfig{}); err != nil {
		t.Fatalf("SetEmailProvider: %v", err)
	}
	want := map[string]interface{}{
		"transport": "resend", "from_address": "new@acme.test", "config": map[string]interface{}{},
	}
	if !reflect.DeepEqual((*bodies)[0], want) {
		t.Errorf("body = %#v\nwant %#v", (*bodies)[0], want)
	}
}

func TestMessagingSetSMSProviderTyped(t *testing.T) {
	c, bodies, paths := captureMessaging(t)
	cases := []struct {
		cfg       SMSProviderConfig
		transport string
		config    map[string]interface{}
	}{
		{TwilioConfig{AccountSID: "AC1", AuthToken: "t", WhatsAppFrom: "+1"}, "twilio",
			map[string]interface{}{"account_sid": "AC1", "auth_token": "t", "whatsapp_from": "+1"}},
		{AWSSNSConfig{Region: "us-east-1", AccessKeyID: "AK", SecretAccessKey: "s"}, "aws_sns",
			map[string]interface{}{"region": "us-east-1", "access_key_id": "AK", "secret_access_key": "s"}},
		{InfobipConfig{BaseURL: "https://x.api.infobip.com", APIKey: "k", From: "Acme"}, "infobip",
			map[string]interface{}{"base_url": "https://x.api.infobip.com", "api_key": "k", "from": "Acme"}},
	}
	for i, tc := range cases {
		if _, err := c.Messaging.SetSMSProvider(context.Background(), "", tc.cfg); err != nil {
			t.Fatalf("SetSMSProvider: %v", err)
		}
		if (*paths)[i] != "PUT /v1/messaging_providers/sms" {
			t.Errorf("hit %s", (*paths)[i])
		}
		want := map[string]interface{}{"transport": tc.transport, "config": tc.config}
		if !reflect.DeepEqual((*bodies)[i], want) {
			t.Errorf("body = %#v\nwant %#v", (*bodies)[i], want)
		}
	}
}

// Every typed config maps to one of the API's transports, on the right channel.
func TestMessagingTransportsCoverAPI(t *testing.T) {
	email := []EmailProviderConfig{ResendConfig{}, SESConfig{}, SMTPConfig{}, BrevoConfig{}, MailgunConfig{}}
	sms := []SMSProviderConfig{TwilioConfig{}, VonageConfig{}, MessageBirdConfig{}, PlivoConfig{}, TelnyxConfig{},
		SinchConfig{}, InfobipConfig{}, ClickSendConfig{}, BandwidthConfig{}, AWSSNSConfig{}}
	var gotE, gotS []string
	for _, c := range email {
		gotE = append(gotE, c.emailTransport())
	}
	for _, c := range sms {
		gotS = append(gotS, c.smsTransport())
	}
	if !reflect.DeepEqual(gotE, []string{"resend", "ses", "smtp", "brevo", "mailgun"}) {
		t.Errorf("email transports = %v", gotE)
	}
	if !reflect.DeepEqual(gotS, []string{"twilio", "vonage", "messagebird", "plivo", "telnyx", "sinch", "infobip", "clicksend", "bandwidth", "aws_sns"}) {
		t.Errorf("sms transports = %v", gotS)
	}
}

// The untyped input still works unchanged.
func TestMessagingSetEmailLegacyInput(t *testing.T) {
	c, bodies, _ := captureMessaging(t)
	_, err := c.Messaging.SetEmail(context.Background(), MessagingProviderInput{
		Transport: "resend", Config: map[string]interface{}{"api_key": "re_x"},
	})
	if err != nil {
		t.Fatalf("SetEmail: %v", err)
	}
	want := map[string]interface{}{"transport": "resend", "config": map[string]interface{}{"api_key": "re_x"}}
	if !reflect.DeepEqual((*bodies)[0], want) {
		t.Errorf("body = %#v", (*bodies)[0])
	}
}
