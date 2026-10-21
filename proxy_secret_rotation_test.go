package atlas

import (
	"context"
	"net/http"
	"testing"
)

// TestProxySecret covers get / create / rotate / delete of the trusted
// reverse proxy secret.
func TestProxySecret(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"proxy_secret","set":true,"created_at":1800000000000,"previous_expires_at":1800003600000,"secret_header":"X-Atlas-Proxy-Secret","client_ip_header":"X-Atlas-Client-IP","secret":"aps_1","rotated":true,"deleted":true}`)

	view, err := c.InstanceSecurity.ProxySecret(ctx)
	if err != nil || !view.Set || view.ClientIPHeader != "X-Atlas-Client-IP" || view.CreatedAt == nil || *view.CreatedAt != 1800000000000 {
		t.Fatalf("get = %+v, %v", view, err)
	}
	rec.expect(t, "GET", "/v1/instance/proxy_secret")

	created, err := c.InstanceSecurity.CreateProxySecret(ctx, CreateProxySecretParams{})
	if err != nil || created.Secret != "aps_1" || !created.Rotated || created.SecretHeader != "X-Atlas-Proxy-Secret" {
		t.Fatalf("create = %+v, %v", created, err)
	}
	rec.expect(t, "POST", "/v1/instance/proxy_secret")
	if rec.RawBody != `{}` {
		t.Errorf("create body = %s", rec.RawBody)
	}

	overlap := 3600
	rotated, _ := c.InstanceSecurity.CreateProxySecret(ctx, CreateProxySecretParams{OverlapSeconds: &overlap})
	if rec.RawBody != `{"overlap_seconds":3600}` || rotated.PreviousExpiresAt == nil || *rotated.PreviousExpiresAt != 1800003600000 {
		t.Errorf("rotate body = %s out = %+v", rec.RawBody, rotated)
	}
	zero := 0
	_, _ = c.InstanceSecurity.CreateProxySecret(ctx, CreateProxySecretParams{OverlapSeconds: &zero})
	if rec.RawBody != `{"overlap_seconds":0}` {
		t.Errorf("rotate now body = %s", rec.RawBody)
	}

	gone, err := c.InstanceSecurity.DeleteProxySecret(ctx)
	if err != nil || !gone.Deleted {
		t.Fatalf("delete = %+v, %v", gone, err)
	}
	rec.expect(t, "DELETE", "/v1/instance/proxy_secret")
}

// TestWebhookRotateSecretWithOverlap sends overlap_seconds and decodes the
// previous secret's expiry; RotateSecret still sends no body.
func TestWebhookRotateSecretWithOverlap(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"webhook_secret","secret":"whsec_new","overlap_seconds":600,"previous_secret_expires_at":1800000600000}`)
	overlap := 600
	out, err := c.Webhooks.Endpoints.RotateSecretWithParams(ctx, "whep_1", RotateWebhookSecretParams{OverlapSeconds: &overlap})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/webhook_endpoints/whep_1/rotate_secret")
	if rec.RawBody != `{"overlap_seconds":600}` || out.OverlapSeconds == nil || *out.OverlapSeconds != 600 || *out.PreviousSecretExpiresAt != 1800000600000 {
		t.Errorf("body=%s out=%+v", rec.RawBody, out)
	}
	_, _ = c.Webhooks.Endpoints.RotateSecret(ctx, "whep_1")
	if rec.RawBody != "" {
		t.Errorf("legacy body = %q", rec.RawBody)
	}

	c, _ = recordingClient(t, `{"object":"webhook_endpoint","id":"whep_1","previous_secret_expires_at":1800000600000}`)
	ep, err := c.Webhooks.Endpoints.Update(ctx, "whep_1", UpdateWebhookEndpointParams{})
	if err != nil || ep.PreviousSecretExpiresAt == nil || *ep.PreviousSecretExpiresAt != 1800000600000 {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
}

// TestPlatformRotationsWithOverlap covers the per-instance platform rotation
// and both Sign in with Atlas app rotations.
func TestPlatformRotationsWithOverlap(t *testing.T) {
	var got []platRecorded
	c := newRecordingClient(t, &got, func(r *http.Request) string {
		switch r.URL.Path {
		case "/v1/platform/apps/app_1/instances/ins_1/rotate_secret":
			return `{"object":"app_secret","app_id":"app_1","instance_id":"ins_1","secret":"sk_new","overlap_seconds":0,"previous_keys_expire_at":null,"note":"n"}`
		case "/v1/platform/atlas_id_apps/aia_1/rotate_secret":
			return `{"object":"atlas_id_app","id":"aia_1","client_secret":"cs_new","overlap_seconds":3600,"previous_secret_expires_at":1800003600000,"secret_issued_at":1800000000000}`
		}
		return `{"object":"atlas_id_app","id":"aia_1","webhook_secret":"whsec_new","webhook_previous_secret_expires_at":1800000600000}`
	})
	ctx := context.Background()
	zero, hour, ten := 0, 3600, 600

	is, err := c.Platform.Apps.RotateInstanceSecretWithParams(ctx, "app_1", "ins_1", RotatePlatformSecretParams{OverlapSeconds: &zero}, WithIdempotencyKey("idem-1"))
	if err != nil || is.InstanceID != "ins_1" || is.AppID != "app_1" || is.PreviousKeysExpireAt != nil || is.OverlapSeconds != 0 {
		t.Fatalf("instance rotation = %+v, %v", is, err)
	}
	last := got[len(got)-1]
	if last.Path != "/v1/platform/apps/app_1/instances/ins_1/rotate_secret" || string(last.Body) != `{"overlap_seconds":0}` || last.Auth != "Bearer psk_test" {
		t.Errorf("instance rotation request = %+v", last)
	}

	app, err := c.Platform.AtlasIDApps.RotateSecretWithParams(ctx, "aia_1", RotateAtlasIDAppSecretParams{OverlapSeconds: &hour})
	if err != nil || *app.SecretIssuedAt != 1800000000000 || *app.PreviousSecretExpiresAt != 1800003600000 || *app.OverlapSeconds != 3600 {
		t.Fatalf("app rotation = %+v, %v", app, err)
	}
	if string(got[len(got)-1].Body) != `{"overlap_seconds":3600}` {
		t.Errorf("app rotation body = %s", got[len(got)-1].Body)
	}

	hook, err := c.Platform.AtlasIDApps.RotateWebhookSecretWithParams(ctx, "aia_1", RotateAtlasIDAppSecretParams{OverlapSeconds: &ten})
	if err != nil || hook.WebhookSecret != "whsec_new" || *hook.WebhookPreviousSecretExpiresAt != 1800000600000 {
		t.Fatalf("webhook rotation = %+v, %v", hook, err)
	}
	last = got[len(got)-1]
	if last.Path != "/v1/platform/atlas_id_apps/aia_1/webhook/rotate_secret" || string(last.Body) != `{"overlap_seconds":600}` {
		t.Errorf("webhook rotation request = %+v", last)
	}
}
