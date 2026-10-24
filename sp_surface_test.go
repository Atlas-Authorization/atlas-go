package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSuiteSpecWireSurface walks the routes added by the integrator-spec
// program: method, path, query and body for each.
func TestSuiteSpecWireSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","data":[],"changes":[],"problems":[],"results":[]}`, WithPlatformKey("psk_test"))
	on := true
	ttl := 3600
	overlap := 0

	cases := []struct {
		method, path, query, body string
		call                      func() error
	}{
		// credentials
		{"GET", "/v1/whoami", "", "", func() error { _, err := c.Whoami(ctx); return err }},
		{"POST", "/v1/secret_keys", "", `{"name":"ci","scopes":["read_only"],"key_format":"legacy"}`, func() error {
			_, err := c.SecretKeys.Create(ctx, CreateSecretKeyParams{Name: "ci", Scopes: []string{"read_only"}, KeyFormat: "legacy"})
			return err
		}},
		{"POST", "/v1/secret_keys", "", `{"scopes":["a"],"expires_at":"2027-01-01T00:00:00Z"}`, func() error {
			_, err := c.SecretKeys.Create(ctx, CreateSecretKeyParams{Scopes: []string{"a"}, ExpiresAtISO: "2027-01-01T00:00:00Z"})
			return err
		}},
		{"GET", "/v1/secret_keys", "", "", func() error { _, err := c.SecretKeys.List(ctx); return err }},
		{"GET", "/v1/secret_keys/key_1", "", "", func() error { _, err := c.SecretKeys.Get(ctx, "key_1"); return err }},
		{"PATCH", "/v1/secret_keys/key_1", "", `{"name":"x","owner":null}`, func() error {
			_, err := c.SecretKeys.Update(ctx, "key_1", UpdateSecretKeyParams{Name: "x", Clear: []string{"owner"}})
			return err
		}},
		{"POST", "/v1/secret_keys/key_1/rotate", "", `{"overlap_seconds":0}`, func() error {
			_, err := c.SecretKeys.Rotate(ctx, "key_1", RotateSecretKeyParams{OverlapSeconds: &overlap})
			return err
		}},
		{"POST", "/v1/secret_keys/key_1/revoke", "", "", func() error { _, err := c.SecretKeys.Revoke(ctx, "key_1"); return err }},
		{"GET", "/v1/keys", "", "", func() error { _, err := c.Keys.List(ctx); return err }},
		{"POST", "/v1/partner_links", "", `{"partner":"cookiemunch","scopes":["privacy:execute"]}`, func() error {
			_, err := c.PartnerLinks.Create(ctx, CreatePartnerLinkParams{Partner: "cookiemunch", Scopes: []string{"privacy:execute"}})
			return err
		}},
		{"GET", "/v1/partner_links", "", "", func() error { _, err := c.PartnerLinks.List(ctx); return err }},
		{"GET", "/v1/partner_links/pl_1", "", "", func() error { _, err := c.PartnerLinks.Get(ctx, "pl_1"); return err }},
		{"POST", "/v1/partner_links/pl_1/rotate_secret", "", "", func() error { _, err := c.PartnerLinks.RotateSecret(ctx, "pl_1"); return err }},
		{"DELETE", "/v1/partner_links/pl_1", "", "", func() error { _, err := c.PartnerLinks.Revoke(ctx, "pl_1"); return err }},
		{"GET", "/v1/partner_links/outbound", "", "", func() error { _, err := c.PartnerLinks.Outbound.List(ctx); return err }},
		{"PUT", "/v1/partner_links/outbound/cookiemunch", "", `{"client_id":"cid","client_secret":"sec"}`, func() error {
			_, err := c.PartnerLinks.Outbound.Save(ctx, "cookiemunch", SaveOutboundPartnerLinkParams{ClientID: "cid", ClientSecret: "sec"})
			return err
		}},
		{"POST", "/v1/partner_links/outbound/cookiemunch/test", "", "", func() error { _, err := c.PartnerLinks.Outbound.Test(ctx, "cookiemunch"); return err }},
		{"DELETE", "/v1/partner_links/outbound/cookiemunch", "", "", func() error { _, err := c.PartnerLinks.Outbound.Remove(ctx, "cookiemunch"); return err }},
		{"GET", "/v1/atlas_id_apps", "", "", func() error { _, err := c.AtlasIDGrants.ListApps(ctx); return err }},
		{"GET", "/v1/atlas_id_apps/app_1/users", "email=a%40b.com", "", func() error { _, err := c.AtlasIDGrants.Lookup(ctx, "app_1", "a@b.com"); return err }},
		{"DELETE", "/v1/atlas_id_apps/app_1/grants/g_1", "", "", func() error { _, err := c.AtlasIDGrants.Revoke(ctx, "app_1", "g_1"); return err }},
		// platform credentials, audit and provisioning
		{"GET", "/v1/platform/whoami", "", "", func() error { _, err := c.Platform.Whoami(ctx); return err }},
		{"GET", "/v1/platform/keys", "kind=secret_key&status=active", "", func() error {
			_, err := c.Platform.Keys.List(ctx, ListPlatformKeysParams{Kind: "secret_key", Status: "active"})
			return err
		}},
		{"POST", "/v1/platform/keys", "", `{"scopes":["apps:read"],"key_format":"atlas"}`, func() error {
			_, err := c.Platform.Keys.Create(ctx, CreatePlatformKeyParams{Scopes: []string{"apps:read"}, KeyFormat: "atlas"})
			return err
		}},
		{"PATCH", "/v1/platform/keys/k_1", "", `{"name":"n"}`, func() error {
			_, err := c.Platform.Keys.Update(ctx, "k_1", UpdatePlatformKeyParams{Name: "n"})
			return err
		}},
		{"POST", "/v1/platform/keys/k_1/revoke", "", "", func() error { _, err := c.Platform.Keys.Revoke(ctx, "k_1"); return err }},
		{"GET", "/v1/platform/audit_logs", "action=app.created&limit=5", "", func() error {
			_, err := c.Platform.Audit.List(ctx, ListAccountAuditParams{ListParams: ListParams{Limit: 5}, Action: "app.created"})
			return err
		}},
		{"GET", "/v1/platform/audit_streams", "", "", func() error { _, err := c.Platform.Audit.Streams.List(ctx); return err }},
		{"POST", "/v1/platform/audit_streams", "", `{"url":"https://x.example.com/a","format":"cloudevents"}`, func() error {
			_, err := c.Platform.Audit.Streams.Create(ctx, CreateAccountAuditStreamParams{URL: "https://x.example.com/a", Format: "cloudevents"})
			return err
		}},
		{"PATCH", "/v1/platform/audit_streams/s_1", "", `{"active":true}`, func() error {
			_, err := c.Platform.Audit.Streams.Update(ctx, "s_1", UpdateAccountAuditStreamParams{Active: &on})
			return err
		}},
		{"DELETE", "/v1/platform/audit_streams/s_1", "", "", func() error { _, err := c.Platform.Audit.Streams.Delete(ctx, "s_1"); return err }},
		{"POST", "/v1/platform/audit_streams/s_1/test", "", "", func() error { _, err := c.Platform.Audit.Streams.Test(ctx, "s_1"); return err }},
		{"POST", "/v1/platform/apps", "", `{"name":"A","external_ref":"ref-1","metadata":{"product":"x","sandbox":true}}`, func() error {
			_, err := c.Platform.Apps.Create(ctx, CreatePlatformAppParams{Name: "A", ProvisioningInput: ProvisioningInput{ExternalRef: "ref-1", Metadata: map[string]interface{}{"product": "x", "sandbox": true}}})
			return err
		}},
		{"GET", "/v1/platform/apps", "metadata%5Bproduct%5D=x", "", func() error {
			_, err := c.Platform.Apps.List(ctx, ListPlatformAppsParams{Metadata: map[string]interface{}{"product": "x"}})
			return err
		}},
		{"POST", "/v1/platform/apps/app_1/secret_keys", "", `{"name":"ci","external_ref":"k-1"}`, func() error {
			_, err := c.Platform.Apps.CreateSecretKey(ctx, "app_1", CreatePlatformSecretKeyParams{Name: "ci", ProvisioningInput: ProvisioningInput{ExternalRef: "k-1"}})
			return err
		}},
		{"GET", "/v1/platform/apps/app_1/secret_keys", "metadata%5Benv%5D=ci", "", func() error {
			_, err := c.Platform.Apps.SecretKeysWithMetadata(ctx, "app_1", map[string]interface{}{"env": "ci"})
			return err
		}},
		{"POST", "/v1/platform/apps/app_1/clone_config", "", `{"dry_run":true,"to_environment":"development"}`, func() error {
			_, err := c.Platform.Apps.CloneConfig(ctx, "app_1", CloneConfigParams{ToEnvironment: "development", DryRun: true})
			return err
		}},
		{"POST", "/v1/platform/apps/bulk_delete", "", `{"dry_run":true,"metadata":{"sandbox":true}}`, func() error {
			_, err := c.Platform.Apps.SandboxTeardown(ctx, nil, true)
			return err
		}},
		{"GET", "/v1/platform/atlas_id_apps", "metadata%5Bk%5D=v", "", func() error {
			_, err := c.Platform.AtlasIDApps.ListWithMetadata(ctx, map[string]interface{}{"k": "v"})
			return err
		}},
		// webhooks
		{"GET", "/v1/webhook_endpoints/we_1", "", "", func() error { _, err := c.Webhooks.Endpoints.Get(ctx, "we_1"); return err }},
		{"GET", "/v1/webhook_endpoints", "include_deprecated=true&metadata%5Ba%5D=b", "", func() error {
			_, err := c.Webhooks.Endpoints.ListWithParams(ctx, ListWebhookEndpointsParams{IncludeDeprecated: true, Metadata: map[string]interface{}{"a": "b"}})
			return err
		}},
		{"PUT", "/v1/webhook_endpoints/by_url", "", `{"url":"https://app.example.com/hook","signature_versions":["v1","v2"],"event_naming":"canonical"}`, func() error {
			_, err := c.Webhooks.Endpoints.UpsertByURL(ctx, UpsertWebhookEndpointParams{URL: "https://app.example.com/hook", WebhookEndpointSettings: WebhookEndpointSettings{SignatureVersions: []string{"v1", "v2"}, EventNaming: "canonical"}})
			return err
		}},
		{"POST", "/v1/webhook_endpoints", "", `{"enabled_events":["*"],"destination":{"type":"aws_eventbridge","region":"us-east-1","event_bus_name":"default"},"destination_credentials":{"access_key_id":"a","secret_access_key":"b"}}`, func() error {
			_, err := c.Webhooks.Endpoints.Create(ctx, CreateWebhookEndpointParams{EnabledEvents: []string{"*"}, WebhookEndpointSettings: WebhookEndpointSettings{
				Destination:            &WebhookDestination{Type: WebhookDestinationAWSEventBridge, Region: "us-east-1", EventBusName: "default"},
				DestinationCredentials: WebhookDestinationCredentials{"access_key_id": "a", "secret_access_key": "b"},
			}})
			return err
		}},
		{"POST", "/v1/webhook_endpoints/we_1/test", "wait=5s", "", func() error { _, err := c.Webhooks.Endpoints.TestNow(ctx, "we_1", "5s"); return err }},
		{"POST", "/v1/webhook_endpoints/we_1/redeliver", "", `{"since":5,"status":"failed"}`, func() error {
			_, err := c.Webhooks.Endpoints.RedeliverWindow(ctx, "we_1", RedeliverWebhookWindowParams{WebhookWindow: WebhookWindow{Since: 5}, Status: "failed"})
			return err
		}},
		{"POST", "/v1/webhook_endpoints/we_1/replay", "", `{"since":9,"event_type":"user.created"}`, func() error {
			_, err := c.Webhooks.Endpoints.Replay(ctx, "we_1", ReplayWebhookParams{WebhookWindow: WebhookWindow{Since: 9}, EventType: "user.created"})
			return err
		}},
		{"GET", "/v1/webhook_endpoints/we_1/deliveries", "event_type=user.created&limit=500&since=1&starting_after=c&status=failed&until=2", "", func() error {
			_, err := c.Webhooks.Endpoints.DeliveriesWithParams(ctx, "we_1", ListWebhookDeliveriesParams{Limit: 500, StartingAfter: "c", Status: "failed", EventType: "user.created", Since: 1, Until: 2})
			return err
		}},
		{"GET", "/v1/meta/egress_ips", "", "", func() error { _, err := c.Delivery.EgressIPs(ctx); return err }},
		{"GET", "/v1/delivery_health", "kind=webhook_endpoint&state=unhealthy", "", func() error {
			_, err := c.Delivery.Health(ctx, DeliveryHealthParams{Kind: DeliveryTargetWebhookEndpoint, State: "unhealthy"})
			return err
		}},
		{"PUT", "/v1/delivery_health/webhook_endpoint/we_1/alert_contacts", "", `{"alert_contacts":["a@b.com"]}`, func() error {
			_, err := c.Delivery.SetAlertContacts(ctx, DeliveryTargetWebhookEndpoint, "we_1", []string{"a@b.com"})
			return err
		}},
		// events, users, audit
		{"GET", "/v1/events", "order=desc&since=2026-01-01T00%3A00%3A00Z", "", func() error {
			_, err := c.Analytics.Events(ctx, ListActivityEventsParams{Since: mustTime(t, "2026-01-01T00:00:00Z"), Order: "desc"})
			return err
		}},
		{"GET", "/v1/users", "order_by=-updated_at&updated_after=100&updated_before=200", "", func() error {
			_, err := c.Users.Search(ctx, UserListParams{UpdatedAfter: 100, UpdatedBefore: 200, OrderBy: "-updated_at"})
			return err
		}},
		{"GET", "/v1/organizations/org_1/memberships", "limit=2&starting_after=c", "", func() error {
			_, err := c.Organizations.Memberships.ListWithParams(ctx, "org_1", ListParams{Limit: 2, StartingAfter: "c"})
			return err
		}},
		{"GET", "/v1/app_roles/admin/users", "limit=2&starting_after=c", "", func() error {
			_, err := c.AppRoles.ListUsersWithParams(ctx, "admin", ListParams{Limit: 2, StartingAfter: "c"})
			return err
		}},
		{"GET", "/v1/logout_notify_endpoints/lne_1/deliveries", "starting_after=c", "", func() error {
			_, err := c.LogoutNotifyEndpoints.DeliveriesWithParams(ctx, "lne_1", ListParams{StartingAfter: "c"})
			return err
		}},
		{"GET", "/v1/api_keys/revoked", "starting_after=c", "", func() error {
			_, err := c.APIKeys.ListRevoked(ctx, ListRevokedAPIKeysParams{StartingAfter: "c"})
			return err
		}},
		{"GET", "/v1/messaging_providers/email", "", "", func() error { _, err := c.Messaging.Channel(ctx, "email"); return err }},
		{"GET", "/v1/config_changelog", "include_no_op=false", "", func() error {
			off := false
			_, err := c.Diagnostics.ConfigChangelog(ctx, ConfigChangelogParams{IncludeNoOp: &off})
			return err
		}},
		{"POST", "/v1/oauth_clients", "", `{"name":"A","redirect_uris":["https://a/cb"],"require_pkce":false,"external_ref":"r"}`, func() error {
			off := false
			_, err := c.OAuthClients.Create(ctx, CreateOAuthClientParams{Name: "A", RedirectURIs: []string{"https://a/cb"}, RequirePKCE: &off, ProvisioningInput: ProvisioningInput{ExternalRef: "r"}})
			return err
		}},
		{"GET", "/v1/oauth_clients", "metadata%5Bk%5D=v", "", func() error {
			_, err := c.OAuthClients.ListWithMetadata(ctx, map[string]interface{}{"k": "v"})
			return err
		}},
		// privacy executor
		{"GET", "/v1/privacy", "", "", func() error { _, err := c.Privacy.Discover(ctx); return err }},
		{"GET", "/v1/privacy/presets/cookiemunch", "", "", func() error { _, err := c.Privacy.Preset(ctx, "cookiemunch"); return err }},
		{"POST", "/v1/privacy/lookup", "", `{"atlas":{"iss":"https://i","sub":"u1"},"emails":["a@b.com"]}`, func() error {
			_, err := c.Privacy.Lookup(ctx, PrivacyLookupParams{Emails: []string{"a@b.com"}, Atlas: &PrivacySubject{Iss: "https://i", Sub: "u1"}})
			return err
		}},
		{"POST", "/v1/privacy/requests", "", `{"subjectId":"u1","type":"deletion","caseId":"c1","executeAfter":1700000000000}`, func() error {
			_, err := c.Privacy.CreateRequest(ctx, CreatePrivacyRequestParams{SubjectID: "u1", Type: PrivacyTypeDeletion, CaseID: "c1", ExecuteAfterMS: 1700000000000}, WithIdempotencyKey("k"))
			return err
		}},
		{"GET", "/v1/privacy/requests/pr_1", "", "", func() error { _, err := c.Privacy.GetRequest(ctx, "pr_1"); return err }},
		{"POST", "/v1/privacy/requests/pr_1/cancel", "", "", func() error { _, err := c.Privacy.CancelRequest(ctx, "pr_1"); return err }},
		{"GET", "/v1/instance/privacy_orchestrator", "", "", func() error { _, err := c.Privacy.Orchestrator.Get(ctx); return err }},
		{"PUT", "/v1/instance/privacy_orchestrator", "", `{"provider":"cookiemunch","sign_requests":true,"cancel_url":null}`, func() error {
			_, err := c.Privacy.Orchestrator.Set(ctx, SetPrivacyOrchestratorParams{Provider: "cookiemunch", SignRequests: &on, Clear: []string{"cancel_url"}})
			return err
		}},
		{"DELETE", "/v1/instance/privacy_orchestrator", "", "", func() error { _, err := c.Privacy.Orchestrator.Delete(ctx); return err }},
		// integrations
		{"GET", "/v1/instance/integrations", "", "", func() error { _, err := c.Instance.ListIntegrations(ctx); return err }},
		{"GET", "/v1/instance/integrations/chatly", "", "", func() error { _, err := c.Instance.GetIntegration(ctx, "chatly"); return err }},
		{"PUT", "/v1/instance/integrations/acme", "dry_run=true", `{"enabled":true,"name":"Acme","ttl_seconds":3600,"events_url":null}`, func() error {
			_, err := c.Instance.SetIntegration(ctx, "acme", SetIntegrationParams{Enabled: &on, Name: "Acme", TTLSeconds: ttl, Clear: []string{"events_url"}}, WithDryRun())
			return err
		}},
		{"DELETE", "/v1/instance/integrations/acme", "", "", func() error { _, err := c.Instance.DeleteIntegration(ctx, "acme"); return err }},
		{"GET", "/v1/instance/integrations/acme/deliveries", "kind=event&limit=5&trace=t1", "", func() error {
			_, err := c.Instance.IntegrationDeliveries(ctx, "acme", ListIntegrationDeliveriesParams{Limit: 5, Trace: "t1", Kind: "event"})
			return err
		}},
		{"POST", "/v1/instance/integrations/acme/events_secret", "", "", func() error { _, err := c.Instance.RevealIntegrationEventsSecret(ctx, "acme"); return err }},
		{"POST", "/v1/instance/integrations/acme/atlas_id_tokens", "", `{"access_token":"at"}`, func() error {
			_, err := c.Instance.IntegrationAtlasIDToken(ctx, "acme", "at")
			return err
		}},
		{"POST", "/v1/sessions/sess_1/integration_tokens/chatly", "", "", func() error { _, err := c.Sessions.GetIntegrationToken(ctx, "sess_1", "chatly"); return err }},
		{"POST", "/v1/sessions/sess_1/tokens/supabase", "", "", func() error { _, err := c.Sessions.CreateTemplateToken(ctx, "sess_1", "supabase"); return err }},
		{"POST", "/v1/integrations/verify_errors", "", `{"integration":"chatly","error":"expired"}`, func() error {
			_, err := c.Integrations.ReportVerifyError(ctx, ReportVerifyErrorParams{Integration: "chatly", Error: IntegrationVerifyExpired})
			return err
		}},
		{"GET", "/v1/integrations/chatly/card", "iss=https%3A%2F%2Fi&sub=u1", "", func() error { _, err := c.Integrations.Card(ctx, "chatly", "u1", "https://i"); return err }},
		{"POST", "/v1/integrations/chatly/card/actions/revoke_sessions", "", `{"agent":{"name":"Ann"},"sub":"u1"}`, func() error {
			_, err := c.Integrations.RevokeSessions(ctx, "chatly", "u1", "", &IntegrationAgent{Name: "Ann"})
			return err
		}},
		{"GET", "/v1/public/instances/ins_1", "", "", func() error { _, err := c.Integrations.InstanceMetadata(ctx, "ins_1"); return err }},
		// entitlements, notices, advisories, sub-processors, audit export
		{"GET", "/v1/entitlements", "subject_id=org_1&subject_type=org", "", func() error { _, err := c.Entitlements.Get(ctx, "org", "org_1"); return err }},
		{"GET", "/v1/instance/notices", "all=true", "", func() error { _, err := c.Notices.List(ctx, true); return err }},
		{"POST", "/v1/instance/notices/n_1/acknowledge", "", "", func() error { _, err := c.Notices.Acknowledge(ctx, "n_1"); return err }},
		{"GET", "/v1/security_advisories", "", "", func() error { _, err := c.SecurityAdvisories.List(ctx); return err }},
		{"POST", "/v1/security_advisories/a_1/acknowledge", "", "", func() error { _, err := c.SecurityAdvisories.Acknowledge(ctx, "a_1"); return err }},
		{"GET", "/v1/public/security_advisories", "", "", func() error { _, err := c.SecurityAdvisories.Catalog(ctx); return err }},
		{"GET", "/v1/instance/sub_processors", "", "", func() error { _, err := c.SubProcessors.Get(ctx); return err }},
		{"GET", "/v1/audit_exports", "", "", func() error { _, err := c.AuditExports.List(ctx); return err }},
		{"GET", "/v1/audit_exports/ae_1", "", "", func() error { _, err := c.AuditExports.Get(ctx, "ae_1"); return err }},
		{"POST", "/v1/audit_exports", "", `{"name":"siem","type":"webhook","destination":{"url":"https://siem.example.com"},"backfill_hours":24}`, func() error {
			_, err := c.AuditExports.Create(ctx, CreateAuditExportParams{Name: "siem", Type: "webhook", Destination: map[string]interface{}{"url": "https://siem.example.com"}, BackfillHours: 24})
			return err
		}},
		{"PATCH", "/v1/audit_exports/ae_1", "", `{"action_filter":null,"enabled":true}`, func() error {
			_, err := c.AuditExports.Update(ctx, "ae_1", UpdateAuditExportParams{Enabled: &on, ClearActionFilter: true})
			return err
		}},
		{"DELETE", "/v1/audit_exports/ae_1", "", "", func() error { _, err := c.AuditExports.Delete(ctx, "ae_1"); return err }},
		{"POST", "/v1/audit_exports/ae_1/test", "", "", func() error { _, err := c.AuditExports.Test(ctx, "ae_1"); return err }},
		{"POST", "/v1/audit_exports/ae_1/rotate_secret", "", "", func() error { _, err := c.AuditExports.RotateSecret(ctx, "ae_1"); return err }},
		// status
		{"GET", "/v1/status", "", "", func() error { _, err := c.Status.Service(ctx); return err }},
		{"GET", "/v1/instance/status_subscription", "", "", func() error { _, err := c.Status.GetSubscription(ctx); return err }},
		{"PUT", "/v1/instance/status_subscription", "", `{"component_ids":[],"min_impact":"major","regions":["eu"]}`, func() error {
			_, err := c.Status.UpdateSubscription(ctx, UpdateStatusSubscriptionParams{Regions: []string{"eu"}, ComponentIDs: []string{}, MinImpact: "major"})
			return err
		}},
		{"DELETE", "/v1/instance/status_subscription", "", "", func() error { _, err := c.Status.DisableSubscription(ctx); return err }},
		{"POST", "/v1/instance/status_subscription/rotate_feed", "", "", func() error { _, err := c.Status.RotateFeed(ctx); return err }},
		{"GET", "/v1/instance/status_incidents", "limit=3&open=true", "", func() error {
			_, err := c.Status.ListIncidents(ctx, ListStatusIncidentsParams{Open: true, Limit: 3})
			return err
		}},
		{"GET", "/v1/instance/status_dependencies", "", "", func() error { _, err := c.Status.ListDependencies(ctx); return err }},
		{"POST", "/v1/instance/status_dependencies", "", `{"name":"Stripe","url":"https://status.stripe.com"}`, func() error {
			_, err := c.Status.CreateDependency(ctx, CreateStatusDependencyParams{Name: "Stripe", URL: "https://status.stripe.com"})
			return err
		}},
		{"GET", "/v1/instance/status_dependencies/d_1", "", "", func() error { _, err := c.Status.GetDependency(ctx, "d_1"); return err }},
		{"PATCH", "/v1/instance/status_dependencies/d_1", "", `{"enabled":true}`, func() error {
			_, err := c.Status.UpdateDependency(ctx, "d_1", UpdateStatusDependencyParams{Enabled: &on})
			return err
		}},
		{"DELETE", "/v1/instance/status_dependencies/d_1", "", "", func() error { _, err := c.Status.DeleteDependency(ctx, "d_1"); return err }},
		{"POST", "/v1/instance/status_dependencies/d_1/refresh", "", "", func() error { _, err := c.Status.RefreshDependency(ctx, "d_1"); return err }},
		// instance extras
		{"GET", "/v1/instance/preflight", "include_suppressed=true&min_severity=warning", "", func() error {
			_, err := c.Instance.PreflightWithParams(ctx, PreflightParams{MinSeverity: "warning", IncludeSuppressed: true})
			return err
		}},
		{"GET", "/v1/instance/unknown_fields_report", "days=7", "", func() error { _, err := c.Instance.UnknownFieldsReport(ctx, 7); return err }},
		{"GET", "/v1/openapi/diff", "since=2026-10-01&surface=bapi", "", func() error { _, err := c.Instance.OpenAPIDiff(ctx, "2026-10-01", "bapi"); return err }},
		{"GET", "/v1/integration-health", "only=webhooks%2Cemail&probe=false", "", func() error {
			_, err := c.Instance.IntegrationHealth(ctx, IntegrationHealthParams{Only: []string{"webhooks", "email"}, NoProbe: true})
			return err
		}},
		{"GET", "/v1/integration-health/providers", "", "", func() error { _, err := c.Instance.IntegrationHealthProviders(ctx); return err }},
		{"GET", "/v1/embed", "instance=ins_1&origin=https%3A%2F%2Fapp.example.com&shape=button", "", func() error {
			_, err := c.Instance.Embed(ctx, EmbedParams{Instance: "ins_1", Origin: "https://app.example.com", Shape: "button"})
			return err
		}},
		{"PUT", "/v1/instance/design", "", `{"brand_url":"https://brand.example.com/tokens.json"}`, func() error {
			_, err := c.Design.ImportBrandURL(ctx, "https://brand.example.com/tokens.json")
			return err
		}},
		{"PUT", "/v1/instance/design", "", `{"brand":null}`, func() error { _, err := c.Design.RemoveBrand(ctx); return err }},
		// referrals
		{"POST", "/v1/instance/referrals/referalli/install", "", `{"return_to":"https://app.example.com/done"}`, func() error {
			_, err := c.Referrals.Install(ctx, "referalli", InstallReferralParams{ReturnTo: "https://app.example.com/done"})
			return err
		}},
	}
	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.path, err)
			continue
		}
		rec.expect(t, tc.method, tc.path)
		if rec.Query != tc.query {
			t.Errorf("%s %s query = %q, want %q", tc.method, tc.path, rec.Query, tc.query)
		}
		if tc.body == "" {
			if rec.RawBody != "" {
				t.Errorf("%s %s unexpected body %s", tc.method, tc.path, rec.RawBody)
			}
			continue
		}
		var want map[string]interface{}
		_ = json.Unmarshal([]byte(tc.body), &want)
		got, _ := json.Marshal(rec.Body)
		exp, _ := json.Marshal(want)
		if string(got) != string(exp) {
			t.Errorf("%s %s body = %s, want %s", tc.method, tc.path, got, exp)
		}
	}
}

func TestDryRunAndTraceparentOptions(t *testing.T) {
	ctx := context.Background()
	var gotTrace, gotIdem, gotRecipient string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotTrace = r.Header.Get("traceparent")
		gotIdem = r.Header.Get("Idempotency-Key")
		gotRecipient = r.Header.Get("X-Secret-Recipient")
		_, _ = w.Write([]byte(`{"object":"dry_run","dry_run":true,"mode":"plan","validated":false,"method":"PATCH","path":"/v1/x","changes":[{"section":"name","before":"a","after":"b"}],"note":"n"}`))
	})
	WithSecretRecipient("x25519:AAAA")(c)
	tp := NewTraceparent()
	if _, _, _, ok := ParseTraceparent(tp); !ok {
		t.Fatalf("NewTraceparent produced %q", tp)
	}
	plan, err := c.DryRun(ctx, "patch", "/v1/x", map[string]string{"name": "b"}, WithIdempotencyKey("k"), WithTraceparent(tp))
	if err != nil || !plan.DryRun || plan.Mode != "plan" || len(plan.Changes) != 1 || plan.Changes[0].Section != "name" {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if gotTrace != tp {
		t.Errorf("traceparent = %q, want %q", gotTrace, tp)
	}
	if gotIdem != "" {
		t.Errorf("Idempotency-Key sent on a dry run: %q", gotIdem)
	}
	if gotRecipient != "x25519:AAAA" {
		t.Errorf("X-Secret-Recipient = %q", gotRecipient)
	}
}

func TestTraceparentParsing(t *testing.T) {
	good := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tid, sid, flags, ok := ParseTraceparent(good)
	if !ok || tid != "4bf92f3577b34da6a3ce929d0e0e4736" || sid != "00f067aa0ba902b7" || flags != "01" {
		t.Errorf("parse = %q %q %q %v", tid, sid, flags, ok)
	}
	for _, bad := range []string{"", "xx", "00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-" + strings.Repeat("0", 16) + "-01"} {
		if _, _, _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	h := http.Header{}
	h.Set("traceparent", good)
	if TraceparentFromHeader(h) != good {
		t.Error("TraceparentFromHeader")
	}
	h.Set("traceparent", "junk")
	if TraceparentFromHeader(h) != "" {
		t.Error("TraceparentFromHeader accepted junk")
	}
}

func TestKeyFormats(t *testing.T) {
	cases := []struct {
		key  string
		kind KeyKind
		env  string
		ok   bool
	}{
		{"atlas_live_sk_AbC123", KeyKindSecret, "live", true},
		{"atlas_test_psk_AbC123", KeyKindPlatform, "test", true},
		{"atlas_live_whsec_x", KeyKindWebhookSecret, "live", true},
		{"atlas_live_pl_x", KeyKindPartnerLink, "live", true},
		{"atlas_live_at_x", KeyKindAccessToken, "live", true},
		{"sk_live_abc", KeyKindSecret, "live", true},
		{"sk_test_abc", KeyKindSecret, "test", true},
		{"pk_live_abc", KeyKindPublishable, "live", true},
		{"psk_abc", KeyKindPlatform, "", true},
		{"psk_live_abc", KeyKindPlatform, "live", true},
		{"whsec_abc", KeyKindWebhookSecret, "", true},
		{"atlas_live_zz_x", "", "", false},
		{"atlas_prod_sk_x", "", "", false},
		{"sk_prod_x", "", "", false},
		{"hello", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		p, ok := ParseKeyPrefix(c.key)
		if ok != c.ok || (ok && (p.Kind != c.kind || p.Environment != c.env)) {
			t.Errorf("ParseKeyPrefix(%q) = %+v %v, want %v %q %v", c.key, p, ok, c.kind, c.env, c.ok)
		}
	}
	if !IsSecretKey("atlas_live_sk_x") || !IsSecretKey("sk_live_x") || IsSecretKey("psk_x") {
		t.Error("IsSecretKey")
	}
	if !IsPlatformKey("atlas_live_psk_x") || !IsPlatformKey("psk_x") || IsPlatformKey("sk_live_x") {
		t.Error("IsPlatformKey")
	}
	if !IsPublishableKey("pk_test_x") || !IsWebhookSecret("whsec_x") || !IsPartnerLinkSecret("atlas_live_pl_x") || !IsAccessToken("atlas_live_at_x") {
		t.Error("kind helpers")
	}
}

func TestErrorCodesAndHelpers(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errors":[{"code":"ROUTE_NOT_FOUND","message":"no route","docs_url":"https://atlasauth.net/errors/ROUTE_NOT_FOUND","did_you_mean":["/v1/users"],"allowed_methods":["GET"]}]}`))
	})
	_, err := c.Users.Get(ctx, "x")
	apiErr, ok := err.(*APIError)
	if !ok || !apiErr.IsRouteNotFound() || len(apiErr.DidYouMean()) != 1 || apiErr.Errors[0].AllowedMethods[0] != "GET" || apiErr.Errors[0].DocsURL == "" {
		t.Fatalf("err = %#v", err)
	}
	scope := &APIError{Status: 403, Errors: []ErrorItem{{Code: "SCOPE_MISSING", Meta: map[string]interface{}{"required_scope": "users:write"}}}}
	if !scope.IsInsufficientScope() || scope.RequiredScope() != "users:write" {
		t.Error("legacy SCOPE_MISSING not tolerated")
	}
	scope2 := &APIError{Status: 403, Errors: []ErrorItem{{Code: ErrCodeInsufficientScope, Meta: map[string]interface{}{"required_scope": "a"}}}}
	if !scope2.IsInsufficientScope() || scope2.RequiredScope() != "a" || scope2.IsStepUpRequired() {
		t.Error("INSUFFICIENT_SCOPE")
	}
	if !(&APIError{Errors: []ErrorItem{{Code: ErrCodeStepUpRequired}}}).IsStepUpRequired() {
		t.Error("STEP_UP_REQUIRED")
	}
}

func TestIntegrationDecodeKeepsRawAndHealth(t *testing.T) {
	ctx := context.Background()
	c, _ := recordingClient(t, `{"object":"integration","id":"chatly","product":"chatly","preset":"chatly","enabled":true,"connected":true,"channel":"support","external_ref":"r1","health":{"last_minted_at":5,"mints_24h":3,"verify_errors_24h":0,"last_verify_error":null,"events":{"url":"https://e","endpoint_id":"we_1","state":"failing","failing_since":1,"consecutive_failures":4,"last_failure":{"at":2,"status":500,"error":null}},"backchannel_logout":null}}`)
	in, err := c.Instance.GetIntegration(ctx, "chatly")
	if err != nil || in.ID != "chatly" || in.Raw["channel"] != "support" || in.Health == nil || in.Health.Events == nil || in.Health.Events.State != "failing" || in.Health.Events.LastFailure.At != 2 || *in.ExternalRef != "r1" {
		t.Fatalf("integration = %+v, %v", in, err)
	}
}

func TestWebhookEventAliases(t *testing.T) {
	if CanonicalWebhookEvent("organizationMembership.created") != "organization_membership.created" || CanonicalWebhookEvent("user.created") != "user.created" {
		t.Error("CanonicalWebhookEvent")
	}
	if !IsDeprecatedWebhookEvent("session.ended") || IsDeprecatedWebhookEvent("session.revoked") {
		t.Error("IsDeprecatedWebhookEvent")
	}
	sp := WebhookEventSpellings("organization_membership.deleted")
	if len(sp) != 3 || sp[0] != "organization_membership.deleted" || sp[1] != "organization.membership.deleted" || sp[2] != "organizationMembership.deleted" {
		t.Errorf("spellings = %v", sp)
	}
	if WebhookEventAliases["user.deletion_cancelled"].Kind != "companion" {
		t.Error("companion kind")
	}
	if WebhookEventStatusIncidentResolved != "status.incident.resolved" || WebhookEventPrivacyRequestCompleted != "privacy_request.completed" || WebhookEventSecretKeyExpiring != "secret_key.expiring" {
		t.Error("event constants")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
