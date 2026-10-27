package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// TestBackendAPIOperations walks every Backend API operation added in this
// release: method, escaped path (first path parameter has a space, so the
// encoding is checked), query, the required scalar body fields and the
// idempotency key on writes.
func TestBackendAPIOperations(t *testing.T) {
	ctx := context.Background()
	yes := true
	_ = yes
	var gotMethod, gotPath, gotQuery, gotIdem, respBody string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotMethod, gotPath, gotQuery, gotIdem = r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Idempotency-Key")
		gotBody = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &gotBody)
		}
		_, _ = w.Write([]byte(respBody))
	}))
	defer srv.Close()
	c := New("sk_test", WithBaseURL(srv.URL))

	rows := []struct {
		key, method, path, query, resp string
		write                          bool
		body                           map[string]interface{}
		call                           func() error
	}{
		{"GET /v1/app_catalog", "GET", "/v1/app_catalog", "limit=5", "{}", false, nil, func() error { _, err := c.AppCatalog.Presets(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/app_catalog/installed", "GET", "/v1/app_catalog/installed", "limit=5", "{}", false, nil, func() error { _, err := c.AppCatalog.Installed(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/app_catalog/{}/install", "POST", "/v1/app_catalog/p%201/install", "", "{}", true, nil, func() error {
			_, err := c.AppCatalog.Install(ctx, "p 1", AppCatalogInstallParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PATCH /v1/app_catalog/installed/{}", "PATCH", "/v1/app_catalog/installed/p%201", "", "{}", true, nil, func() error {
			_, err := c.AppCatalog.Update(ctx, "p 1", AppCatalogUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/app_catalog/installed/{}", "DELETE", "/v1/app_catalog/installed/p%201", "", "{}", true, nil, func() error { return c.AppCatalog.Uninstall(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/ldap_server_clients", "GET", "/v1/ldap_server_clients", "limit=5", "{}", false, nil, func() error { _, err := c.LDAPServerClients.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/ldap_server_clients", "POST", "/v1/ldap_server_clients", "", "{}", true, map[string]interface{}{"name": "x", "base_dn": "x", "bind_cn": "x"}, func() error {
			_, err := c.LDAPServerClients.Create(ctx, LDAPServerClientsCreateParams{Name: "x", BaseDN: "x", BindCn: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/ldap_server_clients/{}", "GET", "/v1/ldap_server_clients/p%201", "", "{}", false, nil, func() error { _, err := c.LDAPServerClients.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/ldap_server_clients/{}", "PATCH", "/v1/ldap_server_clients/p%201", "", "{}", true, nil, func() error {
			_, err := c.LDAPServerClients.Update(ctx, "p 1", LDAPServerClientsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/ldap_server_clients/{}", "DELETE", "/v1/ldap_server_clients/p%201", "", "{}", true, nil, func() error { return c.LDAPServerClients.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/ldap_server_clients/{}/rotate_secret", "POST", "/v1/ldap_server_clients/p%201/rotate_secret", "", "{}", true, nil, func() error {
			_, err := c.LDAPServerClients.RotateSecret(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/users/{}/history", "GET", "/v1/users/p%201/history", "limit=3", "{}", false, nil, func() error { _, err := c.Users.History(ctx, "p 1", UsersHistoryQuery{Limit: 3}); return err }},
		{"GET /v1/users/{}/minor_status", "GET", "/v1/users/p%201/minor_status", "", "{}", false, nil, func() error { _, err := c.Users.MinorStatus(ctx, "p 1"); return err }},
		{"POST /v1/users/{}/minor_status/assess", "POST", "/v1/users/p%201/minor_status/assess", "", "{}", true, nil, func() error { _, err := c.Users.AssessMinor(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/users/{}/links", "POST", "/v1/users/p%201/links", "", "{}", true, map[string]interface{}{"type": "password_reset"}, func() error {
			_, err := c.Users.CreateLink(ctx, "p 1", UsersCreateLinkParams{Type: "password_reset"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/users/{}/device_keys", "GET", "/v1/users/p%201/device_keys", "limit=5", "{}", false, nil, func() error { _, err := c.Users.ListDeviceKeys(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"DELETE /v1/users/{}/device_keys/{}", "DELETE", "/v1/users/p%201/device_keys/v2", "", "{}", true, nil, func() error {
			_, err := c.Users.DeleteDeviceKey(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/users/{}/required_actions", "POST", "/v1/users/p%201/required_actions", "", "{}", true, map[string]interface{}{"action": "update_password"}, func() error {
			_, err := c.Users.RequiredActions.Request(ctx, "p 1", UsersRequiredActionsRequestParams{Action: "update_password"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/users/{}/required_actions", "GET", "/v1/users/p%201/required_actions", "limit=5", "{}", false, nil, func() error { _, err := c.Users.RequiredActions.List(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"DELETE /v1/users/{}/required_actions/{}", "DELETE", "/v1/users/p%201/required_actions/v2", "", "{}", true, nil, func() error {
			_, err := c.Users.RequiredActions.Clear(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/required_actions/bulk", "POST", "/v1/required_actions/bulk", "", "{}", true, map[string]interface{}{"action": "update_password"}, func() error {
			return c.Users.RequiredActions.Bulk(ctx, UsersRequiredActionsBulkParams{Action: "update_password"}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/users/{}/notes", "GET", "/v1/users/p%201/notes", "limit=5", "{}", false, nil, func() error { _, err := c.Users.Notes.List(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/users/{}/notes", "POST", "/v1/users/p%201/notes", "", "{}", true, map[string]interface{}{"body": "x"}, func() error {
			_, err := c.Users.Notes.Create(ctx, "p 1", UsersNotesCreateParams{Body: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PATCH /v1/users/{}/notes/{}", "PATCH", "/v1/users/p%201/notes/v2", "", "{}", true, nil, func() error {
			_, err := c.Users.Notes.Update(ctx, "p 1", "v2", UsersNotesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/users/{}/notes/{}", "DELETE", "/v1/users/p%201/notes/v2", "", "{}", true, nil, func() error {
			_, err := c.Users.Notes.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/users/{}/guardians", "POST", "/v1/users/p%201/guardians", "", "{}", true, nil, func() error {
			_, err := c.Users.Guardians.Request(ctx, "p 1", UsersGuardiansRequestParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/users/{}/guardians/{}/approve", "POST", "/v1/users/p%201/guardians/v2/approve", "", "{}", true, nil, func() error {
			_, err := c.Users.Guardians.Approve(ctx, "p 1", "v2", UsersGuardiansApproveParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/users/{}/guardians/{}", "DELETE", "/v1/users/p%201/guardians/v2", "", "{}", true, nil, func() error {
			_, err := c.Users.Guardians.Revoke(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/flows", "GET", "/v1/flows", "limit=5", "{}", false, nil, func() error { _, err := c.Journeys.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/flows", "POST", "/v1/flows", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.Journeys.Create(ctx, JourneysCreateParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/flows/{}", "GET", "/v1/flows/p%201", "", "{}", false, nil, func() error { _, err := c.Journeys.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/flows/{}", "PATCH", "/v1/flows/p%201", "", "{}", true, nil, func() error {
			_, err := c.Journeys.Update(ctx, "p 1", JourneysUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/flows/{}", "DELETE", "/v1/flows/p%201", "", "{}", true, nil, func() error { return c.Journeys.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/flows/{}/versions", "GET", "/v1/flows/p%201/versions", "limit=5", "{}", false, nil, func() error { _, err := c.Journeys.Versions(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/flows/{}/activate", "POST", "/v1/flows/p%201/activate", "", "{}", true, map[string]interface{}{"version": float64(1)}, func() error {
			_, err := c.Journeys.Activate(ctx, "p 1", JourneysActivateParams{Version: 1}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/flows/{}/simulate", "POST", "/v1/flows/p%201/simulate", "", "{}", true, map[string]interface{}{"user_id": "x"}, func() error {
			_, err := c.Journeys.Simulate(ctx, "p 1", JourneysSimulateParams{UserID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/users/search", "POST", "/v1/users/search", "", "{}", true, nil, func() error {
			_, err := c.Users.Searches.Query(ctx, UsersSearchQueryParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/users/search/export", "POST", "/v1/users/search/export", "", "{}", true, nil, func() error {
			return c.Users.Searches.Export(ctx, UsersSearchExportParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/users/search/views", "GET", "/v1/users/search/views", "limit=5", "{}", false, nil, func() error { _, err := c.Users.Searches.Views.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/users/search/views", "POST", "/v1/users/search/views", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.Users.Searches.Views.Create(ctx, UsersSearchViewsCreateParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PATCH /v1/users/search/views/{}", "PATCH", "/v1/users/search/views/p%201", "", "{}", true, nil, func() error {
			_, err := c.Users.Searches.Views.Update(ctx, "p 1", UsersSearchViewsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/users/search/views/{}", "DELETE", "/v1/users/search/views/p%201", "", "{}", true, nil, func() error {
			_, err := c.Users.Searches.Views.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/groups", "GET", "/v1/groups", "limit=5", "{}", false, nil, func() error { _, err := c.Groups.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/groups", "POST", "/v1/groups", "", "{}", true, map[string]interface{}{"slug": "x", "name": "x"}, func() error {
			_, err := c.Groups.Create(ctx, GroupsCreateParams{Slug: "x", Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/groups/{}", "GET", "/v1/groups/p%201", "", "{}", false, nil, func() error { _, err := c.Groups.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/groups/{}", "PATCH", "/v1/groups/p%201", "", "{}", true, nil, func() error {
			_, err := c.Groups.Update(ctx, "p 1", GroupsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/groups/{}", "DELETE", "/v1/groups/p%201", "", "{}", true, nil, func() error { _, err := c.Groups.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/groups/{}/members", "GET", "/v1/groups/p%201/members", "limit=5", "{}", false, nil, func() error { _, err := c.Groups.ListMembers(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/groups/{}/members", "POST", "/v1/groups/p%201/members", "", "{}", true, nil, func() error {
			return c.Groups.AddMembers(ctx, "p 1", GroupsAddMembersParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/groups/{}/members/remove", "POST", "/v1/groups/p%201/members/remove", "", "{}", true, nil, func() error {
			return c.Groups.RemoveMembers(ctx, "p 1", GroupsAddMembersParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/groups/{}/reapply", "POST", "/v1/groups/p%201/reapply", "", "{}", true, nil, func() error { _, err := c.Groups.Reapply(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/users/{}/groups", "GET", "/v1/users/p%201/groups", "limit=5", "{}", false, nil, func() error { _, err := c.Groups.ForUser(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/group_rules", "GET", "/v1/group_rules", "limit=5", "{}", false, nil, func() error { _, err := c.Groups.Rules.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/group_rules", "POST", "/v1/group_rules", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.Groups.Rules.Create(ctx, GroupsRulesCreateParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/group_rules/apply", "POST", "/v1/group_rules/apply", "", "{}", true, nil, func() error { _, err := c.Groups.Rules.ApplyAll(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/group_rules/{}", "GET", "/v1/group_rules/p%201", "", "{}", false, nil, func() error { _, err := c.Groups.Rules.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/group_rules/{}", "PATCH", "/v1/group_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.Groups.Rules.Update(ctx, "p 1", GroupsRulesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/group_rules/{}", "DELETE", "/v1/group_rules/p%201", "", "{}", true, nil, func() error { _, err := c.Groups.Rules.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/group_rules/{}/apply", "POST", "/v1/group_rules/p%201/apply", "", "{}", true, nil, func() error { _, err := c.Groups.Rules.Apply(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/migrations/{}/exchange", "POST", "/v1/migrations/p%201/exchange", "", "{}", true, map[string]interface{}{"token": "x"}, func() error {
			_, err := c.Migrations.Exchange(ctx, "p 1", MigrationsExchangeParams{Token: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/migrations/sources", "GET", "/v1/migrations/sources", "limit=5", "{}", false, nil, func() error { _, err := c.Migrations.Sources(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/migrations/{}/bridge", "GET", "/v1/migrations/p%201/bridge", "", "{}", false, nil, func() error { _, err := c.Migrations.GetBridge(ctx, "p 1"); return err }},
		{"PUT /v1/migrations/{}/bridge", "PUT", "/v1/migrations/p%201/bridge", "", "{}", true, nil, func() error {
			_, err := c.Migrations.SetBridge(ctx, "p 1", MigrationsSetBridgeParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/migrations/{}/bridge", "DELETE", "/v1/migrations/p%201/bridge", "", "{}", true, nil, func() error {
			_, err := c.Migrations.DeleteBridge(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/migrations/{}/imports/public_key", "GET", "/v1/migrations/p%201/imports/public_key", "", "{}", false, nil, func() error { _, err := c.Migrations.Imports.GetPublicKey(ctx, "p 1"); return err }},
		{"POST /v1/migrations/{}/imports/public_key/rotate", "POST", "/v1/migrations/p%201/imports/public_key/rotate", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.RotatePublicKey(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/migrations/{}/imports", "POST", "/v1/migrations/p%201/imports", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.Create(ctx, "p 1", MigrationsImportsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/migrations/{}/imports", "GET", "/v1/migrations/p%201/imports", "limit=5", "{}", false, nil, func() error { _, err := c.Migrations.Imports.List(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/migrations/{}/imports/{}", "GET", "/v1/migrations/p%201/imports/v2", "", "{}", false, nil, func() error { _, err := c.Migrations.Imports.Get(ctx, "p 1", "v2"); return err }},
		{"DELETE /v1/migrations/{}/imports/{}", "DELETE", "/v1/migrations/p%201/imports/v2", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/migrations/{}/imports/{}/parts/{}", "PUT", "/v1/migrations/p%201/imports/v2/parts/v3", "", "{}", true, map[string]interface{}{"data": "x"}, func() error {
			_, err := c.Migrations.Imports.PutPart(ctx, "p 1", "v2", "v3", MigrationsImportsPutPartParams{Data: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/migrations/{}/imports/{}/finalize", "POST", "/v1/migrations/p%201/imports/v2/finalize", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.Finalize(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/migrations/{}/imports/{}/dry_run", "POST", "/v1/migrations/p%201/imports/v2/dry_run", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.DryRun(ctx, "p 1", "v2", MigrationsImportsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/migrations/{}/imports/{}/apply", "POST", "/v1/migrations/p%201/imports/v2/apply", "", "{}", true, nil, func() error {
			_, err := c.Migrations.Imports.Apply(ctx, "p 1", "v2", MigrationsImportsApplyParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/grant_management/grants", "GET", "/v1/grant_management/grants", "user_id=x", "{}", false, nil, func() error { _, err := c.ManagedGrants.List(ctx, ManagedGrantsListQuery{UserID: "x"}); return err }},
		{"GET /v1/grant_management/grants/{}", "GET", "/v1/grant_management/grants/p%201", "", "{}", false, nil, func() error { _, err := c.ManagedGrants.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/grant_management/grants/{}", "PATCH", "/v1/grant_management/grants/p%201", "", "{}", true, nil, func() error {
			_, err := c.ManagedGrants.Narrow(ctx, "p 1", ManagedGrantsNarrowParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/grant_management/grants/{}", "DELETE", "/v1/grant_management/grants/p%201", "", "{}", true, nil, func() error { _, err := c.ManagedGrants.Revoke(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/least_privilege/report", "GET", "/v1/least_privilege/report", "days=3", "{}", false, nil, func() error { _, err := c.LeastPrivilege.Report(ctx, LeastPrivilegeReportQuery{Days: 3}); return err }},
		{"GET /v1/least_privilege/report/{}/{}", "GET", "/v1/least_privilege/report/p%201/v2", "days=3", "{}", false, nil, func() error {
			_, err := c.LeastPrivilege.Get(ctx, "p 1", "v2", LeastPrivilegeGetQuery{Days: 3})
			return err
		}},
		{"POST /v1/least_privilege/apply", "POST", "/v1/least_privilege/apply", "", "{}", true, nil, func() error {
			_, err := c.LeastPrivilege.Apply(ctx, LeastPrivilegeApplyParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/delivery_health/{}/{}", "GET", "/v1/delivery_health/p%201/v2", "", "{}", false, nil, func() error { _, err := c.Delivery.Get(ctx, "p 1", "v2"); return err }},
		{"PUT /v1/organizations/{}/entitlements", "PUT", "/v1/organizations/p%201/entitlements", "", "{}", true, nil, func() error {
			_, err := c.Flags.AssignOrganizationEntitlements(ctx, "p 1", FlagsAssignOrganizationEntitlementsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/feature_flags", "POST", "/v1/feature_flags", "", "{}", true, map[string]interface{}{"key": "x", "type": "boolean"}, func() error {
			_, err := c.Flags.Create(ctx, FlagsCreateParams{Key: "x", Type: "boolean"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/feature_flags", "GET", "/v1/feature_flags", "limit=5", "{}", false, nil, func() error { _, err := c.Flags.List(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/feature_flags/{}", "GET", "/v1/feature_flags/p%201", "", "{}", false, nil, func() error { _, err := c.Flags.Retrieve(ctx, "p 1"); return err }},
		{"PATCH /v1/feature_flags/{}", "PATCH", "/v1/feature_flags/p%201", "", "{}", true, nil, func() error {
			_, err := c.Flags.Update(ctx, "p 1", FlagsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/feature_flags/{}", "DELETE", "/v1/feature_flags/p%201", "", "{}", true, nil, func() error { _, err := c.Flags.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/feature_flags/evaluate", "POST", "/v1/feature_flags/evaluate", "", "{}", true, nil, func() error {
			_, err := c.Flags.Evaluate(ctx, FlagsEvaluateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/users/{}/entitlements", "PUT", "/v1/users/p%201/entitlements", "", "{}", true, nil, func() error {
			_, err := c.Flags.AssignUserEntitlements(ctx, "p 1", FlagsAssignOrganizationEntitlementsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/instance/yubico_secret", "PUT", "/v1/instance/yubico_secret", "", "{}", true, map[string]interface{}{"secret": "x"}, func() error {
			_, err := c.MFAFactors.SetYubicoSecret(ctx, MFAFactorsSetYubicoSecretParams{Secret: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/instance/yubico_secret", "DELETE", "/v1/instance/yubico_secret", "", "{}", true, nil, func() error { _, err := c.MFAFactors.RemoveYubicoSecret(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"PUT /v1/instance/duo_secret", "PUT", "/v1/instance/duo_secret", "", "{}", true, map[string]interface{}{"secret": "x"}, func() error {
			_, err := c.MFAFactors.SetDuoSecret(ctx, MFAFactorsSetDuoSecretParams{Secret: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/instance/duo_secret", "DELETE", "/v1/instance/duo_secret", "", "{}", true, nil, func() error { _, err := c.MFAFactors.RemoveDuoSecret(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"PUT /v1/instance/smart_card_secret", "PUT", "/v1/instance/smart_card_secret", "", "{}", true, map[string]interface{}{"secret": "x"}, func() error {
			_, err := c.MFAFactors.SetSmartCardSecret(ctx, MFAFactorsSetSmartCardSecretParams{Secret: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/instance/smart_card_secret", "DELETE", "/v1/instance/smart_card_secret", "", "{}", true, nil, func() error {
			_, err := c.MFAFactors.RemoveSmartCardSecret(ctx, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/instance/duo_health_check", "POST", "/v1/instance/duo_health_check", "", "{}", true, nil, func() error { _, err := c.MFAFactors.DuoHealthCheck(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"DELETE /v1/users/{}/security_questions", "DELETE", "/v1/users/p%201/security_questions", "", "{}", true, nil, func() error {
			_, err := c.MFAFactors.ResetSecurityQuestions(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/yubikeys", "GET", "/v1/yubikeys", "limit=5", "{}", false, nil, func() error { _, err := c.MFAFactors.Yubikeys.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/yubikeys", "POST", "/v1/yubikeys", "", "{}", true, map[string]interface{}{"public_id": "x", "aes_key": "x"}, func() error {
			_, err := c.MFAFactors.Yubikeys.Register(ctx, MFAFactorsYubikeysRegisterParams{PublicID: "x", AESKey: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/yubikeys/{}", "DELETE", "/v1/yubikeys/p%201", "", "{}", true, nil, func() error {
			_, err := c.MFAFactors.Yubikeys.Remove(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/users/{}/smartcard_mappings", "GET", "/v1/users/p%201/smartcard_mappings", "limit=5", "{}", false, nil, func() error {
			_, err := c.MFAFactors.SmartCardMappings.List(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"POST /v1/users/{}/smartcard_mappings", "POST", "/v1/users/p%201/smartcard_mappings", "", "{}", true, map[string]interface{}{"kind": "san_email", "value": "x"}, func() error {
			_, err := c.MFAFactors.SmartCardMappings.Add(ctx, "p 1", MFAFactorsSmartCardMappingsAddParams{Kind: "san_email", Value: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/users/{}/smartcard_mappings/{}", "DELETE", "/v1/users/p%201/smartcard_mappings/v2", "", "{}", true, nil, func() error {
			_, err := c.MFAFactors.SmartCardMappings.Remove(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/analytics/funnel", "GET", "/v1/analytics/funnel", "kind=sign_in", "{}", false, nil, func() error { _, err := c.Analytics.Funnel(ctx, AnalyticsFunnelQuery{Kind: "sign_in"}); return err }},
		{"GET /v1/analytics/journey_funnel", "GET", "/v1/analytics/journey_funnel", "journey_id=x", "{}", false, nil, func() error {
			_, err := c.Analytics.JourneyFunnel(ctx, AnalyticsJourneyFunnelQuery{JourneyID: "x"})
			return err
		}},
		{"GET /v1/analytics/failures", "GET", "/v1/analytics/failures", "from=x", "{}", false, nil, func() error { _, err := c.Analytics.Failures(ctx, AnalyticsFailuresQuery{From: "x"}); return err }},
		{"GET /v1/analytics/breakdown", "GET", "/v1/analytics/breakdown", "dimension=method", "{}", false, nil, func() error {
			_, err := c.Analytics.Breakdown(ctx, AnalyticsBreakdownQuery{Dimension: "method"})
			return err
		}},
		{"GET /v1/analytics/active_users", "GET", "/v1/analytics/active_users", "from=x", "{}", false, nil, func() error { _, err := c.Analytics.ActiveUsers(ctx, AnalyticsActiveUsersQuery{From: "x"}); return err }},
		{"GET /v1/analytics/passkey_adoption", "GET", "/v1/analytics/passkey_adoption", "from=x", "{}", false, nil, func() error {
			_, err := c.Analytics.PasskeyAdoption(ctx, AnalyticsPasskeyAdoptionQuery{From: "x"})
			return err
		}},
		{"GET /v1/analytics/api_usage", "GET", "/v1/analytics/api_usage", "subject_type=api_key", "{}", false, nil, func() error {
			_, err := c.Analytics.APIUsage(ctx, AnalyticsAPIUsageQuery{SubjectType: "api_key"})
			return err
		}},
		{"GET /v1/analytics/reports/inactive_users", "GET", "/v1/analytics/reports/inactive_users", "inactive_days=3", "{}", false, nil, func() error {
			_, err := c.Analytics.Reports.InactiveUsers(ctx, AnalyticsReportsInactiveUsersQuery{InactiveDays: 3})
			return err
		}},
		{"GET /v1/analytics/reports/mfa_coverage", "GET", "/v1/analytics/reports/mfa_coverage", "from=x", "{}", false, nil, func() error {
			_, err := c.Analytics.Reports.MFACoverage(ctx, AnalyticsReportsMFACoverageQuery{From: "x"})
			return err
		}},
		{"GET /v1/analytics/reports/access_by_app", "GET", "/v1/analytics/reports/access_by_app", "from=x", "{}", false, nil, func() error {
			_, err := c.Analytics.Reports.AccessByApp(ctx, AnalyticsReportsAccessByAppQuery{From: "x"})
			return err
		}},
		{"GET /v1/analytics/alert_rules", "GET", "/v1/analytics/alert_rules", "limit=5", "{}", false, nil, func() error { _, err := c.Analytics.AlertRules.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/analytics/alert_rules", "POST", "/v1/analytics/alert_rules", "", "{}", true, map[string]interface{}{"name": "x", "metric": "sign_in_success_rate", "comparator": "lt", "threshold": float64(1)}, func() error {
			_, err := c.Analytics.AlertRules.Create(ctx, AnalyticsAlertRulesCreateParams{Name: "x", Metric: "sign_in_success_rate", Comparator: "lt", Threshold: 1}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/analytics/alert_rules/{}", "GET", "/v1/analytics/alert_rules/p%201", "", "{}", false, nil, func() error { _, err := c.Analytics.AlertRules.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/analytics/alert_rules/{}", "PATCH", "/v1/analytics/alert_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.Analytics.AlertRules.Update(ctx, "p 1", AnalyticsAlertRulesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/analytics/alert_rules/{}", "DELETE", "/v1/analytics/alert_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.Analytics.AlertRules.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/analytics/alert_rules/{}/test", "POST", "/v1/analytics/alert_rules/p%201/test", "", "{}", true, nil, func() error {
			_, err := c.Analytics.AlertRules.Test(ctx, "p 1", AnalyticsAlertRulesTestParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/marketing_settings", "GET", "/v1/marketing_settings", "", "{}", false, nil, func() error { _, err := c.Marketing.GetSettings(ctx); return err }},
		{"PUT /v1/marketing_settings", "PUT", "/v1/marketing_settings", "", "{}", true, nil, func() error {
			_, err := c.Marketing.UpdateSettings(ctx, MarketingUpdateSettingsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/leads", "GET", "/v1/leads", "limit=3", "{}", false, nil, func() error { _, err := c.Marketing.ListLeads(ctx, MarketingListLeadsQuery{Limit: 3}); return err }},
		{"DELETE /v1/leads/{}", "DELETE", "/v1/leads/p%201", "", "{}", true, nil, func() error { _, err := c.Marketing.DeleteLead(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/audit_event_schemas", "GET", "/v1/audit_event_schemas", "limit=5", "{}", false, nil, func() error { _, err := c.AuditEventSchemas.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/audit_event_schemas", "POST", "/v1/audit_event_schemas", "", "{}", true, map[string]interface{}{"action": "x"}, func() error {
			_, err := c.AuditEventSchemas.Register(ctx, AuditEventSchemasRegisterParams{Action: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/audit_event_schemas/{}", "GET", "/v1/audit_event_schemas/p%201", "", "{}", false, nil, func() error { _, err := c.AuditEventSchemas.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/audit_event_schemas/{}", "PATCH", "/v1/audit_event_schemas/p%201", "", "{}", true, nil, func() error {
			_, err := c.AuditEventSchemas.Update(ctx, "p 1", AuditEventSchemasUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/audit_event_schemas/{}", "DELETE", "/v1/audit_event_schemas/p%201", "", "{}", true, nil, func() error {
			_, err := c.AuditEventSchemas.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/audit_events/{}/redact", "POST", "/v1/audit_events/p%201/redact", "", "{}", true, map[string]interface{}{"reason": "x"}, func() error {
			_, err := c.AuditEventSchemas.Redact(ctx, "p 1", AuditEventSchemasRedactParams{Reason: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/audit_events/{}/redactions", "GET", "/v1/audit_events/p%201/redactions", "limit=5", "{}", false, nil, func() error { _, err := c.AuditEventSchemas.Redactions(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/directory_pull_sources", "GET", "/v1/directory_pull_sources", "organization_id=x", "{}", false, nil, func() error {
			_, err := c.DirectoryPullSources.List(ctx, DirectoryPullSourcesListQuery{OrganizationID: "x"})
			return err
		}},
		{"POST /v1/directory_pull_sources", "POST", "/v1/directory_pull_sources", "", "{}", true, map[string]interface{}{"organization_id": "x", "name": "x", "provider": "entra"}, func() error {
			_, err := c.DirectoryPullSources.Create(ctx, DirectoryPullSourcesCreateParams{OrganizationID: "x", Name: "x", Provider: "entra"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/directory_pull_sources/{}", "GET", "/v1/directory_pull_sources/p%201", "", "{}", false, nil, func() error { _, err := c.DirectoryPullSources.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/directory_pull_sources/{}", "PATCH", "/v1/directory_pull_sources/p%201", "", "{}", true, nil, func() error {
			_, err := c.DirectoryPullSources.Update(ctx, "p 1", DirectoryPullSourcesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/directory_pull_sources/{}", "DELETE", "/v1/directory_pull_sources/p%201", "", "{}", true, nil, func() error { return c.DirectoryPullSources.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"PUT /v1/directory_pull_sources/{}/csv", "PUT", "/v1/directory_pull_sources/p%201/csv", "", "{}", true, nil, func() error {
			return c.DirectoryPullSources.SetCSV(ctx, "p 1", DirectoryPullSourcesSetCSVParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/directory_pull_sources/{}/sync_runs", "POST", "/v1/directory_pull_sources/p%201/sync_runs", "", "{}", true, nil, func() error {
			_, err := c.DirectoryPullSources.SyncRuns.Create(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/directory_pull_sources/{}/sync_runs", "GET", "/v1/directory_pull_sources/p%201/sync_runs", "limit=5", "{}", false, nil, func() error {
			_, err := c.DirectoryPullSources.SyncRuns.List(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"GET /v1/directory_pull_sources/{}/sync_runs/{}", "GET", "/v1/directory_pull_sources/p%201/sync_runs/v2", "", "{}", false, nil, func() error { _, err := c.DirectoryPullSources.SyncRuns.Get(ctx, "p 1", "v2"); return err }},
		{"GET /v1/org_ldap_connections/{}/sync", "GET", "/v1/org_ldap_connections/p%201/sync", "", "{}", false, nil, func() error { _, err := c.OrgLDAPConnections.GetSync(ctx, "p 1"); return err }},
		{"PUT /v1/org_ldap_connections/{}/sync", "PUT", "/v1/org_ldap_connections/p%201/sync", "", "{}", true, nil, func() error {
			return c.OrgLDAPConnections.SetSync(ctx, "p 1", OrgLDAPConnectionsSetSyncParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/org_ldap_connections/{}/relay", "GET", "/v1/org_ldap_connections/p%201/relay", "", "{}", false, nil, func() error { _, err := c.OrgLDAPConnections.GetRelay(ctx, "p 1"); return err }},
		{"PUT /v1/org_ldap_connections/{}/relay", "PUT", "/v1/org_ldap_connections/p%201/relay", "", "{}", true, nil, func() error {
			return c.OrgLDAPConnections.SetRelay(ctx, "p 1", OrgLDAPConnectionsSetRelayParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/org_ldap_connections/{}/sync_runs", "POST", "/v1/org_ldap_connections/p%201/sync_runs", "", "{}", true, nil, func() error {
			return c.OrgLDAPConnections.SyncRuns.Create(ctx, "p 1", OrgLDAPConnectionsSyncRunsCreateParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/org_ldap_connections/{}/sync_runs", "GET", "/v1/org_ldap_connections/p%201/sync_runs", "limit=5", "{}", false, nil, func() error {
			_, err := c.OrgLDAPConnections.SyncRuns.List(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"GET /v1/org_ldap_connections/{}/sync_runs/{}", "GET", "/v1/org_ldap_connections/p%201/sync_runs/v2", "", "{}", false, nil, func() error { _, err := c.OrgLDAPConnections.SyncRuns.Get(ctx, "p 1", "v2"); return err }},
		{"GET /v1/relay_agents", "GET", "/v1/relay_agents", "limit=5", "{}", false, nil, func() error { _, err := c.RelayAgents.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/relay_agents", "POST", "/v1/relay_agents", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.RelayAgents.Create(ctx, RelayAgentsCreateParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/relay_agents/{}", "GET", "/v1/relay_agents/p%201", "", "{}", false, nil, func() error { _, err := c.RelayAgents.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/relay_agents/{}", "PATCH", "/v1/relay_agents/p%201", "", "{}", true, nil, func() error {
			_, err := c.RelayAgents.Update(ctx, "p 1", RelayAgentsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/relay_agents/{}", "DELETE", "/v1/relay_agents/p%201", "", "{}", true, nil, func() error { return c.RelayAgents.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/relay_agents/{}/rotate_secret", "POST", "/v1/relay_agents/p%201/rotate_secret", "", "{}", true, nil, func() error {
			_, err := c.RelayAgents.RotateSecret(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/oauth_clients/{}/exchange_policy", "GET", "/v1/oauth_clients/p%201/exchange_policy", "", "{}", false, nil, func() error { _, err := c.OAuthClients.GetExchangePolicy(ctx, "p 1"); return err }},
		{"PUT /v1/oauth_clients/{}/exchange_policy", "PUT", "/v1/oauth_clients/p%201/exchange_policy", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.SetExchangePolicy(ctx, "p 1", OAuthClientsSetExchangePolicyParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/oauth_clients/{}/exchange_policy", "DELETE", "/v1/oauth_clients/p%201/exchange_policy", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.DeleteExchangePolicy(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/oauth_clients/{}/profile", "PUT", "/v1/oauth_clients/p%201/profile", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.SetProfile(ctx, "p 1", OAuthClientsSetProfileParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/oauth_clients/{}/delegated_ui", "PUT", "/v1/oauth_clients/p%201/delegated_ui", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.SetDelegatedUI(ctx, "p 1", OAuthClientsSetDelegatedUIParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/oauth_clients/{}/app_settings", "GET", "/v1/oauth_clients/p%201/app_settings", "", "{}", false, nil, func() error { _, err := c.OAuthClients.AppSettings.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/oauth_clients/{}/app_settings", "PATCH", "/v1/oauth_clients/p%201/app_settings", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.AppSettings.Update(ctx, "p 1", OAuthClientsAppSettingsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/workload_identity/presets", "GET", "/v1/workload_identity/presets", "limit=5", "{}", false, nil, func() error { _, err := c.OAuthClients.WorkloadIdentity.Presets(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/workload_identity/cloud_trust", "GET", "/v1/workload_identity/cloud_trust", "audience=x&provider=aws&subject=x", "{}", false, nil, func() error {
			_, err := c.OAuthClients.WorkloadIdentity.CloudTrust(ctx, OAuthClientsWorkloadIdentityCloudTrustQuery{Provider: "aws", Audience: "x", Subject: "x"})
			return err
		}},
		{"GET /v1/oauth_clients/{}/trusted_issuers", "GET", "/v1/oauth_clients/p%201/trusted_issuers", "limit=5", "{}", false, nil, func() error {
			_, err := c.OAuthClients.TrustedIssuers.List(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"POST /v1/oauth_clients/{}/trusted_issuers", "POST", "/v1/oauth_clients/p%201/trusted_issuers", "", "{}", true, map[string]interface{}{"issuer": "x"}, func() error {
			_, err := c.OAuthClients.TrustedIssuers.Create(ctx, "p 1", OAuthClientsTrustedIssuersCreateParams{Issuer: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/oauth_clients/{}/trusted_issuers/{}", "DELETE", "/v1/oauth_clients/p%201/trusted_issuers/v2", "", "{}", true, nil, func() error {
			_, err := c.OAuthClients.TrustedIssuers.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/organizations/{}/connected_apps", "GET", "/v1/organizations/p%201/connected_apps", "limit=5", "{}", false, nil, func() error {
			_, err := c.Organizations.ListConnectedApps(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"DELETE /v1/organizations/{}/connected_apps/{}", "DELETE", "/v1/organizations/p%201/connected_apps/v2", "", "{}", true, nil, func() error {
			_, err := c.Organizations.RevokeConnectedApp(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/organizations/{}/connections/{}/secret", "GET", "/v1/organizations/p%201/connections/v2/secret", "version=x", "{}", false, nil, func() error {
			_, err := c.Organizations.GetConnectionSecret(ctx, "p 1", "v2", OrganizationsGetConnectionSecretQuery{Version: "x"})
			return err
		}},
		{"GET /v1/oauth_client_profiles", "GET", "/v1/oauth_client_profiles", "limit=5", "{}", false, nil, func() error { _, err := c.OAuthClientProfiles.List(ctx, ListParams{Limit: 5}); return err }},
		{"PUT /v1/oauth_client_profiles/{}", "PUT", "/v1/oauth_client_profiles/p%201", "", "{}", true, nil, func() error {
			_, err := c.OAuthClientProfiles.Set(ctx, "p 1", OAuthClientProfilesSetParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/oauth_client_profiles/{}", "DELETE", "/v1/oauth_client_profiles/p%201", "", "{}", true, nil, func() error {
			_, err := c.OAuthClientProfiles.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/oauth_login_requests", "GET", "/v1/oauth_login_requests", "login_challenge=x", "{}", false, nil, func() error {
			_, err := c.OAuthClients.LoginRequests.Get(ctx, OAuthClientsLoginRequestsGetQuery{LoginChallenge: "x"})
			return err
		}},
		{"PUT /v1/oauth_login_requests/accept", "PUT", "/v1/oauth_login_requests/accept", "login_challenge=x", "{}", true, map[string]interface{}{"subject": "x"}, func() error {
			_, err := c.OAuthClients.LoginRequests.Accept(ctx, OAuthClientsLoginRequestsAcceptQuery{LoginChallenge: "x"}, OAuthClientsLoginRequestsAcceptParams{Subject: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/oauth_login_requests/reject", "PUT", "/v1/oauth_login_requests/reject", "login_challenge=x", "{}", true, nil, func() error {
			_, err := c.OAuthClients.LoginRequests.Reject(ctx, OAuthClientsLoginRequestsRejectQuery{LoginChallenge: "x"}, OAuthClientsLoginRequestsRejectParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/oauth_consent_requests", "GET", "/v1/oauth_consent_requests", "consent_challenge=x", "{}", false, nil, func() error {
			_, err := c.OAuthClients.ConsentRequests.Get(ctx, OAuthClientsConsentRequestsGetQuery{ConsentChallenge: "x"})
			return err
		}},
		{"PUT /v1/oauth_consent_requests/accept", "PUT", "/v1/oauth_consent_requests/accept", "consent_challenge=x", "{}", true, nil, func() error {
			_, err := c.OAuthClients.ConsentRequests.Accept(ctx, OAuthClientsConsentRequestsAcceptQuery{ConsentChallenge: "x"}, OAuthClientsConsentRequestsAcceptParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/oauth_consent_requests/reject", "PUT", "/v1/oauth_consent_requests/reject", "consent_challenge=x", "{}", true, nil, func() error {
			_, err := c.OAuthClients.ConsentRequests.Reject(ctx, OAuthClientsConsentRequestsRejectQuery{ConsentChallenge: "x"}, OAuthClientsLoginRequestsRejectParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/passkey_api/registration/init", "POST", "/v1/passkey_api/registration/init", "", "{}", true, map[string]interface{}{"user_id": "x"}, func() error {
			_, err := c.PasskeyAPI.RegistrationInit(ctx, PasskeyAPIRegistrationInitParams{UserID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/passkey_api/registration/finalize", "POST", "/v1/passkey_api/registration/finalize", "", "{}", true, map[string]interface{}{"user_id": "x", "challenge": "x", "attestation_object": "x", "client_data_json": "x"}, func() error {
			_, err := c.PasskeyAPI.RegistrationFinalize(ctx, PasskeyAPIRegistrationFinalizeParams{UserID: "x", Challenge: "x", AttestationObject: "x", ClientDataJSON: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/passkey_api/login/init", "POST", "/v1/passkey_api/login/init", "", "{}", true, nil, func() error {
			_, err := c.PasskeyAPI.LoginInit(ctx, PasskeyAPILoginInitParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/passkey_api/login/finalize", "POST", "/v1/passkey_api/login/finalize", "", "{}", true, map[string]interface{}{"handle": "x", "challenge": "x", "credential_id": "x", "authenticator_data": "x", "client_data_json": "x", "signature": "x"}, func() error {
			_, err := c.PasskeyAPI.LoginFinalize(ctx, PasskeyAPILoginFinalizeParams{Handle: "x", Challenge: "x", CredentialID: "x", AuthenticatorData: "x", ClientDataJSON: "x", Signature: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/passkey_api/users/{}/passkeys", "GET", "/v1/passkey_api/users/p%201/passkeys", "limit=5", "{}", false, nil, func() error { _, err := c.PasskeyAPI.List(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"DELETE /v1/passkey_api/users/{}/passkeys/{}", "DELETE", "/v1/passkey_api/users/p%201/passkeys/v2", "", "{}", true, nil, func() error {
			_, err := c.PasskeyAPI.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/passkey_api/usage", "GET", "/v1/passkey_api/usage", "", "{}", false, nil, func() error { _, err := c.PasskeyAPI.Usage(ctx); return err }},
		{"POST /v1/vc/offers", "POST", "/v1/vc/offers", "", "{}", true, map[string]interface{}{"credential_type_id": "x", "user_id": "x"}, func() error {
			_, err := c.VC.CreateOffer(ctx, VCCreateOfferParams{CredentialTypeID: "x", UserID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/vc/credential_types", "GET", "/v1/vc/credential_types", "limit=5", "{}", false, nil, func() error { _, err := c.VC.CredentialTypes.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/vc/credential_types", "POST", "/v1/vc/credential_types", "", "{}", true, map[string]interface{}{"vct": "x", "name": "x"}, func() error {
			_, err := c.VC.CredentialTypes.Create(ctx, VCCredentialTypesCreateParams{Vct: "x", Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/vc/credential_types/{}", "GET", "/v1/vc/credential_types/p%201", "", "{}", false, nil, func() error { _, err := c.VC.CredentialTypes.Get(ctx, "p 1"); return err }},
		{"DELETE /v1/vc/credential_types/{}", "DELETE", "/v1/vc/credential_types/p%201", "", "{}", true, nil, func() error {
			_, err := c.VC.CredentialTypes.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/vc/credentials", "GET", "/v1/vc/credentials", "user_id=x", "{}", false, nil, func() error { _, err := c.VC.Credentials.List(ctx, VCCredentialsListQuery{UserID: "x"}); return err }},
		{"POST /v1/vc/credentials/{}/revoke", "POST", "/v1/vc/credentials/p%201/revoke", "", "{}", true, nil, func() error {
			_, err := c.VC.Credentials.Revoke(ctx, "p 1", map[string]interface{}{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/vc/presentation_requests", "POST", "/v1/vc/presentation_requests", "", "{}", true, map[string]interface{}{"vct": "x"}, func() error {
			_, err := c.VC.PresentationRequests.Create(ctx, VCPresentationRequestsCreateParams{Vct: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/vc/presentation_requests/{}", "GET", "/v1/vc/presentation_requests/p%201", "", "{}", false, nil, func() error { _, err := c.VC.PresentationRequests.Get(ctx, "p 1"); return err }},
		{"POST /v1/listen/sessions", "POST", "/v1/listen/sessions", "", "{}", true, nil, func() error {
			_, err := c.Listen.CreateSession(ctx, ListenCreateSessionParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/listen/sessions/{}/stream", "GET", "/v1/listen/sessions/p%201/stream", "events=x", "{}", false, nil, func() error {
			_, err := c.Listen.StreamSession(ctx, "p 1", ListenStreamSessionQuery{Events: "x"})
			return err
		}},
		{"GET /v1/agent_registration", "GET", "/v1/agent_registration", "", "{}", false, nil, func() error { _, err := c.AgentRegistration.Get(ctx); return err }},
		{"PUT /v1/agent_registration", "PUT", "/v1/agent_registration", "", "{}", true, nil, func() error {
			return c.AgentRegistration.Replace(ctx, AgentRegistrationReplaceParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/agents/{}/claim", "POST", "/v1/agents/p%201/claim", "", "{}", true, map[string]interface{}{"user_id": "x"}, func() error {
			return c.Agents.Claim(ctx, "p 1", AgentsClaimParams{UserID: "x"}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/agents", "GET", "/v1/agents", "owner_user_id=x", "{}", false, nil, func() error { _, err := c.Agents.List(ctx, AgentsListQuery{OwnerUserID: "x"}); return err }},
		{"GET /v1/agents/{}", "GET", "/v1/agents/p%201", "", "{}", false, nil, func() error { _, err := c.Agents.Get(ctx, "p 1"); return err }},
		{"PUT /v1/agents/{}/owner", "PUT", "/v1/agents/p%201/owner", "", "{}", true, nil, func() error {
			return c.Agents.SetOwner(ctx, "p 1", AgentsSetOwnerParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/agents/{}/revoke_access", "POST", "/v1/agents/p%201/revoke_access", "", "{}", true, nil, func() error {
			return c.Agents.RevokeAccess(ctx, "p 1", AgentsRevokeAccessParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/agent_access_requests/{}/approve", "POST", "/v1/agent_access_requests/p%201/approve", "", "{}", true, nil, func() error {
			return c.AgentAccessRequests.Approve(ctx, "p 1", AgentAccessRequestsApproveParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/agent_access_requests/{}/deny", "POST", "/v1/agent_access_requests/p%201/deny", "", "{}", true, nil, func() error {
			return c.AgentAccessRequests.Deny(ctx, "p 1", AgentAccessRequestsDenyParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/agent_access_requests", "GET", "/v1/agent_access_requests", "status=pending", "{}", false, nil, func() error {
			_, err := c.AgentAccessRequests.List(ctx, AgentAccessRequestsListQuery{Status: "pending"})
			return err
		}},
		{"GET /v1/actions/{}/calls", "GET", "/v1/actions/p%201/calls", "limit=3", "{}", false, nil, func() error { _, err := c.Actions.Calls(ctx, "p 1", ActionsCallsQuery{Limit: 3}); return err }},
		{"GET /v1/workflows", "GET", "/v1/workflows", "limit=5", "{}", false, nil, func() error { _, err := c.Workflows.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/workflows", "POST", "/v1/workflows", "", "{}", true, nil, func() error {
			_, err := c.Workflows.Create(ctx, WorkflowsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/workflows/{}", "GET", "/v1/workflows/p%201", "", "{}", false, nil, func() error { _, err := c.Workflows.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/workflows/{}", "PATCH", "/v1/workflows/p%201", "", "{}", true, nil, func() error {
			_, err := c.Workflows.Update(ctx, "p 1", WorkflowsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/workflows/{}", "DELETE", "/v1/workflows/p%201", "", "{}", true, nil, func() error { _, err := c.Workflows.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/workflows/{}/dry_run", "POST", "/v1/workflows/p%201/dry_run", "", "{}", true, nil, func() error {
			_, err := c.Workflows.DryRun(ctx, "p 1", WorkflowsDryRunParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/workflows/{}/run", "POST", "/v1/workflows/p%201/run", "", "{}", true, nil, func() error {
			_, err := c.Workflows.Run(ctx, "p 1", WorkflowsDryRunParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/workflows/{}/runs", "GET", "/v1/workflows/p%201/runs", "limit=5", "{}", false, nil, func() error { _, err := c.Workflows.Runs(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/instance/page_templates", "GET", "/v1/instance/page_templates", "limit=5", "{}", false, nil, func() error { _, err := c.PageTemplates.List(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/instance/page_templates/{}", "GET", "/v1/instance/page_templates/p%201", "", "{}", false, nil, func() error { _, err := c.PageTemplates.Get(ctx, "p 1"); return err }},
		{"PUT /v1/instance/page_templates/{}", "PUT", "/v1/instance/page_templates/p%201", "", "{}", true, nil, func() error {
			_, err := c.PageTemplates.SaveDraft(ctx, "p 1", PageTemplatesSaveDraftParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/instance/page_templates/{}", "DELETE", "/v1/instance/page_templates/p%201", "status=draft", "{}", true, nil, func() error {
			_, err := c.PageTemplates.Discard(ctx, "p 1", PageTemplatesDiscardQuery{Status: "draft"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/instance/page_templates/{}/preview", "POST", "/v1/instance/page_templates/p%201/preview", "", "{}", true, nil, func() error { _, err := c.PageTemplates.Preview(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/instance/page_templates/{}/promote", "POST", "/v1/instance/page_templates/p%201/promote", "", "{}", true, nil, func() error { _, err := c.PageTemplates.Promote(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/service_connector_catalog", "GET", "/v1/service_connector_catalog", "limit=5", "{}", false, nil, func() error { _, err := c.ServiceConnectors.Catalog(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/service_connectors", "GET", "/v1/service_connectors", "limit=5", "{}", false, nil, func() error { _, err := c.ServiceConnectors.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/service_connectors", "POST", "/v1/service_connectors", "", "{}", true, nil, func() error {
			_, err := c.ServiceConnectors.Create(ctx, ServiceConnectorsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/service_connectors/{}", "GET", "/v1/service_connectors/p%201", "", "{}", false, nil, func() error { _, err := c.ServiceConnectors.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/service_connectors/{}", "PATCH", "/v1/service_connectors/p%201", "", "{}", true, nil, func() error {
			_, err := c.ServiceConnectors.Update(ctx, "p 1", ServiceConnectorsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/service_connectors/{}", "DELETE", "/v1/service_connectors/p%201", "", "{}", true, nil, func() error {
			_, err := c.ServiceConnectors.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/service_connectors/{}/invoke", "POST", "/v1/service_connectors/p%201/invoke", "", "{}", true, nil, func() error {
			_, err := c.ServiceConnectors.Invoke(ctx, "p 1", ServiceConnectorsInvokeParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/desktop_mfa/policy", "GET", "/v1/desktop_mfa/policy", "", "{}", false, nil, func() error { _, err := c.DesktopMFA.GetPolicy(ctx); return err }},
		{"PUT /v1/desktop_mfa/policy", "PUT", "/v1/desktop_mfa/policy", "", "{}", true, nil, func() error {
			_, err := c.DesktopMFA.UpdatePolicy(ctx, DesktopMFAUpdatePolicyParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/desktop_mfa/enrolment_codes", "POST", "/v1/desktop_mfa/enrolment_codes", "", "{}", true, nil, func() error {
			_, err := c.DesktopMFA.CreateEnrolmentCode(ctx, DesktopMFACreateEnrolmentCodeParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/desktop_mfa/devices", "GET", "/v1/desktop_mfa/devices", "user_id=x", "{}", false, nil, func() error {
			_, err := c.DesktopMFA.ListDevices(ctx, DesktopMFAListDevicesQuery{UserID: "x"})
			return err
		}},
		{"GET /v1/desktop_mfa/devices/{}", "GET", "/v1/desktop_mfa/devices/p%201", "", "{}", false, nil, func() error { _, err := c.DesktopMFA.GetDevice(ctx, "p 1"); return err }},
		{"DELETE /v1/desktop_mfa/devices/{}", "DELETE", "/v1/desktop_mfa/devices/p%201", "", "{}", true, nil, func() error {
			_, err := c.DesktopMFA.DeleteDevice(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/desktop_mfa/devices/{}/revoke", "POST", "/v1/desktop_mfa/devices/p%201/revoke", "", "{}", true, nil, func() error {
			_, err := c.DesktopMFA.RevokeDevice(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/desktop_mfa/devices/{}/revoke_offline_cache", "POST", "/v1/desktop_mfa/devices/p%201/revoke_offline_cache", "", "{}", true, nil, func() error {
			_, err := c.DesktopMFA.RevokeOfflineCache(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/identity_verification/settings", "GET", "/v1/identity_verification/settings", "", "{}", false, nil, func() error { _, err := c.IdentityVerification.Settings(ctx); return err }},
		{"PUT /v1/identity_verification/settings", "PUT", "/v1/identity_verification/settings", "", "{}", true, nil, func() error {
			_, err := c.IdentityVerification.UpdateSettings(ctx, IdentityVerificationUpdateSettingsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/identity_verifications", "GET", "/v1/identity_verifications", "status=pending", "{}", false, nil, func() error {
			_, err := c.IdentityVerification.List(ctx, IdentityVerificationListQuery{Status: "pending"})
			return err
		}},
		{"GET /v1/identity_verifications/{}", "GET", "/v1/identity_verifications/p%201", "", "{}", false, nil, func() error { _, err := c.IdentityVerification.Get(ctx, "p 1"); return err }},
		{"POST /v1/identity_verifications/{}/decide", "POST", "/v1/identity_verifications/p%201/decide", "", "{}", true, nil, func() error {
			_, err := c.IdentityVerification.Decide(ctx, "p 1", IdentityVerificationDecideParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/users/{}/identity_verifications", "GET", "/v1/users/p%201/identity_verifications", "limit=5", "{}", false, nil, func() error { _, err := c.IdentityVerification.ForUser(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/users/{}/identity_verifications", "POST", "/v1/users/p%201/identity_verifications", "", "{}", true, nil, func() error {
			_, err := c.IdentityVerification.Start(ctx, "p 1", IdentityVerificationStartParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/entitlements", "GET", "/v1/iga/entitlements", "kind=role", "{}", false, nil, func() error {
			_, err := c.IGA.Entitlements.List(ctx, IGAEntitlementsListQuery{Kind: "role"})
			return err
		}},
		{"POST /v1/iga/entitlements", "POST", "/v1/iga/entitlements", "", "{}", true, map[string]interface{}{"key": "x", "name": "x", "kind": "role"}, func() error {
			_, err := c.IGA.Entitlements.Create(ctx, IGAEntitlementsCreateParams{Key: "x", Name: "x", Kind: "role"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/entitlements/{}", "GET", "/v1/iga/entitlements/p%201", "", "{}", false, nil, func() error { _, err := c.IGA.Entitlements.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/iga/entitlements/{}", "PATCH", "/v1/iga/entitlements/p%201", "", "{}", true, nil, func() error {
			_, err := c.IGA.Entitlements.Update(ctx, "p 1", IGAEntitlementsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/iga/entitlements/{}", "DELETE", "/v1/iga/entitlements/p%201", "", "{}", true, nil, func() error {
			_, err := c.IGA.Entitlements.Delete(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/requests", "GET", "/v1/iga/requests", "status=pending", "{}", false, nil, func() error { _, err := c.IGA.Requests.List(ctx, IGARequestsListQuery{Status: "pending"}); return err }},
		{"POST /v1/iga/requests", "POST", "/v1/iga/requests", "", "{}", true, map[string]interface{}{"entitlement": "x", "user_id": "x"}, func() error {
			_, err := c.IGA.Requests.Create(ctx, IGARequestsCreateParams{Entitlement: "x", UserID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/requests/{}", "GET", "/v1/iga/requests/p%201", "", "{}", false, nil, func() error { _, err := c.IGA.Requests.Get(ctx, "p 1"); return err }},
		{"POST /v1/iga/requests/{}/decide", "POST", "/v1/iga/requests/p%201/decide", "", "{}", true, map[string]interface{}{"decision": "approve"}, func() error {
			_, err := c.IGA.Requests.Decide(ctx, "p 1", IGARequestsDecideParams{Decision: "approve"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/iga/requests/{}/cancel", "POST", "/v1/iga/requests/p%201/cancel", "", "{}", true, nil, func() error { _, err := c.IGA.Requests.Cancel(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/iga/approvals", "GET", "/v1/iga/approvals", "approver_user_id=x", "{}", false, nil, func() error {
			_, err := c.IGA.Requests.Inbox(ctx, IGARequestsInboxQuery{ApproverUserID: "x"})
			return err
		}},
		{"GET /v1/iga/grants", "GET", "/v1/iga/grants", "user_id=x", "{}", false, nil, func() error { _, err := c.IGA.Grants.List(ctx, IGAGrantsListQuery{UserID: "x"}); return err }},
		{"POST /v1/iga/grants", "POST", "/v1/iga/grants", "", "{}", true, map[string]interface{}{"entitlement": "x", "user_id": "x"}, func() error {
			_, err := c.IGA.Grants.Create(ctx, IGAGrantsCreateParams{Entitlement: "x", UserID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/iga/grants/{}/revoke", "POST", "/v1/iga/grants/p%201/revoke", "", "{}", true, nil, func() error {
			_, err := c.IGA.Grants.Revoke(ctx, "p 1", IGAGrantsRevokeParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/delegations", "GET", "/v1/iga/delegations", "delegator_user_id=x", "{}", false, nil, func() error {
			_, err := c.IGA.Delegations.List(ctx, IGADelegationsListQuery{DelegatorUserID: "x"})
			return err
		}},
		{"POST /v1/iga/delegations", "POST", "/v1/iga/delegations", "", "{}", true, map[string]interface{}{"delegator_user_id": "x", "delegate_user_id": "x", "ends_at": float64(1)}, func() error {
			_, err := c.IGA.Delegations.Create(ctx, IGADelegationsCreateParams{DelegatorUserID: "x", DelegateUserID: "x", EndsAt: 1}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/iga/delegations/{}", "DELETE", "/v1/iga/delegations/p%201", "", "{}", true, nil, func() error { _, err := c.IGA.Delegations.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/iga/sod_rules", "GET", "/v1/iga/sod_rules", "limit=5", "{}", false, nil, func() error { _, err := c.IGA.SOD.ListRules(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/iga/sod_rules", "POST", "/v1/iga/sod_rules", "", "{}", true, map[string]interface{}{"name": "x", "entitlement_a": "x", "entitlement_b": "x"}, func() error {
			_, err := c.IGA.SOD.CreateRule(ctx, IGASODCreateRuleParams{Name: "x", EntitlementA: "x", EntitlementB: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PATCH /v1/iga/sod_rules/{}", "PATCH", "/v1/iga/sod_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.IGA.SOD.UpdateRule(ctx, "p 1", IGASODUpdateRuleParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/iga/sod_rules/{}", "DELETE", "/v1/iga/sod_rules/p%201", "", "{}", true, nil, func() error { _, err := c.IGA.SOD.DeleteRule(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/iga/sod_violations", "GET", "/v1/iga/sod_violations", "status=open", "{}", false, nil, func() error { _, err := c.IGA.SOD.Violations(ctx, IGASODViolationsQuery{Status: "open"}); return err }},
		{"POST /v1/iga/sod_violations/scan", "POST", "/v1/iga/sod_violations/scan", "", "{}", true, nil, func() error { _, err := c.IGA.SOD.Scan(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/iga/birthright_rules", "GET", "/v1/iga/birthright_rules", "limit=5", "{}", false, nil, func() error { _, err := c.IGA.Lifecycle.ListBirthrightRules(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/iga/birthright_rules", "POST", "/v1/iga/birthright_rules", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.IGA.Lifecycle.CreateBirthrightRule(ctx, IGALifecycleCreateBirthrightRuleParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PATCH /v1/iga/birthright_rules/{}", "PATCH", "/v1/iga/birthright_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.IGA.Lifecycle.UpdateBirthrightRule(ctx, "p 1", IGALifecycleUpdateBirthrightRuleParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/iga/birthright_rules/{}", "DELETE", "/v1/iga/birthright_rules/p%201", "", "{}", true, nil, func() error {
			_, err := c.IGA.Lifecycle.DeleteBirthrightRule(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/iga/users/{}/reconcile", "POST", "/v1/iga/users/p%201/reconcile", "", "{}", true, nil, func() error {
			_, err := c.IGA.Lifecycle.Reconcile(ctx, "p 1", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/iga/users/{}/offboard", "POST", "/v1/iga/users/p%201/offboard", "", "{}", true, nil, func() error {
			_, err := c.IGA.Lifecycle.Offboard(ctx, "p 1", IGALifecycleOffboardParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/settings", "GET", "/v1/iga/settings", "", "{}", false, nil, func() error { _, err := c.IGA.Lifecycle.Settings(ctx); return err }},
		{"PUT /v1/iga/settings", "PUT", "/v1/iga/settings", "", "{}", true, nil, func() error {
			_, err := c.IGA.Lifecycle.UpdateSettings(ctx, IGALifecycleUpdateSettingsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/campaigns", "GET", "/v1/iga/campaigns", "status=draft", "{}", false, nil, func() error { _, err := c.IGA.Campaigns.List(ctx, IGACampaignsListQuery{Status: "draft"}); return err }},
		{"POST /v1/iga/campaigns", "POST", "/v1/iga/campaigns", "", "{}", true, map[string]interface{}{"name": "x"}, func() error {
			_, err := c.IGA.Campaigns.Create(ctx, IGACampaignsCreateParams{Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/iga/campaigns/{}", "GET", "/v1/iga/campaigns/p%201", "", "{}", false, nil, func() error { _, err := c.IGA.Campaigns.Get(ctx, "p 1"); return err }},
		{"DELETE /v1/iga/campaigns/{}", "DELETE", "/v1/iga/campaigns/p%201", "", "{}", true, nil, func() error { _, err := c.IGA.Campaigns.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/iga/campaigns/{}/launch", "POST", "/v1/iga/campaigns/p%201/launch", "", "{}", true, nil, func() error { _, err := c.IGA.Campaigns.Launch(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/iga/campaigns/{}/close", "POST", "/v1/iga/campaigns/p%201/close", "", "{}", true, nil, func() error { _, err := c.IGA.Campaigns.Close(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/iga/campaigns/{}/items", "GET", "/v1/iga/campaigns/p%201/items", "decision=pending", "{}", false, nil, func() error {
			_, err := c.IGA.Campaigns.Items(ctx, "p 1", IGACampaignsItemsQuery{Decision: "pending"})
			return err
		}},
		{"GET /v1/iga/campaigns/{}/progress", "GET", "/v1/iga/campaigns/p%201/progress", "", "{}", false, nil, func() error { _, err := c.IGA.Campaigns.Progress(ctx, "p 1"); return err }},
		{"GET /v1/iga/campaigns/{}/evidence", "GET", "/v1/iga/campaigns/p%201/evidence", "format=json", "{}", false, nil, func() error {
			_, err := c.IGA.Campaigns.Evidence(ctx, "p 1", IGACampaignsEvidenceQuery{Format: "json"})
			return err
		}},
		{"POST /v1/iga/campaign_items/{}/decide", "POST", "/v1/iga/campaign_items/p%201/decide", "", "{}", true, map[string]interface{}{"decision": "certify"}, func() error {
			_, err := c.IGA.Campaigns.Decide(ctx, "p 1", IGACampaignsDecideParams{Decision: "certify"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/scim_provisioning_presets", "GET", "/v1/scim_provisioning_presets", "limit=5", "{}", false, nil, func() error { _, err := c.SCIMProvisioningPresets.List(ctx, ListParams{Limit: 5}); return err }},
		{"GET /v1/organizations/{}/webhook_endpoints", "GET", "/v1/organizations/p%201/webhook_endpoints", "limit=5", "{}", false, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.List(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"POST /v1/organizations/{}/webhook_endpoints", "POST", "/v1/organizations/p%201/webhook_endpoints", "", "{}", true, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.Create(ctx, "p 1", OrganizationsWebhookEndpointsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/organizations/{}/webhook_endpoints/{}", "GET", "/v1/organizations/p%201/webhook_endpoints/v2", "", "{}", false, nil, func() error { _, err := c.Organizations.WebhookEndpoints.Get(ctx, "p 1", "v2"); return err }},
		{"PATCH /v1/organizations/{}/webhook_endpoints/{}", "PATCH", "/v1/organizations/p%201/webhook_endpoints/v2", "", "{}", true, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.Update(ctx, "p 1", "v2", OrganizationsWebhookEndpointsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/organizations/{}/webhook_endpoints/{}", "DELETE", "/v1/organizations/p%201/webhook_endpoints/v2", "", "{}", true, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/organizations/{}/webhook_endpoints/{}/rotate_secret", "POST", "/v1/organizations/p%201/webhook_endpoints/v2/rotate_secret", "", "{}", true, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.RotateSecret(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/organizations/{}/webhook_endpoints/{}/deliveries", "GET", "/v1/organizations/p%201/webhook_endpoints/v2/deliveries", "limit=3", "{}", false, nil, func() error {
			_, err := c.Organizations.WebhookEndpoints.Deliveries(ctx, "p 1", "v2", OrganizationsWebhookEndpointsDeliveriesQuery{Limit: 3})
			return err
		}},
		{"POST /v1/vault/objects", "POST", "/v1/vault/objects", "", "{}", true, nil, func() error {
			_, err := c.Vault.Create(ctx, VaultCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/vault/objects", "GET", "/v1/vault/objects", "name_prefix=x", "{}", false, nil, func() error { _, err := c.Vault.List(ctx, VaultListQuery{NamePrefix: "x"}); return err }},
		{"GET /v1/vault/objects/{}/metadata", "GET", "/v1/vault/objects/p%201/metadata", "", "{}", false, nil, func() error { _, err := c.Vault.Metadata(ctx, "p 1"); return err }},
		{"GET /v1/vault/objects/{}/versions", "GET", "/v1/vault/objects/p%201/versions", "limit=5", "{}", false, nil, func() error { _, err := c.Vault.Versions(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/vault/objects/{}", "GET", "/v1/vault/objects/p%201", "version=3", "{}", false, nil, func() error { _, err := c.Vault.Read(ctx, "p 1", VaultReadQuery{Version: 3}); return err }},
		{"PUT /v1/vault/objects/{}", "PUT", "/v1/vault/objects/p%201", "", "{}", true, nil, func() error {
			_, err := c.Vault.Update(ctx, "p 1", VaultUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/vault/objects/{}", "DELETE", "/v1/vault/objects/p%201", "", "{}", true, nil, func() error { _, err := c.Vault.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/vault/key_provider", "GET", "/v1/vault/key_provider", "", "{}", false, nil, func() error { _, err := c.Vault.KeyProvider.Get(ctx); return err }},
		{"PUT /v1/vault/key_provider", "PUT", "/v1/vault/key_provider", "", "{}", true, nil, func() error {
			_, err := c.Vault.KeyProvider.Set(ctx, VaultKeyProviderSetParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/vault/key_provider", "DELETE", "/v1/vault/key_provider", "", "{}", true, nil, func() error { _, err := c.Vault.KeyProvider.Remove(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"POST /v1/connections", "POST", "/v1/connections", "", "{}", true, map[string]interface{}{"provider": "x"}, func() error {
			_, err := c.Connections.Create(ctx, ConnectionsCreateParams{Provider: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/connections", "GET", "/v1/connections", "owner_type=organization", "{}", false, nil, func() error {
			_, err := c.Connections.List(ctx, ConnectionsListQuery{OwnerType: "organization"})
			return err
		}},
		{"GET /v1/connections/{}", "GET", "/v1/connections/p%201", "", "{}", false, nil, func() error { _, err := c.Connections.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/connections/{}", "PATCH", "/v1/connections/p%201", "", "{}", true, nil, func() error {
			_, err := c.Connections.Update(ctx, "p 1", ConnectionsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/connections/{}", "DELETE", "/v1/connections/p%201", "revoke=true", "{}", true, nil, func() error {
			return c.Connections.Delete(ctx, "p 1", ConnectionsDeleteQuery{Revoke: &yes}, WithIdempotencyKey("idem-1"))
		}},
		{"PUT /v1/connections/{}/credentials", "PUT", "/v1/connections/p%201/credentials", "", "{}", true, nil, func() error {
			_, err := c.Connections.SetCredentials(ctx, "p 1", ConnectionsSetCredentialsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/{}/connect", "POST", "/v1/connections/p%201/connect", "", "{}", true, map[string]interface{}{"redirect_url": "x"}, func() error {
			_, err := c.Connections.Connect(ctx, "p 1", ConnectionsConnectParams{RedirectURL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/{}/revoke", "POST", "/v1/connections/p%201/revoke", "", "{}", true, nil, func() error {
			_, err := c.Connections.Revoke(ctx, "p 1", map[string]interface{}{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/{}/oauth1/sign", "POST", "/v1/connections/p%201/oauth1/sign", "", "{}", true, map[string]interface{}{"url": "x"}, func() error {
			_, err := c.Connections.Oauth1Sign(ctx, "p 1", ConnectionsOauth1SignParams{URL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/{}/relay", "POST", "/v1/connections/p%201/relay", "", "{}", true, map[string]interface{}{"url": "x"}, func() error {
			_, err := c.Connections.Relay(ctx, "p 1", ConnectionsRelayParams{URL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/connections/{}/token", "GET", "/v1/connections/p%201/token", "min_ttl_seconds=3", "{}", false, nil, func() error {
			_, err := c.Connections.Token(ctx, "p 1", ConnectionsTokenQuery{MinTTLSeconds: 3})
			return err
		}},
		{"POST /v1/connections/{}/token/refresh", "POST", "/v1/connections/p%201/token/refresh", "", "{}", true, nil, func() error {
			_, err := c.Connections.RefreshToken(ctx, "p 1", ConnectionsRefreshTokenParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/tokens/batch", "POST", "/v1/connections/tokens/batch", "", "{}", true, nil, func() error {
			_, err := c.Connections.Tokens(ctx, ConnectionsTokensParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/import", "POST", "/v1/connections/import", "", "{}", true, nil, func() error {
			_, err := c.Connections.ImportConnections(ctx, ConnectionsImportConnectionsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/export", "POST", "/v1/connections/export", "", "{}", true, nil, func() error {
			_, err := c.Connections.ExportConnections(ctx, ConnectionsExportConnectionsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/connections/{}/secret", "GET", "/v1/connections/p%201/secret", "version=x", "{}", false, nil, func() error {
			_, err := c.Connections.Secret(ctx, "p 1", ConnectionsSecretQuery{Version: "x"})
			return err
		}},
		{"GET /v1/connections/{}/credentials/versions", "GET", "/v1/connections/p%201/credentials/versions", "limit=5", "{}", false, nil, func() error { _, err := c.Connections.SecretVersions(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/connections/{}/credentials/rotate", "POST", "/v1/connections/p%201/credentials/rotate", "", "{}", true, nil, func() error {
			_, err := c.Connections.RotateCredentials(ctx, "p 1", ConnectionsRotateCredentialsParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/connections/oauth_clients", "PUT", "/v1/connections/oauth_clients", "", "{}", true, map[string]interface{}{"provider": "x", "client_id": "x"}, func() error {
			_, err := c.Connections.OAuthClients.Set(ctx, ConnectionsOAuthClientsSetParams{Provider: "x", ClientID: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/connections/oauth_clients", "GET", "/v1/connections/oauth_clients", "owner_type=organization", "{}", false, nil, func() error {
			_, err := c.Connections.OAuthClients.List(ctx, ConnectionsOAuthClientsListQuery{OwnerType: "organization"})
			return err
		}},
		{"GET /v1/connections/oauth_clients/{}", "GET", "/v1/connections/oauth_clients/p%201", "", "{}", false, nil, func() error { _, err := c.Connections.OAuthClients.Get(ctx, "p 1"); return err }},
		{"DELETE /v1/connections/oauth_clients/{}", "DELETE", "/v1/connections/oauth_clients/p%201", "", "{}", true, nil, func() error { return c.Connections.OAuthClients.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/connections/{}/webhooks/verify", "POST", "/v1/connections/p%201/webhooks/verify", "", "{}", true, map[string]interface{}{"raw_body": "x"}, func() error {
			_, err := c.Connections.Webhooks.Verify(ctx, "p 1", ConnectionsWebhooksVerifyParams{RawBody: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/connections/{}/webhook_endpoints", "POST", "/v1/connections/p%201/webhook_endpoints", "", "{}", true, map[string]interface{}{"forward_url": "x"}, func() error {
			_, err := c.Connections.Webhooks.CreateEndpoint(ctx, "p 1", ConnectionsWebhooksCreateEndpointParams{ForwardURL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/connections/{}/webhook_endpoints", "GET", "/v1/connections/p%201/webhook_endpoints", "limit=5", "{}", false, nil, func() error {
			_, err := c.Connections.Webhooks.ListEndpoints(ctx, "p 1", ListParams{Limit: 5})
			return err
		}},
		{"PATCH /v1/connections/{}/webhook_endpoints/{}", "PATCH", "/v1/connections/p%201/webhook_endpoints/v2", "", "{}", true, nil, func() error {
			_, err := c.Connections.Webhooks.UpdateEndpoint(ctx, "p 1", "v2", ConnectionsWebhooksUpdateEndpointParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/connections/{}/webhook_endpoints/{}", "DELETE", "/v1/connections/p%201/webhook_endpoints/v2", "", "{}", true, nil, func() error {
			return c.Connections.Webhooks.DeleteEndpoint(ctx, "p 1", "v2", WithIdempotencyKey("idem-1"))
		}},
		{"POST /v1/fga/stores/{}/list-users", "POST", "/v1/fga/stores/p%201/list-users", "", "{}", true, nil, func() error {
			_, err := c.FGA.ListUsers(ctx, "p 1", FGAListUsersParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/fga/stores/{}/changes", "GET", "/v1/fga/stores/p%201/changes", "type=x", "{}", false, nil, func() error { _, err := c.FGA.ReadChanges(ctx, "p 1", FGAReadChangesQuery{Type: "x"}); return err }},
		{"POST /v1/openfga/stores/{}/list-users", "POST", "/v1/openfga/stores/p%201/list-users", "", "{}", true, map[string]interface{}{"relation": "x"}, func() error {
			_, err := c.OpenFGA.ListUsers(ctx, "p 1", OpenFGAListUsersParams{Relation: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/openfga/stores/{}/changes", "GET", "/v1/openfga/stores/p%201/changes", "type=x", "{}", false, nil, func() error {
			_, err := c.OpenFGA.ReadChanges(ctx, "p 1", OpenFGAReadChangesQuery{Type: "x"})
			return err
		}},
		{"PUT /v1/attack_protection/app_attestation_secret", "PUT", "/v1/attack_protection/app_attestation_secret", "", "{}", true, nil, func() error {
			_, err := c.AttackProtection.SetAppAttestationSecret(ctx, AttackProtectionSetAppAttestationSecretParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/attack_protection/app_attestation_secret", "DELETE", "/v1/attack_protection/app_attestation_secret", "kind=play_integrity", "{}", true, nil, func() error {
			_, err := c.AttackProtection.RemoveAppAttestationSecret(ctx, AttackProtectionRemoveAppAttestationSecretQuery{Kind: "play_integrity"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"PUT /v1/risk_based_mfa/reputation_secret", "PUT", "/v1/risk_based_mfa/reputation_secret", "", "{}", true, nil, func() error {
			_, err := c.RiskBasedMFA.SetReputationSecret(ctx, RiskBasedMFASetReputationSecretParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/risk_based_mfa/reputation_secret", "DELETE", "/v1/risk_based_mfa/reputation_secret", "provider=x", "{}", true, nil, func() error {
			_, err := c.RiskBasedMFA.RemoveReputationSecret(ctx, RiskBasedMFARemoveReputationSecretQuery{Provider: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/ssf/streams", "GET", "/v1/ssf/streams", "limit=5", "{}", false, nil, func() error { _, err := c.SSF.Streams.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/ssf/streams", "POST", "/v1/ssf/streams", "", "{}", true, nil, func() error { return c.SSF.Streams.Create(ctx, SSFStreamsCreateParams{}, WithIdempotencyKey("idem-1")) }},
		{"GET /v1/ssf/streams/{}", "GET", "/v1/ssf/streams/p%201", "", "{}", false, nil, func() error { _, err := c.SSF.Streams.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/ssf/streams/{}", "PATCH", "/v1/ssf/streams/p%201", "", "{}", true, nil, func() error {
			return c.SSF.Streams.Update(ctx, "p 1", SSFStreamsUpdateParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"DELETE /v1/ssf/streams/{}", "DELETE", "/v1/ssf/streams/p%201", "", "{}", true, nil, func() error { return c.SSF.Streams.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/ssf/streams/{}/verify", "POST", "/v1/ssf/streams/p%201/verify", "", "{}", true, nil, func() error {
			return c.SSF.Streams.Verify(ctx, "p 1", SSFStreamsVerifyParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/ssf/streams/{}/status", "GET", "/v1/ssf/streams/p%201/status", "", "{}", false, nil, func() error { _, err := c.SSF.Streams.GetStatus(ctx, "p 1"); return err }},
		{"POST /v1/ssf/streams/{}/status", "POST", "/v1/ssf/streams/p%201/status", "", "{}", true, nil, func() error {
			_, err := c.SSF.Streams.UpdateStatus(ctx, "p 1", SSFStreamsUpdateStatusParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/ssf/streams/{}/events", "GET", "/v1/ssf/streams/p%201/events", "limit=5", "{}", false, nil, func() error { _, err := c.SSF.Streams.Events(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"GET /v1/ssf/receivers", "GET", "/v1/ssf/receivers", "limit=5", "{}", false, nil, func() error { _, err := c.SSF.Receivers.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/ssf/receivers", "POST", "/v1/ssf/receivers", "", "{}", true, nil, func() error {
			return c.SSF.Receivers.Create(ctx, SSFReceiversCreateParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"PATCH /v1/ssf/receivers/{}", "PATCH", "/v1/ssf/receivers/p%201", "", "{}", true, nil, func() error {
			return c.SSF.Receivers.Update(ctx, "p 1", SSFReceiversUpdateParams{}, WithIdempotencyKey("idem-1"))
		}},
		{"DELETE /v1/ssf/receivers/{}", "DELETE", "/v1/ssf/receivers/p%201", "", "{}", true, nil, func() error { return c.SSF.Receivers.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/network_zones", "GET", "/v1/network_zones", "limit=5", "{}", false, nil, func() error { _, err := c.NetworkZones.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/network_zones", "POST", "/v1/network_zones", "", "{}", true, nil, func() error {
			_, err := c.NetworkZones.Create(ctx, NetworkZonesCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/network_zones/{}", "GET", "/v1/network_zones/p%201", "", "{}", false, nil, func() error { _, err := c.NetworkZones.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/network_zones/{}", "PATCH", "/v1/network_zones/p%201", "", "{}", true, nil, func() error {
			_, err := c.NetworkZones.Update(ctx, "p 1", NetworkZonesCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/network_zones/{}", "DELETE", "/v1/network_zones/p%201", "", "{}", true, nil, func() error { return c.NetworkZones.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/network_zones/{}/check", "POST", "/v1/network_zones/p%201/check", "", "{}", true, nil, func() error {
			_, err := c.NetworkZones.Check(ctx, "p 1", NetworkZonesCheckParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/access_policies", "GET", "/v1/access_policies", "limit=5", "{}", false, nil, func() error { _, err := c.AccessPolicies.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/access_policies", "POST", "/v1/access_policies", "", "{}", true, nil, func() error {
			_, err := c.AccessPolicies.Create(ctx, AccessPoliciesCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/access_policies/simulate", "POST", "/v1/access_policies/simulate", "", "{}", true, nil, func() error {
			_, err := c.AccessPolicies.Simulate(ctx, AccessPoliciesSimulateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/access_policies/{}", "GET", "/v1/access_policies/p%201", "", "{}", false, nil, func() error { _, err := c.AccessPolicies.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/access_policies/{}", "PATCH", "/v1/access_policies/p%201", "", "{}", true, nil, func() error {
			_, err := c.AccessPolicies.Update(ctx, "p 1", AccessPoliciesCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/access_policies/{}", "DELETE", "/v1/access_policies/p%201", "", "{}", true, nil, func() error { return c.AccessPolicies.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/abac_policies", "GET", "/v1/abac_policies", "limit=5", "{}", false, nil, func() error { _, err := c.ABAC.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/abac_policies", "POST", "/v1/abac_policies", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Create(ctx, ABACCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/abac_policies/{}", "GET", "/v1/abac_policies/p%201", "", "{}", false, nil, func() error { _, err := c.ABAC.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/abac_policies/{}", "PATCH", "/v1/abac_policies/p%201", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Update(ctx, "p 1", ABACUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/abac_policies/{}", "DELETE", "/v1/abac_policies/p%201", "", "{}", true, nil, func() error { return c.ABAC.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/abac_policies/{}/versions", "GET", "/v1/abac_policies/p%201/versions", "limit=5", "{}", false, nil, func() error { _, err := c.ABAC.Versions(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/abac_policies/{}/test", "POST", "/v1/abac_policies/p%201/test", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Test(ctx, "p 1", ABACTestParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/abac/evaluate", "POST", "/v1/abac/evaluate", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Evaluate(ctx, ABACEvaluateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/abac/partial_evaluate", "POST", "/v1/abac/partial_evaluate", "", "{}", true, map[string]interface{}{"action": "x"}, func() error {
			_, err := c.ABAC.PartialEvaluate(ctx, ABACPartialEvaluateParams{Action: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/abac/accessible_resources", "POST", "/v1/abac/accessible_resources", "", "{}", true, map[string]interface{}{"action": "x", "resource_type": "x"}, func() error {
			_, err := c.ABAC.AccessibleResources(ctx, ABACAccessibleResourcesParams{Action: "x", ResourceType: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/abac_policies/{}/diff", "GET", "/v1/abac_policies/p%201/diff", "from=3", "{}", false, nil, func() error { _, err := c.ABAC.Diff(ctx, "p 1", ABACDiffQuery{From: 3}); return err }},
		{"POST /v1/abac/diff", "POST", "/v1/abac/diff", "", "{}", true, map[string]interface{}{"before": "x", "after": "x"}, func() error {
			_, err := c.ABAC.DiffSources(ctx, ABACDiffSourcesParams{Before: "x", After: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/authzen/access/v1/evaluation", "POST", "/v1/authzen/access/v1/evaluation", "", "{}", true, nil, func() error {
			_, err := c.ABAC.AuthzenEvaluation(ctx, ABACAuthzenEvaluationParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/authzen/access/v1/evaluations", "POST", "/v1/authzen/access/v1/evaluations", "", "{}", true, nil, func() error {
			_, err := c.ABAC.AuthzenEvaluations(ctx, ABACAuthzenEvaluationParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/authzen/access/v1/search/subject", "POST", "/v1/authzen/access/v1/search/subject", "", "{}", true, nil, func() error {
			_, err := c.ABAC.AuthzenSearchSubject(ctx, ABACAuthzenSearchSubjectParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/authzen/access/v1/search/resource", "POST", "/v1/authzen/access/v1/search/resource", "", "{}", true, nil, func() error {
			_, err := c.ABAC.AuthzenSearchResource(ctx, ABACAuthzenSearchResourceParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/authzen/access/v1/search/action", "POST", "/v1/authzen/access/v1/search/action", "", "{}", true, nil, func() error {
			_, err := c.ABAC.AuthzenSearchAction(ctx, ABACAuthzenSearchActionParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/abac_templates", "GET", "/v1/abac_templates", "limit=5", "{}", false, nil, func() error { _, err := c.ABAC.Templates.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/abac_templates", "POST", "/v1/abac_templates", "", "{}", true, map[string]interface{}{"name": "x", "source": "x"}, func() error {
			_, err := c.ABAC.Templates.Create(ctx, ABACTemplatesCreateParams{Name: "x", Source: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/abac_templates/{}", "GET", "/v1/abac_templates/p%201", "", "{}", false, nil, func() error { _, err := c.ABAC.Templates.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/abac_templates/{}", "PATCH", "/v1/abac_templates/p%201", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Templates.Update(ctx, "p 1", ABACTemplatesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/abac_templates/{}", "DELETE", "/v1/abac_templates/p%201", "force=true", "{}", true, nil, func() error {
			return c.ABAC.Templates.Delete(ctx, "p 1", ABACTemplatesDeleteQuery{Force: &yes}, WithIdempotencyKey("idem-1"))
		}},
		{"GET /v1/abac_policy_links", "GET", "/v1/abac_policy_links", "template_id=x", "{}", false, nil, func() error { _, err := c.ABAC.Links.List(ctx, ABACLinksListQuery{TemplateID: "x"}); return err }},
		{"POST /v1/abac_policy_links", "POST", "/v1/abac_policy_links", "", "{}", true, map[string]interface{}{"template_id": "x", "name": "x"}, func() error {
			_, err := c.ABAC.Links.Create(ctx, ABACLinksCreateParams{TemplateID: "x", Name: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/abac_policy_links/{}", "GET", "/v1/abac_policy_links/p%201", "", "{}", false, nil, func() error { _, err := c.ABAC.Links.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/abac_policy_links/{}", "PATCH", "/v1/abac_policy_links/p%201", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Links.Update(ctx, "p 1", ABACLinksUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/abac_policy_links/{}", "DELETE", "/v1/abac_policy_links/p%201", "", "{}", true, nil, func() error { return c.ABAC.Links.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/abac_schema", "GET", "/v1/abac_schema", "", "{}", false, nil, func() error { _, err := c.ABAC.Schema.Get(ctx); return err }},
		{"PUT /v1/abac_schema", "PUT", "/v1/abac_schema", "", "{}", true, nil, func() error {
			_, err := c.ABAC.Schema.Set(ctx, ABACSchemaSetParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/abac_schema", "DELETE", "/v1/abac_schema", "", "{}", true, nil, func() error { return c.ABAC.Schema.Delete(ctx, WithIdempotencyKey("idem-1")) }},
		{"POST /v1/abac_schema/validate", "POST", "/v1/abac_schema/validate", "", "{}", true, map[string]interface{}{"source": "x"}, func() error {
			_, err := c.ABAC.Schema.Validate(ctx, ABACSchemaValidateParams{Source: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/resources", "GET", "/v1/resources", "type=x", "{}", false, nil, func() error { _, err := c.Resources.List(ctx, ResourcesListQuery{Type: "x"}); return err }},
		{"PUT /v1/resources", "PUT", "/v1/resources", "", "{}", true, nil, func() error {
			_, err := c.Resources.Upsert(ctx, ResourcesUpsertParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/resources/sync", "POST", "/v1/resources/sync", "", "{}", true, nil, func() error {
			_, err := c.Resources.Sync(ctx, ResourcesSyncParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/resources/{}", "GET", "/v1/resources/p%201", "", "{}", false, nil, func() error { _, err := c.Resources.Get(ctx, "p 1"); return err }},
		{"DELETE /v1/resources/{}", "DELETE", "/v1/resources/p%201", "", "{}", true, nil, func() error { return c.Resources.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/resource_checks", "POST", "/v1/resource_checks", "", "{}", true, nil, func() error {
			_, err := c.Resources.Check(ctx, ResourcesCheckParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/resource_checks/batch", "POST", "/v1/resource_checks/batch", "", "{}", true, nil, func() error {
			_, err := c.Resources.CheckBatch(ctx, ResourcesCheckBatchParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/resource_checks/list", "POST", "/v1/resource_checks/list", "", "{}", true, nil, func() error {
			_, err := c.Resources.Accessible(ctx, ResourcesAccessibleParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/resource_types", "GET", "/v1/resource_types", "limit=5", "{}", false, nil, func() error { _, err := c.Resources.Types.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/resource_types", "POST", "/v1/resource_types", "", "{}", true, nil, func() error {
			_, err := c.Resources.Types.Create(ctx, ResourcesTypesCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/resource_types/{}", "GET", "/v1/resource_types/p%201", "", "{}", false, nil, func() error { _, err := c.Resources.Types.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/resource_types/{}", "PATCH", "/v1/resource_types/p%201", "", "{}", true, nil, func() error {
			_, err := c.Resources.Types.Update(ctx, "p 1", ResourcesTypesUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/resource_types/{}", "DELETE", "/v1/resource_types/p%201", "", "{}", true, nil, func() error { return c.Resources.Types.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/resource_role_assignments", "GET", "/v1/resource_role_assignments", "resource_id=x", "{}", false, nil, func() error {
			_, err := c.Resources.Assignments.List(ctx, ResourcesAssignmentsListQuery{ResourceID: "x"})
			return err
		}},
		{"POST /v1/resource_role_assignments", "POST", "/v1/resource_role_assignments", "", "{}", true, nil, func() error {
			_, err := c.Resources.Assignments.Assign(ctx, ResourcesAssignmentsAssignParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/resource_role_assignments/{}", "DELETE", "/v1/resource_role_assignments/p%201", "", "{}", true, nil, func() error { return c.Resources.Assignments.Revoke(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/org_role_grants", "GET", "/v1/org_role_grants", "grantor_org_id=x", "{}", false, nil, func() error {
			_, err := c.OrgRoleGrants.List(ctx, OrgRoleGrantsListQuery{GrantorOrgID: "x"})
			return err
		}},
		{"POST /v1/org_role_grants", "POST", "/v1/org_role_grants", "", "{}", true, nil, func() error {
			_, err := c.OrgRoleGrants.Create(ctx, OrgRoleGrantsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/org_role_grants/{}", "GET", "/v1/org_role_grants/p%201", "", "{}", false, nil, func() error { _, err := c.OrgRoleGrants.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/org_role_grants/{}", "PATCH", "/v1/org_role_grants/p%201", "", "{}", true, nil, func() error {
			_, err := c.OrgRoleGrants.Update(ctx, "p 1", OrgRoleGrantsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/org_role_grants/{}", "DELETE", "/v1/org_role_grants/p%201", "", "{}", true, nil, func() error { _, err := c.OrgRoleGrants.Revoke(ctx, "p 1", WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/org_role_grants/{}/delegations", "GET", "/v1/org_role_grants/p%201/delegations", "limit=5", "{}", false, nil, func() error { _, err := c.OrgRoleGrants.ListDelegations(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/org_role_grants/{}/delegations", "POST", "/v1/org_role_grants/p%201/delegations", "", "{}", true, nil, func() error {
			_, err := c.OrgRoleGrants.Delegate(ctx, "p 1", OrgRoleGrantsDelegateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/org_role_grants/{}/delegations/{}", "DELETE", "/v1/org_role_grants/p%201/delegations/v2", "", "{}", true, nil, func() error { return c.OrgRoleGrants.Undelegate(ctx, "p 1", "v2", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/org_role_grants/effective", "GET", "/v1/org_role_grants/effective", "user_id=x", "{}", false, nil, func() error {
			_, err := c.OrgRoleGrants.Effective(ctx, OrgRoleGrantsEffectiveQuery{UserID: "x"})
			return err
		}},
		{"GET /v1/devices", "GET", "/v1/devices", "user_id=x", "{}", false, nil, func() error { _, err := c.Devices.List(ctx, DevicesListQuery{UserID: "x"}); return err }},
		{"PUT /v1/devices", "PUT", "/v1/devices", "", "{}", true, nil, func() error {
			_, err := c.Devices.Report(ctx, DevicesReportParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/devices/{}", "GET", "/v1/devices/p%201", "", "{}", false, nil, func() error { _, err := c.Devices.Get(ctx, "p 1"); return err }},
		{"DELETE /v1/devices/{}", "DELETE", "/v1/devices/p%201", "", "{}", true, nil, func() error { return c.Devices.Remove(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"POST /v1/device_posture", "POST", "/v1/device_posture", "", "{}", true, nil, func() error {
			_, err := c.Devices.IngestPosture(ctx, DevicesIngestPostureParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/authz_decisions", "GET", "/v1/authz_decisions", "source=abac", "{}", false, nil, func() error {
			_, err := c.AuthzDecisions.List(ctx, AuthzDecisionsListQuery{Source: "abac"})
			return err
		}},
		{"GET /v1/authz_decisions/stats", "GET", "/v1/authz_decisions/stats", "since=x", "{}", false, nil, func() error { _, err := c.AuthzDecisions.Stats(ctx, AuthzDecisionsStatsQuery{Since: "x"}); return err }},
		{"GET /v1/authz_decisions/{}", "GET", "/v1/authz_decisions/p%201", "", "{}", false, nil, func() error { _, err := c.AuthzDecisions.Get(ctx, "p 1"); return err }},
		{"GET /v1/authz_decision_settings", "GET", "/v1/authz_decision_settings", "", "{}", false, nil, func() error { _, err := c.AuthzDecisions.Settings.Get(ctx); return err }},
		{"PUT /v1/authz_decision_settings", "PUT", "/v1/authz_decision_settings", "", "{}", true, nil, func() error {
			_, err := c.AuthzDecisions.Settings.Update(ctx, AuthzDecisionsSettingsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/policy_bundles/current", "GET", "/v1/policy_bundles/current", "", "{}", false, nil, func() error { _, err := c.PolicyBundles.Current(ctx); return err }},
		{"GET /v1/policy_bundles", "GET", "/v1/policy_bundles", "limit=5", "{}", false, nil, func() error { _, err := c.PolicyBundles.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/policy_bundles", "POST", "/v1/policy_bundles", "", "{}", true, nil, func() error { _, err := c.PolicyBundles.Export(ctx, WithIdempotencyKey("idem-1")); return err }},
		{"GET /v1/policy_bundles/{}", "GET", "/v1/policy_bundles/p%201", "", "{}", false, nil, func() error { _, err := c.PolicyBundles.Get(ctx, "p 1"); return err }},
		{"GET /v1/policy_bundles/{}/archive", "GET", "/v1/policy_bundles/p%201/archive", "", "{}", false, nil, func() error { _, err := c.PolicyBundles.Archive(ctx, "p 1"); return err }},
		{"POST /v1/policy_bundles/verify", "POST", "/v1/policy_bundles/verify", "", "{}", true, map[string]interface{}{"bundle": "x", "signature": "x"}, func() error {
			_, err := c.PolicyBundles.Verify(ctx, PolicyBundlesVerifyParams{Bundle: "x", Signature: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/policy_bundles/import", "POST", "/v1/policy_bundles/import", "", "{}", true, map[string]interface{}{"bundle": "x", "signature": "x"}, func() error {
			_, err := c.PolicyBundles.Import(ctx, PolicyBundlesImportParams{Bundle: "x", Signature: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/proxy_apps", "GET", "/v1/proxy_apps", "limit=5", "{}", false, nil, func() error { _, err := c.ProxyApps.List(ctx, ListParams{Limit: 5}); return err }},
		{"POST /v1/proxy_apps", "POST", "/v1/proxy_apps", "", "{}", true, map[string]interface{}{"name": "x", "hostname": "x", "upstream_url": "x"}, func() error {
			_, err := c.ProxyApps.Create(ctx, ProxyAppsCreateParams{Name: "x", Hostname: "x", UpstreamURL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/proxy_apps/{}", "GET", "/v1/proxy_apps/p%201", "", "{}", false, nil, func() error { _, err := c.ProxyApps.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/proxy_apps/{}", "PATCH", "/v1/proxy_apps/p%201", "", "{}", true, nil, func() error {
			_, err := c.ProxyApps.Update(ctx, "p 1", ProxyAppsUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/proxy_apps/{}", "DELETE", "/v1/proxy_apps/p%201", "", "{}", true, nil, func() error { return c.ProxyApps.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/mcp_gateways", "GET", "/v1/mcp_gateways", "", "{}", false, nil, func() error { _, err := c.MCPGateways.List(ctx); return err }},
		{"POST /v1/mcp_gateways", "POST", "/v1/mcp_gateways", "", "{}", true, map[string]interface{}{"name": "x", "upstream_url": "x"}, func() error {
			_, err := c.MCPGateways.Create(ctx, MCPGatewaysCreateParams{Name: "x", UpstreamURL: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/mcp_gateways/{}", "GET", "/v1/mcp_gateways/p%201", "", "{}", false, nil, func() error { _, err := c.MCPGateways.Get(ctx, "p 1"); return err }},
		{"PATCH /v1/mcp_gateways/{}", "PATCH", "/v1/mcp_gateways/p%201", "", "{}", true, nil, func() error {
			_, err := c.MCPGateways.Update(ctx, "p 1", MCPGatewaysUpdateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/mcp_gateways/{}", "DELETE", "/v1/mcp_gateways/p%201", "", "{}", true, nil, func() error { return c.MCPGateways.Delete(ctx, "p 1", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/mcp_gateways/{}/budgets", "GET", "/v1/mcp_gateways/p%201/budgets", "limit=5", "{}", false, nil, func() error { _, err := c.MCPGateways.Budgets.List(ctx, "p 1", ListParams{Limit: 5}); return err }},
		{"POST /v1/mcp_gateways/{}/budgets", "POST", "/v1/mcp_gateways/p%201/budgets", "", "{}", true, nil, func() error {
			_, err := c.MCPGateways.Budgets.Create(ctx, "p 1", MCPGatewaysBudgetsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"GET /v1/mcp_gateways/{}/budgets/{}", "GET", "/v1/mcp_gateways/p%201/budgets/v2", "", "{}", false, nil, func() error { _, err := c.MCPGateways.Budgets.Get(ctx, "p 1", "v2"); return err }},
		{"PATCH /v1/mcp_gateways/{}/budgets/{}", "PATCH", "/v1/mcp_gateways/p%201/budgets/v2", "", "{}", true, nil, func() error {
			_, err := c.MCPGateways.Budgets.Update(ctx, "p 1", "v2", MCPGatewaysBudgetsCreateParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"DELETE /v1/mcp_gateways/{}/budgets/{}", "DELETE", "/v1/mcp_gateways/p%201/budgets/v2", "", "{}", true, nil, func() error { return c.MCPGateways.Budgets.Delete(ctx, "p 1", "v2", WithIdempotencyKey("idem-1")) }},
		{"GET /v1/mcp_gateways/{}/budgets/{}/usage", "GET", "/v1/mcp_gateways/p%201/budgets/v2/usage", "agent_id=x", "{}", false, nil, func() error {
			_, err := c.MCPGateways.Budgets.Usage(ctx, "p 1", "v2", MCPGatewaysBudgetsUsageQuery{AgentID: "x"})
			return err
		}},
		{"POST /v1/instance/integrations/{}/events_secret/rotate", "POST", "/v1/instance/integrations/p%201/events_secret/rotate", "", "{}", true, nil, func() error {
			_, err := c.Instance.Integrations.RotateEventsSecret(ctx, "p 1", InstanceIntegrationsRotateEventsSecretParams{}, WithIdempotencyKey("idem-1"))
			return err
		}},
		{"POST /v1/integrations/{}/card/actions/{}", "POST", "/v1/integrations/p%201/card/actions/v2", "", "{}", true, map[string]interface{}{"sub": "x"}, func() error {
			_, err := c.Integrations.RunCardAction(ctx, "p 1", "v2", IntegrationsRunCardActionParams{Sub: "x"}, WithIdempotencyKey("idem-1"))
			return err
		}},
	}
	if len(rows) != 452 {
		t.Fatalf("operation table has %d rows, want 452", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.key] {
			t.Errorf("duplicate row %s", r.key)
		}
		seen[r.key] = true
		respBody = r.resp
		gotMethod, gotPath, gotQuery, gotIdem = "", "", "", ""
		if err := r.call(); err != nil {
			t.Errorf("%s: %v", r.key, err)
			continue
		}
		if gotMethod != r.method || gotPath != r.path {
			t.Errorf("%s hit %s %s, want %s %s", r.key, gotMethod, gotPath, r.method, r.path)
		}
		if gotQuery != r.query {
			t.Errorf("%s query = %q, want %q", r.key, gotQuery, r.query)
		}
		if r.write && gotIdem != "idem-1" {
			t.Errorf("%s Idempotency-Key = %q", r.key, gotIdem)
		}
		for k, want := range r.body {
			if !reflect.DeepEqual(gotBody[k], want) {
				t.Errorf("%s body[%s] = %v, want %v", r.key, k, gotBody[k], want)
			}
		}
	}
}

// TestPreservedMethodSignatures pins the signatures of methods that existed
// before the operation catch-up and share a name or a resource with new ones.
func TestPreservedMethodSignatures(t *testing.T) {
	var _ func(*UsersService, context.Context, UserListParams) (*UserSearchPage, error) = (*UsersService).Search
	var _ func(*DeliveryService, context.Context, DeliveryHealthParams) (*DeliveryHealthList, error) = (*DeliveryService).Health
	var _ func(*DeliveryService, context.Context) (*EgressIPs, error) = (*DeliveryService).EgressIPs
	var _ func(*DeliveryService, context.Context, string, string, []string, ...RequestOption) (*DeliveryHealth, error) = (*DeliveryService).SetAlertContacts
	c := New("sk_test")
	if c.Users.Searches == nil {
		t.Fatal("Users.Searches is not wired")
	}
}
