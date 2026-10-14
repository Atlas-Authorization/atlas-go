package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// recorded captures the last request a recordingClient served.
type recorded struct {
	Method, Path, Query, Strict, ContentType string
	Body                                     map[string]interface{}
	RawBody                                  string
}

// recordingClient serves every request with respBody and records it.
func recordingClient(t *testing.T, respBody string, opts ...Option) (*Client, *recorded) {
	t.Helper()
	rec := &recorded{}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*rec = recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Strict: r.Header.Get("Atlas-Strict"), ContentType: r.Header.Get("Content-Type"), RawBody: string(raw)}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}
		_, _ = w.Write([]byte(respBody))
	})
	for _, o := range opts {
		o(c)
	}
	return c, rec
}

func (r *recorded) expect(t *testing.T, method, path string) {
	t.Helper()
	if r.Method != method || r.Path != path {
		t.Errorf("hit %s %s, want %s %s", r.Method, r.Path, method, path)
	}
}

// TestOpenFGAWireSurface walks every /v1/openfga operation, asserting method,
// path, OpenFGA-shaped body, and response decoding.
func TestOpenFGAWireSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"stores":[{"id":"st_1","name":"docs","created_at":"2026-01-01T00:00:00Z"}],"id":"st_1","name":"docs","authorization_model_id":"m_1","authorization_models":[{"id":"m_1","schema_version":"1.1"}],"authorization_model":{"id":"m_1","schema_version":"1.1","type_definitions":[{"type":"user"}]},"allowed":true,"result":{"a":{"allowed":true}},"tuples":[{"key":{"user":"user:1","relation":"viewer","object":"doc:1"},"timestamp":"t"}],"continuation_token":"","objects":["doc:1"],"tree":{"root":{"name":"doc:1#viewer"}}}`)

	stores, err := c.OpenFGA.ListStores(ctx)
	if err != nil || len(stores.Stores) != 1 || stores.Stores[0].ID != "st_1" {
		t.Fatalf("ListStores = %+v, %v", stores, err)
	}
	rec.expect(t, "GET", "/v1/openfga/stores")

	st, _ := c.OpenFGA.CreateStore(ctx, "docs")
	rec.expect(t, "POST", "/v1/openfga/stores")
	if rec.Body["name"] != "docs" || st.Name != "docs" {
		t.Errorf("CreateStore body=%v out=%+v", rec.Body, st)
	}

	_, _ = c.OpenFGA.GetStore(ctx, "st 1")
	if rec.Path != "/v1/openfga/stores/st 1" || !strings.Contains(rec.Query+rec.Path, "st") {
		t.Errorf("GetStore path = %q", rec.Path)
	}

	wm, _ := c.OpenFGA.WriteAuthorizationModel(ctx, "st_1", OpenFGAWriteAuthorizationModelParams{DSL: "model\n  schema 1.1"})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/authorization-models")
	if rec.Body["dsl"] == nil || rec.Body["type_definitions"] != nil || wm.AuthorizationModelID != "m_1" {
		t.Errorf("WriteAuthorizationModel body=%v out=%+v", rec.Body, wm)
	}

	ms, _ := c.OpenFGA.ReadAuthorizationModels(ctx, "st_1")
	rec.expect(t, "GET", "/v1/openfga/stores/st_1/authorization-models")
	if len(ms.AuthorizationModels) != 1 {
		t.Errorf("models = %+v", ms)
	}

	m, _ := c.OpenFGA.ReadAuthorizationModel(ctx, "st_1", "m_1")
	rec.expect(t, "GET", "/v1/openfga/stores/st_1/authorization-models/m_1")
	if m.AuthorizationModel.ID != "m_1" || len(m.AuthorizationModel.TypeDefinitions) != 1 {
		t.Errorf("model = %+v", m)
	}

	chk, _ := c.OpenFGA.Check(ctx, "st_1", OpenFGACheckParams{
		TupleKey:         OpenFGATupleKey{User: "user:1", Relation: "viewer", Object: "doc:1"},
		ContextualTuples: &OpenFGATupleKeys{TupleKeys: []OpenFGATupleKey{{User: "user:2", Relation: "viewer", Object: "doc:1"}}},
	})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/check")
	ct, _ := rec.Body["contextual_tuples"].(map[string]interface{})
	if !chk.Allowed || ct == nil || ct["tuple_keys"] == nil {
		t.Errorf("Check body=%v out=%+v", rec.Body, chk)
	}

	bc, _ := c.OpenFGA.BatchCheck(ctx, "st_1", OpenFGABatchCheckParams{Checks: []OpenFGABatchCheckItem{{TupleKey: OpenFGATupleKey{User: "u", Relation: "r", Object: "o:1"}, CorrelationID: "a"}}})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/batch-check")
	if !bc.Result["a"].Allowed {
		t.Errorf("BatchCheck = %+v", bc)
	}

	if err := c.OpenFGA.Write(ctx, "st_1", OpenFGAWriteParams{Writes: &OpenFGATupleKeys{TupleKeys: []OpenFGATupleKey{{User: "u", Relation: "r", Object: "o:1"}}}}); err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/write")
	if rec.Body["writes"] == nil || rec.Body["deletes"] != nil {
		t.Errorf("Write body = %v", rec.Body)
	}

	rd, _ := c.OpenFGA.Read(ctx, "st_1", OpenFGAReadParams{TupleKey: &OpenFGAReadTupleKey{Object: "doc:1"}, PageSize: 10})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/read")
	if len(rd.Tuples) != 1 || rd.Tuples[0].Key.Object != "doc:1" || rec.Body["page_size"] != float64(10) {
		t.Errorf("Read body=%v out=%+v", rec.Body, rd)
	}

	lo, _ := c.OpenFGA.ListObjects(ctx, "st_1", OpenFGAListObjectsParams{Type: "doc", Relation: "viewer", User: "user:1"})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/list-objects")
	if len(lo.Objects) != 1 {
		t.Errorf("ListObjects = %+v", lo)
	}

	ex, _ := c.OpenFGA.Expand(ctx, "st_1", OpenFGAExpandParams{TupleKey: OpenFGAExpandTupleKey{Object: "doc:1", Relation: "viewer"}})
	rec.expect(t, "POST", "/v1/openfga/stores/st_1/expand")
	if ex.Tree.Root["name"] != "doc:1#viewer" {
		t.Errorf("Expand = %+v", ex)
	}
}

// TestConnectorsSurface covers connector profile CRUD, publish/unlist,
// shared credentials, install, review, and the directory query.
func TestConnectorsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"connector","id":"conn_1","slug":"acme","display_name":"Acme","status":"draft","share_modes":["prefill"],"install_count":3,"rating_avg":4.5,"created_at":1,"connector":"acme","share_mode":"prefill","needs_credentials":true,"rating":5,"data":[{"source":"builtin","key":"google","slug":"google","displayName":"Google","category":"social","rankScore":9.5,"shareModes":[]}]}`)

	conn, err := c.Connectors.Create(ctx, ConnectorParams{Slug: "acme", DisplayName: "Acme", ShareModes: []string{"prefill"}}, StrictBody(true))
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/connectors")
	if rec.Body["slug"] != "acme" || rec.Body["logo_url"] != nil || rec.Strict != "true" || conn.InstallCount != 3 || conn.RatingAvg != 4.5 {
		t.Errorf("Create body=%v strict=%q out=%+v", rec.Body, rec.Strict, conn)
	}

	_, _ = c.Connectors.List(ctx)
	rec.expect(t, "GET", "/v1/connectors")
	_, _ = c.Connectors.Get(ctx, "conn_1")
	rec.expect(t, "GET", "/v1/connectors/conn_1")
	_, _ = c.Connectors.Update(ctx, "conn_1", ConnectorParams{Tagline: "t"})
	rec.expect(t, "PATCH", "/v1/connectors/conn_1")
	if len(rec.Body) != 1 || rec.Body["tagline"] != "t" {
		t.Errorf("Update body = %v, want only tagline", rec.Body)
	}
	_, _ = c.Connectors.Delete(ctx, "conn_1")
	rec.expect(t, "DELETE", "/v1/connectors/conn_1")
	_, _ = c.Connectors.Publish(ctx, "conn_1")
	rec.expect(t, "POST", "/v1/connectors/conn_1/publish")
	_, _ = c.Connectors.Unlist(ctx, "conn_1")
	rec.expect(t, "POST", "/v1/connectors/conn_1/unlist")
	_, _ = c.Connectors.SetSharedCredentials(ctx, "conn_1", ConnectorSharedCredentialsParams{Revoke: true})
	rec.expect(t, "POST", "/v1/connectors/conn_1/shared_credentials")
	if rec.Body["revoke"] != true || rec.Body["client_secret"] != nil {
		t.Errorf("shared creds body = %v", rec.Body)
	}

	inst, _ := c.Connectors.Install(ctx, "acme", ConnectorInstallParams{ShareMode: "prefill", ClientID: "id", ClientSecret: "sec"})
	rec.expect(t, "POST", "/v1/connectors/acme/install")
	if rec.Body["share_mode"] != "prefill" || !inst.NeedsCredentials {
		t.Errorf("Install body=%v out=%+v", rec.Body, inst)
	}

	rv, _ := c.Connectors.Review(ctx, "acme", 5, "")
	rec.expect(t, "POST", "/v1/connectors/acme/reviews")
	if rec.Body["rating"] != float64(5) || rec.Body["body"] != nil || rv.Rating != 5 {
		t.Errorf("Review body=%v out=%+v", rec.Body, rv)
	}

	dir, _ := c.Connectors.Directory(ctx, DirectoryParams{Category: "social", VerifiedOnly: true, Query: "goo", Limit: 5})
	rec.expect(t, "GET", "/v1/directory")
	if rec.Query != "category=social&limit=5&q=goo&verified=true" {
		t.Errorf("directory query = %q", rec.Query)
	}
	if len(dir.Data) != 1 || dir.Data[0].DisplayName != "Google" || dir.Data[0].RankScore != 9.5 {
		t.Errorf("directory = %+v", dir)
	}
}

// TestAuditEventsSurface covers write, batch, list filters, export bytes and
// the test-mode bulk delete.
func TestAuditEventsSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"audit_event","id":"aev_1","actor":{"type":"user","id":"user_1"},"action":"doc.viewed","target":{"type":"doc","id":"d1","name":null},"occurred_at":5,"metadata":{"k":"v"},"created_at":6,"data":[{"id":"aev_1","action":"doc.viewed"}],"has_more":true,"next_cursor":"cur","deleted":4}`)

	ev, err := c.AuditEvents.Create(ctx, CreateAuditEventParams{Actor: AuditEventInputActor{Type: "user", ID: "user_1"}, Action: "doc.viewed", Target: &AuditEventInputTarget{Type: "doc", ID: "d1"}, OccurredAt: 5})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/audit_events")
	if rec.Body["occurred_at"] != float64(5) || rec.Body["organization_id"] != nil || ev.Actor.ID == nil || *ev.Actor.ID != "user_1" || ev.Metadata["k"] != "v" {
		t.Errorf("Create body=%v out=%+v", rec.Body, ev)
	}

	b, _ := c.AuditEvents.CreateBatch(ctx, []CreateAuditEventParams{{Actor: AuditEventInputActor{Type: "system"}, Action: "x"}})
	rec.expect(t, "POST", "/v1/audit_events/batch")
	if evs, _ := rec.Body["events"].([]interface{}); len(evs) != 1 || len(b.Data) != 1 {
		t.Errorf("batch body=%v out=%+v", rec.Body, b)
	}

	from := time.UnixMilli(1000)
	page, _ := c.AuditEvents.List(ctx, ListAuditEventsParams{AuditEventFilter: AuditEventFilter{ActorID: "a,b", From: from, AnyOf: true}, Limit: 10})
	rec.expect(t, "GET", "/v1/audit_events")
	if rec.Query != "actor_id=a%2Cb&any_of=true&from=1000&limit=10" || !page.HasMore || *page.NextCursor != "cur" {
		t.Errorf("list query=%q page=%+v", rec.Query, page)
	}

	raw, _ := c.AuditEvents.Export(ctx, "csv", AuditEventFilter{Action: "doc.viewed"})
	rec.expect(t, "GET", "/v1/audit_events/export")
	if rec.Query != "action=doc.viewed&format=csv" || len(raw) == 0 {
		t.Errorf("export query=%q len=%d", rec.Query, len(raw))
	}

	del, _ := c.AuditEvents.DeleteAll(ctx, "org_1", "")
	rec.expect(t, "DELETE", "/v1/audit_events")
	if rec.Query != "organization_id=org_1" || del.Deleted != 4 {
		t.Errorf("delete query=%q out=%+v", rec.Query, del)
	}
}

// TestDiagnosticsAndAnalytics covers login readiness, request inspector,
// config changelog, events and usage.
func TestDiagnosticsAndAnalytics(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","origin":"https://app.test","live":true,"ready":false,"checks":[{"name":"cors","pass":false,"detail":"add it"}],"would_be_rejected":true,"findings":[{"check":"cors_origin","blocks":true}],"data":[{"id":"e1","at":7,"actor":{"type":"user","id":"u"},"action":"auth_config.updated","changes":[{"section":"session","before":1,"after":2}],"type":"user.created","payload":{"a":1},"created_at":8}],"has_more":false,"next_cursor":null,"available_types":["user.created"],"window":{"from":"2026-10-01","to":"2026-10-07","days":7},"metrics":[{"metric":"sign_ins","additive":true,"points":[{"day":"2026-10-01","count":3}],"peak":3,"total":3,"trend":{"current":3,"previous":1,"changePercent":200,"direction":"up"}}],"monthly_active_users":{"value":12,"window_days":30,"trend":null}}`)

	lr, _ := c.Diagnostics.LoginReadiness(ctx, "https://app.test", true)
	rec.expect(t, "GET", "/v1/diagnostics/login_readiness")
	if rec.Query != "live=true&origin=https%3A%2F%2Fapp.test" || lr.Ready || len(lr.Checks) != 1 || lr.Checks[0].Name != "cors" {
		t.Errorf("login readiness query=%q out=%+v", rec.Query, lr)
	}

	ri, _ := c.Diagnostics.RequestInspector(ctx, RequestInspectorParams{Origin: "https://app.test", Method: "DELETE"})
	rec.expect(t, "GET", "/v1/diagnostics/request_inspector")
	if !strings.Contains(rec.Query, "method=DELETE") || strings.Contains(rec.Query, "token=") || !ri.WouldBeRejected || !ri.Findings[0].Blocks {
		t.Errorf("inspector query=%q out=%+v", rec.Query, ri)
	}

	cl, _ := c.Diagnostics.ConfigChangelog(ctx, ConfigChangelogParams{ListParams: ListParams{Limit: 5}, Action: "auth_config.updated"})
	rec.expect(t, "GET", "/v1/config_changelog")
	if rec.Query != "action=auth_config.updated&limit=5" || len(cl.Data) != 1 || cl.Data[0].Changes[0].Section != "session" {
		t.Errorf("changelog query=%q out=%+v", rec.Query, cl)
	}

	ev, _ := c.Analytics.Events(ctx, ListActivityEventsParams{Type: "user.created", From: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	rec.expect(t, "GET", "/v1/events")
	if rec.Query != "from=2026-10-01T00%3A00%3A00Z&type=user.created" || ev.AvailableTypes[0] != "user.created" || ev.Data[0].Type != "user.created" {
		t.Errorf("events query=%q out=%+v", rec.Query, ev)
	}

	u, _ := c.Analytics.Usage(ctx, 7)
	rec.expect(t, "GET", "/v1/usage")
	if rec.Query != "days=7" || u.Window.Days != 7 || u.Metrics[0].Trend.Direction != "up" || *u.Metrics[0].Total != 3 || *u.MonthlyActiveUsers.Value != 12 {
		t.Errorf("usage query=%q out=%+v", rec.Query, u)
	}
}

// TestExtendedExistingServices covers the operations added to billing, DSR,
// invitations, waitlist, API keys, OAuth clients and sign-in tokens.
func TestExtendedExistingServices(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","id":"id_1","status":"scheduled","eta":99,"quantity":4,"recorded":true,"metered":true,"total":12.5,"data":[{"id":"id_1","revoked_at":5,"client_id":"cid"}],"errors":[{"index":1,"email_address":"bad","code":"VALIDATION_FAILED","message":"m"}],"token":"ey.j","jti":"j1","scopes":["a"],"cnf":{"jkt":"thumb"},"expires_in":60,"revoked":true}`)

	sub, _ := c.Billing.ImportSubscription(ctx, ImportSubscriptionParams{SubjectType: "org", SubjectID: "org_1", StripeSubscriptionID: "sub_1"})
	rec.expect(t, "POST", "/v1/billing/subscriptions/import")
	if rec.Body["stripe_subscription_id"] != "sub_1" || rec.Body["plan_id"] != nil || sub.ID != "id_1" {
		t.Errorf("import body=%v", rec.Body)
	}
	use, _ := c.Billing.ReportUsage(ctx, ReportUsageParams{SubjectType: "org", SubjectID: "org_1", Quantity: 2, IdempotencyKey: "k"})
	rec.expect(t, "POST", "/v1/billing/usage")
	if rec.Body["quantity"] != float64(2) || !use.Metered || use.Total != 12.5 {
		t.Errorf("usage body=%v out=%+v", rec.Body, use)
	}
	seats, _ := c.Billing.SyncSeats(ctx, "org", "org_1")
	rec.expect(t, "POST", "/v1/billing/subjects/org/org_1/sync_seats")
	if seats.Quantity != 4 {
		t.Errorf("seats = %+v", seats)
	}

	dsr, _ := c.DataSubjectRequests.Create(ctx, CreateDataSubjectRequestParams{SubjectEmail: "a@b.c", Type: "erasure"})
	rec.expect(t, "POST", "/v1/data_subject_requests")
	if rec.Body["subject_email"] != "a@b.c" || rec.Body["user_id"] != nil || dsr.ETA == nil || *dsr.ETA != 99 {
		t.Errorf("dsr body=%v out=%+v", rec.Body, dsr)
	}
	_, _ = c.DataSubjectRequests.Cancel(ctx, "dsr_1")
	rec.expect(t, "POST", "/v1/data_subject_requests/dsr_1/cancel")

	bi, _ := c.Invitations.CreateBulk(ctx, []CreateInvitationParams{{EmailAddress: "a@b.c"}, {EmailAddress: "bad"}})
	rec.expect(t, "POST", "/v1/invitations/bulk")
	if invs, _ := rec.Body["invitations"].([]interface{}); len(invs) != 2 || len(bi.Errors) != 1 || bi.Errors[0].Index != 1 {
		t.Errorf("bulk invitations body=%v out=%+v", rec.Body, bi)
	}

	_, _ = c.Waitlist.Create(ctx, "a@b.c")
	rec.expect(t, "POST", "/v1/waitlist_entries")
	if rec.Body["email_address"] != "a@b.c" {
		t.Errorf("waitlist create body = %v", rec.Body)
	}
	bw, _ := c.Waitlist.CreateBulk(ctx, []string{"a@b.c"})
	rec.expect(t, "POST", "/v1/waitlist_entries/bulk")
	if bw.Errors[0].Code != "VALIDATION_FAILED" {
		t.Errorf("waitlist bulk = %+v", bw)
	}
	_, _ = c.Waitlist.Delete(ctx, "wl_1")
	rec.expect(t, "DELETE", "/v1/waitlist_entries/wl_1")

	rk, _ := c.APIKeys.ListRevoked(ctx, ListRevokedAPIKeysParams{Since: "cur_1", Limit: 50})
	rec.expect(t, "GET", "/v1/api_keys/revoked")
	if rec.Query != "limit=50&since=cur_1" || *rk.Data[0].RevokedAt != 5 {
		t.Errorf("revoked query=%q out=%+v", rec.Query, rk)
	}
	tok, _ := c.APIKeys.MintToken(ctx, MintAPIKeyTokenParams{Secret: "ak_1", TTLSeconds: 60, Audience: []string{"https://api"}})
	rec.expect(t, "POST", "/v1/api_keys/token")
	if rec.Body["ttl_seconds"] != float64(60) || tok.Cnf == nil || tok.Cnf.JKT != "thumb" || tok.JTI != "j1" {
		t.Errorf("token body=%v out=%+v", rec.Body, tok)
	}

	imp, _ := c.OAuthClients.Import(ctx, []ImportOAuthClient{{ClientID: "cid", Name: "n", RedirectURIs: []string{"https://x/cb"}, ClientSecretHash: "$2b$..."}})
	rec.expect(t, "POST", "/v1/oauth_clients/import")
	if cl, _ := rec.Body["clients"].([]interface{}); len(cl) != 1 || len(imp.Data) != 1 {
		t.Errorf("import body=%v out=%+v", rec.Body, imp)
	}

	rv, _ := c.SignInTokens.Revoke(ctx, "sit_1")
	rec.expect(t, "POST", "/v1/sign_in_tokens/sit_1/revoke")
	if !rv.Revoked {
		t.Errorf("revoke = %+v", rv)
	}
}

// TestOperationsMiscSurface covers captcha, test mode, MCP, legacy auth, org
// LDAP connections and the PCA admin controls.
func TestOperationsMiscSurface(t *testing.T) {
	ctx := context.Background()
	c, rec := recordingClient(t, `{"object":"x","success":true,"provider":"turnstile","score":0.9,"verdict":"pass","instance_id":"ins_dev","publishable_key":"pk_test_1","created":true,"secret_key":"sk_test_1","purged":3,"has_more":true,"jwt":"ey","expires_in":60,"protocol_version":"2025-06-18","tools":[{"name":"list_users"}],"jsonrpc":"2.0","id":1,"result":{"tools":[]},"enabled":true,"exposed_scopes":["profile"],"configured":false,"ok":true,"frozen":true,"trusted_attestor_keys":["k1"],"grant_ref":"g","cap_id":"c","revoked":true,"stepup_id":"su_1","status":"denied"}`)

	cv, _ := c.Captcha.Verify(ctx, CaptchaVerifyParams{Token: "t", RemoteIP: "1.2.3.4"})
	rec.expect(t, "POST", "/v1/captcha/verify")
	if rec.Body["remote_ip"] != "1.2.3.4" || rec.Body["action"] != nil || !cv.Success || *cv.Score != 0.9 {
		t.Errorf("captcha body=%v out=%+v", rec.Body, cv)
	}

	ti, _ := c.Testing.TestInstance(ctx, true)
	rec.expect(t, "POST", "/v1/test_instance")
	if rec.Body["rotate_secret"] != true || ti.SecretKey != "sk_test_1" {
		t.Errorf("test instance body=%v out=%+v", rec.Body, ti)
	}
	pg, _ := c.Testing.PurgeTestUsers(ctx, 0)
	rec.expect(t, "POST", "/v1/test_users/purge")
	if len(rec.Body) != 0 || pg.Purged != 3 || !pg.HasMore {
		t.Errorf("purge body=%v out=%+v", rec.Body, pg)
	}
	tt, _ := c.Testing.CreateTestingToken(ctx)
	rec.expect(t, "POST", "/v1/testing_tokens")
	if tt.JWT != "ey" {
		t.Errorf("testing token = %+v", tt)
	}

	d, _ := c.MCP.Describe(ctx)
	rec.expect(t, "GET", "/v1/mcp")
	if d.ProtocolVersion != "2025-06-18" || len(d.Tools) != 1 {
		t.Errorf("mcp describe = %+v", d)
	}
	resp, _ := c.MCP.Call(ctx, MCPRequest{ID: 1, Method: "tools/list"})
	rec.expect(t, "POST", "/v1/mcp")
	if rec.Body["jsonrpc"] != "2.0" || rec.Body["method"] != "tools/list" || resp.Result == nil {
		t.Errorf("mcp call body=%v out=%+v", rec.Body, resp)
	}
	_, _ = c.MCP.GetConnector(ctx)
	rec.expect(t, "GET", "/v1/mcp_connector")
	on := true
	mc, _ := c.MCP.UpdateConnector(ctx, UpdateMCPConnectorParams{Enabled: &on, ExposedScopes: []string{"profile"}})
	rec.expect(t, "PUT", "/v1/mcp_connector")
	if rec.Body["enabled"] != true || rec.Body["name"] != nil || !mc.Enabled {
		t.Errorf("mcp connector body=%v out=%+v", rec.Body, mc)
	}
	_, _ = c.MCP.DisableConnector(ctx)
	rec.expect(t, "DELETE", "/v1/mcp_connector")

	la, _ := c.LegacyAuth.Get(ctx)
	rec.expect(t, "GET", "/v1/legacy_auth_connection")
	if la.IsConfigured() {
		t.Errorf("legacy auth should be unconfigured: %+v", la)
	}
	_, _ = c.LegacyAuth.Put(ctx, PutLegacyAuthConnectionParams{VerifyURL: "https://old/verify", SigningSecret: "s"})
	rec.expect(t, "PUT", "/v1/legacy_auth_connection")
	if rec.Body["verify_url"] != "https://old/verify" || rec.Body["enabled"] != nil {
		t.Errorf("legacy put body = %v", rec.Body)
	}
	_, _ = c.LegacyAuth.Delete(ctx)
	rec.expect(t, "DELETE", "/v1/legacy_auth_connection")

	_, _ = c.OrgLDAPConnections.List(ctx, "org_1")
	rec.expect(t, "GET", "/v1/org_ldap_connections")
	if rec.Query != "organization_id=org_1" {
		t.Errorf("ldap list query = %q", rec.Query)
	}
	_, _ = c.OrgLDAPConnections.Create(ctx, OrgLDAPConnectionParams{OrganizationID: "org_1", URL: "ldaps://dc", Attributes: &LDAPAttributeMapping{Email: "mail", FirstName: "givenName"}})
	rec.expect(t, "POST", "/v1/org_ldap_connections")
	if attrs, _ := rec.Body["attributes"].(map[string]interface{}); attrs["firstName"] != "givenName" {
		t.Errorf("ldap create body = %v", rec.Body)
	}
	_, _ = c.OrgLDAPConnections.Get(ctx, "ldap_1")
	rec.expect(t, "GET", "/v1/org_ldap_connections/ldap_1")
	_, _ = c.OrgLDAPConnections.Update(ctx, "ldap_1", OrgLDAPConnectionParams{ClearDefaultRoleID: true})
	rec.expect(t, "PATCH", "/v1/org_ldap_connections/ldap_1")
	if v, ok := rec.Body["default_role_id"]; !ok || v != nil || len(rec.Body) != 1 {
		t.Errorf("ldap update body = %s, want only default_role_id:null", rec.RawBody)
	}
	_, _ = c.OrgLDAPConnections.Delete(ctx, "ldap_1")
	rec.expect(t, "DELETE", "/v1/org_ldap_connections/ldap_1")
	lt, _ := c.OrgLDAPConnections.Test(ctx, "ldap_1", "")
	rec.expect(t, "POST", "/v1/org_ldap_connections/ldap_1/test")
	if !lt.OK {
		t.Errorf("ldap test = %+v", lt)
	}

	at, _ := c.PCA.GetAttestors(ctx)
	rec.expect(t, "GET", "/v1/pca/attestors")
	if at.TrustedAttestorKeys[0] != "k1" {
		t.Errorf("attestors = %+v", at)
	}
	_, _ = c.PCA.SetAttestors(ctx, nil)
	rec.expect(t, "PUT", "/v1/pca/attestors")
	if rec.RawBody != `{"trusted_attestor_keys":[]}` {
		t.Errorf("set attestors body = %s", rec.RawBody)
	}
	fz, _ := c.PCA.Freeze(ctx, "incident")
	rec.expect(t, "POST", "/v1/pca/freeze")
	if rec.Body["reason"] != "incident" || !fz.Frozen {
		t.Errorf("freeze body=%v out=%+v", rec.Body, fz)
	}
	_, _ = c.PCA.Unfreeze(ctx)
	rec.expect(t, "DELETE", "/v1/pca/freeze")
	rvk, _ := c.PCA.Revoke(ctx, "g", "c")
	rec.expect(t, "POST", "/v1/pca/revocations")
	if !rvk.Revoked || rec.Body["cap_id"] != "c" {
		t.Errorf("revoke body=%v out=%+v", rec.Body, rvk)
	}
	su, _ := c.PCA.DenyStepUp(ctx, "su_1", "")
	rec.expect(t, "POST", "/v1/pca/stepups/su_1/deny")
	if su.StepUpID != "su_1" || su.Status != "denied" {
		t.Errorf("deny = %+v", su)
	}
}
