package atlas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
)

// routeRecord is one request captured by newRouteRecorder.
type routeRecord struct {
	method, path, query string
	body                map[string]interface{}
	rawBody             string
}

// newRouteRecorder returns a client whose server records every request and
// answers with the given JSON body.
func newRouteRecorder(t *testing.T, response string) (*Client, *routeRecord) {
	t.Helper()
	rec := &routeRecord{}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec.method, rec.path, rec.query, rec.rawBody = r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(raw)
		rec.body = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
		}
		_, _ = w.Write([]byte(response))
	})
	return c, rec
}

// expectRoute asserts the recorded method/path/query and (when want != nil) body.
func expectRoute(t *testing.T, name string, rec *routeRecord, method, path, query string, body map[string]interface{}) {
	t.Helper()
	if rec.method != method || rec.path != path || rec.query != query {
		t.Errorf("%s: hit %s %s?%s, want %s %s?%s", name, rec.method, rec.path, rec.query, method, path, query)
	}
	if body != nil && !reflect.DeepEqual(rec.body, body) {
		t.Errorf("%s: body = %v, want %v", name, rec.body, body)
	}
}

func TestUsersLifecycleRoutes(t *testing.T) {
	ctx := context.Background()
	userJSON := `{"object":"user","id":"user_1"}`
	type tc struct {
		name, resp, method, path, query string
		body                            map[string]interface{}
		call                            func(c *Client) (interface{}, error)
		check                           func(t *testing.T, out interface{})
	}
	cases := []tc{
		{"SetPassword", userJSON, "POST", "/v1/users/user_1/password", "",
			map[string]interface{}{"password": "pw", "sign_out_of_other_sessions": true},
			func(c *Client) (interface{}, error) {
				return c.Users.SetPassword(ctx, "user_1", SetUserPasswordParams{Password: "pw", SignOutOfOtherSessions: true})
			},
			func(t *testing.T, out interface{}) {
				if out.(*User).ID != "user_1" {
					t.Errorf("user = %+v", out)
				}
			}},
		{"AddPhoneNumber", `{"object":"phone_number","id":"ph_1","phone_number":"+15550001","verified":false,"created_at":5}`, "POST", "/v1/users/user_1/phone_numbers", "",
			map[string]interface{}{"phone_number": "+15550001"},
			func(c *Client) (interface{}, error) { return c.Users.AddPhoneNumber(ctx, "user_1", "+15550001") },
			func(t *testing.T, out interface{}) {
				if p := out.(*UserPhoneNumber); p.ID != "ph_1" || p.CreatedAt != 5 {
					t.Errorf("phone = %+v", p)
				}
			}},
		{"VerifyPhoneNumber", `{"object":"phone_number","id":"ph_1","verified":true}`, "POST", "/v1/users/user_1/phone_numbers/ph_1/verify", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.VerifyPhoneNumber(ctx, "user_1", "ph_1") },
			func(t *testing.T, out interface{}) {
				if !out.(*UserPhoneNumber).Verified {
					t.Errorf("not verified")
				}
			}},
		{"DeletePhoneNumber", `{"object":"phone_number","id":"ph_1","deleted":true}`, "DELETE", "/v1/users/user_1/phone_numbers/ph_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.DeletePhoneNumber(ctx, "user_1", "ph_1") },
			func(t *testing.T, out interface{}) {
				if !out.(*DeletedObject).Deleted {
					t.Errorf("not deleted")
				}
			}},
		{"DeleteProfileImage", userJSON, "DELETE", "/v1/users/user_1/profile_image", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.DeleteProfileImage(ctx, "user_1") }, nil},
		{"DeletePasskey", `{"object":"passkey","id":"pk_1","deleted":true}`, "DELETE", "/v1/users/user_1/passkeys/pk_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.DeletePasskey(ctx, "user_1", "pk_1") }, nil},
		{"EmailAddresses.Verify", `{"object":"email_address","id":"em_1","verified":true}`, "POST", "/v1/email_addresses/em_1/verify", "", nil,
			func(c *Client) (interface{}, error) { return c.EmailAddresses.Verify(ctx, "em_1") }, nil},
		{"EmailAddresses.SetPrimary", `{"object":"email_address","id":"em_1","primary":true}`, "POST", "/v1/email_addresses/em_1/primary", "", nil,
			func(c *Client) (interface{}, error) { return c.EmailAddresses.SetPrimary(ctx, "em_1") }, nil},
		{"ByEmails", `{"object":"list","data":[{"email_address":"a@b.com","user_id":"user_1","verified":false,"deleted":true}]}`, "POST", "/v1/users/by_emails", "",
			map[string]interface{}{"email_addresses": []interface{}{"a@b.com"}, "include_unverified": true, "include_deleted": true},
			func(c *Client) (interface{}, error) {
				return c.Users.ByEmails(ctx, UsersByEmailsParams{EmailAddresses: []string{"a@b.com"}, IncludeUnverified: true, IncludeDeleted: true})
			},
			func(t *testing.T, out interface{}) {
				p := out.(*ListPage[UserEmailMatch])
				if len(p.Data) != 1 || p.Data[0].UserID != "user_1" || !p.Data[0].Deleted {
					t.Errorf("matches = %+v", p)
				}
			}},
		{"Resolved", `{"object":"resolved_user","user_id":"user_1","email":"a@b.com","email_verified":true,"identities":[{"provider":"google","provider_user_id":"g1","email":null}]}`, "GET", "/v1/users/user_1/resolved", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.Resolved(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				r := out.(*ResolvedUser)
				if r.Email == nil || *r.Email != "a@b.com" || len(r.Identities) != 1 || r.Identities[0].Provider != "google" {
					t.Errorf("resolved = %+v", r)
				}
			}},
		{"ListOrganizationMemberships", `{"object":"list","data":[{"organization_id":"org_1","role":"admin","plan":null,"joined_at":3}],"has_more":true,"next_cursor":"c2"}`, "GET", "/v1/users/user_1/organization_memberships", "limit=5&starting_after=c1", nil,
			func(c *Client) (interface{}, error) {
				return c.Users.ListOrganizationMemberships(ctx, "user_1", ListParams{Limit: 5, StartingAfter: "c1"})
			},
			func(t *testing.T, out interface{}) {
				p := out.(*CursorPage[UserOrganizationMembership])
				if !p.HasMore || *p.NextCursor != "c2" || p.Data[0].Role != "admin" {
					t.Errorf("page = %+v", p)
				}
			}},
		{"SignInHistory", `{"object":"list","data":[{"object":"sign_in_event","id":"si_1","method":"password","created_at":9}],"has_more":false}`, "GET", "/v1/users/user_1/sign_in_history", "limit=10", nil,
			func(c *Client) (interface{}, error) {
				return c.Users.SignInHistory(ctx, "user_1", ListParams{Limit: 10})
			},
			func(t *testing.T, out interface{}) {
				if out.(*CursorPage[SignInEvent]).Data[0].Method != "password" {
					t.Errorf("history = %+v", out)
				}
			}},
		{"ImportIdentity", `{"object":"identity","id":"idn_1","type":"oauth","provider":"github","provider_user_id":"42","is_primary":false}`, "POST", "/v1/users/user_1/identities/import", "",
			map[string]interface{}{"provider": "github", "provider_user_id": "42", "email_address": "a@b.com", "verified": true},
			func(c *Client) (interface{}, error) {
				v := true
				return c.Users.ImportIdentity(ctx, "user_1", ImportIdentityParams{Provider: "github", ProviderUserID: "42", EmailAddress: "a@b.com", Verified: &v})
			}, nil},
		{"RemoveIdentityByProvider", `{"object":"identity","id":"idn_1","provider":"github","removed":true}`, "DELETE", "/v1/users/user_1/identities/by-provider/github", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.RemoveIdentityByProvider(ctx, "user_1", "github") },
			func(t *testing.T, out interface{}) {
				if !out.(*RemovedProviderIdentity).Removed {
					t.Errorf("not removed")
				}
			}},
		{"ImposeDirective", `{"object":"directive","user_id":"user_1","read_only":true,"sessions_revoked":2}`, "POST", "/v1/users/user_1/directives", "",
			map[string]interface{}{"read_only": true, "reason": "abuse"},
			func(c *Client) (interface{}, error) {
				return c.Users.ImposeDirective(ctx, "user_1", ImposeDirectiveParams{ReadOnly: true, Reason: "abuse"})
			},
			func(t *testing.T, out interface{}) {
				if out.(*UserDirective).SessionsRevoked != 2 {
					t.Errorf("directive = %+v", out)
				}
			}},
		{"LiftDirective", `{"object":"directive","user_id":"user_1","lifted":true}`, "DELETE", "/v1/users/user_1/directives", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.LiftDirective(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				if !out.(*UserDirective).Lifted {
					t.Errorf("not lifted")
				}
			}},
		{"AppendProgressionEvent", `{"object":"progression_event","track":"xp","xp":110,"level":2,"level_changed":true,"delta":10}`, "POST", "/v1/users/user_1/progression/events", "",
			map[string]interface{}{"track": "xp", "amount": float64(10), "reason": "quest", "idempotency_key": "k1"},
			func(c *Client) (interface{}, error) {
				return c.Users.AppendProgressionEvent(ctx, "user_1", ProgressionEventParams{Track: "xp", Amount: 10, Reason: "quest", IdempotencyKey: "k1"})
			},
			func(t *testing.T, out interface{}) {
				if e := out.(*ProgressionEvent); e.XP != 110 || !e.LevelChanged {
					t.Errorf("event = %+v", e)
				}
			}},
		{"State", `{"object":"user_state","attributes":{"progression":{"xp":{"xp":5,"level":1}},"tier":"gold"},"entitlements":[],"directives":[],"roles":["admin"]}`, "GET", "/v1/users/user_1/state", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.State(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				s := out.(*UserState)
				if s.Attributes.Progression["xp"].XP != 5 || s.Attributes.Tier != "gold" || len(s.Roles) != 1 {
					t.Errorf("state = %+v", s)
				}
			}},
		{"RecordConsent", `{"object":"consent","id":"con_1","policy":"tos","version":"2","status":"accepted","source":null,"created_at":1}`, "POST", "/v1/users/user_1/consents", "",
			map[string]interface{}{"policy": "tos", "version": "2"},
			func(c *Client) (interface{}, error) {
				return c.Users.RecordConsent(ctx, "user_1", RecordConsentParams{Policy: "tos", Version: "2"})
			}, nil},
		{"ListConsents", `{"object":"list","data":[{"object":"consent","id":"con_1","policy":"tos"}]}`, "GET", "/v1/users/user_1/consents", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.ListConsents(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				if out.(*ListPage[UserConsent]).Data[0].Policy != "tos" {
					t.Errorf("consents = %+v", out)
				}
			}},
		{"ScheduleDeletion", userJSON, "POST", "/v1/users/user_1/deletion", "",
			map[string]interface{}{"grace_seconds": float64(3600)},
			func(c *Client) (interface{}, error) {
				return c.Users.ScheduleDeletion(ctx, "user_1", ScheduleDeletionParams{GraceSeconds: 3600})
			}, nil},
		{"CancelDeletion", userJSON, "POST", "/v1/users/user_1/deletion/cancel", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.CancelDeletion(ctx, "user_1") }, nil},
		{"FinalizeDeletion", `{"object":"user","id":"user_1","deleted":true}`, "POST", "/v1/users/user_1/deletion/finalize", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.FinalizeDeletion(ctx, "user_1") }, nil},
		{"AcknowledgeErasure", `{"object":"user_erasure_ack","id":"ack_1","user_id":"user_1","source":"crm","created_at":1}`, "POST", "/v1/users/user_1/erasure_acks", "",
			map[string]interface{}{"source": "crm", "payload": map[string]interface{}{"rows": float64(3)}},
			func(c *Client) (interface{}, error) {
				return c.Users.AcknowledgeErasure(ctx, "user_1", ErasureAckParams{Source: "crm", Payload: map[string]interface{}{"rows": 3}})
			}, nil},
		{"ErasureExport", `{"object":"erasure_export","format_version":1,"user_id":"user_1","atlas":{"user":{}},"app_contributions":[{"source":"crm","contributed_at":2,"payload":{"a":1}}]}`, "GET", "/v1/users/user_1/erasure_export", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.ErasureExport(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				e := out.(*ErasureExport)
				if e.FormatVersion != 1 || len(e.AppContributions) != 1 || e.AppContributions[0].Source != "crm" {
					t.Errorf("export = %+v", e)
				}
			}},
		{"RequestApproval", `{"object":"approval_request","id":"apr_1","status":"pending","match_number":"42","expires_at":7}`, "POST", "/v1/users/user_1/approval_requests", "",
			map[string]interface{}{"description": "Wire $10", "context": map[string]interface{}{"ip": "1.2.3.4"}},
			func(c *Client) (interface{}, error) {
				return c.Users.RequestApproval(ctx, "user_1", CreateApprovalRequestParams{Description: "Wire $10", Context: map[string]string{"ip": "1.2.3.4"}})
			},
			func(t *testing.T, out interface{}) {
				if out.(*ApprovalRequest).MatchNumber != "42" {
					t.Errorf("approval = %+v", out)
				}
			}},
		{"GetApproval", `{"object":"approval_request","id":"apr_1","status":"approved","approved_by_device_id":"dev_1","resolved_at":8}`, "GET", "/v1/users/user_1/approval_requests/apr_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.GetApproval(ctx, "user_1", "apr_1") },
			func(t *testing.T, out interface{}) {
				a := out.(*ApprovalRequest)
				if a.Status != "approved" || *a.ApprovedByDeviceID != "dev_1" || *a.ResolvedAt != 8 {
					t.Errorf("approval = %+v", a)
				}
			}},
		{"GetNotificationPreferences", `{"object":"notification_preferences","preferences":[{"category":"new_device","label":"New device","enabled":true,"optional":false}]}`, "GET", "/v1/users/user_1/notification_preferences", "", nil,
			func(c *Client) (interface{}, error) { return c.Users.GetNotificationPreferences(ctx, "user_1") },
			func(t *testing.T, out interface{}) {
				if out.(*NotificationPreferences).Preferences[0].Category != "new_device" {
					t.Errorf("prefs = %+v", out)
				}
			}},
		{"UpdateNotificationPreferences", `{"object":"notification_preferences","preferences":[]}`, "PATCH", "/v1/users/user_1/notification_preferences", "",
			map[string]interface{}{"preferences": map[string]interface{}{"marketing": false}},
			func(c *Client) (interface{}, error) {
				return c.Users.UpdateNotificationPreferences(ctx, "user_1", map[string]bool{"marketing": false})
			}, nil},
	}
	for _, tc := range cases {
		c, rec := newRouteRecorder(t, tc.resp)
		out, err := tc.call(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		expectRoute(t, tc.name, rec, tc.method, tc.path, tc.query, tc.body)
		if tc.check != nil {
			tc.check(t, out)
		}
	}
}

// TestPathEscapingAndStrictOnNewWrites asserts ids are path-escaped and the
// per-call StrictBody option reaches the new write methods.
func TestPathEscapingAndStrictOnNewWrites(t *testing.T) {
	var gotPath, gotStrict string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotStrict = r.URL.EscapedPath(), r.Header.Get("Atlas-Strict")
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := c.Users.RemoveIdentityByProvider(context.Background(), "user/1", "custom provider", StrictBody(true)); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/users/user%2F1/identities/by-provider/custom%20provider" {
		t.Errorf("path = %s", gotPath)
	}
	if _, err := c.Machines.Approve(context.Background(), "mch_1", StrictBody(true)); err != nil {
		t.Fatal(err)
	}
	if gotStrict != "true" {
		t.Errorf("Atlas-Strict = %q, want true", gotStrict)
	}
}
