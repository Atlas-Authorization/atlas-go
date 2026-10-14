package atlas

import (
	"context"
	"testing"
)

// TestOrgMachinesSessionsNotificationsRoutes covers the organization settings /
// branding / audit streams / end-user pool / reader domain, settings schema,
// machines + enrolment tokens, session-exchange apps, redirect URLs, tickets,
// notifications and session template tokens.
func TestOrgMachinesSessionsNotificationsRoutes(t *testing.T) {
	ctx := context.Background()
	machineJSON := `{"object":"machine","id":"mch_1","name":"m","status":"active","owner_usable":true,"effective_status":"active","metadata":{"hostname":"h"},"created_at":1,"updated_at":2}`
	type tc struct {
		name, resp, method, path, query string
		body                            map[string]interface{}
		call                            func(c *Client) (interface{}, error)
		check                           func(t *testing.T, out interface{})
	}
	str := func(s string) *string { return &s }
	cases := []tc{
		// Organization settings + schema.
		{"GetSettings", `{"object":"organization_settings","organization_id":"org_1","values":{"a":1},"version":3,"updated_by":null,"updated_at":null}`, "GET", "/v1/organizations/org_1/settings", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.GetSettings(ctx, "org_1") },
			func(t *testing.T, out interface{}) {
				s := out.(*OrganizationSettings)
				if s.Version != 3 || s.Values["a"] != float64(1) || s.UpdatedAt != nil {
					t.Errorf("settings = %+v", s)
				}
			}},
		{"ReplaceSettings", `{"object":"organization_settings","version":4}`, "PUT", "/v1/organizations/org_1/settings", "",
			map[string]interface{}{"values": map[string]interface{}{"a": float64(2)}},
			func(c *Client) (interface{}, error) {
				return c.Organizations.ReplaceSettings(ctx, "org_1", map[string]interface{}{"a": 2})
			}, nil},
		{"MergeSettings", `{"object":"organization_settings","version":5}`, "PATCH", "/v1/organizations/org_1/settings", "",
			map[string]interface{}{"values": map[string]interface{}{"gone": nil}},
			func(c *Client) (interface{}, error) {
				return c.Organizations.MergeSettings(ctx, "org_1", map[string]interface{}{"gone": nil})
			}, nil},
		{"SettingsSchema.Get", `{"object":"organization_settings_schema","schema":{"type":"object"},"version":1,"updated_at":9}`, "GET", "/v1/organization_settings_schema", "", nil,
			func(c *Client) (interface{}, error) { return c.OrganizationSettingsSchema.Get(ctx) },
			func(t *testing.T, out interface{}) {
				if s := out.(*OrganizationSettingsSchema); s.Version != 1 || s.Schema["type"] != "object" {
					t.Errorf("schema = %+v", s)
				}
			}},
		{"SettingsSchema.Register", `{"object":"organization_settings_schema","version":1}`, "POST", "/v1/organization_settings_schema", "",
			map[string]interface{}{"schema": map[string]interface{}{"type": "object"}},
			func(c *Client) (interface{}, error) {
				return c.OrganizationSettingsSchema.Register(ctx, map[string]interface{}{"type": "object"})
			}, nil},
		{"SettingsSchema.Replace", `{"object":"organization_settings_schema","version":2}`, "PUT", "/v1/organization_settings_schema", "",
			map[string]interface{}{"schema": map[string]interface{}{"type": "object"}},
			func(c *Client) (interface{}, error) {
				return c.OrganizationSettingsSchema.Replace(ctx, map[string]interface{}{"type": "object"})
			}, nil},
		// Branding.
		{"GetBranding", `{"object":"organization_branding","organization_id":"org_1","display_name":"Acme","logo_url":null}`, "GET", "/v1/organizations/org_1/branding", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.GetBranding(ctx, "org_1") },
			func(t *testing.T, out interface{}) {
				b := out.(*OrganizationBranding)
				if *b.DisplayName != "Acme" || b.LogoURL != nil {
					t.Errorf("branding = %+v", b)
				}
			}},
		{"UpdateBranding", `{"object":"organization_branding"}`, "PUT", "/v1/organizations/org_1/branding", "",
			map[string]interface{}{"display_name": "Acme", "logo_url": nil},
			func(c *Client) (interface{}, error) {
				return c.Organizations.UpdateBranding(ctx, "org_1", UpdateOrganizationBrandingParams{DisplayName: str("Acme"), ClearFields: []string{"logo_url"}})
			}, nil},
		// Audit streams.
		{"ListAuditStreams", `{"object":"list","data":[{"object":"org_audit_stream","id":"as_1","url":"https://siem","has_secret":true}],"has_more":false}`, "GET", "/v1/organizations/org_1/audit_streams", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.ListAuditStreams(ctx, "org_1") },
			func(t *testing.T, out interface{}) {
				if !out.(*CursorPage[OrgAuditStream]).Data[0].HasSecret {
					t.Errorf("streams = %+v", out)
				}
			}},
		{"CreateAuditStream", `{"object":"org_audit_stream","id":"as_1"}`, "POST", "/v1/organizations/org_1/audit_streams", "",
			map[string]interface{}{"url": "https://siem", "secret": "0123456789abcdef"},
			func(c *Client) (interface{}, error) {
				return c.Organizations.CreateAuditStream(ctx, "org_1", CreateOrgAuditStreamParams{URL: "https://siem", Secret: "0123456789abcdef"})
			}, nil},
		{"DeleteAuditStream", `{"object":"org_audit_stream","id":"as_1","deleted":true}`, "DELETE", "/v1/organizations/org_1/audit_streams/as_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.DeleteAuditStream(ctx, "org_1", "as_1") }, nil},
		// End-user pool.
		{"ListEndUsers", `{"object":"list","data":[{"object":"organization_end_user","id":"oeu_1","user_id":"user_1","status":"pending"}],"has_more":false}`, "GET", "/v1/organizations/org_1/end_users", "limit=2&status=pending", nil,
			func(c *Client) (interface{}, error) {
				return c.Organizations.ListEndUsers(ctx, "org_1", ListEndUsersParams{ListParams: ListParams{Limit: 2}, Status: "pending"})
			},
			func(t *testing.T, out interface{}) {
				if out.(*CursorPage[OrganizationEndUser]).Data[0].Status != "pending" {
					t.Errorf("end users = %+v", out)
				}
			}},
		{"AddEndUser", `{"object":"organization_end_user","id":"oeu_1"}`, "POST", "/v1/organizations/org_1/end_users", "",
			map[string]interface{}{"user_id": "user_1", "status": "pending"},
			func(c *Client) (interface{}, error) {
				return c.Organizations.AddEndUser(ctx, "org_1", AddEndUserParams{UserID: "user_1", Status: "pending"})
			}, nil},
		{"UpdateEndUserStatus", `{"object":"organization_end_user","status":"blocked"}`, "PATCH", "/v1/organizations/org_1/end_users/user_1", "",
			map[string]interface{}{"status": "blocked"},
			func(c *Client) (interface{}, error) {
				return c.Organizations.UpdateEndUserStatus(ctx, "org_1", "user_1", "blocked")
			}, nil},
		{"RemoveEndUser", `{"object":"organization_end_user","id":"oeu_1","deleted":true}`, "DELETE", "/v1/organizations/org_1/end_users/user_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.RemoveEndUser(ctx, "org_1", "user_1") }, nil},
		// Reader domain.
		{"ListReaderDomains", `{"object":"list","data":[{"object":"custom_domain","id":"cd_1","host":"r.acme.com","live":true}],"has_more":false}`, "GET", "/v1/organizations/org_1/reader_domain", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.ListReaderDomains(ctx, "org_1") },
			func(t *testing.T, out interface{}) {
				if d := out.(*CursorPage[ReaderDomain]).Data[0]; d.Host != "r.acme.com" || !d.Live {
					t.Errorf("domain = %+v", d)
				}
			}},
		{"BindReaderDomain", `{"object":"custom_domain","id":"cd_1","host":"r.acme.com","instructions":[{"role":"reader","host":"r.acme.com","type":"CNAME","target":"edge.atlasauth.net","purpose":"route"}],"note":"n"}`, "POST", "/v1/organizations/org_1/reader_domain", "",
			map[string]interface{}{"host": "r.acme.com"},
			func(c *Client) (interface{}, error) {
				return c.Organizations.BindReaderDomain(ctx, "org_1", "r.acme.com")
			},
			func(t *testing.T, out interface{}) {
				b := out.(*ReaderDomainBinding)
				if b.ID != "cd_1" || len(b.Instructions) != 1 || b.Instructions[0].Target != "edge.atlasauth.net" {
					t.Errorf("binding = %+v", b)
				}
			}},
		{"RemoveReaderDomain", `{"object":"custom_domain","id":"cd_1","deleted":true}`, "DELETE", "/v1/organizations/org_1/reader_domain", "", nil,
			func(c *Client) (interface{}, error) { return c.Organizations.RemoveReaderDomain(ctx, "org_1") }, nil},
		// Machines.
		{"Machines.List", `{"object":"list","data":[` + machineJSON + `],"has_more":false}`, "GET", "/v1/machines", "metadata=%7B%22os%22%3A%22linux%22%7D&organization_id=org_1&status=active", nil,
			func(c *Client) (interface{}, error) {
				return c.Machines.List(ctx, ListMachinesParams{Status: "active", OrganizationID: "org_1", Metadata: map[string]interface{}{"os": "linux"}})
			},
			func(t *testing.T, out interface{}) {
				if m := out.(*CursorPage[Machine]).Data[0]; m.EffectiveStatus != "active" || m.Metadata["hostname"] != "h" {
					t.Errorf("machine = %+v", m)
				}
			}},
		{"Machines.Create", `{"object":"machine","id":"mch_1","secret":"mk_x"}`, "POST", "/v1/machines", "",
			map[string]interface{}{"name": "m", "owner_user_id": "user_1", "data": map[string]interface{}{"tier": "pro"}},
			func(c *Client) (interface{}, error) {
				return c.Machines.Create(ctx, CreateMachineParams{Name: "m", OwnerUserID: "user_1", Data: Metadata{"tier": "pro"}})
			},
			func(t *testing.T, out interface{}) {
				if out.(*MachineWithSecret).Secret != "mk_x" {
					t.Errorf("secret missing")
				}
			}},
		{"Machines.Get", machineJSON, "GET", "/v1/machines/mch_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.Get(ctx, "mch_1") }, nil},
		{"Machines.Rename", machineJSON, "PATCH", "/v1/machines/mch_1", "", map[string]interface{}{"name": "n"},
			func(c *Client) (interface{}, error) { return c.Machines.Rename(ctx, "mch_1", "n") }, nil},
		{"Machines.Delete", `{"object":"machine","id":"mch_1","deleted":true}`, "DELETE", "/v1/machines/mch_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.Delete(ctx, "mch_1") }, nil},
		{"Machines.MergeMetadata", machineJSON, "PATCH", "/v1/machines/mch_1/metadata", "",
			map[string]interface{}{"metadata": map[string]interface{}{"os": "linux"}},
			func(c *Client) (interface{}, error) {
				return c.Machines.MergeMetadata(ctx, "mch_1", Metadata{"os": "linux"})
			}, nil},
		{"Machines.Approve", machineJSON, "POST", "/v1/machines/mch_1/approve", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.Approve(ctx, "mch_1") }, nil},
		{"Machines.Revoke", machineJSON, "POST", "/v1/machines/mch_1/revoke", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.Revoke(ctx, "mch_1") }, nil},
		{"Machines.RotateSecret", `{"object":"machine","id":"mch_1","secret":"mk_y"}`, "POST", "/v1/machines/mch_1/rotate_secret", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.RotateSecret(ctx, "mch_1") }, nil},
		{"Machines.RotateKey", machineJSON, "POST", "/v1/machines/mch_1/rotate_key", "",
			map[string]interface{}{"public_key_pem": "PEM"},
			func(c *Client) (interface{}, error) { return c.Machines.RotateKey(ctx, "mch_1", "PEM") }, nil},
		{"Machines.ListOrganizationMemberships", `{"object":"list","data":[{"organization_id":"org_1","role":null,"joined_at":1}],"has_more":false}`, "GET", "/v1/machines/mch_1/organization_memberships", "", nil,
			func(c *Client) (interface{}, error) {
				return c.Machines.ListOrganizationMemberships(ctx, "mch_1", ListParams{})
			},
			func(t *testing.T, out interface{}) {
				if m := out.(*CursorPage[MachineOrganizationMembership]).Data[0]; m.Role != nil || m.OrganizationID != "org_1" {
					t.Errorf("membership = %+v", m)
				}
			}},
		{"Machines.VerifyToken", `{"object":"m2m_token_verification","valid":true,"machine_id":"mch_1","name":"m"}`, "POST", "/v1/m2m_tokens/verify", "",
			map[string]interface{}{"token": "mk_x"},
			func(c *Client) (interface{}, error) { return c.Machines.VerifyToken(ctx, "mk_x") },
			func(t *testing.T, out interface{}) {
				if v := out.(*M2MTokenVerification); !v.Valid || v.MachineID != "mch_1" {
					t.Errorf("verify = %+v", v)
				}
			}},
		{"EnrolmentTokens.Create", `{"object":"machine_enrolment_token","id":"met_1","max_uses":5,"uses":0,"expires_at":9,"requires_approval":true,"token":"met_secret"}`, "POST", "/v1/machine_enrolment_tokens", "",
			map[string]interface{}{"organization_id": "org_1", "max_uses": float64(5), "requires_approval": true, "single_session": true},
			func(c *Client) (interface{}, error) {
				return c.Machines.EnrolmentTokens.Create(ctx, CreateMachineEnrolmentTokenParams{OrganizationID: "org_1", MaxUses: 5, RequiresApproval: true, SingleSession: true})
			},
			func(t *testing.T, out interface{}) {
				if tok := out.(*MachineEnrolmentToken); tok.Token != "met_secret" || tok.MaxUses != 5 {
					t.Errorf("token = %+v", tok)
				}
			}},
		{"EnrolmentTokens.List", `{"object":"list","data":[{"object":"machine_enrolment_token","id":"met_1"}],"has_more":false}`, "GET", "/v1/machine_enrolment_tokens", "organization_id=org_1", nil,
			func(c *Client) (interface{}, error) {
				return c.Machines.EnrolmentTokens.List(ctx, ListMachineEnrolmentTokensParams{OrganizationID: "org_1"})
			}, nil},
		{"EnrolmentTokens.Delete", `{"object":"machine_enrolment_token","id":"met_1","deleted":true}`, "DELETE", "/v1/machine_enrolment_tokens/met_1", "", nil,
			func(c *Client) (interface{}, error) { return c.Machines.EnrolmentTokens.Delete(ctx, "met_1") }, nil},
		// Session-exchange apps + session template tokens.
		{"SessionExchangeApps.List", `{"object":"list","data":[{"object":"session_exchange_app","id":"sxa_1","audience":"aud"}],"has_more":false}`, "GET", "/v1/session_exchange_apps", "", nil,
			func(c *Client) (interface{}, error) { return c.SessionExchangeApps.List(ctx) },
			func(t *testing.T, out interface{}) {
				if out.(*CursorPage[SessionExchangeApp]).Data[0].Audience != "aud" {
					t.Errorf("apps = %+v", out)
				}
			}},
		{"SessionExchangeApps.Create", `{"object":"session_exchange_app","id":"sxa_1"}`, "POST", "/v1/session_exchange_apps", "",
			map[string]interface{}{"name": "Wiki", "backchannel_logout_uri": "https://wiki/logout"},
			func(c *Client) (interface{}, error) {
				return c.SessionExchangeApps.Create(ctx, CreateSessionExchangeAppParams{Name: "Wiki", BackchannelLogoutURI: "https://wiki/logout"})
			}, nil},
		{"SessionExchangeApps.Get", `{"object":"session_exchange_app","id":"sxa_1"}`, "GET", "/v1/session_exchange_apps/sxa_1", "", nil,
			func(c *Client) (interface{}, error) { return c.SessionExchangeApps.Get(ctx, "sxa_1") }, nil},
		{"SessionExchangeApps.Update", `{"object":"session_exchange_app","id":"sxa_1"}`, "PATCH", "/v1/session_exchange_apps/sxa_1", "",
			map[string]interface{}{"name": "Wiki 2", "audience": nil},
			func(c *Client) (interface{}, error) {
				return c.SessionExchangeApps.Update(ctx, "sxa_1", UpdateSessionExchangeAppParams{Name: str("Wiki 2"), ClearAudience: true})
			}, nil},
		{"SessionExchangeApps.Delete", `{"object":"session_exchange_app","id":"sxa_1","deleted":true}`, "DELETE", "/v1/session_exchange_apps/sxa_1", "", nil,
			func(c *Client) (interface{}, error) { return c.SessionExchangeApps.Delete(ctx, "sxa_1") }, nil},
		{"Sessions.CreateTemplateToken", `{"object":"token","jwt":"ey.x","expires_in":60}`, "POST", "/v1/sessions/sess_1/tokens/supabase", "", nil,
			func(c *Client) (interface{}, error) { return c.Sessions.CreateTemplateToken(ctx, "sess_1", "supabase") },
			func(t *testing.T, out interface{}) {
				if tok := out.(*SessionTemplateToken); tok.JWT != "ey.x" || tok.ExpiresIn != 60 {
					t.Errorf("token = %+v", tok)
				}
			}},
		// Redirect URLs.
		{"RedirectURLs.List", `{"object":"list","data":[{"object":"redirect_url","id":"ru_1","url":"https://a/cb","created_at":1}],"has_more":false}`, "GET", "/v1/redirect_urls", "", nil,
			func(c *Client) (interface{}, error) { return c.RedirectURLs.List(ctx) },
			func(t *testing.T, out interface{}) {
				if out.(*CursorPage[RedirectURL]).Data[0].URL != "https://a/cb" {
					t.Errorf("urls = %+v", out)
				}
			}},
		{"RedirectURLs.Create", `{"object":"redirect_url","id":"ru_1"}`, "POST", "/v1/redirect_urls", "",
			map[string]interface{}{"url": "https://a/cb"},
			func(c *Client) (interface{}, error) { return c.RedirectURLs.Create(ctx, "https://a/cb") }, nil},
		{"RedirectURLs.Get", `{"object":"redirect_url","id":"ru_1"}`, "GET", "/v1/redirect_urls/ru_1", "", nil,
			func(c *Client) (interface{}, error) { return c.RedirectURLs.Get(ctx, "ru_1") }, nil},
		{"RedirectURLs.Delete", `{"object":"redirect_url","id":"ru_1","deleted":true}`, "DELETE", "/v1/redirect_urls/ru_1", "", nil,
			func(c *Client) (interface{}, error) { return c.RedirectURLs.Delete(ctx, "ru_1") }, nil},
		// Tickets.
		{"Tickets.Create", `{"object":"ticket","id":"tkt_id","ticket":"tkt_secret","single_use":true,"bound_user":"user_1","bound_org":null,"expires_at":5}`, "POST", "/v1/tickets", "",
			map[string]interface{}{"payload": map[string]interface{}{"file": "a.pdf"}, "ttl_seconds": float64(300), "bound_user": "user_1"},
			func(c *Client) (interface{}, error) {
				return c.Tickets.Create(ctx, CreateTicketParams{Payload: map[string]string{"file": "a.pdf"}, TTLSeconds: 300, BoundUser: "user_1"})
			},
			func(t *testing.T, out interface{}) {
				if tk := out.(*Ticket); tk.Ticket != "tkt_secret" || *tk.BoundUser != "user_1" || tk.BoundOrg != nil {
					t.Errorf("ticket = %+v", tk)
				}
			}},
		{"Tickets.Redeem", `{"object":"ticket_redemption","id":"tkt_id","payload":{"file":"a.pdf"},"single_use":true}`, "POST", "/v1/tickets/redeem", "",
			map[string]interface{}{"ticket": "tkt_secret", "for_user": "user_1"},
			func(c *Client) (interface{}, error) {
				return c.Tickets.Redeem(ctx, RedeemTicketParams{Ticket: "tkt_secret", ForUser: "user_1"})
			},
			func(t *testing.T, out interface{}) {
				if out.(*TicketRedemption).Payload.(map[string]interface{})["file"] != "a.pdf" {
					t.Errorf("redemption = %+v", out)
				}
			}},
		// Notifications.
		{"Notifications.Send", `{"object":"notification","id":"ntf_1","status":"suppressed"}`, "POST", "/v1/notifications", "",
			map[string]interface{}{"user_id": "user_1", "template": "new_device", "data": map[string]interface{}{"device": "Mac"}},
			func(c *Client) (interface{}, error) {
				return c.Notifications.Send(ctx, SendNotificationParams{UserID: "user_1", Template: "new_device", Data: map[string]string{"device": "Mac"}})
			},
			func(t *testing.T, out interface{}) {
				if out.(*NotificationSend).Status != "suppressed" {
					t.Errorf("send = %+v", out)
				}
			}},
		{"Categories.List", `{"object":"list","data":[{"object":"notification_category","id":"nc_1","key":"billing","label":"Billing","optional":true}]}`, "GET", "/v1/notification_categories", "", nil,
			func(c *Client) (interface{}, error) { return c.Notifications.Categories.List(ctx) }, nil},
		{"Categories.Create", `{"object":"notification_category","key":"billing"}`, "POST", "/v1/notification_categories", "",
			map[string]interface{}{"key": "billing", "label": "Billing"},
			func(c *Client) (interface{}, error) {
				return c.Notifications.Categories.Create(ctx, "billing", "Billing")
			}, nil},
		{"Categories.Update", `{"object":"notification_category","key":"billing"}`, "PUT", "/v1/notification_categories/billing", "",
			map[string]interface{}{"label": "Invoices"},
			func(c *Client) (interface{}, error) {
				return c.Notifications.Categories.Update(ctx, "billing", "Invoices")
			}, nil},
		{"Categories.Delete", `{"object":"notification_category","key":"billing","deleted":true}`, "DELETE", "/v1/notification_categories/billing", "", nil,
			func(c *Client) (interface{}, error) { return c.Notifications.Categories.Delete(ctx, "billing") },
			func(t *testing.T, out interface{}) {
				if d := out.(*NotificationCategoryDeleted); !d.Deleted || d.Key != "billing" {
					t.Errorf("deleted = %+v", d)
				}
			}},
		{"Templates.List", `{"object":"list","data":[{"object":"notification_template","name":"welcome"}]}`, "GET", "/v1/notification_templates", "", nil,
			func(c *Client) (interface{}, error) { return c.Notifications.Templates.List(ctx) }, nil},
		{"Templates.Create", `{"object":"notification_template","name":"welcome"}`, "POST", "/v1/notification_templates", "",
			map[string]interface{}{"name": "welcome", "subject": "Hi", "body": "Hello {{name}}", "category": "billing"},
			func(c *Client) (interface{}, error) {
				return c.Notifications.Templates.Create(ctx, CreateNotificationTemplateParams{Name: "welcome", Subject: "Hi", Body: "Hello {{name}}", Category: "billing"})
			}, nil},
		{"Templates.Get", `{"object":"notification_template","name":"welcome","subject":"Hi"}`, "GET", "/v1/notification_templates/welcome", "", nil,
			func(c *Client) (interface{}, error) { return c.Notifications.Templates.Get(ctx, "welcome") },
			func(t *testing.T, out interface{}) {
				if out.(*NotificationTemplate).Subject != "Hi" {
					t.Errorf("template = %+v", out)
				}
			}},
		{"Templates.Update", `{"object":"notification_template","name":"welcome"}`, "PUT", "/v1/notification_templates/welcome", "",
			map[string]interface{}{"subject": "Hey", "body": "B", "category": "billing"},
			func(c *Client) (interface{}, error) {
				return c.Notifications.Templates.Update(ctx, "welcome", UpdateNotificationTemplateParams{Subject: "Hey", Body: "B", Category: "billing"})
			}, nil},
		{"Templates.Delete", `{"object":"notification_template","name":"welcome","deleted":true}`, "DELETE", "/v1/notification_templates/welcome", "", nil,
			func(c *Client) (interface{}, error) { return c.Notifications.Templates.Delete(ctx, "welcome") }, nil},
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
