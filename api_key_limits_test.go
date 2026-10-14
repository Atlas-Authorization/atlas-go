package atlas

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const limitStateJSON = `{"unit":"usd_cents","period":"month","amount":5000,"used":12,"remaining":4988,"window_start":1790000000000,"resets_at":1792000000000}`
const counterJSON = `{"unit":"usd_cents","period":"month","used":12,"window_start":1790000000000,"resets_at":1792000000000}`

func TestAPIKeyCreateSendsLimits(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key","id":"eak_1","secret":"ak_x","limits":[{"unit":"usd_cents","amount":5000,"period":"month"}],"usage":[`+limitStateJSON+`]}`)
	out, err := c.APIKeys.Create(context.Background(), CreateAPIKeyParams{
		SubjectType: "user",
		SubjectID:   "user_1",
		Limits:      []APIKeyLimit{{Unit: "usd_cents", Amount: 5000, Period: APIKeyLimitPeriodMonth}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/api_keys")
	limits, _ := rec.Body["limits"].([]interface{})
	if len(limits) != 1 || limits[0].(map[string]interface{})["period"] != "month" {
		t.Errorf("limits body = %v", rec.Body["limits"])
	}
	if len(out.Limits) != 1 || out.Limits[0].Amount != 5000 || len(out.Usage) != 1 || out.Usage[0].Remaining != 4988 {
		t.Errorf("decoded = %+v", out.APIKey)
	}
	if out.Usage[0].ResetsAt == nil || *out.Usage[0].ResetsAt != 1792000000000 {
		t.Errorf("resets_at = %v", out.Usage[0].ResetsAt)
	}
}

func TestAPIKeyCreateOmitsUnsetLimits(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key","id":"eak_1"}`)
	_, _ = c.APIKeys.Create(context.Background(), CreateAPIKeyParams{SubjectType: "user", SubjectID: "u"})
	if _, ok := rec.Body["limits"]; ok {
		t.Errorf("limits sent when unset: %s", rec.RawBody)
	}
}

func TestAPIKeyUpdateLimitsAndClear(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key","id":"eak_1","limits":null,"usage":[]}`)
	ctx := context.Background()

	_, _ = c.APIKeys.Update(ctx, "eak_1", UpdateAPIKeyParams{Limits: []APIKeyLimit{{Unit: "requests", Amount: 10, Period: APIKeyLimitPeriodDay}}})
	rec.expect(t, "PATCH", "/v1/api_keys/eak_1")
	if l, _ := rec.Body["limits"].([]interface{}); len(l) != 1 {
		t.Errorf("limits body = %s", rec.RawBody)
	}

	out, err := c.APIKeys.Update(ctx, "eak_1", UpdateAPIKeyParams{ClearLimits: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec.RawBody != `{"limits":null}` {
		t.Errorf("clear body = %s, want {\"limits\":null}", rec.RawBody)
	}
	if out.Limits != nil {
		t.Errorf("Limits = %v, want nil", out.Limits)
	}
}

func TestAPIKeyRecordUsageAllowed(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key_usage_debit","key_id":"eak_1","unit":"usd_cents","amount":12,"allowed":true,"exceeded":[],"usage":[`+limitStateJSON+`],"counters":[`+counterJSON+`],"idempotent_replay":true}`)
	out, err := c.APIKeys.RecordUsage(context.Background(), "eak_1", RecordAPIKeyUsageParams{Amount: 12, Unit: "usd_cents", IdempotencyKey: "req_1"})
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/api_keys/eak_1/usage")
	if rec.Body["amount"] != float64(12) || rec.Body["unit"] != "usd_cents" || rec.Body["idempotency_key"] != "req_1" {
		t.Errorf("body = %s", rec.RawBody)
	}
	if !out.Allowed || out.Code != "" || !out.IdempotentReplay || out.KeyID != "eak_1" || len(out.Counters) != 1 || out.Counters[0].WindowStart != 1790000000000 {
		t.Errorf("decoded = %+v", out)
	}
}

func TestAPIKeyRecordUsageOmitsEmptyIdempotencyKey(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key_usage_debit","allowed":true}`)
	_, _ = c.APIKeys.RecordUsage(context.Background(), "eak_1", RecordAPIKeyUsageParams{Amount: 1, Unit: "requests"})
	if _, ok := rec.Body["idempotency_key"]; ok {
		t.Errorf("idempotency_key sent when empty: %s", rec.RawBody)
	}
}

func TestAPIKeyRecordUsageRefusalIsNotAnError(t *testing.T) {
	c, _ := recordingClient(t, `{"object":"api_key_usage_debit","key_id":"eak_1","unit":"usd_cents","amount":9999,"allowed":false,"code":"LIMIT_EXCEEDED","exceeded":[`+limitStateJSON+`],"usage":[`+limitStateJSON+`],"counters":[],"idempotent_replay":false}`)
	out, err := c.APIKeys.RecordUsage(context.Background(), "eak_1", RecordAPIKeyUsageParams{Amount: 9999, Unit: "usd_cents"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed || out.Code != ErrCodeLimitExceeded || len(out.Exceeded) != 1 {
		t.Errorf("decoded = %+v", out)
	}
}

func TestAPIKeyRecordUsageIdempotencyConflict(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"code":"IDEMPOTENCY_CONFLICT","message":"reused","param":"idempotency_key"}]}`))
	})
	_, err := c.APIKeys.RecordUsage(context.Background(), "eak_1", RecordAPIKeyUsageParams{Amount: 1, Unit: "requests", IdempotencyKey: "k"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || !apiErr.HasCode(ErrCodeIdempotencyConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIKeyGetUsage(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"api_key_usage","key_id":"eak_1","limits":[{"unit":"usd_cents","amount":5000,"period":"month"}],"usage":[`+limitStateJSON+`],"counters":[`+counterJSON+`]}`)
	out, err := c.APIKeys.GetUsage(context.Background(), "eak_1")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "GET", "/v1/api_keys/eak_1/usage")
	if out.Object != "api_key_usage" || len(out.Limits) != 1 || out.Usage[0].Used != 12 || out.Counters[0].Period != "month" {
		t.Errorf("decoded = %+v", out)
	}
}

func TestAPIKeyVerifyDecodesPolicyAndUsage(t *testing.T) {
	c, _ := recordingClient(t, `{"object":"api_key_verification","valid":true,"id":"eak_1","subject_type":"user","subject_id":"user_1","name":"CI","claims":{},"scopes":["read"],"constraints":{"ip":["10.0.0.0/8"]},"limits":[{"unit":"usd_cents","amount":5000,"period":"month"}],"usage":[`+limitStateJSON+`],"last_used_at":null,"expires_at":null}`)
	v, err := c.APIKeys.Verify(context.Background(), "ak_x")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Name == nil || *v.Name != "CI" || len(v.Scopes) != 1 || v.Constraints["ip"] == nil || len(v.Limits) != 1 || len(v.Usage) != 1 {
		t.Errorf("decoded = %+v", v)
	}
}

func TestSessionTouch(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"session","id":"sess_1","user_id":"user_1","status":"active","last_active_organization_id":null,"impersonated_by":null,"last_active_at":1,"expire_at":3,"abandon_at":2,"idle_expires_at":2,"created_at":0,"extended":true}`)
	s, err := c.Sessions.Touch(context.Background(), "sess_1")
	if err != nil {
		t.Fatal(err)
	}
	rec.expect(t, "POST", "/v1/sessions/sess_1/touch")
	if rec.RawBody != "" {
		t.Errorf("touch sent a body: %q", rec.RawBody)
	}
	if !s.Extended || s.IdleExpiresAt != 2 || s.ID != "sess_1" {
		t.Errorf("decoded = %+v", s)
	}
}

func TestSessionTouchEndedSession(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"code":"SESSION_IDLE_EXPIRED","message":"timed out"}]}`))
	})
	_, err := c.Sessions.Touch(context.Background(), "sess_1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.HasCode(ErrCodeSessionIdleExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestUserCreateAndImportNotify(t *testing.T) {
	c, rec := recordingClient(t, `{"object":"user","id":"user_1"}`)
	ctx := context.Background()
	f := false
	_, _ = c.Users.Create(ctx, CreateUserParams{EmailAddress: "a@b.test", Notify: &f})
	rec.expect(t, "POST", "/v1/users")
	if v, ok := rec.Body["notify"]; !ok || v != false {
		t.Errorf("create body = %s", rec.RawBody)
	}

	tr := true
	_, _ = c.ImportExport.ImportUsers(ctx, ImportUsersParams{Users: []ImportUserRow{{}}, Notify: &tr})
	rec.expect(t, "POST", "/v1/user_imports")
	if rec.Body["notify"] != true {
		t.Errorf("import body = %s", rec.RawBody)
	}

	_, _ = c.Users.Create(ctx, CreateUserParams{EmailAddress: "a@b.test"})
	if _, ok := rec.Body["notify"]; ok {
		t.Errorf("notify sent when unset: %s", rec.RawBody)
	}
}
