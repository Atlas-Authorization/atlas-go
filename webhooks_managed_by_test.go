package atlas

import (
	"encoding/json"
	"testing"
)

func TestUpdateWebhookEndpointManagedBy(t *testing.T) {
	b, _ := json.Marshal(UpdateWebhookEndpointParams{ManagedBy: "cookiemunch"})
	if string(b) != `{"managed_by":"cookiemunch"}` {
		t.Fatalf("set: %s", b)
	}
	b, _ = json.Marshal(UpdateWebhookEndpointParams{ClearManagedBy: true})
	if string(b) != `{"managed_by":null}` {
		t.Fatalf("clear: %s", b)
	}
	var e WebhookEndpoint
	_ = json.Unmarshal([]byte(`{"id":"wh_1","managed_by":"cookiemunch"}`), &e)
	if e.ManagedBy == nil || *e.ManagedBy != "cookiemunch" {
		t.Fatalf("read: %+v", e.ManagedBy)
	}
}
