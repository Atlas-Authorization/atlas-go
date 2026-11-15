package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeneratedCursorListIterator(t *testing.T) {
	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("starting_after")
		cursors = append(cursors, after)
		w.Header().Set("Content-Type", "application/json")
		if after == "" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"a"},{"id":"b"}],"has_more":true,"next_cursor":"b"}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"c"}],"has_more":false,"next_cursor":null}`))
	}))
	defer srv.Close()

	c := New("sk_test", WithBaseURL(srv.URL))
	items, err := c.AbuseSignals.ListIter(context.Background(), AbuseSignalsListQuery{}).Collect()
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("want 3 items across 2 pages, got %d", len(items))
	}
	if len(cursors) != 2 || cursors[0] != "" || cursors[1] != "b" {
		t.Fatalf("cursors=%v", cursors)
	}
}

func TestGeneratedPatchBodyCanSendExplicitNull(t *testing.T) {
	name := "Ops"
	b, err := json.Marshal(AdministrativeUnitsUpdateParams{Name: &name, ClearFields: []string{"description"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"description":null,"name":"Ops"}` {
		t.Fatalf("body=%s", b)
	}
	unset, _ := json.Marshal(AdministrativeUnitsUpdateParams{Name: &name})
	if string(unset) != `{"name":"Ops"}` {
		t.Fatalf("unset fields must stay omitted, got %s", unset)
	}
}
