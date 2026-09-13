package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient wires a Client to an httptest.Server so no test touches the
// network. The server's handler asserts request shape and writes canned JSON.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New("sk_test_123", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
}

// TestAuthHeaderAndBaseURL asserts the bearer token, Accept header, path, and
// that a 2xx body decodes into the typed struct.
func TestAuthHeaderAndBaseURL(t *testing.T) {
	var gotAuth, gotPath, gotAccept string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"user","id":"user_1","first_name":"Ada"}`))
	})

	u, err := c.Users.Get(context.Background(), "user_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer sk_test_123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer sk_test_123")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotPath != "/v1/users/user_1" {
		t.Errorf("path = %q, want /v1/users/user_1", gotPath)
	}
	// 2xx decoded into the typed struct.
	if u.ID != "user_1" || u.FirstName == nil || *u.FirstName != "Ada" {
		t.Errorf("decoded user = %+v, want id=user_1 first_name=Ada", u)
	}
}

// TestCreateDecodesTypedStruct exercises a POST create with a request body and a
// typed 2xx response.
func TestCreateDecodesTypedStruct(t *testing.T) {
	var gotMethod, gotCT string
	var gotBody CreateUserParams
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"object":"user","id":"user_new","mfa_enabled":true}`))
	})

	u, err := c.Users.Create(context.Background(), CreateUserParams{EmailAddress: "ada@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.EmailAddress != "ada@example.com" {
		t.Errorf("request body email = %q, want ada@example.com", gotBody.EmailAddress)
	}
	if u.ID != "user_new" || !u.MFAEnabled {
		t.Errorf("decoded user = %+v, want id=user_new mfa_enabled=true", u)
	}
}

// TestAPIErrorRecoverableViaErrorsAs is the mutation-check: a 4xx must return an
// *APIError carrying the code and param. The nil-error guard makes the test fail
// if the error path is ever skipped (e.g. a refactor that swallows non-2xx).
func TestAPIErrorRecoverableViaErrorsAs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"code":"FORM_IDENTIFIER_EXISTS","message":"That email is taken.","param":"email_address"}]}`))
	})

	u, err := c.Users.Create(context.Background(), CreateUserParams{EmailAddress: "dup@example.com"})
	// Mutation-check: if the error path is skipped, err is nil here and we fail.
	if err == nil {
		t.Fatal("expected an error for a 422 response, got nil")
	}
	if u != nil && u.ID != "" {
		t.Errorf("expected no decoded user on error, got %+v", u)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) = false; err has type %T: %v", err, err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", apiErr.Status)
	}
	if apiErr.Code() != "FORM_IDENTIFIER_EXISTS" {
		t.Errorf("code = %q, want FORM_IDENTIFIER_EXISTS", apiErr.Code())
	}
	if !apiErr.HasCode("FORM_IDENTIFIER_EXISTS") {
		t.Error("HasCode(FORM_IDENTIFIER_EXISTS) = false, want true")
	}
	if len(apiErr.Errors) != 1 || apiErr.Errors[0].Param != "email_address" {
		t.Errorf("errors = %+v, want one item with param=email_address", apiErr.Errors)
	}
}

// TestNotFoundError checks the IsNotFound helper on a 404.
func TestNotFoundError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND","message":"Not found."}]}`))
	})

	_, err := c.Organizations.Get(context.Background(), "org_missing")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsNotFound() {
		t.Error("IsNotFound() = false, want true for a 404")
	}
}

// TestIdempotencyKeySentOnCreate asserts WithIdempotencyKey sets the header, and
// (mutation-check) that a create WITHOUT the option omits it.
func TestIdempotencyKeySentOnCreate(t *testing.T) {
	var gotKey string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Idempotency-Key")
		_, _ = w.Write([]byte(`{"object":"organization","id":"org_1","name":"Acme"}`))
	})

	// With the option: header present.
	if _, err := c.Organizations.Create(
		context.Background(),
		CreateOrganizationParams{Name: "Acme", Slug: "acme", CreatedBy: "user_1"},
		WithIdempotencyKey("key-abc"),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotKey != "key-abc" {
		t.Errorf("Idempotency-Key = %q, want key-abc", gotKey)
	}

	// Without the option: header absent (mutation-check that the option, not a
	// hardcoded value, drives the header).
	gotKey = "sentinel"
	if _, err := c.Organizations.Create(
		context.Background(),
		CreateOrganizationParams{Name: "Acme", Slug: "acme", CreatedBy: "user_1"},
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotKey != "" {
		t.Errorf("Idempotency-Key = %q on a keyless create, want empty", gotKey)
	}
}

// TestPaginationIteratesPages drives the cursor Iterator across two pages and
// asserts the second request carried the starting_after cursor.
func TestPaginationIteratesPages(t *testing.T) {
	var pageCalls int
	var secondCursor string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pageCalls++
		cursor := r.URL.Query().Get("starting_after")
		w.Header().Set("Content-Type", "application/json")
		if cursor == "" {
			// Page 1: two items, more to come.
			_, _ = w.Write([]byte(`{"data":[{"id":"user_1"},{"id":"user_2"}],"has_more":true,"next_cursor":"user_2"}`))
			return
		}
		secondCursor = cursor
		// Page 2: one item, done.
		_, _ = w.Write([]byte(`{"data":[{"id":"user_3"}],"has_more":false,"next_cursor":null}`))
	})

	it := Paginate(func(startingAfter string) (*CursorPage[User], error) {
		return c.Users.List(context.Background(), ListParams{Limit: 2, StartingAfter: startingAfter})
	})

	var ids []string
	for it.Next() {
		ids = append(ids, it.Item().ID)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}

	want := []string{"user_1", "user_2", "user_3"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("iterated ids = %v, want %v", ids, want)
	}
	if pageCalls != 2 {
		t.Errorf("page fetches = %d, want 2", pageCalls)
	}
	if secondCursor != "user_2" {
		t.Errorf("second page starting_after = %q, want user_2", secondCursor)
	}
}

// TestPaginationStopsOnError surfaces a mid-iteration error through Err and stops.
func TestPaginationStopsOnError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"code":"INTERNAL","message":"boom"}]}`))
	})

	it := Paginate(func(startingAfter string) (*CursorPage[User], error) {
		return c.Users.List(context.Background(), ListParams{StartingAfter: startingAfter})
	})
	if it.Next() {
		t.Error("Next() = true on a failing fetch, want false")
	}
	if it.Err() == nil {
		t.Fatal("Err() = nil after a failed fetch, want an error")
	}
	var apiErr *APIError
	if !errors.As(it.Err(), &apiErr) || apiErr.Status != 500 {
		t.Errorf("Err() = %v, want *APIError with status 500", it.Err())
	}
}

// TestListQueryParams checks the sessions namespace threads its required user_id
// into the query string.
func TestListQueryParams(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"sess_1","user_id":"user_1"}]}`))
	})

	page, err := c.Sessions.List(context.Background(), "user_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotQuery, "user_id=user_1") {
		t.Errorf("query = %q, want it to contain user_id=user_1", gotQuery)
	}
	if len(page.Data) != 1 || page.Data[0].ID != "sess_1" {
		t.Errorf("decoded page = %+v, want one session sess_1", page)
	}
}

// TestDeleteReturnsAck covers a DELETE decoding into DeletedObject.
func TestDeleteReturnsAck(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"user","id":"user_1","deleted":true}`))
	})

	ack, err := c.Users.Delete(context.Background(), "user_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ack.Deleted || ack.ID != "user_1" {
		t.Errorf("ack = %+v, want deleted user_1", ack)
	}
}

// TestPathEscaping ensures ids with reserved characters are percent-encoded.
func TestPathEscaping(t *testing.T) {
	var gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"user","id":"x"}`))
	})
	if _, err := c.Users.Get(context.Background(), "a b/c"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(gotPath, " ") {
		t.Errorf("escaped path %q still contains a raw space", gotPath)
	}
	if !strings.Contains(gotPath, "/v1/users/") {
		t.Errorf("escaped path = %q, want it under /v1/users/", gotPath)
	}
}

// Example shows the canonical create-user + branch-on-APIError flow.
func Example() {
	c := New("sk_live_...", WithBaseURL("https://api.atlas.dev"))
	_, err := c.Users.Create(context.Background(), CreateUserParams{EmailAddress: "ada@example.com"})
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code() == "FORM_IDENTIFIER_EXISTS" {
		fmt.Println("email already registered")
	}
}
