package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// WaitlistService is the /v1/waitlist_entries namespace.
type WaitlistService struct{ client *Client }

// WaitlistEntry is one entry on the sign-up waitlist.
type WaitlistEntry struct {
	Object       string  `json:"object"`
	ID           string  `json:"id"`
	EmailAddress string  `json:"email_address"`
	Status       string  `json:"status"`
	Note         *string `json:"note"`
	DecidedBy    *string `json:"decided_by"`
	DecidedAt    *int64  `json:"decided_at"`
	CreatedAt    int64   `json:"created_at"`
}

// ListWaitlistParams filters the waitlist and paginates it.
type ListWaitlistParams struct {
	ListParams
	Status string
	Query  string
}

// ListWaitlistResponse is the waitlist list envelope with per-status counts.
type ListWaitlistResponse struct {
	Object     string          `json:"object"`
	Data       []WaitlistEntry `json:"data"`
	Counts     map[string]int  `json:"counts"`
	HasMore    bool            `json:"has_more"`
	NextCursor *string         `json:"next_cursor"`
}

// DecideWaitlistParams approves or denies an entry.
type DecideWaitlistParams struct {
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// List returns a page of waitlist entries. GET /v1/waitlist_entries.
func (s *WaitlistService) List(ctx context.Context, params ListWaitlistParams) (*ListWaitlistResponse, error) {
	out := &ListWaitlistResponse{}
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.StartingAfter != "" {
		q.Set("starting_after", params.StartingAfter)
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	if params.Query != "" {
		q.Set("query", params.Query)
	}
	return out, s.client.get(ctx, "/v1/waitlist_entries", q, out)
}

// Decide approves or denies a waitlist entry.
// POST /v1/waitlist_entries/:id/decide.
func (s *WaitlistService) Decide(ctx context.Context, id string, params DecideWaitlistParams) (*WaitlistEntry, error) {
	out := &WaitlistEntry{}
	return out, s.client.post(ctx, "/v1/waitlist_entries/"+url.PathEscape(id)+"/decide", params, out)
}
