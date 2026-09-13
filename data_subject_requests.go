package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// DataSubjectRequestsService is the /v1/data_subject_requests namespace — §13.4
// GDPR/DSAR admin surface. A fulfilled or rejected request is terminal.
type DataSubjectRequestsService struct{ client *Client }

// DataSubjectRequest is a data-subject export/erasure request.
type DataSubjectRequest struct {
	Object          string      `json:"object"`
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	Status          string      `json:"status"`
	UserID          string      `json:"user_id"`
	RequestedByType *string     `json:"requested_by_type"`
	RequestedByID   *string     `json:"requested_by_id"`
	Reason          *string     `json:"reason"`
	ScheduledFor    *int64      `json:"scheduled_for"`
	RequestedAt     int64       `json:"requested_at"`
	UpdatedAt       int64       `json:"updated_at"`
	CompletedAt     *int64      `json:"completed_at"`
	Result          interface{} `json:"result,omitempty"`
}

// ListDataSubjectRequestsParams filters the list. GET /v1/data_subject_requests.
type ListDataSubjectRequestsParams struct {
	Limit         int
	StartingAfter string
	Type          string
	Status        string
	UserID        string
}

func (p ListDataSubjectRequestsParams) values() url.Values {
	v := url.Values{}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.StartingAfter != "" {
		v.Set("starting_after", p.StartingAfter)
	}
	if p.Type != "" {
		v.Set("type", p.Type)
	}
	if p.Status != "" {
		v.Set("status", p.Status)
	}
	if p.UserID != "" {
		v.Set("user_id", p.UserID)
	}
	return v
}

// List returns data-subject requests. GET /v1/data_subject_requests.
func (s *DataSubjectRequestsService) List(ctx context.Context, params ListDataSubjectRequestsParams) (*CursorPage[DataSubjectRequest], error) {
	out := &CursorPage[DataSubjectRequest]{}
	return out, s.client.get(ctx, "/v1/data_subject_requests", params.values(), out)
}

// Get returns one request. GET /v1/data_subject_requests/:id.
func (s *DataSubjectRequestsService) Get(ctx context.Context, id string) (*DataSubjectRequest, error) {
	out := &DataSubjectRequest{}
	return out, s.client.get(ctx, "/v1/data_subject_requests/"+url.PathEscape(id), nil, out)
}

// Fulfill fulfils a request now, ahead of schedule.
// POST /v1/data_subject_requests/:id/fulfill.
func (s *DataSubjectRequestsService) Fulfill(ctx context.Context, id string, opts ...RequestOption) (*DataSubjectRequest, error) {
	out := &DataSubjectRequest{}
	return out, s.client.post(ctx, "/v1/data_subject_requests/"+url.PathEscape(id)+"/fulfill", nil, out, opts...)
}

// Reject rejects a request with a recorded reason. Terminal.
// POST /v1/data_subject_requests/:id/reject.
func (s *DataSubjectRequestsService) Reject(ctx context.Context, id, reason string, opts ...RequestOption) (*DataSubjectRequest, error) {
	out := &DataSubjectRequest{}
	body := map[string]string{}
	if reason != "" {
		body["reason"] = reason
	}
	return out, s.client.post(ctx, "/v1/data_subject_requests/"+url.PathEscape(id)+"/reject", body, out, opts...)
}
