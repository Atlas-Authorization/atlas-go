package atlas

import (
	"context"
	"net/url"
)

// LogStreamsService is the /v1/log_streams namespace — the instance event feed
// forwarded to an external sink (HTTP, Datadog, Splunk). Destination secrets are
// write-only.
type LogStreamsService struct{ client *Client }

// LogStream is a log stream. Destination carries only non-secret fields + has_*
// markers.
type LogStream struct {
	Object              string                 `json:"object"`
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Type                string                 `json:"type"`
	Enabled             bool                   `json:"enabled"`
	Status              string                 `json:"status"`
	EventFilter         []string               `json:"event_filter"`
	Destination         map[string]interface{} `json:"destination"`
	Cursor              *string                `json:"cursor"`
	ConsecutiveFailures int                    `json:"consecutive_failures"`
	LastError           *string                `json:"last_error"`
	LastDeliveredAt     *int64                 `json:"last_delivered_at"`
	CreatedAt           int64                  `json:"created_at"`
	UpdatedAt           int64                  `json:"updated_at"`
}

// CreateLogStreamParams is the body of POST /v1/log_streams.
type CreateLogStreamParams struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Destination map[string]interface{} `json:"destination"`
	EventFilter []string               `json:"event_filter,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// UpdateLogStreamParams is the body of PATCH /v1/log_streams/:id.
type UpdateLogStreamParams struct {
	Name        string                 `json:"name,omitempty"`
	Destination map[string]interface{} `json:"destination,omitempty"`
	EventFilter []string               `json:"event_filter,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Status      string                 `json:"status,omitempty"`
}

// LogStreamTestResult is the tester's outcome.
type LogStreamTestResult struct {
	Object string  `json:"object"`
	ID     string  `json:"id"`
	OK     bool    `json:"ok"`
	Status *int    `json:"status"`
	Error  *string `json:"error"`
}

// List returns the log streams. GET /v1/log_streams.
func (s *LogStreamsService) List(ctx context.Context) (*ListPage[LogStream], error) {
	out := &ListPage[LogStream]{}
	return out, s.client.get(ctx, "/v1/log_streams", nil, out)
}

// Get returns one stream. GET /v1/log_streams/:id.
func (s *LogStreamsService) Get(ctx context.Context, id string) (*LogStream, error) {
	out := &LogStream{}
	return out, s.client.get(ctx, "/v1/log_streams/"+url.PathEscape(id), nil, out)
}

// Create creates a stream. POST /v1/log_streams.
func (s *LogStreamsService) Create(ctx context.Context, params CreateLogStreamParams, opts ...RequestOption) (*LogStream, error) {
	out := &LogStream{}
	return out, s.client.post(ctx, "/v1/log_streams", params, out, opts...)
}

// Update patches a stream. PATCH /v1/log_streams/:id.
func (s *LogStreamsService) Update(ctx context.Context, id string, params UpdateLogStreamParams) (*LogStream, error) {
	out := &LogStream{}
	return out, s.client.patch(ctx, "/v1/log_streams/"+url.PathEscape(id), params, out)
}

// Delete removes a stream. DELETE /v1/log_streams/:id.
func (s *LogStreamsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/log_streams/"+url.PathEscape(id), out)
}

// Test sends one synthetic event with the real credentials.
// POST /v1/log_streams/:id/test.
func (s *LogStreamsService) Test(ctx context.Context, id string) (*LogStreamTestResult, error) {
	out := &LogStreamTestResult{}
	return out, s.client.post(ctx, "/v1/log_streams/"+url.PathEscape(id)+"/test", nil, out)
}
