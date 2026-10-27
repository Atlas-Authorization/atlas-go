package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ListenService is the listen resource.
type ListenService struct {
	client *Client
}

// CreateSession: Start a local webhook forwarding session (what `atlas listen` uses). Returns a
// session id, a signing secret for that session only (it is unrelated to any registered endpoint's
// secret) and the stream URL. The session needs no storage: it expires at `expires_at` (default 1
// hour, `ttl_seconds` 60 to 43200).
// POST /v1/listen/sessions.
func (s *ListenService) CreateSession(ctx context.Context, params ListenCreateSessionParams, opts ...RequestOption) (*ListenCreateSessionResult, error) {
	out := &ListenCreateSessionResult{}
	return out, s.client.do(ctx, "POST", "/v1/listen/sessions", nil, params, out, opts...)
}

// ListenStreamSessionQuery holds the query parameters of ListenService.StreamSession.
type ListenStreamSessionQuery struct {
	// Comma-separated event types or patterns (`user.*`).
	Events string
	// Resume after this event id.
	After string
	// Close the stream after this many forwarded events.
	MaxEvents int64
	// How often the stream checks for new events, in milliseconds.
	PollMs int64
	// Close the stream after this long.
	MaxWaitSeconds int64
}

func (q ListenStreamSessionQuery) values() url.Values {
	v := url.Values{}
	if q.Events != "" {
		v.Set("events", q.Events)
	}
	if q.After != "" {
		v.Set("after", q.After)
	}
	if q.MaxEvents != 0 {
		v.Set("max_events", strconv.FormatInt(q.MaxEvents, 10))
	}
	if q.PollMs != 0 {
		v.Set("poll_ms", strconv.FormatInt(q.PollMs, 10))
	}
	if q.MaxWaitSeconds != 0 {
		v.Set("max_wait_seconds", strconv.FormatInt(q.MaxWaitSeconds, 10))
	}
	return v
}

// StreamSession: Server-Sent Events stream of the instance's new events for a listen session. Each
// `webhook` event carries `{id, type, headers, body}`: the headers (`atlas-id`, `atlas-timestamp`,
// `atlas-signature`) and the exact JSON body of a would-be delivery, signed with the session
// secret. Starts at "now" unless resumed with `Last-Event-ID` or `after`. Query: `events`
// (comma-separated types or patterns), `max_events` and `max_wait_seconds` (end the stream early,
// for scripts and CI). A `: keep-alive` comment is sent every 15 seconds; an `expired` event ends
// the stream at the session expiry. 404 for an unknown session id, 400 once expired.
// The stream is read to its end, so bound it with max_events or max_wait_seconds; the result is
// the raw Server-Sent Events text.
// GET /v1/listen/sessions/{id}/stream.
func (s *ListenService) StreamSession(ctx context.Context, id string, query ListenStreamSessionQuery) ([]byte, error) {
	return s.client.doBytes(ctx, "GET", "/v1/listen/sessions/"+url.PathEscape(id)+"/stream", query.values())
}
