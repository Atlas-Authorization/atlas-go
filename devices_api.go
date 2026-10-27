package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// DevicesService is the devices resource.
type DevicesService struct {
	client *Client
}

// DevicesListQuery holds the query parameters of DevicesService.List.
type DevicesListQuery struct {
	// Only devices tied to this user.
	UserID string
	// Only devices reported by this posture source (the `source` sent with PUT /v1/devices; default
	// api).
	Source string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q DevicesListQuery) values() url.Values {
	v := url.Values{}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.Source != "" {
		v.Set("source", q.Source)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List registered devices, filtered by user_id or source.
// GET /v1/devices.
func (s *DevicesService) List(ctx context.Context, query DevicesListQuery) (*CursorPage[DevicesListItem], error) {
	out := &CursorPage[DevicesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/devices", query.values(), nil, out)
}

// Report: Create or refresh one device by (source, external_id), reporting managed/compliant
// posture. Tie it to a user with user_id or a verified user_email. Access policies read the result
// through the deviceTrust condition: trusted = a managed, compliant device reported within 30
// days.
// PUT /v1/devices.
func (s *DevicesService) Report(ctx context.Context, params DevicesReportParams, opts ...RequestOption) (*DevicesListItem, error) {
	out := &DevicesListItem{}
	return out, s.client.do(ctx, "PUT", "/v1/devices", nil, params, out, opts...)
}

// Get: Fetch a device and its latest posture.
// GET /v1/devices/{id}.
func (s *DevicesService) Get(ctx context.Context, id string) (*DevicesListItem, error) {
	out := &DevicesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/devices/"+url.PathEscape(id), nil, nil, out)
}

// Remove: Remove a device from the registry.
// DELETE /v1/devices/{id}.
func (s *DevicesService) Remove(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/devices/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// IngestPosture: Posture ingestion for your MDM/EDR or its relay: up to 500 device reports per
// call, same fields as PUT /v1/devices.
// POST /v1/device_posture.
func (s *DevicesService) IngestPosture(ctx context.Context, params DevicesIngestPostureParams, opts ...RequestOption) (*CursorPage[DevicesListItem], error) {
	out := &CursorPage[DevicesListItem]{}
	return out, s.client.do(ctx, "POST", "/v1/device_posture", nil, params, out, opts...)
}
