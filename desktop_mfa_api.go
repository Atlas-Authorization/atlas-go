package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// DesktopMFAService is the desktopMfa resource.
type DesktopMFAService struct {
	client *Client
}

// GetPolicy: The desktop-login MFA policy: who must pass a second factor at OS login, the allowed
// factors and the offline grace window.
// GET /v1/desktop_mfa/policy.
func (s *DesktopMFAService) GetPolicy(ctx context.Context) (*DesktopMFAGetPolicyResult, error) {
	out := &DesktopMFAGetPolicyResult{}
	return out, s.client.do(ctx, "GET", "/v1/desktop_mfa/policy", nil, nil, out)
}

// UpdatePolicy: Change the desktop-login MFA policy. Send only the fields to change. `applies_to:
// "selected"` needs at least one user or organization while enabled.
// PUT /v1/desktop_mfa/policy.
func (s *DesktopMFAService) UpdatePolicy(ctx context.Context, params DesktopMFAUpdatePolicyParams, opts ...RequestOption) (*DesktopMFAGetPolicyResult, error) {
	out := &DesktopMFAGetPolicyResult{}
	return out, s.client.do(ctx, "PUT", "/v1/desktop_mfa/policy", nil, params, out, opts...)
}

// CreateEnrolmentCode: Issue a single-use code a user types into the workstation agent to enrol
// it. Valid for `expires_in_minutes` (default 60, at most 7 days). Shown once.
// POST /v1/desktop_mfa/enrolment_codes.
func (s *DesktopMFAService) CreateEnrolmentCode(ctx context.Context, params DesktopMFACreateEnrolmentCodeParams, opts ...RequestOption) (*DesktopMFACreateEnrolmentCodeResult, error) {
	out := &DesktopMFACreateEnrolmentCodeResult{}
	return out, s.client.do(ctx, "POST", "/v1/desktop_mfa/enrolment_codes", nil, params, out, opts...)
}

// DesktopMFAListDevicesQuery holds the query parameters of DesktopMFAService.ListDevices.
type DesktopMFAListDevicesQuery struct {
	// Only this user's workstations.
	UserID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q DesktopMFAListDevicesQuery) values() url.Values {
	v := url.Values{}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// ListDevices: List enrolled workstations, optionally for one `user_id`.
// GET /v1/desktop_mfa/devices.
func (s *DesktopMFAService) ListDevices(ctx context.Context, query DesktopMFAListDevicesQuery) (*CursorPage[DesktopMFAListDevicesItem], error) {
	out := &CursorPage[DesktopMFAListDevicesItem]{}
	return out, s.client.do(ctx, "GET", "/v1/desktop_mfa/devices", query.values(), nil, out)
}

// GetDevice: Read one workstation with the offline verifiers issued to it.
// GET /v1/desktop_mfa/devices/{id}.
func (s *DesktopMFAService) GetDevice(ctx context.Context, id string) (*DesktopMFAGetDeviceResult, error) {
	out := &DesktopMFAGetDeviceResult{}
	return out, s.client.do(ctx, "GET", "/v1/desktop_mfa/devices/"+url.PathEscape(id), nil, nil, out)
}

// DeleteDevice: Delete a workstation and its device key.
// DELETE /v1/desktop_mfa/devices/{id}.
func (s *DesktopMFAService) DeleteDevice(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/desktop_mfa/devices/"+url.PathEscape(id), nil, nil, out, opts...)
}

// RevokeDevice: Revoke a workstation. Its next call is refused with `device_status: revoked` and
// it wipes its offline cache; offline unlock stops working at the latest when the cached verifier
// expires.
// POST /v1/desktop_mfa/devices/{id}/revoke.
func (s *DesktopMFAService) RevokeDevice(ctx context.Context, id string, opts ...RequestOption) (*DesktopMFAListDevicesItem, error) {
	out := &DesktopMFAListDevicesItem{}
	return out, s.client.do(ctx, "POST", "/v1/desktop_mfa/devices/"+url.PathEscape(id)+"/revoke", nil, nil, out, opts...)
}

// RevokeOfflineCache: Void every offline verifier issued to the workstation without revoking it.
// It receives a fresh one on its next sync.
// POST /v1/desktop_mfa/devices/{id}/revoke_offline_cache.
func (s *DesktopMFAService) RevokeOfflineCache(ctx context.Context, id string, opts ...RequestOption) (*DesktopMFAListDevicesItem, error) {
	out := &DesktopMFAListDevicesItem{}
	return out, s.client.do(ctx, "POST", "/v1/desktop_mfa/devices/"+url.PathEscape(id)+"/revoke_offline_cache", nil, nil, out, opts...)
}
