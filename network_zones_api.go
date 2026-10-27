package atlas

import (
	"context"
	"net/url"
)

// NetworkZonesService is the networkZones resource.
type NetworkZonesService struct {
	client *Client
}

// List: List reusable network zones — named sets of CIDRs, countries, ASNs and anonymizer classes
// (tor, datacenter, vpn) that network ACL rules reference by zone_id.
// GET /v1/network_zones.
func (s *NetworkZonesService) List(ctx context.Context, params ListParams) (*CursorPage[NetworkZonesListItem], error) {
	out := &CursorPage[NetworkZonesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/network_zones", params.values(), nil, out)
}

// Create: Create a network zone. `name` is unique per instance; `cidrs`, `countries` (ISO
// alpha-2), `asns` and `anonymizers` are unioned (any match = in the zone). Malformed entries are
// refused.
// POST /v1/network_zones.
func (s *NetworkZonesService) Create(ctx context.Context, params NetworkZonesCreateParams, opts ...RequestOption) (*NetworkZonesListItem, error) {
	out := &NetworkZonesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/network_zones", nil, params, out, opts...)
}

// Get: Read one network zone.
// GET /v1/network_zones/{id}.
func (s *NetworkZonesService) Get(ctx context.Context, id string) (*NetworkZonesListItem, error) {
	out := &NetworkZonesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/network_zones/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update a network zone. Sending any of cidrs/countries/asns/anonymizers replaces that
// list; omitted lists keep their value.
// PATCH /v1/network_zones/{id}.
func (s *NetworkZonesService) Update(ctx context.Context, id string, params NetworkZonesCreateParams, opts ...RequestOption) (*NetworkZonesListItem, error) {
	out := &NetworkZonesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/network_zones/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a network zone. The network ACL rules that reference it are deleted with it.
// DELETE /v1/network_zones/{id}.
func (s *NetworkZonesService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/network_zones/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// Check: What-if: does an IP address fall inside this zone? Returns the resolved country / ASN /
// Tor / datacenter facts alongside the answer. Facts the instance has no IP-intelligence data for
// are null and never match.
// POST /v1/network_zones/{id}/check.
func (s *NetworkZonesService) Check(ctx context.Context, id string, params NetworkZonesCheckParams, opts ...RequestOption) (*NetworkZonesCheckResult, error) {
	out := &NetworkZonesCheckResult{}
	return out, s.client.do(ctx, "POST", "/v1/network_zones/"+url.PathEscape(id)+"/check", nil, params, out, opts...)
}
