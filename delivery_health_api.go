package atlas

import (
	"context"
	"net/url"
)

// Get: Delivery health of one target. 404 until a delivery to it has been recorded.
// GET /v1/delivery_health/{kind}/{id}.
func (s *DeliveryService) Get(ctx context.Context, kind string, id string) (*DeliveryHealthGetResult, error) {
	out := &DeliveryHealthGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/delivery_health/"+url.PathEscape(kind)+"/"+url.PathEscape(id), nil, nil, out)
}
