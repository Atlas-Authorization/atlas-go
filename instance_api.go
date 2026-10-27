package atlas

import (
	"context"
	"net/url"
)

// InstanceIntegrationsService is the instance integrations group of InstanceService.
type InstanceIntegrationsService struct {
	client *Client
}

// RotateEventsSecret: Rotate the signing secret of the integration's event receiver. The new
// secret is revealed exactly once. By default (`overlap_seconds` 0) the old secret stops signing
// at once. With `overlap_seconds` (at most 604800 = 7 days) every delivery carries two signatures
// in `Atlas-Signature` (`v1,<new> v1,<old>`, the new one first), so the service verifies with
// either secret while it deploys the new one; after that only the new secret signs.
// `previous_secret_expires_at` says when the old secret stops signing (epoch ms), or null when it
// already has. Audited as integration.<id>.events_secret_rotated. 404 when the integration has no
// event receiver.
// POST /v1/instance/integrations/{product}/events_secret/rotate.
func (s *InstanceIntegrationsService) RotateEventsSecret(ctx context.Context, product string, params InstanceIntegrationsRotateEventsSecretParams, opts ...RequestOption) (*InstanceIntegrationsRotateEventsSecretResult, error) {
	out := &InstanceIntegrationsRotateEventsSecretResult{}
	return out, s.client.do(ctx, "POST", "/v1/instance/integrations/"+url.PathEscape(product)+"/events_secret/rotate", nil, params, out, opts...)
}
