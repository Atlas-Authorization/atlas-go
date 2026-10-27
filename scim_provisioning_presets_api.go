package atlas

import (
	"context"
)

// SCIMProvisioningPresetsService is the scimProvisioningPresets resource.
type SCIMProvisioningPresetsService struct {
	client *Client
}

// List: List the pre-built outbound provisioning targets (Slack, GitHub, Zoom, Salesforce,
// Atlassian) with their base-URL template and required parameters.
// GET /v1/scim_provisioning_presets.
func (s *SCIMProvisioningPresetsService) List(ctx context.Context, params ListParams) (*SCIMProvisioningPresetsListResult, error) {
	out := &SCIMProvisioningPresetsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/scim_provisioning_presets", params.values(), nil, out)
}
