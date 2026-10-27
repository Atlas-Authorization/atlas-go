package atlas

import (
	"context"
	"net/url"
)

// RunCardAction: Run a card action. revoke_sessions signs the user out of every device (their
// sessions end, back-channel logouts go out) and is audited with the agent the integration names.
// Partner link with sessions:write, or the secret key.
// POST /v1/integrations/{integration}/card/actions/{action}.
func (s *IntegrationsService) RunCardAction(ctx context.Context, integration string, action string, params IntegrationsRunCardActionParams, opts ...RequestOption) (*IntegrationsRunCardActionResult, error) {
	out := &IntegrationsRunCardActionResult{}
	return out, s.client.do(ctx, "POST", "/v1/integrations/"+url.PathEscape(integration)+"/card/actions/"+url.PathEscape(action), nil, params, out, opts...)
}
