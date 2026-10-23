package atlas

import (
	"context"
	"net/url"
)

// ActionsService is the /v1/actions namespace — tenant code run in the hardened
// isolate at a trigger. Secret values are write-only; a read reports only
// SecretNames.
type ActionsService struct{ client *Client }

// Action is a stored action.
type Action struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Trigger     string   `json:"trigger"`
	Code        string   `json:"code"`
	Runtime     string   `json:"runtime"`
	Enabled     bool     `json:"enabled"`
	SecretNames []string `json:"secret_names"`
	CreatedAt   int64    `json:"created_at"`
	UpdatedAt   int64    `json:"updated_at"`
}

// CreateActionParams is the body of POST /v1/actions.
type CreateActionParams struct {
	Name    string            `json:"name"`
	Trigger string            `json:"trigger"`
	Code    string            `json:"code"`
	Enabled *bool             `json:"enabled,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

// UpdateActionParams is the body of PATCH /v1/actions/:id.
type UpdateActionParams struct {
	Name    string            `json:"name,omitempty"`
	Code    string            `json:"code,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

// ActionTestEvent is the sample event a dry-run runs against.
type ActionTestEvent struct {
	User *struct {
		ID            string                 `json:"id,omitempty"`
		Email         string                 `json:"email,omitempty"`
		EmailVerified *bool                  `json:"emailVerified,omitempty"`
		Metadata      map[string]interface{} `json:"metadata,omitempty"`
		// Organizations are the user's memberships, as event.user.organizations.
		Organizations []ActionTestOrganization `json:"organizations,omitempty"`
	} `json:"user,omitempty"`
	Connection *struct {
		Strategy string `json:"strategy,omitempty"`
	} `json:"connection,omitempty"`
	Request *struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
		// Country is the ISO code event.request.country should carry.
		Country string `json:"country,omitempty"`
	} `json:"request,omitempty"`
}

// ActionTestOrganization is one membership in a sample event.
type ActionTestOrganization struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// ActionTestHTTPRequest is an outbound request the code queued with api.http
// (a dry run sends nothing). Query values in URL are masked; only header
// names are echoed.
type ActionTestHTTPRequest struct {
	Method         string   `json:"method"`
	URL            string   `json:"url"`
	HeaderNames    []string `json:"header_names"`
	HasBody        bool     `json:"has_body"`
	SaveResponseAs *string  `json:"save_response_as"`
}

// ActionTestResult is what an action produced against a sample event.
type ActionTestResult struct {
	Object            string                 `json:"object"`
	ID                string                 `json:"id"`
	Denied            bool                   `json:"denied"`
	DenyReason        *string                `json:"deny_reason"`
	AccessTokenClaims map[string]interface{} `json:"access_token_claims"`
	IDTokenClaims     map[string]interface{} `json:"id_token_claims"`
	AppMetadata       map[string]interface{} `json:"app_metadata"`
	Logs              []string               `json:"logs"`
	// HTTPRequests is what the code queued with api.http; sent only on a real
	// post_login / post_user_registration run.
	HTTPRequests []ActionTestHTTPRequest `json:"http_requests,omitempty"`
	Error        *string                 `json:"error"`
}

// ActionBindingList is the ordered binding list for a trigger.
type ActionBindingList struct {
	Object    string   `json:"object"`
	Trigger   string   `json:"trigger"`
	ActionIDs []string `json:"action_ids"`
}

// List returns the actions. GET /v1/actions.
func (s *ActionsService) List(ctx context.Context) (*ListPage[Action], error) {
	out := &ListPage[Action]{}
	return out, s.client.get(ctx, "/v1/actions", nil, out)
}

// Create creates an action. POST /v1/actions.
func (s *ActionsService) Create(ctx context.Context, params CreateActionParams, opts ...RequestOption) (*Action, error) {
	out := &Action{}
	return out, s.client.post(ctx, "/v1/actions", params, out, opts...)
}

// Get returns one action. GET /v1/actions/:id.
func (s *ActionsService) Get(ctx context.Context, id string) (*Action, error) {
	out := &Action{}
	return out, s.client.get(ctx, "/v1/actions/"+url.PathEscape(id), nil, out)
}

// Update patches an action. PATCH /v1/actions/:id.
func (s *ActionsService) Update(ctx context.Context, id string, params UpdateActionParams, opts ...RequestOption) (*Action, error) {
	out := &Action{}
	return out, s.client.patch(ctx, "/v1/actions/"+url.PathEscape(id), params, out, opts...)
}

// Delete removes an action. DELETE /v1/actions/:id.
func (s *ActionsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/actions/"+url.PathEscape(id), out, opts...)
}

// Test dry-runs an action against a sample event; nothing is persisted.
// POST /v1/actions/:id/test.
func (s *ActionsService) Test(ctx context.Context, id string, event ActionTestEvent, opts ...RequestOption) (*ActionTestResult, error) {
	out := &ActionTestResult{}
	body := map[string]ActionTestEvent{"event": event}
	return out, s.client.post(ctx, "/v1/actions/"+url.PathEscape(id)+"/test", body, out, opts...)
}

// GetBindings returns the actions bound to a trigger, in run order.
// GET /v1/actions/bindings/:trigger.
func (s *ActionsService) GetBindings(ctx context.Context, trigger string) (*ActionBindingList, error) {
	out := &ActionBindingList{}
	return out, s.client.get(ctx, "/v1/actions/bindings/"+url.PathEscape(trigger), nil, out)
}

// SetBindings replaces a trigger's ordered binding set.
// PUT /v1/actions/bindings/:trigger.
func (s *ActionsService) SetBindings(ctx context.Context, trigger string, actionIDs []string, opts ...RequestOption) (*ActionBindingList, error) {
	out := &ActionBindingList{}
	body := map[string][]string{"action_ids": actionIDs}
	return out, s.client.put(ctx, "/v1/actions/bindings/"+url.PathEscape(trigger), body, out, opts...)
}
