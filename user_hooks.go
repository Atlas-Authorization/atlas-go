package atlas

import "context"

// UserHooksService is the /v1/instance/hooks namespace: the before_user_create
// hook. Just before Atlas creates a user from a self-service sign-up, it sends
// your endpoint a signed POST (the webhook headers; verify it with
// VerifyWebhook) of type user.before_create, with data {user, strategy,
// referral}, and stamps the external_id and metadata you answer. A slow or
// failing hook never blocks a sign-up. The signing secret is write-only.
type UserHooksService struct{ client *Client }

// BeforeUserCreateHookLastCall is the last call Atlas made to the hook.
type BeforeUserCreateHookLastCall struct {
	// At is epoch ms.
	At int64 `json:"at"`
	// Status is ok, timeout, error or invalid_response.
	Status *string `json:"status"`
	Error  *string `json:"error"`
}

// BeforeUserCreateHook is GET /v1/instance/hooks/before_user_create.
type BeforeUserCreateHook struct {
	Object  string  `json:"object"`
	Enabled bool    `json:"enabled"`
	URL     *string `json:"url"`
	// SigningSecretSet says whether a signing secret is stored (it is never returned).
	SigningSecretSet bool `json:"signing_secret_set"`
	// TimeoutMS is 500-5000, default 3000.
	TimeoutMS int                           `json:"timeout_ms"`
	LastCall  *BeforeUserCreateHookLastCall `json:"last_call"`
	UpdatedAt *int64                        `json:"updated_at"`
}

// UpdateBeforeUserCreateHookParams is the body of PATCH
// /v1/instance/hooks/before_user_create: only the fields set change. Turning
// it on needs URL and SigningSecret. Clear names nullable fields to send as
// null: url, signing_secret.
type UpdateBeforeUserCreateHookParams struct {
	Enabled *bool `json:"enabled,omitempty"`
	// URL must be https (http only for localhost on a development instance).
	URL string `json:"url,omitempty"`
	// SigningSecret is write-only, 16-512 characters.
	SigningSecret string `json:"signing_secret,omitempty"`
	// TimeoutMS is 500-5000.
	TimeoutMS int      `json:"timeout_ms,omitempty"`
	Clear     []string `json:"-"`
}

// MarshalJSON sends the Clear keys as null.
func (p UpdateBeforeUserCreateHookParams) MarshalJSON() ([]byte, error) {
	type plain UpdateBeforeUserCreateHookParams
	var extra map[string]interface{}
	if len(p.Clear) > 0 {
		extra = map[string]interface{}{}
		for _, k := range p.Clear {
			extra[k] = nil
		}
	}
	return marshalWithExtra(plain(p), extra)
}

// BeforeUserCreateHookAnswer is what the hook answered to a test.
type BeforeUserCreateHookAnswer struct {
	ExternalID         *string                `json:"external_id"`
	PublicMetadata     map[string]interface{} `json:"public_metadata"`
	PrivateMetadataSet bool                   `json:"private_metadata_set"`
	UnsafeMetadata     map[string]interface{} `json:"unsafe_metadata"`
}

// BeforeUserCreateHookTest is POST /v1/instance/hooks/before_user_create/test:
// a sample draft sent to the hook; nothing is stored.
type BeforeUserCreateHookTest struct {
	OK        bool                        `json:"ok"`
	LatencyMS int                         `json:"latency_ms"`
	Answer    *BeforeUserCreateHookAnswer `json:"answer,omitempty"`
	// Error.Code is timeout, error, invalid_response or not_configured.
	Error *ReferralTestError `json:"error,omitempty"`
}

// GetBeforeUserCreate reads the hook settings and its last call.
// GET /v1/instance/hooks/before_user_create.
func (s *UserHooksService) GetBeforeUserCreate(ctx context.Context) (*BeforeUserCreateHook, error) {
	out := &BeforeUserCreateHook{}
	return out, s.client.get(ctx, "/v1/instance/hooks/before_user_create", nil, out)
}

// UpdateBeforeUserCreate patches the hook.
// PATCH /v1/instance/hooks/before_user_create.
func (s *UserHooksService) UpdateBeforeUserCreate(ctx context.Context, params UpdateBeforeUserCreateHookParams, opts ...RequestOption) (*BeforeUserCreateHook, error) {
	out := &BeforeUserCreateHook{}
	return out, s.client.patch(ctx, "/v1/instance/hooks/before_user_create", params, out, opts...)
}

// TestBeforeUserCreate sends the hook a sample draft and returns its answer.
// POST /v1/instance/hooks/before_user_create/test.
func (s *UserHooksService) TestBeforeUserCreate(ctx context.Context) (*BeforeUserCreateHookTest, error) {
	out := &BeforeUserCreateHookTest{}
	return out, s.client.post(ctx, "/v1/instance/hooks/before_user_create/test", nil, out)
}
