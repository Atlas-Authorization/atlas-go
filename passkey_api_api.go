package atlas

import (
	"context"
	"net/url"
)

// PasskeyAPIService is the passkeyApi resource.
type PasskeyAPIService struct {
	client *Client
}

// RegistrationInit: Start registering a passkey for one of your users. Returns WebAuthn creation
// options for the browser.
// POST /v1/passkey_api/registration/init.
func (s *PasskeyAPIService) RegistrationInit(ctx context.Context, params PasskeyAPIRegistrationInitParams, opts ...RequestOption) (*PasskeyAPIRegistrationInitResult, error) {
	out := &PasskeyAPIRegistrationInitResult{}
	return out, s.client.do(ctx, "POST", "/v1/passkey_api/registration/init", nil, params, out, opts...)
}

// RegistrationFinalize: Verify the browser’s attestation and store the passkey for the user. 409
// if the credential is already registered; 403 if the authenticator is blocked by the passkey
// policy.
// POST /v1/passkey_api/registration/finalize.
func (s *PasskeyAPIService) RegistrationFinalize(ctx context.Context, params PasskeyAPIRegistrationFinalizeParams, opts ...RequestOption) (*PasskeyAPIRegistrationFinalizeResult, error) {
	out := &PasskeyAPIRegistrationFinalizeResult{}
	return out, s.client.do(ctx, "POST", "/v1/passkey_api/registration/finalize", nil, params, out, opts...)
}

// LoginInit: Start a passkey login. With user_id the user’s credentials are listed; without it the
// login is discoverable and the credential names the user.
// POST /v1/passkey_api/login/init.
func (s *PasskeyAPIService) LoginInit(ctx context.Context, params PasskeyAPILoginInitParams, opts ...RequestOption) (*PasskeyAPIRegistrationInitResult, error) {
	out := &PasskeyAPIRegistrationInitResult{}
	return out, s.client.do(ctx, "POST", "/v1/passkey_api/login/init", nil, params, out, opts...)
}

// LoginFinalize: Verify the browser’s assertion. Returns the user_id the passkey belongs to; your
// backend then starts its own session. Pass user_id to require that exact user. Challenges are
// single use.
// POST /v1/passkey_api/login/finalize.
func (s *PasskeyAPIService) LoginFinalize(ctx context.Context, params PasskeyAPILoginFinalizeParams, opts ...RequestOption) (*PasskeyAPILoginFinalizeResult, error) {
	out := &PasskeyAPILoginFinalizeResult{}
	return out, s.client.do(ctx, "POST", "/v1/passkey_api/login/finalize", nil, params, out, opts...)
}

// List: List the passkeys registered for one of your users.
// GET /v1/passkey_api/users/{userId}/passkeys.
func (s *PasskeyAPIService) List(ctx context.Context, userID string, params ListParams) (*CursorPage[PasskeyAPIRegistrationFinalizeResult], error) {
	out := &CursorPage[PasskeyAPIRegistrationFinalizeResult]{}
	return out, s.client.do(ctx, "GET", "/v1/passkey_api/users/"+url.PathEscape(userID)+"/passkeys", params.values(), nil, out)
}

// Delete: Delete one of your user’s passkeys.
// DELETE /v1/passkey_api/users/{userId}/passkeys/{id}.
func (s *PasskeyAPIService) Delete(ctx context.Context, userID string, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/passkey_api/users/"+url.PathEscape(userID)+"/passkeys/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Usage: Passkeys stored through the Passkey API on this instance (the metered quantity).
// GET /v1/passkey_api/usage.
func (s *PasskeyAPIService) Usage(ctx context.Context) (*PasskeyAPIUsageResult, error) {
	out := &PasskeyAPIUsageResult{}
	return out, s.client.do(ctx, "GET", "/v1/passkey_api/usage", nil, nil, out)
}
