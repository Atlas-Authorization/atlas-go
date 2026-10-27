package atlas

import (
	"context"
	"net/url"
)

// OAuthClientProfilesService is the oauthClientProfiles resource.
type OAuthClientProfilesService struct {
	client *Client
}

// List: List the OAuth client policy profiles: the built-ins (fapi2_security,
// fapi2_message_signing, pkce_required, par_required, dpop_required) and your custom ones.
// GET /v1/oauth_client_profiles.
func (s *OAuthClientProfilesService) List(ctx context.Context, params ListParams) (*CursorPage[OAuthClientProfilesListItem], error) {
	out := &CursorPage[OAuthClientProfilesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/oauth_client_profiles", params.values(), nil, out)
}

// Set: Create or replace a custom client policy profile (rules: PKCE, PAR, sender constraint,
// signed request object, allowed auth methods and signing algorithms, https-only redirects,
// allowed claims). Built-in names are reserved.
// PUT /v1/oauth_client_profiles/{name}.
func (s *OAuthClientProfilesService) Set(ctx context.Context, name string, params OAuthClientProfilesSetParams, opts ...RequestOption) (*OAuthClientProfilesListItem, error) {
	out := &OAuthClientProfilesListItem{}
	return out, s.client.do(ctx, "PUT", "/v1/oauth_client_profiles/"+url.PathEscape(name), nil, params, out, opts...)
}

// Delete: Delete a custom client policy profile. 409 while any client is assigned it.
// DELETE /v1/oauth_client_profiles/{name}.
func (s *OAuthClientProfilesService) Delete(ctx context.Context, name string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/oauth_client_profiles/"+url.PathEscape(name), nil, nil, out, opts...)
}
