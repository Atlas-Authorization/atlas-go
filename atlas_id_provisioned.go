package atlas

import (
	"context"
	"fmt"
	"net/url"
)

// AtlasIDProvisionedAccountsService is
// /v1/platform/atlas_id_apps/{id}/provisioned_accounts: Sign in with Atlas
// test and review accounts confined to one app (reviewer logins, CI, demos).
// It needs the platform:atlas_id_apps:provision scope or the per-app
// atlas_id_apps:<app id>:provision scope. Passwords come back exactly once, on
// Create and on RotatePassword; build the client with WithSecretRecipient to
// receive them sealed (SealedPassword) and open them with OpenSealedSecret.
type AtlasIDProvisionedAccountsService struct{ client *Client }

// AtlasIDProvisionedAccountApp names an app a provisioned account may use.
type AtlasIDProvisionedAccountApp struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
}

// AtlasIDProvisionedAccountCreator is who created a provisioned account.
type AtlasIDProvisionedAccountCreator struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AtlasIDProvisionedAccount is a Sign in with Atlas test or review account,
// confined to the app(s) it was made for. Password and SealedPassword are
// present only on Create and RotatePassword, and are redacted when the value
// is printed or formatted.
type AtlasIDProvisionedAccount struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Sub is the Atlas ID subject the app sees.
	Sub           string  `json:"sub"`
	Email         *string `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Label         string  `json:"label"`
	// Kind is provisioned, test_mode or developer.
	Kind string `json:"kind"`
	// ProvisionedBy is app or staff.
	ProvisionedBy   string                         `json:"provisioned_by"`
	AppIDs          []string                       `json:"app_ids"`
	Apps            []AtlasIDProvisionedAccountApp `json:"apps"`
	AnyApp          bool                           `json:"any_app"`
	TwoFactorExempt bool                           `json:"two_factor_exempt"`
	// ExpiresAt is epoch ms; nil never expires.
	ExpiresAt          *int64                           `json:"expires_at"`
	Expired            bool                             `json:"expired"`
	DeveloperAccountID *string                          `json:"developer_account_id"`
	CreatedBy          AtlasIDProvisionedAccountCreator `json:"created_by"`
	LastSignInAt       *int64                           `json:"last_sign_in_at"`
	PasswordRotatedAt  *int64                           `json:"password_rotated_at"`
	CreatedAt          int64                            `json:"created_at"`
	UpdatedAt          int64                            `json:"updated_at"`
	// Password is returned exactly once, on create and password rotation.
	Password string `json:"password,omitempty"`
	// SealedPassword is the password sealed to the client's secret recipient.
	SealedPassword string `json:"sealed_password,omitempty"`
	Note           string `json:"note,omitempty"`
}

// String redacts the password.
func (a AtlasIDProvisionedAccount) String() string {
	email := ""
	if a.Email != nil {
		email = *a.Email
	}
	return fmt.Sprintf("AtlasIDProvisionedAccount{ID:%q Email:%q Label:%q Kind:%q Password:[redacted]}", a.ID, email, a.Label, a.Kind)
}

// GoString redacts the password for %#v.
func (a AtlasIDProvisionedAccount) GoString() string { return a.String() }

// AtlasIDProvisionedAccountList lists an app's accounts.
type AtlasIDProvisionedAccountList struct {
	Object string                      `json:"object"`
	Data   []AtlasIDProvisionedAccount `json:"data"`
	// Limit is the account-wide cap (default 25).
	Limit int `json:"limit"`
	// Total is the test accounts the account holds across all its apps.
	Total int `json:"total"`
}

// CreateAtlasIDProvisionedAccountParams is the body of POST
// /v1/platform/atlas_id_apps/:id/provisioned_accounts. The Password field is
// redacted when printed.
type CreateAtlasIDProvisionedAccountParams struct {
	Email string `json:"email"`
	// Label says what the account is for, e.g. "app-store reviewer".
	Label string `json:"label"`
	// Password is at least 12 characters. Leave it empty and Atlas generates
	// one. It is returned once either way.
	Password string `json:"password,omitempty"`
	// EmailVerified defaults to true.
	EmailVerified *bool `json:"email_verified,omitempty"`
	// TwoFactorExempt never asks for a second factor on this app. A risk you
	// opt into.
	TwoFactorExempt bool `json:"two_factor_exempt,omitempty"`
	// ExpiresAt is epoch ms or an ISO 8601 string (int64 or string); nil for a
	// non-expiring account.
	ExpiresAt interface{} `json:"expires_at,omitempty"`
}

// String redacts the password.
func (p CreateAtlasIDProvisionedAccountParams) String() string {
	return fmt.Sprintf("CreateAtlasIDProvisionedAccountParams{Email:%q Label:%q Password:[redacted]}", p.Email, p.Label)
}

// GoString redacts the password for %#v.
func (p CreateAtlasIDProvisionedAccountParams) GoString() string { return p.String() }

// RotateAtlasIDProvisionedPasswordParams is the body of POST
// .../provisioned_accounts/:acct/password. Password is redacted when printed.
type RotateAtlasIDProvisionedPasswordParams struct {
	// Password is at least 12 characters; empty means Atlas generates one.
	Password string `json:"password,omitempty"`
}

// String redacts the password.
func (p RotateAtlasIDProvisionedPasswordParams) String() string {
	return "RotateAtlasIDProvisionedPasswordParams{Password:[redacted]}"
}

// GoString redacts the password for %#v.
func (p RotateAtlasIDProvisionedPasswordParams) GoString() string { return p.String() }

// AtlasIDProvisionedAccountDeleted acknowledges a removal.
type AtlasIDProvisionedAccountDeleted struct {
	Object        string `json:"object"`
	ID            string `json:"id"`
	Deleted       bool   `json:"deleted"`
	SessionsEnded int    `json:"sessions_ended"`
}

func provisionedPath(appID string) string {
	return "/v1/platform/atlas_id_apps/" + url.PathEscape(appID) + "/provisioned_accounts"
}

// List returns the app's accounts. GET .../provisioned_accounts.
func (s *AtlasIDProvisionedAccountsService) List(ctx context.Context, appID string) (*AtlasIDProvisionedAccountList, error) {
	out := &AtlasIDProvisionedAccountList{}
	return out, s.client.platGet(ctx, provisionedPath(appID), nil, out)
}

// Create makes a test or review account; the password is in this response
// only. POST .../provisioned_accounts.
func (s *AtlasIDProvisionedAccountsService) Create(ctx context.Context, appID string, params CreateAtlasIDProvisionedAccountParams, opts ...RequestOption) (*AtlasIDProvisionedAccount, error) {
	out := &AtlasIDProvisionedAccount{}
	return out, s.client.platPost(ctx, provisionedPath(appID), params, out, opts...)
}

// Get fetches one account. GET .../provisioned_accounts/:acct.
func (s *AtlasIDProvisionedAccountsService) Get(ctx context.Context, appID, accountID string) (*AtlasIDProvisionedAccount, error) {
	out := &AtlasIDProvisionedAccount{}
	return out, s.client.platGet(ctx, provisionedPath(appID)+"/"+url.PathEscape(accountID), nil, out)
}

// Remove deletes the account and ends every session and grant it holds.
// DELETE .../provisioned_accounts/:acct.
func (s *AtlasIDProvisionedAccountsService) Remove(ctx context.Context, appID, accountID string, opts ...RequestOption) (*AtlasIDProvisionedAccountDeleted, error) {
	out := &AtlasIDProvisionedAccountDeleted{}
	return out, s.client.platDel(ctx, provisionedPath(appID)+"/"+url.PathEscape(accountID), out, opts...)
}

// RotatePassword sets a new password (yours, or one Atlas generates), returned
// once. POST .../provisioned_accounts/:acct/password.
func (s *AtlasIDProvisionedAccountsService) RotatePassword(ctx context.Context, appID, accountID string, params RotateAtlasIDProvisionedPasswordParams, opts ...RequestOption) (*AtlasIDProvisionedAccount, error) {
	out := &AtlasIDProvisionedAccount{}
	return out, s.client.platPost(ctx, provisionedPath(appID)+"/"+url.PathEscape(accountID)+"/password", params, out, opts...)
}

// --- Platform domains -------------------------------------------------------

// PlatformDomainsService is /v1/platform/domains: domains the account
// verified by DNS. They gate test sign-in mode and the test-account domain
// restriction.
type PlatformDomainsService struct{ client *Client }

// AccountDomainVerification is the TXT record to publish.
type AccountDomainVerification struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AccountDomain is a domain the account claimed; verified ones gate test
// sign-in mode.
type AccountDomain struct {
	Object        string                    `json:"object"`
	ID            string                    `json:"id"`
	Domain        string                    `json:"domain"`
	Verified      bool                      `json:"verified"`
	VerifiedAt    *int64                    `json:"verified_at"`
	LastCheckedAt *int64                    `json:"last_checked_at"`
	Verification  AccountDomainVerification `json:"verification"`
	// RecordFound is set by Check: whether the TXT record was seen.
	RecordFound *bool `json:"record_found,omitempty"`
}

// AccountDomainList lists the account's claimed domains.
type AccountDomainList struct {
	Object string          `json:"object"`
	Data   []AccountDomain `json:"data"`
	// VerifiedDomains are the domains that passed verification.
	VerifiedDomains []string `json:"verified_domains"`
}

// List returns the account's domains. GET /v1/platform/domains.
func (s *PlatformDomainsService) List(ctx context.Context) (*AccountDomainList, error) {
	out := &AccountDomainList{}
	return out, s.client.platGet(ctx, "/v1/platform/domains", nil, out)
}

// Claim claims a domain and returns the TXT record to publish.
// POST /v1/platform/domains.
func (s *PlatformDomainsService) Claim(ctx context.Context, domain string, opts ...RequestOption) (*AccountDomain, error) {
	out := &AccountDomain{}
	return out, s.client.platPost(ctx, "/v1/platform/domains", map[string]string{"domain": domain}, out, opts...)
}

// Check looks for the TXT record and verifies the domain.
// POST /v1/platform/domains/:id/verify.
func (s *PlatformDomainsService) Check(ctx context.Context, id string, opts ...RequestOption) (*AccountDomain, error) {
	out := &AccountDomain{}
	return out, s.client.platPost(ctx, "/v1/platform/domains/"+url.PathEscape(id)+"/verify", nil, out, opts...)
}

// Verify is an alias for Check.
func (s *PlatformDomainsService) Verify(ctx context.Context, id string, opts ...RequestOption) (*AccountDomain, error) {
	return s.Check(ctx, id, opts...)
}

// Remove deletes a claimed domain. DELETE /v1/platform/domains/:id.
func (s *PlatformDomainsService) Remove(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.platDel(ctx, "/v1/platform/domains/"+url.PathEscape(id), out, opts...)
}
