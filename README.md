# atlas-go

The official Go backend SDK for **Atlas** — an idiomatic, typed client over the
secret-key (`sk_`) Backend API (BAPI). It is the Go peer of the TypeScript SDK
(`@atlas/backend`, `packages/backend/src/client`): the same namespaces, the same
snake_case wire types, the same `{ errors: [...] }` error envelope.

- Standard library only (`net/http` + `encoding/json`) — no dependencies.
- One service per BAPI area, each method taking a `context.Context` and typed
  params, returning a typed struct and an `error`.
- A first-class `*APIError` recoverable with `errors.As`.
- A cursor `Iterator` for paginated endpoints and an `Idempotency-Key` option on
  creates.

## Install

```sh
go get github.com/Atlas-Authorization/atlas-go
```

```go
import atlas "github.com/Atlas-Authorization/atlas-go"
```

Requires Go 1.21+.

## Quick start

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	atlas "github.com/Atlas-Authorization/atlas-go"
)

func main() {
	// Base URL defaults to https://api.atlasauth.net; override for self-hosted.
	c := atlas.New(
		"sk_live_...",
		atlas.WithBaseURL("https://api.atlasauth.net"),
	)
	ctx := context.Background()

	// Create a user.
	user, err := c.Users.Create(ctx, atlas.CreateUserParams{
		EmailAddress: "ada@example.com",
		FirstName:    "Ada",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created", user.ID)

	// List organizations (one cursor page).
	orgs, err := c.Organizations.List(ctx, atlas.ListParams{Limit: 20})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("first page: %d orgs, has_more=%t\n", len(orgs.Data), orgs.HasMore)
}
```

## Configuration

`New(secretKey string, opts ...Option)` accepts:

- `WithBaseURL(url string)` — override the BAPI origin (`BAPI_ORIGIN`).
- `WithHTTPClient(*http.Client)` — inject a client for timeouts, proxies, or a
  test transport.
- `WithStrict(bool)` — send `Atlas-Strict` on every write (see
  [Strict request bodies](#strict-request-bodies)).
- `WithUnknownFieldsHandler(fn)` — be told about body fields an endpoint ignored.
- `WithPlatformKey("psk_...")` — the platform key used by `c.Platform`
  (see [Platform](#platform-apps-and-sign-in-with-atlas)).

The secret key is sent as `Authorization: Bearer sk_...` on every request and is
never placed in a URL.

## Error handling

Every method returns `*APIError` on a non-2xx response. It carries the HTTP
status and the full, ordered error envelope. Recover it with `errors.As` and
branch on the stable `code`:

```go
_, err := c.Users.Create(ctx, atlas.CreateUserParams{EmailAddress: "dup@example.com"})

var apiErr *atlas.APIError
if errors.As(err, &apiErr) {
	switch {
	case apiErr.Code() == "FORM_IDENTIFIER_EXISTS":
		// param names the offending field, e.g. "email_address".
		fmt.Println("already registered:", apiErr.Errors[0].Param)
	case apiErr.IsNotFound():
		fmt.Println("gone")
	default:
		fmt.Printf("status %d: %s\n", apiErr.Status, apiErr.Code())
	}
}
```

`apiErr.HasCode("...")` checks any error in the envelope; `apiErr.Errors[i].Meta`
carries extras such as a rate limit's `retry_after`.

## API key spend caps

Give an end-user API key caps per unit and period (`request`, `day`, `month` or
`total`), then meter what each call costs. A debit that would exceed a cap records
nothing and returns `Allowed=false`; it is not an error.

```go
key, err := c.APIKeys.Create(ctx, atlas.CreateAPIKeyParams{
	SubjectType: "user",
	SubjectID:   "user_123",
	Limits: []atlas.APIKeyLimit{
		{Unit: "requests", Amount: 1000, Period: atlas.APIKeyLimitPeriodDay},
		{Unit: "usd_cents", Amount: 5000, Period: atlas.APIKeyLimitPeriodMonth},
	},
})

debit, err := c.APIKeys.RecordUsage(ctx, key.ID, atlas.RecordAPIKeyUsageParams{
	Unit: "usd_cents", Amount: 12,
	IdempotencyKey: "req_8f2c", // a retry returns the first outcome without counting again
})
if err == nil && !debit.Allowed {
	// debit.Code == atlas.ErrCodeLimitExceeded; debit.Exceeded lists the caps
}

usage, err := c.APIKeys.GetUsage(ctx, key.ID) // Used / Remaining / ResetsAt per cap
_, err = c.APIKeys.Update(ctx, key.ID, atlas.UpdateAPIKeyParams{ClearLimits: true})
```

`APIKeys.Verify` also returns the key's `Name`, `Scopes`, `Constraints`, `Limits`
and current `Usage`.

## Session keep-alive

If your app loads the Atlas frontend SDK only on some pages, time spent on the
other pages can count as inactivity. Touch the session from your backend to
slide its inactivity window:

```go
s, err := c.Sessions.Touch(ctx, sessionID)
// s.IdleExpiresAt is the new deadline; s.Extended is false when a touch in the last minute already did it
```

A touch never extends past the session's absolute expiry and never revives an
ended session (409 `SESSION_REVOKED`, `SESSION_IDLE_EXPIRED` or
`SESSION_EXPIRED`). It writes at most once a minute, so calling it on every
request is safe.

`Users.ListSessions` items carry the same `IdleExpiresAt`,
`LastActiveOrganizationID` and `ImpersonatedBy` fields as `Sessions.Get`.

## Logout without a confirmation page

A first-party OAuth client can skip the logout confirmation page: RP-initiated
logout (`/oauth2/logout`) with its `client_id` and an exactly registered
`post_logout_redirect_uri` then ends the session and redirects straight back
with `state`. A third-party client is refused with `422 VALIDATION_FAILED`.

```go
skip := true
_, err := c.OAuthClients.Update(ctx, clientID, atlas.UpdateOAuthClientParams{SkipLogoutConfirmation: &skip})
```

## Cookie settings link

Add a "cookie settings" link to the hosted pages that reopens your consent
manager. It needs a preset or at least one attribute:

```go
cc, err := c.Instance.SetCookieConsent(ctx, atlas.SetCookieConsentParams{
	ScriptURL: "https://consent.cookiebot.com/uc.js",
	SiteID:    "your-cbid",
	SettingsLink: &atlas.CookieSettingsLinkInput{
		Label:  "Cookie settings",
		Preset: atlas.CookieSettingsLinkPresetCookiebot,
	},
})
// cc.SettingsLink.RenderedAttributes: your attributes plus the preset's trigger
```

## Removing the email provider

Removing the email provider is refused with `409 EMAIL_PROVIDER_IN_USE` while
email-dependent features (email codes, email links, email verification,
password reset) are on and nothing else would deliver email; the error's
`Meta["features"]` lists them. Force it if you mean it:

```go
_, err := c.Messaging.DeleteChannel(ctx, "email")
if errors.As(err, &apiErr) && apiErr.HasCode(atlas.ErrCodeEmailProviderInUse) {
	_, err = c.Messaging.DeleteChannelWithParams(ctx, "email", atlas.DeleteMessagingProviderParams{Force: true})
}
```

## Pagination

Cursor-paginated list methods (`Users.List`, `Organizations.List`,
`Invitations.List`, `AuditLogs.List`) return a `*CursorPage[T]`
(`Data`, `HasMore`, `NextCursor`). Walk every page with `Paginate`:

```go
it := atlas.Paginate(func(cursor string) (*atlas.CursorPage[atlas.User], error) {
	return c.Users.List(ctx, atlas.ListParams{Limit: 100, StartingAfter: cursor})
})
for it.Next() {
	u := it.Item()
	fmt.Println(u.ID)
}
if err := it.Err(); err != nil {
	log.Fatal(err)
}

// Or collect the whole set:
all, err := atlas.Paginate(func(cursor string) (*atlas.CursorPage[atlas.User], error) {
	return c.Users.List(ctx, atlas.ListParams{StartingAfter: cursor})
}).Collect()
```

## Idempotency

Pass `WithIdempotencyKey` to any create/mutation to de-duplicate retries
server-side (§9.1); it sets the `Idempotency-Key` header:

```go
org, err := c.Organizations.Create(ctx,
	atlas.CreateOrganizationParams{Name: "Acme", Slug: "acme", CreatedBy: user.ID},
	atlas.WithIdempotencyKey("provisioning-run-42"),
)
```

## Strict request bodies

By default, a body field an endpoint does not accept is ignored and named in the
`Atlas-Unknown-Fields` response header. Turn on strict mode to have such a write
refused with `422 UNKNOWN_FIELD` before anything is saved, or register a handler
to log the ignored fields:

```go
c := atlas.New("sk_live_...",
	atlas.WithStrict(true),
	atlas.WithUnknownFieldsHandler(func(method, path string, fields []string) {
		log.Printf("%s %s ignored fields: %v", method, path, fields)
	}),
)

// Override per call: opt one write out of (or into) strict mode.
_, err := c.Roles.Create(ctx, params, atlas.StrictBody(false))
if errors.As(err, &apiErr) && apiErr.HasCode(atlas.ErrCodeUnknownField) {
	fmt.Println("unknown field:", apiErr.Errors[0].Param)
}
```

Every write method accepts `...atlas.RequestOption` (`WithIdempotencyKey`,
`StrictBody`, `WithHeader`).

Named error codes are exported as constants: `ErrCodeUnknownField`,
`ErrCodeEmailDeliveryNotConfigured`, `ErrCodeEmailProviderRequired`,
`ErrCodeEmailProviderInUse`, `ErrCodePlanInUse`, `ErrCodeWrongKeySurface`,
`ErrCodeInvalidKey`.

## Platform: apps and Sign in with Atlas

Platform calls use a platform key (`psk_...`). Use `NewPlatform` for a
platform-only client, or add `WithPlatformKey` to a regular one:

```go
p := atlas.NewPlatform("psk_live_...")

app, err := p.Platform.AtlasIDApps.Create(ctx, atlas.CreateAtlasIDAppParams{
	Name:                   "Acme",
	RedirectURIs:           []string{"https://acme.example/callback"},
	PostLogoutRedirectURIs: []string{"https://acme.example/"},
	BackchannelLogoutURI:   "https://acme.example/logout/backchannel",
})
// app.ClientSecret is shown once.
```

`c.Platform.Apps` provisions and manages apps (instances, secret rotation with
overlap, archive, transfer, claim); `c.Platform.AtlasIDApps` manages Sign in with
Atlas apps (logout URIs, branding, page text, design, secret rotation, design
preview); `c.Platform.DesignAssets` uploads and lists the images those designs use.

## Sign-in page design

```go
d, err := c.Design.Get(ctx)                     // stored + resolved design
_, err = c.Design.Update(ctx, atlas.DesignPatch{ // partial change; nil removes a setting
	"palette": map[string]interface{}{"accent": "#4f46e5"},
})
logo, _ := os.ReadFile("logo.png")
asset, err := c.Design.Assets.Upload(ctx, logo, "image/png", "logo")
```

Organizations have their own override layered over the instance design
(`c.Design.GetOrganization`, `ReplaceOrganization`, `UpdateOrganization`).
`c.Instance.Preflight(ctx)` checks your setup in one call and returns typed
findings (severity, code, message, fix, subject).

## Domain moves, logout fan-out and managed email

```go
// Move every URL from the old origin to the new one. DryRun first shows the diff.
preview, err := atlas.Instance.MoveOrigin(ctx, atlasauth.OriginMoveParams{From: "https://old.example.com", To: "https://example.com", DryRun: true})
if err != nil {
	return err
}
for _, c := range preview.Changes {
	fmt.Println(c.Object, c.Field, c.Before, "->", c.After)
}

// Send the same logout_token your OIDC apps get to another service.
_, err = atlas.LogoutNotifyEndpoints.Create(ctx, atlasauth.CreateLogoutNotifyEndpointParams{URL: "https://api.example.com/atlas/logout"})

// Set your domain up on your own Resend or Brevo account, then publish the returned DNS records.
managed, err := atlas.Messaging.CreateManagedEmail(ctx, atlasauth.CreateManagedEmailParams{
	FromAddress: "Acme <no-reply@example.com>",
	Transport:   "resend",
	Config:      &atlasauth.ManagedEmailProviderKey{APIKey: os.Getenv("RESEND_API_KEY")},
})

// A development instance can send sign-in emails through your provider without a verified domain.
_, err = atlas.Messaging.EnableDevelopmentEmail(ctx, atlasauth.EnableDevelopmentEmailParams{ProviderID: "mp_123"})
```

## OAuth client secret rotation

The previous secret keeps working for the overlap (default 24 hours, at most 7 days), so you can deploy the
new one without downtime. Pass `0` to revoke it now, for example after a leak:

```go
overlap := 3600
rotated, err := atlas.OAuthClients.RotateSecretWithParams(ctx, clientID, atlasauth.RotateOAuthClientSecretParams{OverlapSeconds: &overlap})
// rotated.ClientSecret is shown once; rotated.PreviousSecretExpiresAt says when the old one stops.
```

## Webhooks

`VerifyWebhook` accepts an `atlas-signature` header that carries several signatures separated by spaces
(`v1,<sig> v1,<sig>`). While an endpoint secret rotates, Atlas may sign each delivery with the old and the
new secret; the delivery verifies when any one signature matches.

A rotation stops the old secret at once by default. Pass an overlap (at most 7 days) to keep it signing each
delivery next to the new one while you deploy; choose an overlap only once every receiver accepts several
signatures:

```go
overlap := 3600
rotated, err := atlas.Webhooks.Endpoints.RotateSecretWithParams(ctx, endpointID, atlasauth.RotateWebhookSecretParams{OverlapSeconds: &overlap})
// rotated.PreviousSecretExpiresAt says when the old secret stops signing.
```

## Trusted reverse proxy

If a reverse proxy serves the Frontend API from your own origin, give it a proxy secret. It sends the secret in
`X-Atlas-Proxy-Secret` and the browser's IP in `X-Atlas-Client-IP`; Atlas then uses that IP for rate limits,
lockout, risk signals and audit logs.

```go
created, err := atlas.InstanceSecurity.CreateProxySecret(ctx, atlasauth.CreateProxySecretParams{})
// created.Secret is shown once; store it in your proxy's environment.
state, err := atlas.InstanceSecurity.ProxySecret(ctx) // Set, CreatedAt, PreviousExpiresAt (never the secret)
overlap := 3600
_, err = atlas.InstanceSecurity.CreateProxySecret(ctx, atlasauth.CreateProxySecretParams{OverlapSeconds: &overlap}) // rotate
_, err = atlas.InstanceSecurity.DeleteProxySecret(ctx)
```

Platform rotations take an overlap too: `Platform.Apps.RotateInstanceSecretWithParams` (default 72 hours),
`Platform.AtlasIDApps.RotateSecretWithParams` (default 24 hours) and
`Platform.AtlasIDApps.RotateWebhookSecretWithParams` (default 0).

With a platform key, `Platform.AtlasIDApps.FindUsers(ctx, id, email)` answers a privacy request for one app,
`RevokeGrant` revokes one person's approval, and `Platform.AtlasIDPublisher` claims and verifies the publisher name
shown on consent screens.

## Referral attribution

With referral attribution on, Atlas reports every interactive sign-up to your referral platform before
`user.created` is sent. `User` gains `Referral` (who referred them, or nil), `ReferralCode` and `ReferralLink`.

```go
on := true
_, err := c.Referrals.Update(ctx, atlas.UpdateReferralSettingsParams{
	Enabled:       &on,
	Provider:      "webhook", // the Atlas referral protocol; or a built-in vendor adapter
	EndpointURL:   "https://referrals.example.com/atlas",
	SigningSecret: os.Getenv("REFERRAL_SIGNING_SECRET"),
	Clear:         []string{"link_template"}, // sent as null
})
test, err := c.Referrals.Test(ctx) // OK, HTTPStatus, LatencyMS, Error
failed, err := c.Referrals.ListCalls(ctx, atlas.ListReferralCallsParams{Status: "failed"})
_, err = c.Referrals.RetryCall(ctx, failed.Data[0].ID)

_, err = c.Users.Update(ctx, "user_123", atlas.UpdateUserParams{ReferralCode: "ada-1"}) // 409 REFERRAL_CODE_TAKEN
_, err = c.Users.FlagReferral(ctx, "user_123", atlas.FlagReferralParams{Reason: "self-referral"})
```

Enabling without what the provider needs is `422 REFERRALS_NOT_CONFIGURED`. A late answer from the platform
arrives as the `user.referral_attributed` webhook (`UserReferralAttributedEvent`).

A referral platform that implements the Atlas referral protocol verifies Atlas's calls with
`VerifyReferralRequest`. Every call is a POST signed like a webhook, and its JSON body says which operation
it is (`op`: `signup`, `erase`, `export`, `partner`, `signal`). Pass the path the call arrived on: a signed
body whose `op` does not match the endpoint is `ErrReferralOpMismatch`.

```go
body, _ := io.ReadAll(r.Body)
req, err := atlas.VerifyReferralRequest(body, r.Header, secret, &atlas.ReferralVerifyOptions{Path: r.URL.Path})
if err != nil {
	w.WriteHeader(http.StatusUnauthorized)
	return
}
switch req.Op {
case atlas.ReferralOpSignup:
	_ = json.NewEncoder(w).Encode(atlas.ReferralSignupResponse{Referral: match(req.Signup)})
case atlas.ReferralOpExport:
	if req.Test {
		w.WriteHeader(http.StatusNotFound)
	}
}
```

A retry of one call keeps its `DeliveryID`; sign-ups are idempotent on `customerRef`, so answer a retry the
same way.

## Back-channel logout

Verify the `logout_token` Atlas posts to your `backchannel_logout_uri`
(OIDC Back-Channel Logout 1.0), then end the matching local sessions:

```go
v, err := atlas.NewLogoutTokenVerifier(atlas.LogoutTokenVerifierOptions{
	JWKSURL:     "https://atlasauth.net/.well-known/jwks.json",
	Issuer:      "https://atlasauth.net",
	ClientID:    "your-client-id",
	ReplayGuard: &atlas.MemoryReplayGuard{}, // use a shared store with several servers
})
if err != nil {
	log.Fatal(err)
}

http.HandleFunc("/logout/backchannel", func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := v.VerifyRequest(r) // reads the logout_token form field
	if err != nil {
		http.Error(w, "invalid logout token", http.StatusBadRequest)
		return
	}
	if claims.Sid != "" {
		endSessionsBySid(claims.Sid) // your session store
	} else {
		endSessionsBySubject(claims.Sub)
	}
	w.WriteHeader(http.StatusOK)
})
```

The verifier accepts RS256 only and checks the issuer, audience, `iat`, `exp`,
`jti`, the back-channel logout event, `sid`/`sub`, the absence of `nonce`, and
`typ: logout+jwt`. With a `ReplayGuard`, a token id seen before is refused.

## Token verification

Backend services verify a session JWT locally against the instance JWKS — fast,
offline, and correct within the short token lifetime — without an outbound call
per request. `AtlasBackend` caches the JWKS in-process and refetches on an unknown
`kid` at most once a minute (the rate limit is a security property, not politeness).

```go
backend, err := atlas.NewAtlasBackend(atlas.AtlasBackendOptions{
	JWKSURL: "https://auth.yourdomain.com/.well-known/jwks.json",
	Issuer:  "https://auth.yourdomain.com", // required — pins the token's iss
	// AuthorizedParties: []string{"https://app.example.com"}, // optional azp allowlist
})
if err != nil {
	log.Fatal(err)
}

claims, err := backend.Verify(ctx, token)
if err != nil {
	// errors.Is(err, atlas.ErrInvalidToken) / ErrMalformed / ErrNoKeys / ErrUnauthorizedParty
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
if !claims.HasPermission("billing:read") {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
// claims.Sub, claims.Sid, claims.OrgID, claims.OrgRole, claims.OrgPermissions, claims.Raw

// Or verify straight from a request (Authorization: Bearer … wins over the __session cookie):
claims, err = backend.AuthenticateRequest(ctx, r)
```

For the handful of operations where a ~60-second revocation window is too long,
`c.Tokens.Verify` is the documented authoritative (online) slow path.

## Namespaces

Every Backend API and platform operation in the public OpenAPI document is
covered:

| Service | Field | Highlights |
| --- | --- | --- |
| Users | `c.Users` | CRUD, ban/unban, lock/unlock, MFA, sessions, emails, OAuth tokens, identities, grants |
| Sessions | `c.Sessions` | create (mint), list (by user), get, revoke |
| Organizations | `c.Organizations` | CRUD, metadata, policy, parent/hierarchy, entitlements; `.Memberships`, `.Invitations`, `.Domains`, `.GroupRoles` |
| Invitations | `c.Invitations` | list, create, revoke |
| Roles / Permissions | `c.Roles` / `c.Permissions` | CRUD, `SetPermissions`, delete-with-reassign |
| API keys | `c.APIKeys` | mint, verify, CRUD (end-user keys) |
| OAuth clients | `c.OAuthClients` | CRUD, rotate secret, skip logout confirmation; `.Grants` |
| OAuth providers | `c.OAuthProviders` | catalog, upsert credentials, enable, scope, test |
| Resource servers | `c.ResourceServers` | CRUD (API audiences + scopes) |
| SSO connections | `c.SSOConnections` | CRUD, SAML metadata |
| SSO onboarding | `c.SSOOnboarding` | self-service profiles + one-time tickets |
| SCIM tokens | `c.SCIMTokens` | list, create, revoke (inbound) |
| SCIM provisioning | `c.SCIMProvisioning` | outbound targets: CRUD, test, sync user/group |
| Domains | `c.Domains` | custom domains: list, create, verify, delete |
| Webhooks | `c.Webhooks` | `.Endpoints` CRUD, `.Deliveries` |
| Waitlist | `c.Waitlist` | list (filtered), decide |
| Allowlist / Blocklist | `c.Allowlist` / `c.Blocklist` | list, add, remove |
| Restrictions | `c.NetworkACLs` | IP allow/deny rules CRUD |
| Attack protection | `c.AttackProtection` | get, update |
| Managed WAF | `c.ManagedWAF` | config, status, provision/deprovision |
| Bot signals | `c.BotSignals` | export signal lake + labels, add labels |
| Risk-based MFA | `c.RiskBasedMFA` | get, update (adaptive MFA) |
| Rate-limit policy | `c.RateLimitPolicy` | get, update |
| Actor / Sign-in tokens | `c.ActorTokens` / `c.SignInTokens` | create, revoke |
| Audit logs | `c.AuditLogs` | list (filtered) |
| Log streams | `c.LogStreams` | CRUD, test (HTTP/Datadog/Splunk sinks) |
| JWT templates | `c.JWTTemplates` | CRUD (keyed by name) |
| Branding | `c.Branding` | get, update, preview |
| Email / SMS templates | `c.EmailTemplates` / `c.SMSTemplates` | list, update, preview, revert |
| Localizations | `c.Localizations` | per-locale overrides CRUD |
| Actions | `c.Actions` | CRUD, test, trigger bindings |
| Billing | `c.Billing` | plans CRUD, subscriptions read |
| Messaging | `c.Messaging` | BYOK email/SMS providers, test, delete (with force) |
| Import / export | `c.ImportExport` | user import/export jobs |
| Data-subject requests | `c.DataSubjectRequests` | list, get, fulfill, reject (GDPR) |
| RADIUS clients | `c.RadiusClients` | CRUD |
| LTI platforms | `c.LTIPlatforms` | CRUD (LTI 1.3) |
| FGA | `c.FGA` | stores, models, tuples, check/batch-check/list-objects/expand; `.Store(id)` binding |
| Instance | `c.Instance` / `c.InstanceSecurity` | config, security kill-switches, write-only secrets |
| Referrals | `c.Referrals` | referral attribution settings, connection test, call log, retry |
| Tokens | `c.Tokens` | authoritative online verify |
| Platform | `c.Platform` | `.Apps`, `.AtlasIDApps` (Sign in with Atlas), `.DesignAssets` (platform key) |
| Design | `c.Design` | instance + organization design, preview, catalog; `.Assets` image uploads |
| Entitlement overrides | `c.EntitlementOverrides` | grant, list, revoke sales-led overrides |
| Email addresses | `c.EmailAddresses` | verify, make primary |
| Machines | `c.Machines` | machine identities, approve/revoke, key + secret rotation, m2m verify; `.EnrolmentTokens` |
| Org settings schema | `c.OrganizationSettingsSchema` | register / replace the settings JSON Schema |
| Session exchange | `c.SessionExchangeApps` | downstream apps with back-channel logout |
| Redirect URLs | `c.RedirectURLs` | allowlist CRUD |
| Tickets | `c.Tickets` | mint, redeem one-time capability tickets |
| Notifications | `c.Notifications` | send; `.Categories`, `.Templates` |
| OpenFGA | `c.OpenFGA` | OpenFGA-compatible stores, models, check, batch-check, read/write, list-objects, expand |
| Connectors | `c.Connectors` | community connectors, publish, install, review, directory |
| Audit events | `c.AuditEvents` | write, batch, query, JSONL/CSV export |
| Diagnostics / Analytics | `c.Diagnostics` / `c.Analytics` | login readiness, request inspector, config changelog; events feed, usage |
| Captcha | `c.Captcha` | server-side token verification |
| MCP | `c.MCP` | MCP calls; remote MCP connector settings |
| Legacy auth / Org LDAP | `c.LegacyAuth` / `c.OrgLDAPConnections` | lazy-migration connection; org-owned LDAP CRUD + test |
| PCA | `c.PCA` | attestors, kill switch, revocations, step-up deny |
| Testing | `c.Testing` | paired test instance, test-user purge, testing tokens |

Users and organizations also cover phone numbers, passwords, directives,
progression and state, consents, graceful deletion and erasure, transaction
approvals, notification preferences, organization settings, branding, audit
streams, end-user pools, reader domains, typed security policy (`SetPolicy`) and
cookie consent (`c.Instance.CookieConsent`). OAuth providers can be filtered and
re-branded (display name, icon, mode, wallet settings); webhook endpoints can be
updated in place, tested, redelivered and have their secret revealed or rotated.

## Development

```sh
go build ./...
go vet ./...
go test -p 1 ./...
gofmt -l .
```

Tests run entirely against an in-process `httptest` server — no network.
