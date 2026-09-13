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
go get github.com/atlas-auth/atlas-go
```

```go
import atlas "github.com/atlas-auth/atlas-go"
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

	atlas "github.com/atlas-auth/atlas-go"
)

func main() {
	// Base URL defaults to https://api.atlas.dev; override for self-hosted.
	c := atlas.New(
		"sk_live_...",
		atlas.WithBaseURL("https://api.atlas.dev"),
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

## Token verification

Backend services verify a session JWT locally against the instance JWKS — fast,
offline, and correct within the short token lifetime — without an outbound call
per request. `AtlasBackend` caches the JWKS in-process and refetches on an unknown
`kid` at most once a minute (the rate limit is a security property, not politeness).

```go
backend, err := atlas.NewAtlasBackend(atlas.AtlasBackendOptions{
	JWKSURL: "https://your-instance.atlas.dev/.well-known/jwks.json",
	Issuer:  "https://your-instance.atlas.dev", // required — pins the token's iss
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

Full parity with the TypeScript SDK — 45 services + the token verifier covering
the whole BAPI surface:

| Service | Field | Highlights |
| --- | --- | --- |
| Users | `c.Users` | CRUD, ban/unban, lock/unlock, MFA, sessions, emails, OAuth tokens, identities, grants |
| Sessions | `c.Sessions` | create (mint), list (by user), get, revoke |
| Organizations | `c.Organizations` | CRUD, metadata, policy, parent/hierarchy, entitlements; `.Memberships`, `.Invitations`, `.Domains`, `.GroupRoles` |
| Invitations | `c.Invitations` | list, create, revoke |
| Roles / Permissions | `c.Roles` / `c.Permissions` | CRUD, `SetPermissions`, delete-with-reassign |
| API keys | `c.APIKeys` | mint, verify, CRUD (end-user keys) |
| OAuth clients | `c.OAuthClients` | CRUD, rotate secret; `.Grants` |
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
| Messaging | `c.Messaging` | BYOK email/SMS providers, test |
| Import / export | `c.ImportExport` | user import/export jobs |
| Data-subject requests | `c.DataSubjectRequests` | list, get, fulfill, reject (GDPR) |
| RADIUS clients | `c.RadiusClients` | CRUD |
| LTI platforms | `c.LTIPlatforms` | CRUD (LTI 1.3) |
| FGA | `c.FGA` | stores, models, tuples, check/batch-check/list-objects/expand; `.Store(id)` binding |
| Instance | `c.Instance` / `c.InstanceSecurity` | config, security kill-switches, write-only secrets |
| Tokens | `c.Tokens` | authoritative online verify |

## Development

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

Tests run entirely against an in-process `httptest` server — no network.
