# Changelog

All notable changes to `atlas-go` are documented here. Go modules are versioned
by git tag: tag a release `vX.Y.Z` (and `gin/vX.Y.Z`, `echo/vX.Y.Z` for the
middleware modules) to match an entry below.

## 0.3.0 (unreleased — next tag `v0.3.0`)

### Added

- **Complete API coverage.** Every Backend API and platform operation in the
  public OpenAPI document now has a typed method (447 of 447).
- **Strict request bodies.** `WithStrict(true)` sends `Atlas-Strict: true` on
  every write so an unknown body field is refused with `422 UNKNOWN_FIELD`;
  `StrictBody(bool)` overrides it per call. `WithUnknownFieldsHandler` reports
  the fields a non-strict write ignored (`Atlas-Unknown-Fields`). Every write
  method now accepts `...RequestOption` (`WithIdempotencyKey`, `StrictBody`,
  `WithHeader`).
- **Platform client.** `NewPlatform` / `WithPlatformKey` and `c.Platform`:
  apps (instances, overlapping secret rotation, archive, transfer, claim,
  accountless apps), Sign in with Atlas apps (redirect and post-logout URIs,
  back-channel and front-channel logout, branding, page text, design, secret
  rotation, design preview) and account design images.
- **Sign-in page design.** `c.Design`: read, replace, patch and preview the
  instance design; per-organization overrides; the design catalog; image
  uploads (`c.Design.Assets.Upload` sends the raw image bytes).
- **Setup check.** `c.Instance.Preflight` returns typed findings.
- **Cookie consent** for the hosted pages: `c.Instance.CookieConsent`,
  `SetCookieConsent`, `DeleteCookieConsent`.
- **Back-channel logout.** `NewLogoutTokenVerifier` verifies OIDC Back-Channel
  Logout tokens; `MemoryReplayGuard` / `LogoutReplayGuard` refuse replays.
- **OAuth providers:** list filters (`provider`, `configured`), display name,
  icon, mode and wallet settings on upsert, settings that can be cleared with
  null, and `icon_url` / `mode` / `setting_values` on read.
- **Webhook endpoints:** update in place, reveal and rotate the signing secret,
  send a test event, delivery log with a limit, redeliver.
- **Entitlement overrides** (`c.EntitlementOverrides`) and a typed
  organization security policy (`Organizations.SetPolicy`).
- **Users:** password reset, phone numbers, passkey and profile-image removal,
  batch lookup by email, resolved identity, organization memberships, sign-in
  history, identity import/removal, directives, progression and portable state,
  consents, graceful deletion and erasure, transaction approvals, notification
  preferences. Flat email-address verify / make-primary (`c.EmailAddresses`).
- **Organizations:** settings documents and the settings schema, branding
  overlay, audit streams, end-user (reader) pool, reader domains.
- **Machines** (`c.Machines`): machine identities, enrolment tokens, approve,
  revoke, key and secret rotation, m2m token verification.
- **More services:** session-exchange apps, redirect URLs, capability tickets,
  notifications (send, categories, templates), session template tokens,
  OpenFGA-compatible authorization (`c.OpenFGA`), community connectors and the
  directory, custom audit events with export, diagnostics, analytics (events,
  usage), CAPTCHA verification, MCP and the remote MCP connector, the
  lazy-migration connection, organization LDAP connections, PCA controls,
  test-mode helpers, bulk invitations, waitlist create/bulk/delete,
  data-request create and cancel, API-key revocation feed and token minting,
  Stripe subscription import, metered usage, seat sync, OAuth client import.
- **Typed messaging provider config** per transport.
- Named error-code constants (`ErrCodeUnknownField`, `ErrCodeInvalidKey`, …).

### Fixed

- `Organizations.Entitlements` now decodes: `Features` is a list (it was typed
  as a map) and `Limits` is included. The never-populated `Catalog` field is
  deprecated.

### Deprecated

- `SignInTokens.Revoke` (the endpoint sunsets 2027-04-01) — mint sessions
  instead.

## 0.2.0

### Added

- Framework middleware: `net/http` (`middleware`), Gin (`gin`) and Echo
  (`echo`) as nested modules.

## 0.1.0

- Initial release: typed Backend API client and networkless session-token
  verification.
