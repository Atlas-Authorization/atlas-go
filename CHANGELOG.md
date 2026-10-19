# Changelog

All notable changes to `atlas-go` are documented here. Go modules are versioned
by git tag: tag a release `vX.Y.Z` (and `gin/vX.Y.Z`, `echo/vX.Y.Z` for the
middleware modules) to match an entry below.

## 0.6.0

### Added

- **Back-channel logout, retryable failures.** `(*VerificationError).Retryable()` and `IsRetryable(err)`
  are true for `ErrNoKeys`: the issuer's keys could not be fetched (a network error, a JWKS outage, or a
  just-rotated key whose refetch failed). Answer `503` with `Retry-After` then, so Atlas retries the
  delivery, and `400` otherwise. A logout token whose `kid` is unknown after a failed JWKS refetch is now
  `ErrNoKeys` (was `ErrInvalidToken`).
- **Webhook verification.** `VerifyWebhook(body, header, secret, opts)` returns `*VerifiedWebhook`
  (`Event`, `DeliveryID`, `Timestamp`) or one of `ErrWebhookMissingHeaders`, `ErrWebhookMalformedSignature`,
  `ErrWebhookStaleTimestamp`, `ErrWebhookSignatureMismatch`. `DeliveryID` is the signed `atlas-id` header,
  the same on every retry of one event: deduplicate on it.
- **Domain moves.** `Instance.MoveOrigin(ctx, OriginMoveParams{From, To, DryRun})` rewrites every URL on one origin
  to another across the instance, its OAuth clients, webhooks, redirect URLs and Sign in with Atlas apps
  (`*OriginMove`: `Changes`, `Problems`, `Applied`); `Platform.AtlasIDApps.MoveOrigin(ctx, id, params)` does it for one app.
- **Connections and integrations.** `Instance.Connections`, and `Instance.ChatlyIntegration / SetChatlyIntegration /
  DeleteChatlyIntegration / ForumulateIntegration / SetForumulateIntegration / DeleteForumulateIntegration`.
- **Logout fan-out.** New `LogoutNotifyEndpoints` service: `List`, `Create`, `Get`, `Update`, `Delete`, `Deliveries`.
- **Managed email.** `Messaging.ManagedEmail / CreateManagedEmail / VerifyManagedEmail / DeleteManagedEmail`
  (`ManagedEmail`, `ManagedEmailRecord`). `MessagingProviders` gains `ManagedEmail`.
- **Back-channel logout logs.** `OAuthClients.ListBackchannelDeliveries` / `TestBackchannelLogout` and the same on
  `Platform.AtlasIDApps` (`BackchannelLogoutDelivery`, `BackchannelLogoutTest`).
- **Sign in with Atlas apps.** `Platform.AtlasIDApps.Preflight`, `FindUsers`, `RevokeGrant`, `RotateWebhookSecret`.
  `AtlasIDApp` gains `WebhookURL`, `WebhookEvents`, `WebhookActive`, `WebhookSecret`; `UpdateAtlasIDAppParams`
  gains `WebhookURL`.
- **Publisher.** `Platform.AtlasIDPublisher`: `Get`, `Set`, `SetSkipConsent`, `Delete`, `Verify`; and
  `Platform.ConfigChangelog(ctx, params)`.
- **More fields.** `User.Version`; `CookieConsent.Culture` / `DeclaredCookies`; `SetCookieConsentParams.Culture`;
  `Preflight.SDKVersionsSeen`; `WebhookDelivery.Error` / `Location`; `WebhookEndpointList.EventCatalog` /
  `EventAudiences`; `CustomDomain.DNS` and `CreateDomainParams.DNS`; `ConfigChange.Target`.
  `Users.RevokeSessionsWithParams(ctx, id, RevokeSessionsParams{RevokeGrants: true})` returns `GrantsRevoked`.

## 0.5.1

### Added

- **Captcha is bring-your-own-keys.** `ErrCodeCaptchaKeysRequired` (422) and `ErrCodeCaptchaInUse` (409, `Meta["flows"]`).
- `InstanceSecurity.SetCaptchaSecretWithParams` (`SetCaptchaSecretParams{Secret, Provider}`) stores the secret for a named
  provider before captcha is turned on.
- `InstanceSecurity.DeleteCaptchaSecretWithParams` (`DeleteCaptchaSecretParams{Provider, Force}`); `CaptchaSecretResult`
  gains `FlowsTurnedOff`.

## 0.5.0

All changes are backward compatible: every new field is optional and every
existing method keeps its signature.

### Added

- **Logout without confirmation.** `CreateOAuthClientParams.SkipLogoutConfirmation`
  and `UpdateOAuthClientParams.SkipLogoutConfirmation` (`*bool`, sent as
  `skip_logout_confirmation`); `OAuthClient` gains `SkipLogoutConfirmation`
  (`bool`, default false). First-party clients only (a third-party client is
  refused with `422 VALIDATION_FAILED`, param `skip_logout_confirmation`). When
  true, RP-initiated logout with this client and an exactly registered
  `post_logout_redirect_uri` ends the session and redirects straight back with
  `state`, without the confirmation page.
- **Cookie settings link.** `SetCookieConsentParams.SettingsLink`
  (`*CookieSettingsLinkInput`: `Label`, `Preset`, `Attributes`; nil for no
  link). `CookieConsent` gains `SettingsLink` (`*CookieSettingsLink`: `Label`,
  `Preset` (`*string`), `Attributes`, `RenderedAttributes`). Preset constants
  `CookieSettingsLinkPresetCookiemunch`, `CookieSettingsLinkPresetCookiebot`,
  `CookieSettingsLinkPresetOneTrust`, `CookieSettingsLinkPresetCustom`; an
  unknown preset still decodes.
- **Force-remove the email provider.** `Messaging.DeleteChannelWithParams(ctx,
  channel, DeleteMessagingProviderParams{Force})` sends `?force=true` when
  `Force` is set (no query otherwise); `Messaging.DeleteChannel` is unchanged.
  Without it, removing the email provider is refused with
  `409 EMAIL_PROVIDER_IN_USE` (`Meta["features"]` lists the email-dependent
  features that are on) while nothing else would deliver email.
- **Sessions.** `UserSession` (the `Users.ListSessions` item) gains
  `IdleExpiresAt`, `LastActiveOrganizationID` and `ImpersonatedBy`, matching
  `Session`.
- **Error codes.** `ErrCodeEmailProviderInUse`.

## 0.4.0 (unreleased — next tag `v0.4.0`)

### Added

- **API key spend caps.** `CreateAPIKeyParams.Limits` and
  `UpdateAPIKeyParams.Limits` (`[]APIKeyLimit`: `Unit`, `Amount`, `Period` —
  `APIKeyLimitPeriodRequest`, `Day`, `Month`, `Total`);
  `UpdateAPIKeyParams.ClearLimits` sends `limits: null` to remove them.
  `APIKey` gains `Limits` and `Usage` (`[]APIKeyLimitState`: `Unit`, `Period`,
  `Amount`, `Used`, `Remaining`, `WindowStart`, `ResetsAt`).
- **Usage metering.** `APIKeys.RecordUsage(ctx, id, RecordAPIKeyUsageParams{Amount,
  Unit, IdempotencyKey})` returns `*APIKeyUsageDebit` (`KeyID`, `Unit`, `Amount`,
  `Allowed`, `Code`, `Exceeded`, `Usage`, `Counters`, `IdempotentReplay`); a
  refusal is `Allowed=false` with `Code` `"LIMIT_EXCEEDED"`, not an error.
  `APIKeys.GetUsage(ctx, id)` returns `*APIKeyUsage` (`KeyID`, `Limits`, `Usage`,
  `Counters` of `APIKeyUsageCounter`).
- **Verify.** `APIKeyVerification` gains `Name`, `Scopes`, `Constraints`,
  `Limits`, `Usage` and `ExpiresAt`.
- **Session keep-alive.** `Sessions.Touch(ctx, id)` returns `*TouchedSession`
  (the session plus `Extended`). `Session` gains `IdleExpiresAt`.
- **Users.** `CreateUserParams.Notify` and `ImportUsersParams.Notify` (`*bool`;
  unset or false sends nothing to the user).
- **Error codes.** `ErrCodeLimitExceeded`, `ErrCodeIdempotencyConflict`,
  `ErrCodeSessionRevoked`, `ErrCodeSessionIdleExpired`, `ErrCodeSessionExpired`.
- Coverage: 450 of 450 Backend API and platform operations.

## 0.3.0

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
