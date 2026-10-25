# Changelog

All notable changes to `atlas-go` are documented here. Go modules are versioned
by git tag: tag a release `vX.Y.Z` (and `gin/vX.Y.Z`, `echo/vX.Y.Z` for the
middleware modules) to match an entry below.

## 0.20.0 — 2026-10-25

### Added

- **Test and review accounts.** `Platform.AtlasIDApps.ProvisionedAccounts` (`List`, `Create`, `Get`, `Remove`, `RotatePassword`; `/v1/platform/atlas_id_apps/{id}/provisioned_accounts`) with typed `AtlasIDProvisionedAccount`. The password is returned once; with `WithSecretRecipient` it arrives as `SealedPassword`. It is redacted when the account or the create and rotate params are printed or formatted. Needs the `platform:atlas_id_apps:provision` scope or the per-app `atlas_id_apps:<app id>:provision` scope.
- **Verified domains.** `Platform.Domains` (`List`, `Claim`, `Check`, `Verify`, `Remove`; `/v1/platform/domains`) with typed `AccountDomain`.
- **Test sign-in mode.** `AtlasIDApp.TestMode` and `ProvisionedVerifiedDomainsOnly`, and `UpdateAtlasIDAppParams.TestMode` and `ProvisionedVerifiedDomainsOnly`.
- **Errors.** `ErrCodeTestAccountRestricted` (403), `ErrCodeProvisionedAccountLimitReached` (409) and `ErrCodeDomainNotVerified` (422).

## 0.19.0 — 2026-10-25

### Added

- **Partner platforms.** `Client.PartnerPlatforms` (`List`, `Get`, `Set`, `Remove`, `Registration`, `StoreToken`, `Deliveries`; `/v1/partner_platforms`) with typed `PartnerPlatform`, `PartnerPlatformRegistration` and `PartnerDelivery`. The partner token is write-only: `StorePartnerPlatformTokenParams` redacts it when printed or formatted, and no response carries it.
- **Per-call audiences.** `PerCallAudience` on `Integration`, `PerCallAudienceParams` on `SetIntegrationParams` (clear it with `Clear: []string{"per_call_audience"}`), and `Sessions.GetIntegrationTokenFor` with `IntegrationTokenParams` (`Audience`, `CBID`, `AudienceParams`).
- **Data-rights orchestrator.** `PrivacyOrchestrator` and `SetPrivacyOrchestratorParams` gain `PartnerLinkID`, `SiteID` and `CancelDeletionOnSignIn`. `OutboundPartnerLink.Source` can be `registration`.
- **Settings.** `ComplianceRetentionConfig` (`cancelDeletionOnSignIn`, `deletedUserGraceDays`, `erasureGraceDays`); `OperatorConfiguration` gains `Audiences` and `AccessTokenClaims`.
- **Users.** `UserListParams.IncludeDeleted` lists soft-deleted users still in their scrub window.
- **Errors.** `ErrCodeManagedWAFNotConfigured` (422, `Meta["action"]`).
- **Sign in with Atlas grants.** `AtlasIDGrants.Lookup` and `Revoke` document that the matching platform routes also accept the managing instance's secret key.

## 0.18.0 — 2026-10-24

### Added

- **Enterprise SSO claims.** `SessionClaims` carries `SSOConnectionID`, `SSOOrganizationID` and `SSOConnectionType`; `OIDCSSOContext` (from `OIDCSSOOf`) carries `OrganizationID` and `Type`. Scope a per-organization "require SSO" rule on `sso_organization_id`, never on "signed in via SSO".
- **Adopting a Sign in with Atlas app.** `Platform.AtlasIDApps.SetManagedBy(ctx, id, instanceID *string)` (`PUT /v1/platform/atlas_id_apps/{id}/managed_by`; nil takes it back) returning `SetManagedByResult`. `AtlasIDApp` and `ManagedAtlasIDApp` gain `ManagedVia` (`instance_toggle` | `adopted`); `ManagedAtlasIDApp` gains `ButtonRenderedOrigins`.
- **Instance-surface app setup check.** `Client.AtlasIDGrants.Preflight(ctx, appID)` (`GET /v1/atlas_id_apps/{id}/preflight`). `AtlasIDAppPreflight` (both surfaces) gains `ButtonRenderedOrigins`, `AuthorizeRequests7d`, `FallbackOrigins` and `HomepageIncludesScript`.
- **Dry run.** `DryRunResult` gains `Warnings`, `WouldReturnStatus`, `Suppressed` and `ValidationSkipped`; `Mode` is `native`, `rollback` or `plan`.
- **Sealed secrets.** `SealedFields` (`sealed_secret`, `sealed_client_secret`, `sealed_webhook_secret`, `secrets_sealed`) and `SecretsSealed` are embedded in every shown-once secret response type (webhook endpoints and secrets, OAuth clients, Sign in with Atlas apps, SCIM tokens, machines, API keys, platform apps and keys, audit streams, partner links), so `WithSecretRecipient` works on every newly covered route.

## 0.17.0 — 2026-10-24

### Added

- **Credentials.** `Client.SecretKeys` (`Create`, `List`, `Get`, `Update`, `Rotate`, `Revoke`; scopes, expiry, IP allowlist, `key_format`), `Client.Keys.List` (the standard key shape), `Client.Whoami` and `Platform.Whoami`, `Client.PartnerLinks` (`Create`, `List`, `Get`, `RotateSecret`, `Revoke`, and `Outbound`: `List`, `Save`, `Test`, `Remove`), `Client.AtlasIDGrants` (`ListApps`, `Lookup`, `Revoke`), `Platform.Keys` (`List`, `Create`, `Update`, `Revoke`) and `Platform.Audit` (account audit log; `Streams`: `List`, `Create`, `Update`, `Delete`, `Test`).
- **Key formats.** `ParseKeyPrefix`, `IsSecretKey`, `IsPlatformKey`, `IsPublishableKey`, `IsWebhookSecret`, `IsPartnerLinkSecret`, `IsAccessToken` accept the suite format `atlas_<live|test>_<kind>_…` alongside `sk_` / `pk_` / `psk_` / `whsec_`.
- **Operator sign-in and token exchange** for CLIs: `GetOperatorConfiguration`, `StartOperatorLogin`, `PollOperatorLogin` (RFC 8628, `slow_down` aware), `ExchangeOperatorToken` (RFC 8693), `PartnerLinkToken`, `RevokeLeakedKeys`, `NewClientFromAccessToken`. **Sealed secret delivery**: `WithSecretRecipient`, `GenerateSealKeyPair`, `OpenSealedSecret`, `SealBox` / `OpenSealedBox` (libsodium sealed boxes, standard library only).
- **Data-rights executor.** `Client.Privacy` (`Discover`, `Preset`, `Lookup`, `CreateRequest`, `GetRequest`, `CancelRequest`) and `Privacy.Orchestrator` (`Get`, `Set`, `Delete`); `VerifyPrivacyCall` verifies the signed case calls and `privacy_request.*` events Atlas sends (with the W3C `traceparent`), `PrivacyRequestFromEvent`. Constants for the canonical types, statuses, scopes (`privacy:execute`, `privacy:grants:revoke`) and events (`privacy_request.updated` / `.completed`, `user.deletion_scheduled` / `.deletion_canceled`).
- **Identity integrations.** `Instance.ListIntegrations`, `GetIntegration`, `SetIntegration` (with `WithDryRun`), `DeleteIntegration`, `IntegrationDeliveries` (`trace`, `kind`), `RevealIntegrationEventsSecret`, `IntegrationAtlasIDToken`; `Sessions.GetIntegrationToken` (server-side mint, the Go form of `getToken({ for })`); `Client.Integrations` (`ReportVerifyError`, `Card`, `RevokeSessions`, `InstanceMetadata`).
- **Webhooks.** Endpoint `Get`, `UpsertByURL` (find-or-create), `TestNow` (`?wait=`), `RedeliverWindow`, `Replay`, `DeliveriesWithParams` (`status`, `event_type`, `since`, `until`, `starting_after`, limit up to 1000, `latency_ms`), `ListWithParams` (`include_deprecated`, `metadata[…]`); new endpoint fields (`event_naming`, `external`, `signature_versions`, `destination` with `credentials_set`, `description`, `health`, `last_success_at`, `last_failure`, `consecutive_failures`, `success_rate_24h`, `attempts_24h`, `alert_contacts`, `alerts_sent`, `auto_disable`, `replay`, `created`, `updated_at`) and create / update fields for event destinations (`WebhookDestination`, `WebhookDestinationCredentials`). `Client.Delivery` (`EgressIPs`, `Health`, `SetAlertContacts`). `VerifyWebhookURL` checks `v2` signature entries (HMAC over `id.timestamp.url.body`, `requireV2`) and ignores unknown versions. `WebhookEventAliases`, `CanonicalWebhookEvent`, `IsDeprecatedWebhookEvent`, `WebhookEventSpellings`; constants for `webhook_endpoint.*`, `delivery_target.*`, `webhook.test`, `secret_key.expiring` / `.revoked`, `status.incident.*` and the `webhooks:reveal` scope.
- **Provisioning.** `ProvisioningInput` (`ExternalRef`, `Metadata`) on app, instance, Sign in with Atlas app, OAuth client and webhook endpoint creates, `ProvisioningFields` (`metadata`, `external_ref`, `idempotent_replay`) on the responses, `MetadataQuery` and `…WithMetadata` list filters, `Platform.Apps.CreateSecretKey`, `CloneConfig`, `SandboxTeardown` (and `mode`, `dry_run`, `changes` on the bulk-delete result). `WithDryRun()` and `Client.DryRun` (`DryRunResult`), `WithTraceparent`, `NewTraceparent`, `ParseTraceparent`, `TraceparentFromHeader`.
- **Status.** `Client.Status` (`Service`, `GetSubscription`, `UpdateSubscription`, `DisableSubscription`, `RotateFeed`, `ListIncidents`, `ListDependencies`, `CreateDependency`, `GetDependency`, `UpdateDependency`, `DeleteDependency`, `RefreshDependency`), `StatusIncidentEventData`, the `status.incident.*` events and the `status_dependency_*` preflight codes.
- **Compliance.** `Client.Notices`, `Client.SecurityAdvisories` (`List`, `Acknowledge`, `Catalog`), `Client.SubProcessors`, `Client.AuditExports` (CRUD, `Test`, `RotateSecret`, CloudEvents types), `Client.Entitlements.Get` (standard entitlements document), `Internal` on entitlement overrides.
- **Instance.** `Instance.UnknownFieldsReport`, `OpenAPIDiff`, `IntegrationHealth`, `IntegrationHealthProviders`, `Embed` (embed manifest), `PreflightWithParams` (`min_severity`, `include_suppressed`; `group`, `suppressed`, `integrations`; new finding codes), `Messaging.Channel`, `configured` on the singleton views, `Design.ImportBrandURL` / `ImportBrand` / `RemoveBrand` (`brand`, `precedence`, `sources`, `ignored`), config changelog `values_recorded`, `no_op`, `recorded`, `IncludeNoOp`, audit-log `actor`, activity `Since` / `Until` / `Order`, users `UpdatedAfter` / `UpdatedBefore` / `updated_at` ordering, `RequirePKCE` on OAuth client create, Sign in with Atlas app button-rendered origins and authorize-source counters.
- **Cursor pagination everywhere.** `…ListWithParams` / `StartingAfter` on org memberships, app role holders, logout-notify deliveries and the revoked API key feed.
- **Errors.** `ErrCodeInsufficientScope` (the former `SCOPE_MISSING` is still tolerated: `APIError.IsInsufficientScope`, `RequiredScope`), `ErrCodeStepUpRequired`, `ErrCodeRouteNotFound` with `ErrorItem.DidYouMean`, `AllowedMethods`, `DocsURL`, `ErrCodeNotALiveInstance`, `ErrCodeTestModeOnly`, `ErrCodeTestingUnavailable`, `ErrCodePartnerLinkUnavailable`.
- **Back-channel logout receiver.** `BackchannelLogoutHandler`, a plain `http.Handler` (net/http, chi, gin `WrapH`, echo `WrapHandler`) that verifies the `logout_token`, calls `OnLogout`, and answers 200 / 400 / 503 + `Retry-After` the way Atlas retries expect.
- **Referrals.** `Referrals.Install` (one-click), `context_cookies`, `provider_aliases`, `capabilities`, `one_click`, provider `aliases` and `default_context_cookies`, call `trace_id` and the `Trace` filter, consent provider `gpc`; the built-in provider id is now `referalli` (`referally` is still accepted).
- **Gap fixes.** OIDC relying parties: `OIDCOrganizationOf` (`org_id`, `org_slug`, `org_role`, `org_permissions`), `OIDCOrganizationsOf` (the `orgs` claim of the `organizations` scope, `OIDCScopeOrganizations`), `OIDCSSOOf` (`sso_connection_id`, `sso_tenant_id`, `sso_issuer`, `sso_domain`) and `OIDCAuthorizeURLWithOrganization` (the `organization` authorize parameter). Partner link requests: `PartnerLinks.Requests` (`List`, `Get`, `Approve`, `Deny`), `PartnerLinks.SetCertificates` (mTLS `cert_fingerprints`), `PartnerLinks.Outbound.Request`; for a partner product `RequestPartnerLink`, `GetPartnerLinkRequest`, `VerifyPartnerLinkDelivery` (the signed `partner_link.credentials` / `partner_link.denied` delivery). `AllowedOrigins` on `CreateSecretKeyParams`, `UpdateSecretKeyParams` and `CreatePlatformKeyParams` / `UpdatePlatformKeyParams`, plus `Owner`, `ExpiresAt` and `AllowedOrigins` on the key objects; `ErrCodeOriginNotAllowed` with `APIError.IsOriginNotAllowed`. Replay and redelivery take `SinceKeyword: SinceFailingSince`; `WebhookEndpoint.LastFailingSince`. `AtlasIDIntegrationTokenFor` calls the browser route `POST /v1/client/integrations/:id/atlas_id_tokens` for Sign in with Atlas users (Bearer or DPoP).

### Changed

- Sealed secrets (`OpenSealedSecret`, `SealBox`, `OpenSealedBox`) use `golang.org/x/crypto/nacl/box` instead of a hand-written Salsa20 / Poly1305 / BLAKE2b implementation; the public API is unchanged. The module now depends on `golang.org/x/crypto`.
- The referral provider id `referally` is spelled `referalli` in docs and tests; both are accepted by the API.

## 0.16.0 — 2026-10-24

### Added

- **Policy acceptance.** `Client.Policies` (`List`, `Create`, `Get`, `Update`, `Delete`, `ListAcceptances`, `ExportAcceptancesCSV`, `ForUser`) with `Policies.Versions` (`List`, `Create`, `Get`, `Update`, `Delete`, `Publish`, `Retire`) and `Policies.Settings` (`Get`, `Update`: the `pol` session claim), and `Client.PolicySource` (`Get`, `Update`, `Delete`, `Test`, `Sync`, `ListDeliveries`; the signing secret is write-only). `Clear` flags send nulls. `RecordConsentParams` / `UserConsent` carry the acceptance evidence (`PolicyVersionID`, `ContentSHA256`, `Display`, `ScrolledToEnd`, `ViewMS`, `Locale`).
- **Policy source helpers** for a CMS written in Go: `VerifyPolicyFeedRequest(method, pathAndQuery, header, secret, opts)` checks Atlas's signed feed request (`atlas-id`, `atlas-timestamp` in ms, `atlas-signature` with one or more `v1,<base64 HMAC-SHA256>` values over `{id}.{ts}.GET\n{path+query}`, five-minute window) and returns the `Key` Atlas asked for; `PolicyFeedHandler` serves a `PolicyFeed` behind it; `SignPolicySourceEvent(event, secret, opts)` signs a `policy.published` / `policy.retired` event for Atlas (`SignedPolicySourceEvent.Request` builds the POST). `PolicySourceProtocolVersion`.
- `SessionClaims.Policies()` and `AcceptedPolicyVersion(key)` read the `pol` session claim. `WebhookEventUserPolicyAccepted`, `WebhookEventPolicyVersionPublished`.

## 0.15.0 — 2026-10-24

### Added

- **Migrate from Better Auth: sealed-bundle imports.** `Client.BetterAuthImports`: `GetPublicKey`, `RotatePublicKey`, `Create`, `List`, `Get`, `UploadPart` (text/plain), `Finalize`, `DryRun`, `Apply` (resumes a failed import), `Delete`, `ListJWKS`, `DeleteJWK`. Helpers: `Upload(ctx, bundle, UploadBetterAuthBundleOptions{Options, PartBytes, OnPart})` creates the import, uploads the bundle in line-aligned parts of at most 8 MiB (`SplitBundleParts`, `BetterAuthImportPartBytes`) and finalizes it; `WaitFor(ctx, id, WaitForBetterAuthImportOptions{Interval, Timeout, OnProgress})` polls until the import leaves `analyzing` / `queued` / `applying` (honours the context). Typed `BetterAuthImport`, `BetterAuthImportKey`, `BetterAuthImportOptions`, `BetterAuthImportReport`, `ImportedJWK`, status constants.
- **Better Auth session bridge.** `Client.BetterAuthBridge`: `Get` / `Update` (`UpdateBetterAuthBridgeParams`, merged; `ClearEndsAt`, live-fallback `ClearSecret` / `ClearBaseURL` send nulls; the secret is write-only) / `Delete`, and `Exchange` on the secret-key Backend API route, forwarding the end user's IP and user agent (`X-Atlas-Client-IP`, `X-Atlas-Client-User-Agent`). `Client.ExchangeBetterAuthSession` classifies the outcome (`session`, `needs_mfa`, `refused` with `meta.bridge_outcome`; never errors). `NewBetterAuthBridge(BetterAuthBridgeOptions{Client, CookiePrefix, CookieName, BetterAuthCookieDomain, Insecure, SignInURL, ClientIP})`: `Decide` returns a `BridgeDecision` (Atlas cookies to set, Better Auth cookies cleared only on a final refusal, `ContinuationURL` for a second factor); `Handle` / `Middleware` exchange a GET/HEAD's Better Auth cookie and redirect to the same URL signed in. `middleware.BetterAuthBridge`, `gin.BetterAuthBridge` and `echo.BetterAuthBridge` adapters. `ReadBetterAuthSessionCookie`, `BetterAuthCookieNames`, `ClientIPFromRequest`.
- **Better Auth JWTs during the cutover.** `AtlasBackendOptions.LegacyIssuers` (`LegacyIssuer{Issuer, JWKS | JWKSURL, Audience, Until, Algorithms, ResolveSubject}`) with `SecretKey` / `APIURL`: a token from that issuer, inside its window, is verified against that issuer's keys only (EdDSA, ES256, ES512, RS256, PS256; `exp` required) and its `sub` is mapped to the Atlas user id through `external_id` (Backend API lookup cached 5 minutes, at most 10 000 entries; failures are not cached). The claims carry `Raw["external_id"]` and `Raw["legacy"]`.

## 0.14.0 — 2026-10-24

### Added

- **DPoP (RFC 9449) on the access-token verifier.** A DPoP-bound token (`cnf.jkt`) is accepted only with the DPoP scheme and a valid proof (never as Bearer): `typ` `dpop+jwt`, `DPoPAlgs` (ES256/384/512, RS256/384/512, PS256/384/512, EdDSA), public embedded JWK, signature, `htm`, normalised `htu` (`NormalizeHTU`; `PublicOrigin` for path-only URLs), `iat` window (`DPoPProofMaxAgeSeconds`), `ath`, `jti` replay via `DPoPReplayStore` (`NewMemoryDPoPReplayStore` by default), RFC 7638 `JWKThumbprint` match. `RequireDPoP` refuses unbound tokens; `DPoPNonces` (`NewHMACDPoPNonceSource`) demands a server nonce (`use_dpop_nonce`, `DPoP-Nonce` header via `AccessTokenResult.DPoPNonce`). Challenges use the `DPoP` scheme with `algs`. `VerifyResource(ctx, ResourceRequest{...})`; `VerifyRequest` and `middleware.RequireAccessToken` read the `DPoP` header and set `DPoP-Nonce`. Metadata advertises `dpop_signing_alg_values_supported`; `ProtectedResourceMetadataRequiringDPoP`.
- **Billing: several subscriptions per subject, add-ons, Chargebee / Autumn / Commet.** Provider constants `BillingProviderChargebee`, `BillingProviderAutumn`, `BillingProviderCommet` (config keys documented on `SetBillingProviderParams`). Plans: `Kind` (`BillingPlanKindBase` / `BillingPlanKindAddon`), `Limits`, `SeatFeatureID` (Autumn; `ClearSeatFeatureID` on update). Subscriptions carry `Entitlements`. New `Billing.GetSubscription`, `SyncPlanEntitlements`, `GetSettings` / `UpdateSettings` (limit merge `max` / `sum`), `CheckFeature`. `ReportUsageParams` takes `Feature` and `SubscriptionID`.
- **Custom OAuth / OIDC providers.** `CustomOAuthProviders`: `List`, `Get`, `Create`, `Update` (`Clear` sends nulls), `Delete`, `Discover`, `PreviewProfileMapping` (stored or ad-hoc mapping), `SigningKeys(id).List` / `Rotate` / `Retire`. Typed `ProfileMapping` / `ProfileMappingRule`, `UpstreamLogoutSettings`, `IdpInitiatedLoginSettings`, `UpstreamURLs`. OIDC SSO connections take the same relying-party settings and gain `PreviewProfileMapping` and `SigningKeys`.
- **Actions gallery.** `ActionGallery` (`List` with filters, `Get`, `Install`, `Installs`, `Update`) and `ActionTemplates` (`List`, `Create`, `Get`, `Update`, `Delete`, `AddVersion`, `SubmitVersion`, `DeleteVersion`, `Publish`, `Unlist`). Action dry runs report `HTTPRequests` (what `api.http` queued); sample events take `user.organizations` and `request.country`.
- **Session custom data.** `Sessions.SetCustomData` (replace; nil clears) and `UpdateCustomData` (merge; a nil value removes a key); `Session.CustomData`; `CreateSessionParams.CustomData`. The `session.updated` webhook (`WebhookEventSessionUpdated`) fires on a change.
- **Sign-in settings.** `InstanceSecurity.SetWalletRPCSecret(chainID, url)`; per-endpoint rate-limit `Rules` (`RateLimitRule`, keys `ip` / `user` / `instance`) on the rate-limit policy, plus the verify and LDAP budgets and the group catalog; `Instance.SetAccountLinkingTrust` (`LinkingTrustAlways` / `Verified` / `Never`); `Instance.SetCaptchaConfig` with a typed `CaptchaConfig` (incl. `AttestationURL`) and `CaptchaProvider*` constants (incl. `captchafox`, `vercel_botid`).
- **Vercel BotID attestations.** `CreateBotIDAttestation(secret, verdict, opts)` signs a verdict in Atlas's `atlas_botid.v1` format; `BotIDAttestationHandler` serves `{token}` from your own verdict check.
- **Enterprise SSO.** SAML Single Logout fields (`SAMLSingleLogout`, `SAMLIDPSLOURL`, `SAMLIDPSLOResponseURL`, `SAMLIDPSLOBinding`, `SAMLIDPSLOSOAPURL`), `SAMLRequireEncryptedAssertions` and the encryption-key flags on connections; `SamlMetadata.SLOURL`; `GetSAMLEncryptionKey`, `CreateSAMLEncryptionKey` (create or rotate), `RetirePreviousSAMLEncryptionKey`, `DeleteSAMLEncryptionKey`. Attack protection `DormantAccounts`; risk weight and signal `DormantAccount`; `EmailTemplateAccountReactivated`; `WebhookEventUserReactivated`.
- **Atlas as OAuth provider.** OAuth clients: `AccessTokenFormat` (`AccessTokenFormatJWT` / `AccessTokenFormatOpaque`) and `TokenLifetimes`. Resource servers: `AccessTokenFormat`, refresh-token lifetimes, `IntrospectionClientIDs`. `SigningKey.Provider`; `InstanceSecurity.GetSigningKeyProvider` / `SetSigningKeyProvider` / `RemoveSigningKeyProvider` (AWS KMS, Google Cloud KMS, Azure Key Vault).
- **Opaque access tokens.** `AccessTokenVerifierOptions.Introspection` validates non-JWT access tokens at Atlas's RFC 7662 endpoint with your API's client credentials, cached by token hash (TTL, negative TTL, never past `exp`, bounded); `IntrospectJWTs` checks JWTs live too. `NewIntrospector` is exported.
- **Device sign-in approval.** `NewDeviceAuthorizations(frontendAPI, sessionToken, opts)`: `Lookup`, `Approve`, `Deny` on the Frontend API with the user's session token; `DeviceAuthorizationError` (`NeedsReverification`, `IsInvalidCode`); `FormatUserCode`, `UserCodeFromURL`.

### Changed

- A token that is not a JWT is now refused with "configure Introspection to accept opaque tokens" instead of "malformed" when `Introspection` is not set.

## 0.13.0 — 2026-10-23

### Added

- **App roles.** `AppRoles` (`/v1/app_roles`): `List`, `Create`, `Get`, `Update`, `Delete`, `ListUsers`, and per user `GetForUser`, `SetForUser` (replace, or add/remove), `RemoveFromUser`. `SessionClaims.HasAppRole` / `HasAppPermission` read the `app_roles` / `app_permissions` claims (no active organization needed).
- **Organization teams and custom roles.** `Organizations.Teams` (list, create, get, update, delete, members list/add/remove) and `Organizations.Roles` (the roles an org can assign; create/update/delete its own, with `reassign_to`). `Organizations.GetBySlug`, `Organizations.CheckSlug`, `Organizations.Invitations.Resend`.
- **User search.** `Users.Search(ctx, UserListParams{...})`: `query`, `email_address`, `username`, `phone_number`, `external_id`, `banned`, `email_verified`, `organization_id`, `created_after` / `created_before`, `order_by`, `offset`, `include_total_count` (`UserSearchPage.TotalCount`).
- **Timed bans.** `Users.BanWithParams(ctx, id, BanParams{Reason, Note, ExpiresInSeconds, ExpiresAt})`; `User.BanExpiresAt`.
- **API key controls.** Create: `Prefix`, `ExpiresInSeconds`, `Enabled`, `RateLimit`, `Remaining`, `Scopes`. Update: `Enabled`, `RateLimit` / `ClearRateLimit`, `Remaining` / `ClearRemaining`, `Scopes`. `APIKeys.VerifyWithParams` with `RequiredScopes`; the verdict carries `Code` (`insufficient_scope`, `rate_limited`, `usage_exhausted`), `MissingScopes`, `RetryAfterMS`, `Remaining`.
- **Billing providers (bring your own key).** `Billing.ListProviders`, `GetProvider`, `SetProvider`, `TestProvider`, `DeleteProvider(force)`; subscription `ChangeSubscription`, `CancelSubscription(immediately)`, `RestoreSubscription`. Plans take `Provider`, `ProviderPriceID`, `AnnualPriceID`, `AnnualAmount`; subscriptions report the provider, account, interval, scheduled change, trial and cancellation fields.
- **OAuth server administration.** `InstanceSecurity.ListSigningKeys` / `RotateSigningKey` (`alg` RS256 or ES256, grace period, emergency); `OAuthInitialAccessTokens` (list, create, revoke). OAuth clients: `Disabled`, `RequirePKCE`, `SubjectType` (public / pairwise), `SectorIdentifierURI`, `SecretExpiresInSeconds`, and `ClientSecretExpiresAt` on reads. Resource servers: `PublishResourceMetadata`.
- **Access-token verification for your API.** `NewAccessTokenVerifier` checks an Atlas-issued OAuth access token locally (issuer, expiry, `token_use`, audience, scopes) and returns the RFC 6750 / RFC 9728 `WWW-Authenticate` challenge on refusal; `BuildWWWAuthenticate`, `ProtectedResourceMetadata`, `ProtectedResourceMetadataPath`; `middleware.RequireAccessToken`. DPoP-bound tokens are refused.
- SCIM tokens: `Scopes`, `RoleMappings`, `SCIMTokens.Update`. User imports: row `ExternalID`, `CreatedAt`, `PasswordSalt`, `PhoneNumber(s)`, `OrganizationMemberships`; job `CreateOrganizations`, `PasswordHashConfig`. `UserHooks.ListBeforeUserCreateCalls`, `Referrals.GetCall`.

### Changed

- Session, logout-token and access-token verification accept **ES256** as well as RS256 (`SigningAlgs`), and nothing else; the token's `kid` selects one key whose type fixes the algorithm.
- `CreateBillingPlanParams.StripePriceID` is omitted when empty (a free plan, or a plan priced with `ProviderPriceID`).

## 0.12.0

### Added

- Referral settings carry browser capture: `browser_sources` (the referral programs whose script or cookie the browser reads; null on update resets to the provider's default), `browser_sources_default`, and `consent_provider` (`auto`, one consent manager, or `app`). Reset the list with `Clear: []string{"browser_sources"}`.

## 0.11.0

### Added

- **Two-way referral sync.** Referral settings carry two-way sync: `inbound` (`url`, `secret_set`, `endpoint_id`, `last_event`) on reads, write-only `inbound_secret` and `inbound_endpoint_id` on updates (null clears), and provider capability `inbound`. Clear the secret with `Clear: []string{"inbound_secret"}`.
- `SignReferralUpdatedEvent(...)`: builds and signs a `referral.updated` event for a referral platform reporting changes to `POST /v1/webhooks/referrals/{instance_id}`.

## 0.10.0

### Added

- **Referral attribution v2.** `Referrals.RetryFailed(ctx, RetryFailedReferralCallsParams{Kind, ErrorCode})`
  (`POST /v1/instance/referrals/calls/retry_failed`, `ReferralRetryFailedResult` with `Requeued`),
  `Referrals.Simulate(ctx, ReferralSimulateParams{Code})` (`POST /v1/instance/referrals/simulate`,
  `ReferralSimulateResult`: `CallID`, `CustomerRef`, `Result`, `Response`), `Referrals.Backfill(ctx,
  ReferralBackfillParams{Since, Codes, CodeMetadataPath})` and `Referrals.GetBackfill(ctx, id)`
  (`POST /v1/instance/referrals/backfill`, `GET /v1/instance/referrals/backfill/{id}`; `ReferralBackfillJob`:
  `UsersScanned`, `UsersSkipped`, `CallsQueued`, `Truncated`, `NextSince`, `Calls`), and
  `Referrals.GetForUser(ctx, userID)` (`GET /v1/users/{id}/referral`, `UserReferralResult`).
- **Settings.** `ReferralSettings` gains `TrackingToken`, `CodeLookupURL`, `SignupCodeField`, `ForwardLifecycle`,
  `MirrorToPublicMetadata` and `IncludeReferralClaims`; `UpdateReferralSettingsParams` gains the same (the
  booleans as `*bool`; `Clear` takes `tracking_token` and `code_lookup_url`). `Provider` can be `referalli`.
  `ReferralProviderCapabilities` gains `Alias`, `User` and `Ping`. `ReferralConnectionStatus` gains `LastPing`
  (`ReferralPing`) and `Alert` (`ReferralAlert`: `signature_rejected` or `connection_paused`).
  `ReferralConnectionTest` gains `Method` (`ping` or `probe`), `Ping` and `Warnings`.
- **Call log.** `ListReferralCallsParams` gains `ErrorCode` and `StartingAfter`; `Limit` goes up to 1000.
  `ReferralCall.Kind` adds `alias`, `user` and `ping`; calls gain `LatencyMS`, `ErrorCode`, `Response`,
  `Highlights` (`ReferralCallHighlights`), `RequestID` and `BatchID`.
- **Users.** `Users.SetExternalID(ctx, id, externalID)` (`PATCH /v1/users/{id}`; `""` clears; with referrals on,
  the change is forwarded to the platform as an alias). `UpdateUserParams` gains `ExternalID` and
  `ClearExternalID`; `User` gains `ExternalID`. `UserReferral` gains `PartnerExternalRef`, `ReferralStatus` and
  `Notes`. `UserReferralResolvedEvent` (the full `User`) types the `data` of the new `user.referral_resolved`
  webhook.
- **before_user_create hook.** New `UserHooks` service: `GetBeforeUserCreate(ctx)`,
  `UpdateBeforeUserCreate(ctx, UpdateBeforeUserCreateHookParams{Enabled, URL, SigningSecret, TimeoutMS, Clear})`
  and `TestBeforeUserCreate(ctx)` (`/v1/instance/hooks/before_user_create`; `BeforeUserCreateHook`,
  `BeforeUserCreateHookTest`). The hook call is signed like a webhook with type `user.before_create`; verify it
  with `VerifyWebhook`.
- **Preflight** can report `referrals_secret_invalid`, `referrals_program_inactive`, `referrals_unreachable`,
  `referrals_clock_skew` and `referrals_external_id_unset`.
- **Referral protocol receiver.** `VerifyReferralRequest` accepts the operations `ReferralOpAlias` (`/aliases`,
  `ReferralAliasPayload`), `ReferralOpUser` (`/users`, `ReferralUserPayload`) and `ReferralOpPing` (`/ping`,
  `ReferralPingPayload`; answer `ReferralPingResponse`), set on `ReferralRequest.Alias`, `.User` and `.Ping`, and
  returns `ProtocolVersion` (the `Atlas-Referrals-Version` header). `ReferralSignupResponse` gains `Notes`. New
  constants `ReferralProtocolVersion` (`2026-10-21`) and `ReferralProtocolVersionHeader`.

### Changed

- On the server, `User.Referral.Status` is now where attribution stands (`pending`, `attributed`, `none`, `failed`,
  `held`, `flagged`); the platform's own status moved to `ReferralStatus`. The user `Referral` is present for every
  user reported to the platform, and `user.created` carries `status: "pending"` while the platform has not
  answered.

## 0.9.0

### Added

- **Referral attribution settings.** New `Referrals` service: `Get(ctx)` and `Update(ctx,
  UpdateReferralSettingsParams{...})` (`GET`/`PATCH /v1/instance/referrals`; `ReferralSettings`; nested
  `Security` as `ReferralSecuritySettings` on read and `UpdateReferralSecurityParams` on write; `Clear` sends
  nullable fields as null), `Test(ctx)` (`ReferralConnectionTest`), `ListCalls(ctx, ListReferralCallsParams{Limit,
  Status, Kind, UserID})` (`ReferralCall`) and `RetryCall(ctx, id)`. Also `ReferralProvider`,
  `ReferralProviderCapabilities`, `ReferralConnectionStatus`, `ReferralRisk`.
- **Users.** `User` gains `Referral` (`UserReferral`: `PartnerID`, `ReferrerExternalID`, `ReferrerUserID`,
  `MatchedVia`, `Status`, `RiskLevel`, `Flagged`), `ReferralCode` and `ReferralLink`. `CreateUserParams` gains
  `Referral` (`CreateUserReferral`: `Code`, `ClickID`, `AnonID`) and `ReferralCode`; `UpdateUserParams` gains
  `ReferralCode` and `ClearReferralCode` (sends null). New `Users.FlagReferral(ctx, id, FlagReferralParams{Reason})`
  (`UserReferralFlag`).
- **Webhooks.** `UserReferralAttributedEvent` types the `data` of the new `user.referral_attributed` event.
- **Error codes.** `ErrCodeReferralsNotConfigured` (422) and `ErrCodeReferralCodeTaken` (409). Preflight can
  report `referrals_enabled_unverified` and `referrals_without_bot_protection`.
- **Referral protocol receiver.** `VerifyReferralRequest(body, header, secret, &ReferralVerifyOptions{Path,
  ExpectedOp})` verifies a call from Atlas to a referral platform (the webhook signature scheme; every call is a
  POST whose signed body carries `op` and `customerRef`) and returns `ReferralRequest` (`Op`: `ReferralOpSignup`,
  `ReferralOpErase`, `ReferralOpExport`, `ReferralOpPartner`, `ReferralOpSignal`; typed `Signup`, `Erase`, `Export`,
  `Partner`, `Signal` payloads; `CustomerRef`, `Test`, `DeliveryID`, `Timestamp`, `IdempotencyKey`). Besides the
  webhook errors it returns `ErrReferralMalformedBody`, `ErrReferralMissingOp`, `ErrReferralUnknownOp`,
  `ErrReferralUnknownEndpoint` and `ErrReferralOpMismatch` (the signed `op` does not match the path or
  `ExpectedOp`). Also `ReferralOpForPath`, `ReferralOpEndpoints`, `ReferralSignupResponse`, `ReferralContext`, the
  `ReferralSignal*` constants, `ReferralConnectionTestRef` and `ReferralProtocolUserAgent`.

### Changed

- `UpdateUserParams` now has a `MarshalJSON` method; the JSON it sends is unchanged unless you set
  `ClearReferralCode`.

## 0.8.0

### Added

- **Trusted reverse proxy secret.** `InstanceSecurity.ProxySecret(ctx)` (`ProxySecret`: `Set`, `CreatedAt`,
  `PreviousExpiresAt`, `SecretHeader`, `ClientIPHeader`), `InstanceSecurity.CreateProxySecret(ctx,
  CreateProxySecretParams{OverlapSeconds: &n})` (`ProxySecretCreated`: adds `Secret`, shown once, and `Rotated`;
  on a rotation the old secret keeps working for the overlap, default 86400, `0` stops it now) and
  `InstanceSecurity.DeleteProxySecret(ctx)` (`ProxySecretDeleted`).
- **Webhook secret rotation with an overlap.** `Webhooks.Endpoints.RotateSecretWithParams(ctx, id,
  RotateWebhookSecretParams{OverlapSeconds: &n})` (default 0, at most 604800). `WebhookSecret` gains
  `OverlapSeconds` and `PreviousSecretExpiresAt`; `WebhookEndpoint` gains `PreviousSecretExpiresAt`.
- **Per-instance platform rotation with an overlap.** `Platform.Apps.RotateInstanceSecretWithParams(ctx, id,
  instanceID, RotatePlatformSecretParams{OverlapSeconds: &n})` (default 259200, `0` revokes the prior keys now).
  `PlatformInstanceSecret` gains `AppID`, `InstanceID`, `OverlapSeconds` and `PreviousKeysExpireAt`.
- **Sign in with Atlas apps.** `Platform.AtlasIDApps.RotateSecretWithParams` (default 24 hours) and
  `RotateWebhookSecretWithParams` (default 0) take `RotateAtlasIDAppSecretParams`. `AtlasIDApp` gains
  `PreviousSecretExpiresAt`, `SecretIssuedAt`, `WebhookPreviousSecretExpiresAt` and `OverlapSeconds`.

### Changed

- `PlatformInstanceSecret.ID` is deprecated: the API never sent it; read `InstanceID`.
- `Platform.Apps.RotateInstanceSecret` without an overlap now keeps the prior keys valid for 72 hours (the
  server's new default). Use `RotateInstanceSecretWithParams` with `OverlapSeconds: 0` for the old behaviour.

## 0.7.0

### Added

- **OAuth client secret rotation with overlap.** `OAuthClients.RotateSecretWithParams(ctx, id,
  RotateOAuthClientSecretParams{OverlapSeconds: &n})` (default 86400, `0` revokes the old secret now, at most
  604800). `OAuthClientWithSecret` gains `OverlapSeconds`; `OAuthClient` gains `PreviousSecretExpiresAt`.
- **Development email sender.** `Messaging.DevelopmentEmail`, `EnableDevelopmentEmail`
  (`EnableDevelopmentEmailParams`) and `DisableDevelopmentEmail` (`DevelopmentEmail`,
  `DisabledDevelopmentEmail`). `MessagingProviders` gains `DevelopmentEmail`.
- **Managed email on your own provider account.** `CreateManagedEmailParams` gains `Transport`, `Config`
  (`ManagedEmailProviderKey`) and `ProviderID`. `ManagedEmail` gains `Backend`, `ProviderID` and
  `FeedbackWebhook`; `Limits` is now always null (reads as zero) and `Reputation` is `your_provider_account`.
  `DeletedManagedEmail` gains `ProviderRemoved`.
- **Provider mode.** `MessagingProvider` gains `ID` and `Mode`; `MessagingProviderInput` gains `Mode`;
  `SetEmailProviderWithParams(ctx, EmailProviderParams{FromAddress, Mode, Config})` sets it with a typed config
  (`ProviderModeStandard`, `ProviderModeDevelopment`, `ProviderModeManagedDomain`).
- **Allowed origins with an integration.** `AllowedOriginEntries []AllowedOriginEntry` on
  `UpdateInstanceParams`, `CreatePlatformAppParams`, `UpdatePlatformAppParams`, `CreatePlatformInstanceParams`
  and `CreateAccountlessAppParams` is sent as `allowed_origins` (a string, or `{origin, integration}` with
  `OriginIntegrationRedirect`, `OriginIntegrationEmbedded` or `OriginIntegrationAuto`).
- **Issuer and verification endpoints.** `Instance` gains `Issuer`, `DiscoveryURL`, `JWKSURI` and
  `AllowedOriginIntegrations`; `InstanceUpdateResult` gains `AllowedOriginIntegrations`; `PlatformApp` gains
  `FrontendAPIHost`, `Issuer`, `DiscoveryURL`, `JWKSURI` and `AllowedOriginIntegrations`.
- **Login readiness.** `LoginReadiness` gains `Integration` (`LoginReadinessIntegration`); `LoginReadinessCheck`
  gains `Applies`.
- **Email verification.** `EmailAddress` gains `Verification` (`EmailAddressVerification`: `Status`, `Strategy`).
- **Branding audiences.** `Branding` and `ResolvedBranding` gain `Audiences` (`BrandingAudience`).
- **Error codes.** `ErrCodeReadOnlyField`, `ErrCodeDevelopmentEmailNotAllowed`,
  `ErrCodeDevelopmentEmailUnavailable`, `ErrCodeDevelopmentEmailLimitReached`,
  `ErrCodeDevelopmentEmailTemplateNotAllowed`.
- **Webhooks, several signatures.** `VerifyWebhook` accepts an `atlas-signature` header with several
  space-separated `v1,<signature>` entries and verifies when any one matches (each compared in constant time).
  A single signature works as before.

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
