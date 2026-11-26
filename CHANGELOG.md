# Changelog

## 0.6.0 – unreleased

Rest of priority 1: typed clients for rate limiting, WAF, bots, custom hostnames, Authenticated Origin Pulls, TLS settings, Logpush and API token
management, plus DNS helpers. Same rules as 0.5.0: every write checks `AllowWrites`/`WriteFilter` (methods that read before writing check it **before**
the read, so with `AllowWrites = false` nothing is sent), has a `Preview…` sister that sends nothing, checks its input locally, and risky options need an
explicit `allow…` switch. Endpoints from the API schema `cloudflare/api-schemas@650bd71`; plans and limits from developers.cloudflare.com (retrieved
17.11.2026, sources in the XML documentation of each client).

* New `RateLimiting` (`RateLimitingClient`): rate limiting rules of phase `http_ratelimit` typed (`RateLimitRuleInput`: period, requests, mitigation timeout,
  characteristics with `cf.colo.id` added, counting expression), `ListRulesAsync`, `PreviewUpsertRuleAsync`/`UpsertRuleAsync` (by ref, writes only on change),
  `RemoveRuleAsync`; local check of the supported periods; the action has no default, `block` on a match-all expression needs `allowBroadMatch`.
  Deprecated classic rate limits: `ListLegacyRateLimitsAsync`, `DeleteLegacyRateLimitAsync` (for the migration).
* New `Waf` (`WafClient`): custom rules (`UpsertCustomRuleAsync`, `RemoveCustomRuleAsync`; `skip` needs `allowSkip`, blocking everything `allowBroadMatch`),
  managed rules (`ListManagedRulesetsAsync`, `ListManagedDeploymentsAsync`, `DeployManagedRulesetAsync` with `ManagedRulesetOverrides` for ruleset, categories,
  rules and OWASP sensitivity; disabling, `log`/`skip` or low sensitivity need `allowLoosen`; `RemoveManagedDeploymentAsync` refuses without `allowLoosen`),
  `ManagedRulesetIds`. Both build on the new base `RulesetPhaseClient`, which changes **one** rule (PATCH by rule id, POST to append, PUT only for a new entry
  point) instead of replacing the phase like `Rulesets.UpsertRuleByRefAsync`, so concurrent edits of other rules are not lost. `Rulesets` itself is unchanged.
* New `Bots` (`BotsClient`): typed `BotManagementSettings` (Bot Fight Mode, Super Bot Fight Mode, Bot Management, AI bots), `UpdateSettingsAsync` with
  `BotManagementChange` (only set fields are sent). Bot Fight Mode on and `block`/`managed_challenge` for (likely) automated traffic need
  `allowChallengeAutomation` (they hit your own API clients; Bot Fight Mode cannot be skipped), blocking verified bots needs `allowBlockVerifiedBots`.
  Feedback reports, leaked credential checks (`Get/SetLeakedCredentialChecksAsync`) and custom detection locations (list, create, `Ensure…`, update, delete).
* New `CustomHostnames` (`CustomHostnamesClient`, Cloudflare for SaaS): list (filter, `MaxItems`), get, find, create, `EnsureAsync` (survives a concurrent
  create), update, delete (idempotent), fallback origin get/set/remove (`RemoveFallbackOriginAsync` needs `allowRemoval`). Email validation needs
  `allowEmailValidation`. Custom certificates with a private key are deliberately not supported; `custom_key`/`private_key` are stripped from every answer.
* New `OriginPulls` (`OriginPullsClient`, `origin_tls_client_auth`): zone-level setting and certificates, per-hostname certificates and associations.
  `OriginPullKeyPair.FromPem` checks certificate and key locally (PEM, not encrypted, key matches); the key is only written into the request body, never into
  previews, `ToString`, models or errors, and `private_key` is stripped from every answer. Lock-out protection like mTLS: switching AOP off, deleting a
  certificate and disabling/invalidating a hostname need `allowDisable`.
* New `Tls` (`TlsSettingsClient`): `GetOverviewAsync` (SSL mode, minimum TLS, TLS 1.3, HTTPS rewrites, ECH, HTTP/3, 0-RTT, HSTS in one call),
  `SetSslModeAsync` and `SetMinTlsVersionAsync` (read the current value first; weakening needs `allowWeaken`, TLS 1.3 only `allowTls13Only`),
  `SetHstsAsync` (max-age above one day, includeSubDomains or preload need `allowLongLivedHsts`), `SetSwitchAsync` (with warnings, for example 0-RTT replay).
* New `Logpush` (`LogpushClient`, zone and account scope): jobs typed as `LogpushJobInfo` with the **destination redacted** (credentials in query, user info,
  path of HTTP destinations), dataset fields, create, `EnsureJobAsync` (by name and dataset), enable/disable, delete, ownership challenge, destination check;
  `LogpushClient.RedactDestination` for own logs. `Monitoring.LogpushJob.DestinationConf` stays unredacted (documented).
* New `ApiTokens` (`ApiTokensClient`): user and account-owned tokens: list, get, verify, permission groups (filter), create, update, enable/disable, roll and
  revoke. The token value of `CreateAsync`/`RollAsync` exists only in `ApiTokenSecret` (`TakeValue` hands it over once; `ToString` and JSON write
  `[redacted]`), never in `ApiToken`, `AdditionalData`, previews or errors. Least privilege: wildcard resources need `allowBroadResources`, a token
  without expiry `allowNoExpiry`; rolling, disabling or revoking the token the client itself uses needs `allowSelf`. Create is never repeated after a server
  error (it could create a second token).
* `Dns`: `PreviewCreate`, `PreviewUpdate`, `PreviewDelete`, `DeleteIfExistsAsync` (false on 404), `PreviewUpsertAsync` and `SafeUpsertAsync` (writes only on change,
  refuses to switch a proxied record to DNS-only without `allowUnproxy`, because that publishes the origin address). `DnsClient` is now `partial`.
* **Obsolete:** `Certificates.CreateClientCertificateAsync` (no local checks) → `ApiShield.CreateClientCertificateAsync` (CSR only, private keys refused,
  preview). With `TreatWarningsAsErrors` callers have to switch or suppress CS0618. Removed in 1.0.
* **Breaking (source, rare):** `ICloudflareClient` has the new members `RateLimiting`, `Waf`, `Bots`, `CustomHostnames`, `OriginPulls`, `Tls`, `Logpush`,
  `ApiTokens` (own implementations of the interface, in practice test doubles, must add them). No other public signature changed.
* Not included (reachable through `OpenApi`): per-hostname TLS settings (Advanced Certificate Manager), custom certificates for custom hostnames,
  account-level rate limiting rulesets, GraphQL analytics additions (the owner's 0.2.1 changes to `Analytics`/`Rulesets` are pending and were not touched).
* Tests: 17 new (`Priority1Tests`, `ApiTokenTests`) with the fake handler: success, errors, rate limit, not entitled, conflict, previews send nothing,
  `AllowWrites = false` sends nothing (36 write methods), token value, origin pull key and Logpush credentials never in outputs.

## 0.5.0 – unreleased

Shield writes. Every new write method checks `AllowWrites`/`WriteFilter`, has a `Preview…` sister that sends nothing, validates its input locally and goes through the
shared retries (429 always, 502/503/504 only for PUT/DELETE; POST is never repeated after a server error).

* New: `CloudflareNotEntitledException` (plan or add-on does not include the feature, recognised from Cloudflare's error text such as "not entitled" or
  "not available on your plan") and `CloudflareConflictException` (HTTP 409 or "already exists"). Both derive from `CloudflareApiException`, so existing `catch`
  blocks keep working; a missing token permission ("Authentication error", code 10000) stays a plain `CloudflareApiException`. `CloudflareApiException.Create`
  picks the type and is used by the connection for every response.
* `ApiShield`, operations: `AddOperationsAsync` (bulk), `EnsureOperationsAsync`/`PreviewEnsureOperationsAsync` (only missing ones, one call),
  `DeleteOperationAsync` (idempotent, false when already gone), `DeleteOperationsAsync` (bulk). API Discovery: `SetDiscoveryStateAsync`, `SetDiscoveryStatesAsync`.
  Session identifier: `SetSessionIdentifierAsync` (header, cookie or JWT claim).
* `ApiShield`, schema validation: `UploadSchemaAsync` (JSON endpoint, local checks for name, size, OpenAPI 3.x and allowed hosts; validation stays **off** by default;
  the preview shows size and SHA-256 instead of the text), `EnsureSchemaAsync` (by name, survives a concurrent create), `SetSchemaValidationEnabledAsync`,
  `DeleteSchemaAsync`, `SetOverrideActionAsync`, `SetOperationActionsAsync` (bulk), `ResetOperationActionAsync`.
  **Block is never a default:** `"block"` needs `allowBlock: true` (also for the existing `SetDefaultActionAsync`/`SetOperationActionAsync`), previews carry a warning.
  `SetOperationActionAsync` accepts null (inherit the zone default).
* `ApiShield`, JWT token validation: `CreateTokenValidationConfigAsync`, `UpdateTokenValidationConfigAsync`, `ReplaceTokenValidationKeysAsync` (key rotation, answer
  with key values redacted), `DeleteTokenValidationConfigAsync`, rules `Create…`/`Update…` (with position)/`DeleteTokenValidationRuleAsync`. Keys travel as `JwtKeySet`:
  private key members are refused, `ToString`, previews, models and error messages contain key id, type and algorithm only; `TokenValidationConfig.Credentials`
  keeps no key values.
* `ApiShield`, labels: `CreateUserLabelsAsync`, `EnsureUserLabelAsync`, `UpdateUserLabelAsync`, `DeleteUserLabelAsync`, `AddLabelsToOperationsAsync`,
  `RemoveLabelsFromOperationsAsync` (names `cf-…` are reserved for managed labels).
* `ApiShield`, mTLS: `CreateClientCertificateAsync` (CSR only, input with a private key is refused before anything is sent), `RevokeClientCertificateAsync`,
  `ReactivateClientCertificateAsync`, `GetHostnameAssociationsAsync`, `PreviewReplaceHostnameAssociationsAsync` (lists added and removed hostnames) and
  `ReplaceHostnameAssociationsAsync`, which refuses to remove a hostname unless `allowRemovals: true` (lock-out risk with an mTLS rule). `ZoneClientCertificate.Certificate`.
* `PageShield`: `EnsurePolicyAsync` (by description, writes only on change), `DeletePolicyAsync` returns false when the rule was already gone, policies need description,
  expression and value; action `"allow"` (enforces the CSP) needs `allowEnforce: true`; `SetSettingsAsync` refuses an empty change and the preview warns when Page Shield is switched off.
* Breaking against the unreleased 0.4.0: the optional parameters `allowBlock`/`allowEnforce` sit before the `CancellationToken`; `PageShield.DeletePolicyAsync` returns `Task<bool>`.
* Not included: token validation rule preview (`rules/preview`, a POST that only reads) and bulk rule create/edit; reachable through `OpenApi`.
* 14 new tests (`ShieldWriteTests`) with the fake handler: success, errors, rate limit, not entitled, conflict, previews send nothing, `AllowWrites = false` sends nothing.

## 0.4.0 – unreleased

* New: `PageShield` (Page Shield / client-side security): typed settings, detected scripts, connections and cookies (filter by host, URL, status, page, order; `MaxItems` caps the amount),
  single items, content security rules (policies) with create, replace and delete. Scripts and connections now carry `UrlReportedMalicious`, `DomainReportedMalicious`, `Hash`, scores and `PageUrls`.
* New: `ApiShield`: saved operations (with optional `feature` details), API Discovery operations (state filter), uploaded schemas (schema text only on request), zone and per-operation schema validation settings
  (read, set default action, set operation action), JWT token validation configurations and rules (read only, key material is not modelled), operation labels, mTLS client certificates of the zone (read only),
  session identifier configuration.
* New: `CloudflareChangePreview` and `Preview…` methods for the Shield write calls: they build method, path, body and a summary and send nothing, so an application can show the change and ask for approval first.
  Write methods still need `AllowWrites` (and pass `WriteFilter`); actions are checked locally.
* Fix: `PageShieldResource.IsMalicious` of `Security` ignored `url_reported_malicious` and `domain_reported_malicious`; both are modelled now.
* Not included on purpose: schema upload (multipart), operation labels writes, token validation writes, mTLS certificate creation (private key). They stay reachable through `OpenApi`.

## 0.3.0 – unreleased

Release notes. Everything below goes through the same write guard (`AllowWrites`, `WriteFilter`) and retries (429 always, 502/503/504 for idempotent methods) as the existing clients.

* New: `Lists` (custom lists of the account, `accounts/{id}/rules/lists`). Create, read, find by name, `EnsureAsync` (create when missing), change the description, delete;
  read all entries (cursor paging), add, replace and remove IP entries (asynchronous on Cloudflare's side), `GetOperationAsync` and `WaitForOperationAsync` for the bulk status
  (completed, failed with reason, timeout). A rule that refers to a list needs one rule slot however many addresses it holds.
* New: `IpAccess` (IP access rules, zone and account scope): list with filters (mode, target, value, notes), create, change mode or notes, delete. `IpAccessModes`, `IpAccessTargets`.
* `ZoneSettingIds`: `ChallengeTtl` (`challenge_ttl`), `ZeroRtt` (`0rtt`), `Ech` (`ech`), `SslRecommender` (`ssl_recommender`).
* `Certificates`: Universal SSL status (`GetUniversalSslSettingsAsync`, `SetUniversalSslEnabledAsync`), validation state (`GetSslVerificationAsync`), certificate packs (`ListCertificatePacksAsync`)
  and a check of the name depth: `CertificateHostMatcher.Covers` / `FindUncoveredHostnamesAsync` tell which hostnames no active pack covers (a wildcard covers one label, so `a.b.example.com` is not covered by Universal SSL).
* `Tunnels`: `ListConnectionsAsync`, `ListConnectorsAsync`, `GetConnectorAsync` (replicas, data centres, pending reconnects, version).
* `Monitoring`: `ListAlertHistoryAsync` (`alerting/v3/history`, with time window and paging).
* `Access`: identity providers (`ListIdentityProvidersAsync`, `GetIdentityProviderAsync`, create, update, delete) and request logs (`ListRequestLogsAsync`, newest first, filters by user, Ray ID and application).
* `Ips`: `IpsResult.AllCidrs` and `IpsResult.Contains(IPAddress)` (trusted proxies, firewall rule sets). `ICloudflareClient` has the new members `Lists` and `IpAccess`
  (source-breaking only for your own implementations of the interface).
* Tests with a fake HTTP handler for all of the above; no call to the real Cloudflare API is made by the tests.

Package split (this release also contains it):

* New package `InfinitySuite360.Cloudflare.Core`: everything except the generated client (curated clients, raw access, Access JWT, Turnstile, options, write guard,
  retries, dependency injection). It depends only on `Microsoft.Extensions.*`, so a service that needs Access JWT or DNS (such as `InfinitySuite360.Security.Edge`)
  no longer pulls the 12 MB generated client and Kiota. Registration: `AddCloudflareInfinitySuite360Core(...)`.
* `InfinitySuite360.Cloudflare` is now core + `InfinitySuite360.Cloudflare.OpenApi`: same package, same namespaces, same `AddCloudflareInfinitySuite360(...)`, which also
  registers the generated client. Its assembly forwards every type that moved to the core, so assemblies built against 0.2 keep working.
* `InfinitySuite360.Cloudflare.AspNetCore` depends on the core only.
* Breaking (source, rarely used): `OpenApi` is no longer a member of `ICloudflareClient` but an extension property from `InfinitySuite360.Cloudflare`
  (`CloudflareClientOpenApiExtensions`); `client.OpenApi` keeps compiling with C# 14 (default for net10.0), older language versions use `client.GetOpenApi()`.
  The `CloudflareClient` constructor no longer takes an OpenAPI factory: use `client.WithOpenApi(factory)`. Binary: callers of `ICloudflareClient.OpenApi`,
  of that constructor overload or of `AddCloudflareInfinitySuite360` must be recompiled against 0.3 (the method moved to `CloudflareOpenApiServiceCollectionExtensions`).
* `CloudflareWriteGuardHandler` moved to the core (same namespace).

## 0.2.1 – unreleased

* Access JWT: service tokens as Cloudflare really sends them (`"sub": ""`, client id in `common_name`) were refused as malformed. Empty `sub`, `email` and
  `common_name` now count as missing; the subject of a service token is its client id. Found while moving `InfinitySuite360.Security.Edge` onto this package.

## 0.2.0 – unreleased

* `InfinitySuite360.Cloudflare`: `ICloudflareAccessJwtValidator` checks the token Cloudflare Access adds to requests (RS256 only, issuer, audience, expiry), with a validated team domain,
  key cache, rate-limited refetch for unknown key ids and a stale-key allowance during outages; `Cloudflare:AccessJwt` settings.
* `InfinitySuite360.Cloudflare.AspNetCore`: authentication scheme `AddCloudflareAccess()` so that `[Authorize]` works, claims for subject, e-mail, service tokens and groups.
  Extracted from the AureonTradeAI MT5 Server gateway (`CloudflareAccessValidator`) and hardened: team domain validation (SSRF), minimum key size, size limits, no redirects when fetching keys.

## 0.1.0

* `InfinitySuite360.Cloudflare.OpenApi`: complete client generated with Kiota 1.36.1 from `cloudflare/api-schemas@650bd71`.
* `InfinitySuite360.Cloudflare`: `ICloudflareClient` with the generated client (`OpenApi`), curated clients and raw access;
  write guard, retries and token-safe errors shared by all three; Turnstile siteverify; dependency injection.
