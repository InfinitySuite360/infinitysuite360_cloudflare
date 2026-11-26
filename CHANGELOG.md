# Changelog

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
