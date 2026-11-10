# Changelog

## 0.3.0 – unreleased

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
