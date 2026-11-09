# Cloudflare InfinitySuite360

.NET client for the [Cloudflare API v4](https://developers.cloudflare.com/api/), published by the
[InfinitySuite360](https://github.com/InfinitySuite360) organisation.

| Package | Content |
|---|---|
| `InfinitySuite360.Cloudflare` | Entry point: `ICloudflareClient`, dependency injection, curated clients for common tasks, Turnstile siteverify. References the OpenAPI package, so one install gives you everything. |
| `InfinitySuite360.Cloudflare.AspNetCore` | Authentication for applications behind Cloudflare Access: checks the signed token Access adds to every request, so that `[Authorize]` works. |
| `InfinitySuite360.Cloudflare.OpenApi` | Every operation and model of Cloudflare's [official OpenAPI schema](https://github.com/cloudflare/api-schemas), generated with [Microsoft Kiota](https://learn.microsoft.com/openapi/kiota/). XML documentation comes from the schema. |

Targets **net8.0** and **net10.0**. Community package, not affiliated with Cloudflare, Inc.

## Why this package

Cloudflare publishes official SDKs for TypeScript, Python, Go and Java, but not for .NET. This package fills the gap with
the complete API surface, generated from the same schema Cloudflare's own SDKs use, plus a thin safety layer:

* **Writes are off by default.** `AllowWrites = false` rejects POST/PUT/PATCH/DELETE locally before anything is sent;
  `WriteFilter` restricts writes to an allow-list. This applies to the generated client too.
* **Retries** on HTTP 429 (honouring `Retry-After`) and on 502/503/504 for idempotent methods only.
* **The token never appears** in exception messages.
* **IDs are URL-encoded** in the curated client, so an ID can never address another endpoint.

## Install

The packages are published to GitHub Packages of the organisation:

```bash
dotnet nuget add source "https://nuget.pkg.github.com/InfinitySuite360/index.json" --name infinitysuite360 --username <github-user> --password <token-with-read:packages>
dotnet add package InfinitySuite360.Cloudflare
```

## Configure

```json
{
  "Cloudflare": {
    "ApiToken": "",
    "AccountId": "…",
    "ZoneId": "…",
    "AllowWrites": false,
    "Turnstile": { "SiteKey": "…", "SecretKey": "", "ExpectedHostname": "app.example.com" }
  }
}
```

Keep `ApiToken` and `Turnstile:SecretKey` out of source control (user secrets, environment variables such as
`Cloudflare__ApiToken`, or a vault).

```csharp
builder.Services.AddCloudflareInfinitySuite360(builder.Configuration);
```

## Use

### Complete API (generated)

Every endpoint of the schema, typed request and response models, IntelliSense from Cloudflare's documentation:

```csharp
public sealed class WaitingRoomService(ICloudflareClient cloudflare)
{
    public async Task ListAsync(string zoneId, CancellationToken ct)
    {
        var rooms = await cloudflare.OpenApi.Zones[zoneId].Waiting_rooms.GetAsync(cancellationToken: ct);
        // …
    }
}
```

The generated client is also registered on its own (`CloudflareApiClient`) and can be created without DI:
`CloudflareOpenApi.CreateClient(options)`.

### Curated clients

Short, task-oriented methods for the most common areas:

```csharp
await cloudflare.Dns.UpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = true });
await cloudflare.Zones.SetSettingAsync(ZoneSettingIds.MinTlsVersion, "1.2");
await cloudflare.Rulesets.UpsertRuleByRefAsync(RulesetPhases.FirewallCustom, new RulesetRule
{
    Ref = "login-challenge", Action = "managed_challenge", Expression = "http.request.uri.path eq \"/login\"",
});
var events = await cloudflare.Analytics.GetSecurityEventsAsync(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow);
```

| Area | Client |
|---|---|
| Accounts and tokens | `Accounts` |
| Zones, settings, cache purge, DNSSEC | `Zones` |
| DNS records | `Dns` |
| Rulesets / WAF / rate limiting | `Rulesets` |
| Turnstile widgets and siteverify | `Turnstile`, `ITurnstileVerifier` |
| Cloudflare Tunnel | `Tunnels` |
| Zero Trust Access | `Access` |
| Email Routing | `EmailRouting` |
| R2 buckets | `R2` |
| Workers scripts and routes | `Workers` |
| Health Checks, Logpush, audit logs, notifications | `Monitoring` |
| Page Shield, Security Center, API Shield, bots | `Security` |
| Origin CA and mTLS certificates | `Certificates` |
| GraphQL Analytics, Web Analytics | `Analytics` |
| Cloudflare IP ranges | `Ips` |

### Raw access

Any endpoint, with the same guard, retries and error handling:

```csharp
var result = await cloudflare.Api.GetAsync<JsonElement>($"accounts/{accountId}/d1/database");
```

### Without dependency injection

```csharp
var cloudflare = CloudflareClient.Create(new CloudflareOptions { ApiToken = token, ZoneId = zoneId });
```

### Separate read and write tokens

Run the registered client read-only and create a dedicated writer only where changes are needed:

```csharp
var writer = CloudflareClient.Create(new CloudflareOptions
{
    ApiToken = writeToken, ZoneId = zoneId, AllowWrites = true,
    WriteFilter = (method, path) => path.EndsWith("/purge_cache", StringComparison.Ordinal),
});
```

## Cloudflare Access: check the token at the origin

Cloudflare Access adds a signed token (`Cf-Access-Jwt-Assertion`) to every request that passed it. **Check it at your application** — anyone who can reach the origin directly (a leaked
address, another container, a misconfigured firewall) can send the header with any content, and an application that trusts it unchecked is open to the world.
`ICloudflareAccessJwtValidator` checks signature, issuer, audience and expiry:

* **Only RS256.** No `none`, no HS256 (a published public key must never work as a shared secret).
* **The audience ties the token to your application.** Without the application audience tag a token minted for another application of the same team would be accepted.
* **The team domain is validated** (`*.cloudflareaccess.com`, or a custom domain only if you allow it) before keys are fetched from it: no URL, IP address, port or path, so a setting
  or a request can never point the server at another host. Keys are fetched over HTTPS without redirects, limited to 64 KB.
* **Key cache:** keys are kept for an hour; a token with an unknown key id triggers a new fetch at most every 30 seconds (forged tokens cannot flood Cloudflare); if the fetch fails, known
  keys are used for up to 12 hours (Cloudflare rotates keys with an overlap of weeks). `MaxStaleKeyAge = 0` fails closed.
* Keys shorter than 2048 bits and non-signing keys are ignored; tokens longer than 8 KB are refused before they are parsed.

```json
{
  "Cloudflare": {
    "AccessJwt": {
      "TeamDomain": "myteam.cloudflareaccess.com",
      "Audiences": [ "<application audience tag>" ]
    }
  }
}
```

The audience tag is under Zero Trust → Access → Applications → your application → Overview. Several applications behind one server: list all their tags.

```csharp
builder.Services.AddCloudflareInfinitySuite360(builder.Configuration);       // registers ICloudflareAccessJwtValidator (singleton: it holds the key cache)
builder.Services.AddAuthentication(CloudflareAccessAuthenticationOptions.DefaultScheme).AddCloudflareAccess();
builder.Services.AddAuthorization();
app.UseAuthentication(); app.UseAuthorization();

app.MapGet("/me", (ClaimsPrincipal user) => user.CloudflareAccess())          // subject, e-mail, groups, service token or person
   .RequireAuthorization();
```

Without a token the request is anonymous; a token that fails the check gives 401 (the reason is logged, not shown). There is no redirect: Cloudflare Access is the login. The token is read from
the header; `AllowCookieFallback = true` also accepts the `CF_Authorization` cookie. Without ASP.NET Core use the validator directly:

```csharp
var result = await validator.ValidateAsync(request.Headers["Cf-Access-Jwt-Assertion"]);
if (!result.Ok) { log.LogWarning("Access refused: {Failure}", result.Failure); return Unauthorized(); }   // show the caller nothing more than "no"
var who = result.Identity!;                                                                                // Subject, Email, CommonName (service token), IdentityNonce, Groups …
```

`ProbeAsync()` fetches the team's keys and returns how many there are — a good "is the team domain right?" check for a settings page. `Groups` contains the groups the token carries (identity
providers that send them); for everything else use the `IdentityNonce` with Cloudflare's `get-identity` endpoint.

## Keeping up with the API

The generated client is pinned to a commit of `cloudflare/api-schemas`
([openapi/cloudflare-openapi.lock.json](openapi/cloudflare-openapi.lock.json)). The workflow
`.github/workflows/openapi-update.yml` pins the latest commit every Monday, regenerates, builds, tests and opens a pull request.
It needs *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*.

Regenerate locally:

```bash
dotnet run tools/generate.cs
dotnet run tools/generate.cs -- --update
```

The schema is normalized before generation; see [openapi/normalization.md](openapi/normalization.md). Counts per area are in
[openapi/COVERAGE.md](openapi/COVERAGE.md).

## Build, test, release

```bash
dotnet test -c Release
dotnet pack -c Release -o out
```

A tag `v<major>.<minor>.<patch>` on `master` builds, tests and publishes both packages to GitHub Packages
(`.github/workflows/ci.yml`).

## Licence

Not chosen yet. The OpenAPI schema used for generation is © Cloudflare, Inc., BSD-3-Clause.
