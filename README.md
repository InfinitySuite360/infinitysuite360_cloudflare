# Cloudflare InfinitySuite360

.NET client for the [Cloudflare API v4](https://developers.cloudflare.com/api/), published by the
[InfinitySuite360](https://github.com/InfinitySuite360) organisation.

| Package | Content |
|---|---|
| `InfinitySuite360.Cloudflare` | Everything: the core plus the generated client (`ICloudflareClient.OpenApi`). One install, nothing else to choose. |
| `InfinitySuite360.Cloudflare.Core` | The core without the generated client: `ICloudflareClient`, dependency injection, curated clients for common tasks, raw access, Cloudflare Access token validation, Turnstile siteverify. Depends only on `Microsoft.Extensions.*`; for services that need Access JWT or DNS but not the whole API. |
| `InfinitySuite360.Cloudflare.AspNetCore` | Authentication for applications behind Cloudflare Access: checks the signed token Access adds to every request, so that `[Authorize]` works. Needs only the core. |
| `InfinitySuite360.Cloudflare.OpenApi` | Every operation and model of Cloudflare's [official OpenAPI schema](https://github.com/cloudflare/api-schemas), generated with [Microsoft Kiota](https://learn.microsoft.com/openapi/kiota/). XML documentation comes from the schema. |

Targets **net8.0** and **net10.0**. Community package, not affiliated with Cloudflare, Inc.

## Why this package

Cloudflare publishes official SDKs for TypeScript, Python, Go and Java, but not for .NET. This package fills the gap with
the complete API surface, generated from the same schema Cloudflare's own SDKs use, plus a thin safety layer:

* **Writes are off by default.** `AllowWrites = false` rejects POST/PUT/PATCH/DELETE locally before anything is sent;
  `WriteFilter` restricts writes to an allow-list. This applies to the generated client too, but there it is the only protection: the
  `allow…` switches, previews and lock-out checks belong to the curated clients.
* **Retries** on HTTP 429 (honouring `Retry-After`) and on 502/503/504 for idempotent methods only.
* **The token never appears** in exception messages.
* **IDs are URL-encoded and checked** in the curated client, so an ID can never address another endpoint: `.`, `..` (also percent-encoded),
  empty segments, control characters, `/` and `\` inside an ID are refused before anything is sent, and every path is checked as Cloudflare resolves it (0.7.1).
* **Bounded answers:** HTTPS base address required (plain HTTP only for loopback), at most 10 retries, answers above `MaxResponseBytes` (32 MiB) fail (0.7.1).

## Install

The packages are published to GitHub Packages of the organisation:

```bash
dotnet nuget add source "https://nuget.pkg.github.com/InfinitySuite360/index.json" --name infinitysuite360 --username <github-user> --password <token-with-read:packages>
dotnet add package InfinitySuite360.Cloudflare        # core + generated client
dotnet add package InfinitySuite360.Cloudflare.Core   # core only (Access JWT, DNS, curated clients, raw access)
```

The generated client is large (the `.nupkg` of `InfinitySuite360.Cloudflare.OpenApi` is about 12 MB). A service that only checks Access tokens or
manages DNS records references `InfinitySuite360.Cloudflare.Core`; everything in this README except `OpenApi`/`CloudflareApiClient` works the same there.

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
builder.Services.AddCloudflareInfinitySuite360(builder.Configuration);       // InfinitySuite360.Cloudflare: core + generated client
builder.Services.AddCloudflareInfinitySuite360Core(builder.Configuration);   // InfinitySuite360.Cloudflare.Core: without the generated client
```

## Use

### Complete API (generated, package `InfinitySuite360.Cloudflare`)

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
`CloudflareOpenApi.CreateClient(options)`. `OpenApi` is an extension property on `ICloudflareClient` (C# 14, the default for net10.0);
with an older language version call `cloudflare.GetOpenApi()`.
Write protection of the generated client: **only** `AllowWrites` and `WriteFilter` (no `allow…` switches, no previews, no lock-out checks).

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
| R2 buckets, custom domains, CORS, lifecycle | `R2` |
| Workers scripts, routes, domains, cron triggers, versions, deployments, secret names | `Workers` |
| Workers KV namespaces, keys, bulk operations | `Kv` |
| D1 databases and SQL (read-only unless allowed) | `D1` |
| Queues, consumers, publishing | `Queues` |
| Cache rules, purge, Cache Reserve, regional tiered cache | `Cache` |
| Argo Smart Routing and tiered caching | `Argo` |
| Load balancing: monitors, pools, load balancers | `LoadBalancing` |
| Spectrum applications (TCP/UDP proxy) | `Spectrum` |
| Health Checks, Logpush, audit logs, notifications | `Monitoring` |
| Page Shield, Security Center, API Shield, bots (older, untyped parts) | `Security` |
| Page Shield: settings, scripts, connections, cookies, content security rules | `PageShield` |
| API Shield: operations, discovery, schema validation, token validation, labels, mTLS client certificates | `ApiShield` |
| Origin CA and mTLS certificates | `Certificates` |
| GraphQL Analytics, Web Analytics | `Analytics` |
| Cloudflare IP ranges | `Ips` |
| Custom lists (IP lists, bulk status) | `Lists` |
| IP access rules (zone and account) | `IpAccess` |
| Rate limiting rules (and the deprecated classic rate limits) | `RateLimiting` |
| WAF custom rules, managed rules and overrides | `Waf` |
| Bot Fight Mode, Super Bot Fight Mode, Bot Management, leaked credential checks | `Bots` |
| Custom hostnames (Cloudflare for SaaS), fallback origin | `CustomHostnames` |
| Authenticated Origin Pulls (zone-level and per-hostname) | `OriginPulls` |
| SSL mode, minimum TLS version, HSTS, TLS switches | `Tls` |
| Logpush jobs (destinations redacted) | `Logpush` |
| API tokens: create, roll, revoke, permission groups | `ApiTokens` |

Page Shield and API Shield (0.4.0; whether a feature is available depends on the plan and is decided by Cloudflare, an unavailable one throws `CloudflareNotEntitledException`, a subclass of `CloudflareApiException`):

```csharp
var scripts = await cloudflare.PageShield.ListScriptsAsync(new PageShieldQuery { Status = "active,infrequent", ExcludeCdnCgi = true, PrioritizeMalicious = true });
var suspicious = scripts.Where(s => s.IsMalicious);
var cookies = await cloudflare.PageShield.ListCookiesAsync();

// A change is first described, shown to the user and only then sent (and only with AllowWrites = true).
var plan = cloudflare.PageShield.PreviewCreatePolicy(new PageShieldPolicyInput { Action = "log", Description = "CSP report only", Expression = "(http.host eq \"app.example.com\")", Value = "script-src 'self'" });
Console.WriteLine($"{plan.Method} {plan.Path}\n{plan.BodyJson}");

var discovered = await cloudflare.ApiShield.ListDiscoveredOperationsAsync(new ApiOperationQuery { State = "review" });
var operations = await cloudflare.ApiShield.ListOperationsAsync(new ApiOperationQuery { Host = "api.example.com" });
var validation = await cloudflare.ApiShield.GetSchemaValidationSettingsAsync();
var jwtRules = await cloudflare.ApiShield.ListTokenValidationRulesAsync();
```

Shield writes (0.5.0). Each write method has a `Preview…` sister, needs `AllowWrites` and is checked locally first:

```csharp
// Idempotent: only operations that are not saved yet are added, in one call.
var ops = await writer.ApiShield.EnsureOperationsAsync([new("GET", "api.example.com", "/v1/users/{var1}"), new("POST", "api.example.com", "/v1/orders")]);

// Schema: stored with validation OFF, the preview shows size and SHA-256 instead of the text.
var (schema, created) = await writer.ApiShield.EnsureSchemaAsync(new ApiShieldSchemaInput { Name = "api v1", Source = openApiJson },
    new ApiShieldSchemaUploadOptions { AllowedHosts = ["api.example.com"] });
await writer.ApiShield.SetDefaultActionAsync(ApiShieldActions.Log);           // "log" needs Enterprise; "block" only with allowBlock: true

// JWT validation (Enterprise + API Shield add-on): keys never appear in previews, models, ToString or errors.
var keys = JwtKeySet.Parse(jwksJson);                                          // private key members are refused
var config = await writer.ApiShield.CreateTokenValidationConfigAsync(new TokenValidationConfigInput
    { Title = "gateway", Description = "", TokenSources = ["http.request.headers[\"authorization\"][0]"], Keys = keys });

// mTLS: removing a hostname is refused unless allowRemovals: true (an mTLS rule would then lock out every client).
var change = await writer.ApiShield.PreviewReplaceHostnameAssociationsAsync(["api.example.com", "admin.example.com"]);

try { await writer.PageShield.EnsurePolicyAsync(cspReportOnly); }
catch (CloudflareNotEntitledException ex) { /* plan lacks the feature (rules need Page Shield "Advanced"); show ex.Errors */ }
```

| Write | Default | Explicit opt-in | Risk |
|---|---|---|---|
| Schema / token validation action | `log` or `none` | `allowBlock: true` for `block` | legitimate clients rejected |
| Page Shield content security rule | `log` (report only) | `allowEnforce: true` for `allow` | unlisted scripts blocked in browsers |
| mTLS hostname associations | additions only | `allowRemovals: true` | every client blocked by an mTLS rule |
| Uploaded schema | validation off | `ValidationEnabled = true` / `SetSchemaValidationEnabledAsync` | – |

Errors: `CloudflareNotEntitledException` (plan or add-on missing), `CloudflareConflictException` (409, "already exists"; the `Ensure…` methods handle it),
`CloudflareWriteNotAllowedException` (blocked locally, nothing sent), otherwise `CloudflareApiException` (for example a missing token permission).
Token permissions: "Zone: API Gateway: Edit" (operations, schemas, JWT, labels), "Zone: Page Shield: Edit", "Zone: SSL and Certificates: Edit" (mTLS).

Protection and operations (0.6.0). Same pattern: `Preview…` first, writes only with `AllowWrites`, risky options only with an explicit `allow…`:

```csharp
// Rate limiting rule by ref; only this rule is changed (PATCH/POST), nothing is written when it is already as wanted.
var (_, changed) = await writer.RateLimiting.UpsertRuleAsync(new RateLimitRuleInput
{
    Ref = "login", Expression = "(http.request.uri.path eq \"/api/login\")", Action = WafActions.ManagedChallenge, RequestsPerPeriod = 10, Period = 60,
});

// Managed rules: deploy the free managed ruleset; overrides that weaken it need allowLoosen: true.
await writer.Waf.DeployManagedRulesetAsync(ManagedRulesetIds.FreeManaged, "free-managed");

// Bot Fight Mode also challenges your own API clients and cannot be skipped: refused without allowChallengeAutomation.
var bots = writer.Bots.PreviewUpdateSettings(new BotManagementChange { AiBotsProtection = "block" });

// Authenticated Origin Pulls with your own certificate: the key stays out of previews, ToString, models and errors.
var pair = OriginPullKeyPair.FromPem(certificatePem, privateKeyPem);
var cert = await writer.OriginPulls.UploadZoneCertificateAsync(pair);
await writer.OriginPulls.SetZoneEnabledAsync(true);                  // switching off needs allowDisable: true (origin would reject Cloudflare)

var tls = await cloudflare.Tls.GetOverviewAsync();                   // SSL mode, minimum TLS, HSTS, HTTP/3, ECH, 0-RTT
await writer.Tls.SetMinTlsVersionAsync("1.2");                       // lowering needs allowWeaken, "1.3" needs allowTls13Only

var jobs = await cloudflare.Logpush.ListJobsAsync();                 // destination_conf with credentials redacted
```

API tokens (0.6.0). The value Cloudflare shows once exists only in `ApiTokenSecret`:

```csharp
var groups = await admin.ApiTokens.ListPermissionGroupsAsync(nameContains: "DNS Write");
var issued = await admin.ApiTokens.CreateAsync(new ApiTokenInput
{
    Name = "dns-edit-app", ExpiresOn = DateTimeOffset.UtcNow.AddDays(90), AllowedIps = ["203.0.113.0/24"],
    Policies = [new ApiTokenPolicyInput { PermissionGroupIds = [groups[0].Id], Resources = new JsonObject { [ApiTokenResources.Zone(zoneId)] = "*" } }],
});
secretStore.Save("cloudflare-dns", issued.Secret.TakeValue());      // hand over once; issued.ToString() and JSON show [redacted]

using var rolled = await admin.ApiTokens.RollAsync(issued.Token.Id); // the old value stops working at once
await admin.ApiTokens.RevokeAsync(oldTokenId);                       // own token: refused unless allowSelf: true
```

| Write | Default | Explicit opt-in | Risk |
|---|---|---|---|
| Rate limit / WAF rule that blocks every request | refused | `allowBroadMatch: true` | everyone locked out |
| WAF `skip` rule | refused | `allowSkip: true` | matching requests bypass protection |
| Managed rules disabled, `log`, low sensitivity, removed | refused | `allowLoosen: true` | weaker protection |
| Bot Fight Mode, (likely) automated → challenge/block | refused | `allowChallengeAutomation: true` | own API and app clients blocked |
| Verified bots → block | refused | `allowBlockVerifiedBots: true` | search engines, monitors blocked |
| Authenticated Origin Pulls off, certificate deleted, hostname disabled | refused | `allowDisable: true` | origin rejects all Cloudflare traffic |
| Custom hostname fallback origin removed | refused | `allowRemoval: true` | hostnames without own origin stop |
| Custom hostname email validation | refused | `allowEmailValidation: true` | mail to the customer's admin addresses |
| SSL mode / minimum TLS lowered | refused | `allowWeaken: true` | weaker encryption |
| Minimum TLS 1.3 | refused | `allowTls13Only: true` | older clients locked out |
| HSTS > 1 day, subdomains, preload | refused | `allowLongLivedHsts: true` | HTTPS cannot be dropped for max-age |
| DNS record proxied → DNS only | refused | `allowUnproxy: true` | origin address published |
| API token with wildcard resources / without expiry | refused | `allowBroadResources` / `allowNoExpiry` | more rights or lifetime than needed |
| Roll, disable or revoke the client's own token | refused | `allowSelf: true` | client cut off |

Token permissions (minimal, check names in the dashboard): "Zone WAF" (rate limiting, WAF, leaked credentials), "Bot Management", "SSL and Certificates"
(custom hostnames, origin pulls), "Zone Settings" (TLS), "Logs" (Logpush), "API Tokens" / "Account API Tokens" (token management, a dedicated short-lived token).
Plans (developers.cloudflare.com, 17.11.2026): rate limiting rules Free 1, Pro 2, Business 5, Enterprise 100; Super Bot Fight Mode from Pro; custom hostnames
on all plans (100 included), custom certificates Enterprise; Authenticated Origin Pulls and Logpush on all plans. Cloudflare decides: a missing feature
throws `CloudflareNotEntitledException` with Cloudflare's text.

`Certificates.CreateClientCertificateAsync` is obsolete since 0.6.0; use `ApiShield.CreateClientCertificateAsync` (CSR only, private keys refused, preview).

Workers, storage, cache and load balancing (0.7.0). Same pattern again: every write checks `AllowWrites`/`WriteFilter` first (methods that read before they write check it
**before** the read, so with `AllowWrites = false` nothing is sent), has a `Preview…` sister, checks its input locally, and risky options need an explicit `allow…`:

```csharp
// Workers: deploying code and changing secrets change what runs on the edge at once, so they need allowDeploy: true.
var preview = writer.Workers.PreviewUploadScript("api", source);                  // size and SHA-256, never the source; WARNING in the summary
await writer.Workers.UploadScriptAsync("api", source, allowDeploy: true);         // existing secrets are kept (keep_bindings)
await writer.Workers.PutSecretAsync("api", "API_KEY", WorkerSecretText.From(value), allowDeploy: true);   // the value is only in the request body
var names = await cloudflare.Workers.ListSecretsAsync("api");                     // names and types; Cloudflare never returns values
await writer.Workers.SetSchedulesAsync("api", ["*/15 * * * *"]);                  // read first, written only on change; an empty list needs allowClear
await writer.Workers.DeployVersionsAsync("api", [new(oldId, 90), new(newId, 10)], allowDeploy: true);   // gradual rollout; rollback = deploy the old version

// KV: namespaces, keys, bulk operations with Cloudflare's limits checked locally.
var (ns, _) = await writer.Kv.EnsureNamespaceAsync("cache");
await writer.Kv.PutValueAsync(ns.Id, "greeting", "hello", expirationTtl: 3600, allowOverwrite: false);
await writer.Kv.RemoveNamespaceAsync(ns.Id, allowDelete: true);                   // a namespace with keys additionally needs allowNonEmpty: true

// D1: parameters are bound, never concatenated; writes and destructive SQL need their own switch.
var rows = await writer.D1.QueryAsync(dbId, "SELECT id, name FROM users WHERE id = ?", [42]);
await writer.D1.QueryAsync(dbId, "DELETE FROM sessions WHERE expires < ?", [now], allowWriteSql: true);   // DELETE/UPDATE without WHERE, DROP, ALTER: allowDestructiveSql

// R2: buckets are private; a custom domain or the r2.dev address publishes every object.
await writer.R2.EnsureBucketAsync("assets", locationHint: "weur");
await writer.R2.EnsureCustomDomainAsync("assets", "cdn.example.com", zoneId, allowPublicAccess: true);
await writer.R2.SetLifecycleAsync("assets", [new R2LifecycleRule("ia", Prefix: "logs/", InfrequentAccessAfter: TimeSpan.FromDays(30))]);   // deleting rules: allowDeletion

// Cache: one rule at a time (phase http_request_cache_settings), purge in batches of 100, purge everything only deliberately.
await writer.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "static", Expression = "starts_with(http.request.uri.path, \"/static/\")", Cache = true, EdgeTtl = new("override_origin", 3600) });
await writer.Cache.PurgeUrlsAsync(["https://example.com/static/app.css"]);
await writer.Cache.PurgeEverythingAsync(allowPurgeAll: true);

// Load balancing: the last healthy pool of a load balancer is protected.
await writer.LoadBalancing.SetPoolEnabledAsync(poolId, false);                    // refused when it is the last healthy pool of a load balancer in the zone
await writer.LoadBalancing.SetPoolEnabledAsync(poolId, false, allowLastHealthyPool: true);
```

| Write | Default | Explicit opt-in | Risk |
|---|---|---|---|
| Upload a Worker, deploy a version, set or delete a secret | refused | `allowDeploy: true` | new code or configuration runs on the edge at once |
| Delete a Worker, also with `force` | refused | `allowDelete` / `allowForce` | code, versions, triggers, bindings gone |
| Route with a wildcard host (`*.example.com/*`) | refused | `allowBroadRoute: true` | Worker in front of every subdomain |
| Detach a Worker custom domain | refused | `allowRemoval: true` | hostname no longer served |
| Remove every cron trigger | refused | `allowClear: true` | scheduled work stops |
| Delete a KV namespace / with keys / bulk delete | refused | `allowDelete` / `allowNonEmpty` / `allowBulkDelete` | data lost |
| D1 write SQL / DROP, ALTER, DELETE or UPDATE without WHERE | refused | `allowWriteSql` / `allowDestructiveSql` | data or schema changed |
| Delete a D1 database, a queue, a Spectrum application | refused | `allowDelete: true` | data or service gone |
| Purge a queue, pause its delivery | refused | `allowPurge` / `allowPause` | messages lost, consumers idle |
| R2 custom domain or r2.dev address on | refused | `allowPublicAccess: true` | every object readable by anyone |
| R2 CORS origin `*` | refused | `allowAnyOrigin: true` | any website may call the bucket |
| R2 lifecycle rule that deletes objects | refused | `allowDeletion: true` | objects removed automatically |
| Delete an R2 bucket, remove a custom domain | refused | `allowDelete` (and the bucket must be empty) / `allowRemoval` | name may be taken, hostname dark |
| Cache rule that caches everything / edge TTL above one day | refused | `allowBroadCache` / `allowLongTtl` | private pages cached, stale content |
| Purge everything | refused | `allowPurgeAll: true` | whole load on the origin |
| Cache Reserve, Argo Smart Routing on | refused | `allowBilling: true` | usage-based charges |
| Last healthy pool disabled or emptied | refused | `allowLastHealthyPool: true` | load balancer without a target |
| Disable or delete an enabled load balancer | refused | `allowDisableActive` / `allowDeleteActive` | hostname no longer balanced |
| Monitor without certificate check | refused | `allowInsecureTls: true` | broken origin certificate stays unseen |
| Spectrum on SSH, RDP, SMB, database ports … | refused | `allowSensitivePort: true` | management port on the internet |

Secrets: Worker secret values exist only in `WorkerSecretText` (`ToString` and JSON write `[redacted]`) and in the one request body; secret bindings in upload
metadata are refused. Load balancer monitor header values (often an `Authorization` header) are redacted in every model and preview. KV values, D1 parameters
and queue message bodies are user data: previews show sizes and counts only.
Reading many KV keys, D1 queries and the like are `POST` calls on the API, so the write guard applies to them: with `AllowWrites = false` nothing is sent.
Not included (reachable through `OpenApi`): Durable Objects, Secrets Store, Hyperdrive, Workflows, Pages, D1 export/import and Time Travel restore, Queues pull/acknowledge,
R2 buckets with a jurisdiction, bucket locks, event notifications, Cache Reserve clear, Argo analytics, account-level load balancers and monitor groups.
Plans and limits (developers.cloudflare.com/kv, d1, queues, r2, workers, cache, load-balancing, spectrum, argo-smart-routing, retrieved 17.11.2026): KV key 512 B, value 25 MiB,
10 000 pairs per bulk write; D1 SQL 100 KB, 100 parameters, 10 databases on Free; queue message 128 KB, batch 100 messages; purge 100 items per request on all plans;
Spectrum custom TCP/UDP needs Enterprise with the add-on. Cloudflare decides: a missing feature throws `CloudflareNotEntitledException` with Cloudflare's text.
Token permissions (check names in the dashboard): "Workers Scripts", "Workers KV Storage", "D1", "Queues", "Workers R2 Storage" (Account, Edit; reading "Read"),
"Workers Routes", "Cache Purge", "Cache Rules", "Load Balancers", "Zone Settings" (Zone).

Obsolete since 0.7.0 (removed in 1.0): `Workers.UploadModuleAsync`, `DeleteScriptAsync`, `CreateRouteAsync`, `DeleteRouteAsync`; `R2.CreateBucketAsync`, `DeleteBucketAsync`,
`PutLifecycleAsync`, `PutCorsAsync`; `Zones.PurgeEverythingAsync`; since 0.7.1 also `Monitoring.DeleteLogpushJobAsync`. Since 0.7.1 they take the guarded paths with the
safe defaults (see the next section): methods whose risk needs a switch they do not have are always refused, the others apply the same checks.

#### Safe defaults everywhere (0.7.1)

An independent security review of 0.7.0 found ways around the `allow…` switches. Since 0.7.1 every curated method applies them:

| Method | Since 0.7.1 |
|---|---|
| `Zones.SetSettingAsync` / `SetSettingsAsync` | weaker `ssl` or `min_tls_version` (one read), TLS 1.3 only, `tls_1_3`/`always_use_https`/`opportunistic_encryption` off: refused → `Tls` with `allowWeaken` |
| `Zones.Purge…Async` | same checks as `Cache.Purge…Async`; `PurgeEverythingAsync` always refused → `Cache.PurgeEverythingAsync(allowPurgeAll: true)` |
| `Dns.UpdateAsync` / `PatchAsync` / `UpsertAsync` | a proxied record is never switched to DNS-only (→ `SafeUpsertAsync(allowUnproxy: true)`); `Proxied = null` keeps the current value |
| `Rulesets.Put…EntrypointAsync`, `UpsertRuleByRefAsync`, `RemoveRuleByRefAsync`, `Add/Update/DeleteRuleAsync` | compared with the current phase: new skip rules, blocking every request, loosening managed overrides, and in the WAF phases removing, disabling or logging instead of acting are refused → `Waf`/`RateLimiting`/`Cache` with the switch |
| `R2.DeleteBucketAsync`, `Workers.UploadModuleAsync`, `DeleteScriptAsync`, `Monitoring.DeleteLogpushJobAsync` | always refused → `RemoveBucketAsync`, `UploadScriptAsync`, `RemoveScriptAsync`, `Logpush.DeleteJobAsync` with the switch |
| `R2.PutLifecycleAsync` / `PutCorsAsync` | deleting rules and wildcard origins refused |
| `Monitoring.ListLogpushJobsAsync` / `CreateLogpushJobAsync` | destination redacted |

New switches for lock-out and loosening (each refuses locally without a request; the previews name the risk):

| Method | Switch |
|---|---|
| `ApiShield.RevokeClientCertificateAsync` | `allowRevoke` |
| `ApiShield.ReplaceTokenValidationKeysAsync` (drops a current key; one read) | `allowKeyRemoval` |
| `ApiShield.SetOverrideActionAsync("none")` | `allowLoosen` |
| `ApiShield.DeleteTokenValidationConfigAsync` / `DeleteTokenValidationRuleAsync` | `allowRemoval` |
| `Workers.AttachDomainAsync` | `allowDeploy` |
| `Waf.RemoveCustomRuleAsync` | `allowLoosen` |
| `Tls.SetSwitchAsync` (`tls_1_3`, `always_use_https`, `opportunistic_encryption` off) | `allowWeaken` |
| `CustomHostnames.Create/Ensure/UpdateAsync`, `R2.EnsureCustomDomainAsync` with minimum TLS 1.0/1.1 | `allowWeaken` |
| `Logpush.SetJobEnabledAsync(false)` / `DeleteJobAsync` | `allowRemoval` |
| `ApiTokens.UpdateAsync` on the token this client uses (one verify) | `allowSelf` |

Further: cache rule `ExtraParameters` may not set `cache`, `edge_ttl` or `browser_ttl`; Spectrum checks origin ports against the sensitive ports; R2 CORS accepts a
wildcard only as a leading `*.` before at least two labels (`https://*` counts as `*`); D1 counts PRAGMAs in their setting form (`user_version(5)`), `WHERE 1`, `WHERE 1=1`,
`… OR 'a'='a'` and triggers that delete or update as writes or destructive; a load balancer pool without monitor or health report no longer counts as healthy fallback, and
an origin with weight 0 or without address as unusable; changing one origin keeps every other member (headers such as `Host`, `virtual_network_id`); upserts check the
allow-list again with the actual plan; rolling an API token is never retried; Logpush redaction also covers bare query parameters and collector paths (`splunk://`, `datadog://`);
`ApiTokenSecret`, `WorkerSecretText`, `OriginPullKeyPair` and `JwtKeySet` hide their values from the debugger and overwrite their buffer on `Dispose`.

Limits (documented, not enforced): expressions that match every request are recognised syntactically (`true`, `not false`, `1 == 1`, `http.host ne ""`,
`ip.src in {0.0.0.0/0 ::/0}`, also behind a top-level `or`), not by evaluation; the D1 classification does not evaluate expressions either. `CloudflareNotEntitledException`
and `CloudflareConflictException` are recognised from Cloudflare's status code and message text; use them for messages, not to steer security decisions.
Preview methods ending in `…Async` (for example `PreviewSetSslModeAsync`, `PreviewUpsertAsync`, `Preview…RuleAsync`) **read** the current state with GET requests; the
other `Preview…` methods send nothing.

Edge status and lists (0.3.0):

```csharp
// A list the watchdog fills itself: one rule refers to it ("ip.src in $watchdog"), so it costs one rule slot however many addresses it holds.
var list = await cloudflare.Lists.EnsureAsync("watchdog", description: "Blocked by the watchdog");
var op = await cloudflare.Lists.AddIpsAsync(list.Id, ["203.0.113.7", "198.51.100.0/24"], comment: "ssh scan");
await cloudflare.Lists.WaitForOperationAsync(op.OperationId);   // the change runs asynchronously; throws when it failed

await cloudflare.IpAccess.CreateAsync(IpAccessModes.Block, IpAccessTargets.Ip, "203.0.113.9", notes: "scanner");

var gaps = await cloudflare.Certificates.FindUncoveredHostnamesAsync(["app.example.com", "a.b.example.com"]);  // names no active certificate covers
var connectors = await cloudflare.Tunnels.ListConnectionsAsync(tunnelId);                                       // replicas and their data centres
var sent = await cloudflare.Monitoring.ListAlertHistoryAsync(since: DateTimeOffset.UtcNow.AddDays(-1));         // notifications that were sent
var refused = (await cloudflare.Access.ListRequestLogsAsync(limit: 200)).Where(l => !l.Allowed);              // Access request log
var ips = await cloudflare.Ips.GetAsync(); var viaCloudflare = ips.Contains(remoteAddress);                    // ranges as trusted proxies
```

### Raw access

Any endpoint, with the same guard, retries and error handling. `Api` and the generated `OpenApi` client know only `AllowWrites` and `WriteFilter`: none of the
`allow…` switches, previews or lock-out checks of the curated clients apply there. Use them for reads and for writes you have checked yourself.

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
builder.Services.AddCloudflareInfinitySuite360Core(builder.Configuration);   // registers ICloudflareAccessJwtValidator (singleton: it holds the key cache)
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

A tag `v<major>.<minor>.<patch>` on `master` builds, tests and publishes all four packages (`.OpenApi`, `.Core`, the full package, `.AspNetCore`) to GitHub Packages
(`.github/workflows/ci.yml`).

## Licence

Not chosen yet. The OpenAPI schema used for generation is © Cloudflare, Inc., BSD-3-Clause.
