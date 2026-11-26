# Changelog

## 0.9.1 – unreleased

Hardening of stage P6 after an independent review of 0.9.0 (one high, three medium, eight low findings). Contains 0.9.0, which was never published on a feed.
Every finding is covered by tests with the fake handler and a fake clock (no network, no real token).

* **H-1 last super administrator (high):** `Members.RemoveAsync` also recognises a super administrator by policy (`policies[].permission_groups[].name`
  "Super Administrator – All Privileges", allow policies only; new models `AccountMemberPolicy`, `AccountPermissionGroup`, `AccountResourceGroup`), counts only
  members with status `accepted` (a pending invitation cannot step in), refuses a member that carries neither roles nor policies (fail-closed), and runs list and
  DELETE under one lock per account and API address in the process (64 stripes), so two parallel removals cannot both pass. Remaining gap, documented: changes
  from outside the process between list and DELETE (no conditional DELETE at Cloudflare).
* **M-1 budget deadline and queue (medium):** `MaxDelay` now bounds the whole wait of one call (deadline = start + `MaxDelay`, across every re-check, also when a
  429 extends the block while the call waits); waiting calls are served first come, first served (one queue per kind, so a waiting read never holds up a write);
  new `RateBudget.MaxQueued` (default 1000): one more waiting call fails at once (`CloudflareRateBudgetExceededException.QueueFull`); `Delayed` is raised once per
  call; a cancelled call gives up its place. `HttpClient.Timeout` does not cover this wait; the budget's deadline and the cancellation token do.
* **M-2 monotonic time (medium):** the window, the 429 block and the pruning use `TimeProvider.GetTimestamp`/`GetElapsedTime`; a changed system time neither
  frees nor blocks slots. `Snapshot().BlockedUntil` is wall-clock time for display only. Note for own `TimeProvider`s in tests: override `GetTimestamp` too.
* **M-3 client factory (medium):** a cached client is replaced when *any* option value changes (keyed hash over every read-write property of the options and of
  their nested option objects, except the token and the filter delegate, which are compared separately), not only the fields of `ToString`; `Clone` is deep
  (`Turnstile`, `AccessJwt` with its audience list, `RateBudget`); compare-and-build runs under a lock, so parallel first calls get the same client.
* **L-1:** the coverage tests read commit, checksum and operation count from `openapi/cloudflare-openapi.lock.json` and `openapi/GENERATION.md` instead of fixed
  values, so the weekly regeneration (`openapi-update.yml`) passes for a new schema.
* **L-2:** the reads a write method makes to prepare its change (member list before a removal, current state before Ensure/upsert) count against the write share
  until the write is sent. The mark starts at the write guard check and lives in the asynchronous flow of the method; the 16 public write methods that were
  synchronous (`Task`-returning without `async`) are `async` now, so the mark never reaches the caller (their argument and guard exceptions now arrive through the
  task instead of being thrown at the call). The four always-refused obsolete Access methods check the guard without marking.
* **L-3:** an exception in a `Delayed`/`Throttled` subscriber is swallowed and counted (`cloudflare.budget.subscriber_errors`); the 429 answer is disposed if
  reporting it fails (connection and `CloudflareRateBudgetHandler`).
* **L-4:** `[DebuggerBrowsable(Never)]` on `CloudflareOptions.ApiToken`, `TurnstileOptions.SecretKey`, `AccessServiceToken.ClientSecret`, `TurnstileWidget.Secret`
  and the value of `CloudflareOneTimeSecret`; `TurnstileOptions.ToString` without the secret.
* **L-5:** the budget registry keeps at most `MaxBudgets` (1024) budgets: idle budgets are removed, least recently used first; a client that still holds a
  removed budget is moved to the current budget of its token on its next request (no split count). At most 100 budget labels per process in metrics, then `other`.
  New counter `cloudflare.budget.refused`.
* **L-6:** Pages and Workflows remove every secret-looking member from their answers in addition to their named members (`ResourceKit.SendHiddenSecretFreeAsync`,
  `ListHiddenSecretFreeAsync`).
* **L-7:** `Retry-After` as HTTP date is read with the budget's clock (connection and `CloudflareRateBudgetHandler`; the handler read only seconds before).
* **L-8 tests:** WriteFilter-before-read for *all* curated clients (reflective), single-dot ids (`.`, `%2e`) in the reflective path test and in named calls,
  `Workflows.ChangeInstanceStatusAsync` reached by the reflective surface (the scenario workaround is gone), parallelism, clock jumps and cancellation in the
  budget, factory race. A fifth sample answer (list item with status and role) keeps `Members.RemoveAsync` in the coverage matrix.
* Supply chain (documentation): the packages are not published on a feed; the platform keeps them in its local feed with `SHA512SUMS`. Reserving the prefix
  `InfinitySuite360.*` on nuget.org is an open task for the owner of the organisation (protects against a foreign package with the same id).
* Tests: 28 new, 473 in total.

**Breaking changes (against the unpublished 0.9.0)**

* `WorkflowsClient.ChangeInstanceStatusAsync` and `PreviewChangeInstanceStatus` take `WorkflowInstanceAction` (`Pause`, `Resume`, `Restart`, `Terminate`) instead of a
  string; an undefined value throws `ArgumentOutOfRangeException`.
* `CloudflareRateBudgetExceededException` is a regular class (new `QueueFull`); `CloudflareRateBudgetSnapshot` has `Queued`; `RateBudget.MaxDelay` is limited to
  24 hours; budgets measure with `TimeProvider.GetTimestamp`.
* Behaviour: a preparing read of a write method draws from the write share; the 16 former synchronous write methods report argument and guard errors through the
  returned task.

## 0.9.0 – unreleased

Stage P6 of the plan: cross-cutting work and the rest of the API. Contains 0.8.1. Defaults are cautious; no real Cloudflare call in any test (fake handler only).

* **Coverage matrix as a tool:** `dotnet run tools/coverage.cs` writes [openapi/COVERAGE.md](openapi/COVERAGE.md) from the schema and from reflection over every
  curated client (each public method is called with sample arguments against a fake handler, each request is matched against the schema): per product area the
  operations, how many are curated (GET and writes), how many are only reachable through `OpenApi`, and the priority. It replaces the hand-maintained file. The
  test `CoverageReportTests.Coverage_md_is_current` fails when the file is stale; `--check` does the same locally. New `openapi/operations.tsv`: compact index
  (method, path template) of the pinned schema `cloudflare/api-schemas@650bd71`, written by `coverage.cs --index` (called by `generate.cs`). The former contents of
  COVERAGE.md (schema counts, normalization) moved to `openapi/GENERATION.md`. The weekly update workflow regenerates COVERAGE.md before the tests.
* **Contract tests against the schema:** every method and path a curated client sends must be an operation of the schema; deliberate exceptions are listed with
  their reason (GraphQL; generic Radar dataset). The test found two endpoints that are not in the schema and are kept for compatibility (open points):
  `IpAccess.GetAsync` (GET of a single zone IP access rule) and `Tunnels.ListConnectorsAsync` (connector list; use `ListConnectionsAsync`).
* **`ICloudflareClientFactory` for several tenants:** one client per tenant with its own copy of the options, a shared HTTP connection pool, a cached client is
  never reused for another token or changed settings, `Dispose`. Registration: `AddCloudflareTenant(name, section | configure)` and `AddCloudflareClientFactory()`
  (core), `AddCloudflareTenants(section, resolve)` with `ValidateOnStart` and `HttpContext.GetCloudflareClient()` (AspNetCore package). Tenant names: letters,
  digits, `.`, `_`, `-`, at most 64.
* **Request budget per token:** `CloudflareRateBudget` counts the requests of all clients that share a token in a sliding window (default 1200 per five minutes)
  and delays a request before it is sent when the share of its kind is used up (reads 80 %, writes 95 %); a 429 blocks the budget until `Retry-After`;
  `MaxDelay` (default five minutes) bounds the wait (`CloudflareRateBudgetExceededException`, nothing sent). Events `Delayed`/`Throttled`, `Snapshot()`, meter
  `InfinitySuite360.Cloudflare`. Registry keyed by an HMAC of the token with a random key per process; labels are the tenant name or a short keyed hash.
  `CloudflareRateBudgetHandler` puts the generated client on the same budget.
* **Narrow wrappers for priority-3 areas:** `Images`, `Stream`, `Registrar`, `Members`, `AuditLogs` (v2), `Radar`, `Pages`, `Hyperdrive`, `Workflows`,
  `DurableObjects`, `SecretsStore`: typed reads; writes only where sensible (deletes with `allowDelete`, auto-renew off with `allowDisableAutoRenew`, member removal
  with `allowRemoval` and protection of the last super administrator, Pages rollback with `allowDeploy`, Workflows terminate/restart with `allowTerminate`), each
  with `Preview…`; secrets removed from every answer (Hyperdrive password and access secret, Pages environment variables, Secrets Store values, Workflows
  parameters and step outputs). What stays `OpenApi` only, and why, is listed in the README with plans and limits (developers.cloudflare.com, retrieved 17.11.2026).
* **One helper base:** the helper classes `P1`, `P2` and `ZT` are merged into `ResourceKit` without a change of behaviour (`ZT.Strip` → `StripSecrets`,
  `ZT.SendAsync` → `SendSecretFreeAsync`, `ZT.ResultAsync` → `SecretFreeResultAsync`, `ZT.GetListAsync`/`ListAllAsync`/`GetOrNullAsync` → `…SecretFree…`); the
  record `CloudflareChangePreview` has its own file; `CloudflareResourceClient` gained `Preview`, `GuardedWriteAsync` and `GuardedDeleteAsync`. The reflective
  guard tests (no write without `AllowWrites`, no preparing read before the guard, no `..` path) cover the new clients automatically.
* **Options:** `CloudflareOptions.RateBudget`, `Clone()`, and `ToString()` without the token (`[redacted]`); `CloudflareApiConnection.RateBudget` (init) and
  `ToString()`.
* Tests: 50 new (`CoverageReportTests`, `ClientFactoryTests`, `RateBudgetTests`, `Priority3Tests`), 445 in total; the reflective sample arguments know domain names and
  start times.

**Breaking changes**

* `ICloudflareClient` has eleven new members (`Images`, `Stream`, `Registrar`, `Members`, `AuditLogs`, `Radar`, `Pages`, `Hyperdrive`, `Workflows`,
  `DurableObjects`, `SecretsStore`): only own implementations of the interface are affected (in practice test doubles).
* Behaviour: clients from dependency injection (`AddCloudflareInfinitySuite360`, `AddCloudflareInfinitySuite360Core`) now count against the request budget and
  **wait** instead of running into 429 once 960 reads or 1140 writes were sent in five minutes with one token. Switch it off with `Cloudflare:RateBudget:Enabled =
  false`. `CloudflareClient.Create` without a registry is unchanged.
* `CloudflareOptions.Validate` also checks `RateBudget` (a null `RateBudget` or shares outside (0, 1] are refused).
* `openapi/COVERAGE.md` has a new format; the old counts are in `openapi/GENERATION.md`.
* Internal only (no public API): `P1`, `P2`, `ZT` no longer exist.

## 0.8.1 – unreleased

Security hardening of the Zero Trust clients after an independent review of 0.8.0; contains 0.7.1 (merged). Defaults are cautious: every finding refuses locally
(or after the fresh read) and names the switch. All findings are covered by tests with the fake handler (no network, no real token).

* **H1 path traversal (high):** with the 0.7.1 fix an id `..` (also `%2e%2e`, `.`) is refused in every Access, Gateway, Tunnels and Devices method before anything is
  sent. Regression tests per client (reflective over every public method) and for the reviewed calls (`ChangeApplicationPolicyAsync("..", …)`,
  `RemoveApplicationPolicyAsync("..", …)`, `Tunnels.RemoveAsync("..")` and others).
* **H2 Access loosening (high):** a) added include rules of an allow/bypass/non_identity policy (also `ip 0.0.0.0/0`, `email_domain`, `any_valid_service_token`)
  are loosening; b) a deny policy that gets exclude or require rules matches fewer requests (loosening); c) "admits everyone" also with a require rule that does not
  narrow (`everyone`, 0.0.0.0/0), with `ip` shorter than /8 (IPv6 /16, 0.0.0.0/0, ::/0), `any_valid_service_token` and the `email_domain` of a public mail provider;
  d) an earlier precedence (admitting) or a later one (deny) and a longer `session_duration` are loosening; e) `ChangeApplicationPolicyAsync`/`ChangePolicyAsync` lay
  the change over the current policy, so `approval_required`, `approval_groups`, `isolation_required`, `purpose_justification_required`, `mfa_config`,
  `connection_rules` are kept instead of being reset by the PUT.
* **H3 Gateway (high):** permissive actions (`allow`, `off`, `noscan`, `noisolate`, `override`, `l4_override`, `resolve`, `egress`) that match all traffic (empty or
  tautological selector) or that would run before an enabled protective rule of the same filter need `allowLoosen` (`EnsureRuleAsync` – new parameter –, `ChangeRuleAsync`);
  `SetRuleEnabledAsync(true)` of a permissive rule needs `allowLoosen`; the rule comparison covers precedence (protective later), filters and `rule_settings`; the PUT of
  `ChangeRuleAsync` keeps `schedule`, `expiration`, `rule_settings`, `precedence` and other members the input does not set.
* **M1 ingress:** `originRequest` per rule counts in the diff and is kept by `UpsertIngressRuleAsync`; a path rule without hostname is treated like a catch-all
  (`allowCatchAllService`); the diff compares the first matching rule before and after (a wildcard or a new order that answers first is "shadowed", `allowDisconnect`);
  the configuration version is read again right before the PUT (concurrent change: `CloudflareConflictException`).
* **M2 device profiles:** loosening settings already at `EnsureProfileAsync` need `allowLoosen` (new parameter); the broad-match check knows `identity.email matches ".*"`,
  `ne ""`, `os.name in {…}` with every platform, `… or true`; changing the match of a profile is loosening.
* **M3 Split Tunnel:** exclusions shorter than /8 (IPv6 /16, 0.0.0.0/0, ::/0) need `allowBroadRoute` (new parameter); the profile is read and Include mode is refused.
* **M4:** `EnsureApplicationAsync` validates inline policy objects like `AddApplicationPolicyAsync` and reads policies referenced by id (admitting everyone:
  `allowLoosen`, deny for everyone: `allowBlock`, new parameters; fail-closed); unknown policy entries are refused.
* **M5:** changing the rules of a group that policies, applications or groups use needs `allowInUse` (new parameter of `ChangeGroupAsync`); the PUT keeps unknown members.
* **M6:** `Gateway.AddListItemsAsync` checks the rules that use the list (`allowInUse`, new parameter); removing entries or lists reports disabled rules as well.
* **M7 obsolete methods:** the 17 obsolete Access and 6 obsolete Tunnels methods carry `[EditorBrowsable(Never)]` and go through the guarded methods with every
  `allow…` switch off (`PublishHostnameAsync` is `PublishAsync` with `SafeUpsertAsync`, `PutConfigurationAsync` is `SetIngressAsync`); `UpdateApplicationAsync`,
  `UpdateIdentityProviderAsync`, `CreateServiceTokenAsync`, `RotateServiceTokenAsync` and `GetTokenAsync` are always refused. No obsolete method returns a secret.
* **M8:** `RemoveIdentityProviderAsync` refuses (`allowRemoveLast`) when an application allows only this provider.
* **L1:** `RemoveServiceTokenAsync` also checks groups and policies bound to applications. **L2:** longer `session_duration`/`warp_auth_session_duration`,
  `allow_authenticate_via_warp` on and `is_ui_read_only` off need `allowLoosen`. **L3:** one rule for secret member names in `Strip` and `Redact` (names of
  `ZT.SecretMembers` plus everything with "secret", "password", "private_key", "credential"). **L4:** `GetRunTokenAsync` needs `allowReadSecret` (new parameter).
  **L5:** `UpdatePostureRuleAsync` writes only on change, keeps `expiration`, and counts device profile matches as users. **L6:** version re-check for tunnel
  configurations; the other Zero Trust endpoints offer no `If-Match` (documented). **L7:** a tunnel whose ingress still serves hostnames is not deleted without
  `allowDeleteActive`, also when it is "down". **L8:** `PublishAsync` checks that the zone belongs to the tunnel's account, refuses to re-point an existing CNAME
  without `allowDisconnect`, reads the DNS plan before the ingress write and rolls the ingress back when the DNS write fails.
* Tests: 37 new (`ZeroTrustHardeningTests`, 395 in total), among them the ones the review missed: `WriteFilter` before every preparing read of the Zero Trust clients
  (reflective), the async previews send no write, allow switch refusals of `SetCertificateHostnamesAsync`/`RemoveCertificateAsync`, `ChangeGroupAsync`,
  `RemoveVirtualNetworkAsync` with routes, `ChangeRuleAsync`, `SetLoggingAsync`, `UpdateProfileAsync` with a match change, `PublishAsync` with a redirect;
  `originRequest`, Gateway permissive rules, Split Tunnel. Test infrastructure: `ClientSurface` uses a `NullabilityInfoContext` per thread (the reflective tests run
  in parallel) and builds value tuples.
* **Breaking (behaviour):** the methods above refuse what 0.8.0 wrote; the obsolete methods listed under M7 refuse or check; `GetRunTokenAsync` without
  `allowReadSecret` is refused; `UpdatePostureRuleAsync`, `PublishAsync`, `RemoveAsync`, `SetSplitTunnelExcludeAsync` and the ingress writes send additional GET requests.
* **Breaking (source, rare):** new optional parameters after the account parameter and before the `CancellationToken`: `Access.EnsureApplicationAsync(…, allowLoosen,
  allowBlock)`, `ChangeGroupAsync(…, allowInUse)`, `Gateway.EnsureRuleAsync(…, allowLoosen)`, `AddListItemsAsync(…, allowInUse)`, `Devices.EnsureProfileAsync(…, allowLoosen)`,
  `SetSplitTunnelExcludeAsync(…, allowBroadRoute)`, `Tunnels.GetRunTokenAsync(…, allowReadSecret)`; calls that pass the token positionally need `ct:`.
  `AccessApplication` has the new property `AllowedIdps`.

## 0.8.0 – unreleased

Zero Trust: Access, Gateway, Tunnels and WARP devices as typed, guarded clients, DLP and risk scoring read-only. Same rules as 0.5.0–0.7.0: every write checks
`AllowWrites`/`WriteFilter` first (methods that read before writing check it **before** the read; POST calls that only read, such as Access policy tests, fall under the
guard as well), has a `Preview…` sister that sends nothing, validates input locally, writes only on change, and risky options need an explicit `allow…` switch; POST is
never repeated after a server error. New: **lock-out protection** for Zero Trust – checks that depend on the current state read it right before the write and refuse when
it cannot be read (fail-closed). Endpoints from `cloudflare/api-schemas@650bd71`; limits from developers.cloudflare.com/cloudflare-one/account-limits/ and
…/tunnel/reference/tunnel-tokens/ (retrieved 17.11.2026, sources in the XML documentation).

* New `CloudflareOneTimeSecret` (like `ApiTokenSecret`: `TakeValue` once, `ToString`/JSON `[redacted]`) for Access service token client secrets and tunnel run tokens.
* `Access` (extended, now `partial`): `EnsureApplicationAsync` (needs a policy unless `allowNoPolicy`), `RemoveApplicationAsync` (`allowUnprotect`), `RevokeApplicationTokensAsync`
  (`allowDisconnect`); application policies `AddApplicationPolicyAsync`, `ChangeApplicationPolicyAsync`, `RemoveApplicationPolicyAsync`; reusable policies `GetPolicyAsync`,
  `EnsurePolicyAsync`, `ChangePolicyAsync`, `RemovePolicyAsync`. **Lock-out protection:** the last policy of an application, or the last one that admits anyone, is not removed
  without `allowRemoveLast` (reusable policies: all applications are read, fail-closed). **Loosening** (bypass, allow/non_identity for everyone, more permissive decision,
  removed require/exclude rules, narrower deny, removing a deny policy) needs `allowLoosen`; deny for everyone needs `allowBlock`. Policy tests `StartPolicyTestAsync`
  (guarded POST), `GetPolicyTestAsync`, `ListPolicyTestUsersAsync`. Groups `EnsureGroupAsync`, `ChangeGroupAsync`, `RemoveGroupAsync` (`allowInUse` when policies,
  applications or groups refer to it). Service tokens `IssueServiceTokenAsync` (secret only in `IssuedServiceToken.ClientSecret`, "forever" needs `allowNoExpiry`),
  `RotateServiceTokenSecretAsync` (grace period or `allowDisconnect`), `RemoveServiceTokenAsync` (used or referenced tokens need `allowDisconnect`). Identity providers
  `EnsureIdentityProviderAsync` (secrets redacted in the preview, stripped from the model), `RemoveIdentityProviderAsync` (last one: `allowRemoveLast`). mTLS root
  certificates `ListCertificatesAsync`, `EnsureCertificateAsync` (public PEM only, private keys refused, preview with size and SHA-256), `SetCertificateHostnamesAsync`
  and `RemoveCertificateAsync` (`allowRemovals`), `GetCertificateSettingsAsync`. Organization `GetOrganizationAsync`, `UpdateOrganizationAsync` (PATCH of changed fields;
  team domain `allowDisconnect`, deny unmatched requests / MFA for all apps on `allowBlock`, off `allowLoosen`). Users `ListUsersAsync`, `ListActiveSessionsAsync`,
  `RevokeUserSessionsAsync` (`allowDisconnect`, e-mail not in the preview). `AccessRules.ValidCertificate()`.
* New `Gateway` (`ZeroTrustGatewayClient`): rules (`ListRulesAsync`, `EnsureRuleAsync`, `ChangeRuleAsync`, `SetRuleEnabledAsync`, `RemoveRuleAsync`; no default action, a protective
  rule without selector needs `allowBroadMatch`, block → allow and disabling/deleting/re-matching a protective rule `allowLoosen`, allow → block and enabling a block rule
  `allowBlock`, read-only rules refused), lists (`EnsureListAsync`, `AddListItemsAsync`, `RemoveListItemsAsync`, `RemoveListAsync`; entries checked per type, at most 5000;
  lists used by an enabled rule need `allowInUse`), DNS locations (`EnsureLocationAsync`, `RemoveLocationAsync` with `allowDelete`), configuration (`UpdateConfigurationAsync`:
  PATCH of the changed sections merged with a fresh read; inspection/antivirus/activity log off `allowLoosen`, TLS decryption on or another certificate `allowTlsDecrypt`,
  fail-closed `allowBlock`), logging (`SetLoggingAsync`: PII redaction off `allowPii`, less logging `allowLoosen`), proxy endpoints, inspection certificates (create, activate,
  deactivate/delete in use `allowDisable`), categories, application types, account.
* `Tunnels` (extended, now `partial`): `EnsureAsync` (run token of a new tunnel only in `EnsuredTunnel.RunToken`), `GetRunTokenAsync`, `RotateRunTokenAsync` (tunnel secret
  generated locally, `allowDisconnect`), `RemoveAsync` (connected tunnels and tunnels with routes need `allowDeleteActive`; tunnel, connectors and routes are read, fail-closed),
  `DisconnectAsync`; ingress `PreviewSetIngressAsync`, `SetIngressAsync`, `UpsertIngressRuleAsync`, `RemoveIngressRuleAsync`, `PublishAsync` – removing or re-pointing a hostname
  needs `allowDisconnect`, a forwarding catch-all `allowCatchAllService`, `originRequest` and `warp-routing` are kept, written only on change; private routes
  (`ListRoutesAsync`, `EnsureRouteAsync` with `allowBroadRoute` below /8 or /16 and a conflict for a network of another tunnel, `MoveRouteAsync`, `RemoveRouteAsync`); virtual
  networks (`EnsureVirtualNetworkAsync`, `SetDefaultVirtualNetworkAsync` with `allowDefaultChange`, `RemoveVirtualNetworkAsync` refuses the default network).
* New `Devices` (`DevicesClient`): default and custom profiles (`UpdateDefaultProfileAsync` always `allowBroadProfile`; `EnsureProfileAsync`/`UpdateProfileAsync` with a match
  for all devices `allowBroadProfile`; loosening – WARP can be switched off, mode switch, leaving, self-updates, no auto-reconnect – `allowLoosen`; `RemoveProfileAsync`
  `allowDelete`), Split Tunnel (`SetSplitTunnelExcludeAsync`: new exclusions `allowLoosen`, removed ones `allowDisconnect`), fallback domains (read), posture rules (ensure, update
  and delete; rules used by Access or Gateway need `allowInUse`), devices (read, `maxItems`), registrations revoke (`allowDisconnect`) and un-revoke (`allowLoosen`). Previews
  of device operations carry counts only.
* New `Dlp` (`DlpClient`, read-only): profiles without patterns and word lists, datasets without cells, payload log settings. New `RiskScoring` (`RiskScoringClient`,
  read-only): behaviors and user summary.
* **Secrets:** `client_secret`, `secret`, `token`, `tunnel_secret`, `credentials_file`, `private_key`, `password` and similar members are removed from every Zero Trust answer
  before a model is built – also in the older `Access.List…/Get…` (applications, service tokens, identity providers) and `Tunnels.ListAsync/GetAsync/CreateAsync`
  (behaviour change: these members are no longer in `AdditionalData`).
* **Obsolete** (still working, removed in 1.0): `Access.CreateApplicationAsync`, `UpdateApplicationAsync`, `DeleteApplicationAsync`, `CreateApplicationPolicyAsync`,
  `UpdateApplicationPolicyAsync`, `DeleteApplicationPolicyAsync`, `CreatePolicyAsync`, `DeletePolicyAsync`, `CreateGroupAsync`, `UpdateGroupAsync`, `DeleteGroupAsync`,
  `CreateServiceTokenAsync`, `RotateServiceTokenAsync`, `DeleteServiceTokenAsync`, `CreateIdentityProviderAsync`, `UpdateIdentityProviderAsync`, `DeleteIdentityProviderAsync`,
  the property `AccessServiceToken.ClientSecret`; `Tunnels.CreateAsync`, `DeleteAsync`, `CleanupConnectionsAsync`, `GetTokenAsync`, `PutConfigurationAsync`,
  `PublishHostnameAsync`. With `TreatWarningsAsErrors` callers have to switch to the guarded replacements or suppress CS0618.
* **Breaking (source, rare):** `ICloudflareClient` has the new members `Gateway`, `Devices`, `Dlp`, `RiskScoring` (own implementations, in practice test doubles, must add them).
  `AccessClient` and `TunnelsClient` are now `partial`; `AccessServiceToken` has the new properties `Enabled` and `LastSeenAt`. No other public signature changed.
* Not included (reachable through `OpenApi`): Access SCIM, JIT logs, infrastructure targets, MCP portals, bookmarks, custom pages, tags, application settings; Gateway PAC files,
  audit SSH, egress pairs, rule expiration reset, list upload; DEX, posture integrations, override codes, IP profiles, managed networks, deployment groups; DLP writes and dataset
  uploads; email security; risk score reset.
* Tests: 41 new (`ZeroTrustTests`, 251 in total) with the fake handler: success, errors, rate limit (429 retried), not entitled, conflict, previews send nothing, `AllowWrites = false` sends
  nothing (66 write methods including POST reads), `WriteFilter` before the preparing read, every unconditional allow switch refuses without a request, conditional checks
  send no write (last policy, loosening, organization defaults, groups/lists/posture rules in use, used service tokens, connected tunnels, ingress removals, Gateway rule
  direction, inspection settings, PII, device profiles, Split Tunnel), fail-closed when the state cannot be read, secrets never in models, previews, `ToString` or errors.

## 0.7.1 – unreleased

Security hardening after an independent review of 0.7.0. Defaults are cautious: where an older method had no switch for a risk, it now refuses (and names the
guarded replacement) instead of writing. All findings are covered by tests with the fake handler (no network, no real token).

* **H-1 path traversal (high):** `Uri.EscapeDataString` does not encode `.`, and `new Uri(base, path)` resolves dot segments, so an id `..` turned
  `DELETE zones/{zone}/dns_records/..` into `DELETE zones/{zone}/`. `CloudflarePath.Of` now refuses `.`, `..` (also percent-encoded, also double-encoded), empty
  segments, control characters, `/` and `\` inside a segment (`ArgumentException`, nothing sent). New `CloudflarePath.Append` for free-form names that may contain `/`
  (KV keys, sent as `%2F`). The connection refuses such paths for reads and writes (`CloudflarePath.EnsureSafe`, also for raw `Api` calls), and
  `CloudflareWritePolicy.EnsureAllowed` checks the path as Cloudflare resolves it: a path that resolves elsewhere is refused, `WriteFilter` sees the resolved path.
  Regression test: every public method of every curated client is called with `..` and `%2e%2e` for every string; no path with a dot segment reaches the connection.
* **H-2 load balancing (high):** changing one origin rebuilt the pool from the typed model and dropped `header` (`Host`) and `virtual_network_id` of every origin.
  `SetOriginEnabledAsync`, `UpsertOriginAsync` and `RemoveOriginAsync` now work on the origins as Cloudflare returned them and change only the one origin
  (`UpsertOriginAsync` keeps members the input cannot express).
* **M-1 old methods around the switches:** `Zones.SetSettingAsync`/`SetSettingsAsync` apply the TLS guards (weaker `ssl`/`min_tls_version`, TLS 1.3 only,
  `tls_1_3`/`always_use_https`/`opportunistic_encryption` off are refused); `Zones.Purge…Async` use the checks of `Cache.Purge…Async`, `Zones.PurgeEverythingAsync` is always
  refused; `Dns.UpdateAsync`/`PatchAsync`/`UpsertAsync` never switch a proxied record to DNS-only (`UpsertAsync` is `SafeUpsertAsync` without `allowUnproxy`);
  `Rulesets.PutPhaseEntrypointAsync`, `PutAccountPhaseEntrypointAsync`, `UpsertRuleByRefAsync`, `RemoveRuleByRefAsync`, `AddRuleAsync`, `UpdateRuleAsync`, `DeleteRuleAsync`
  refuse new skip rules, blocking every request, loosening managed overrides and, in the WAF phases, removing, disabling or "log instead of act" (compared with the
  current phase; unchanged rules never count); `R2.DeleteBucketAsync`, `Workers.UploadModuleAsync`, `Workers.DeleteScriptAsync` and the newly obsolete
  `Monitoring.DeleteLogpushJobAsync` are always refused; `R2.PutLifecycleAsync` refuses deleting rules, `R2.PutCorsAsync` wildcard origins;
  `Monitoring.ListLogpushJobsAsync`/`CreateLogpushJobAsync` redact the destination. The README marks `Api`/`OpenApi` as "only `AllowWrites`/`WriteFilter`".
* **M-2:** cache rule `ExtraParameters` may not set `cache`, `edge_ttl` or `browser_ttl` (they bypassed `allowBroadCache`/`allowLongTtl`).
* **M-3:** Spectrum checks `OriginDirect` ports and `OriginPort` against the sensitive ports (`allowSensitivePort`).
* **M-4:** R2 CORS: `https://*`, `http://*` and `https://*.com` count as `*` (`allowAnyOrigin`); a wildcard is only valid as a leading `*.` before at least two labels.
* **M-5:** D1: PRAGMAs are read-only only in their reading form (`user_version(5)` and `= 5` write; `schema_version`/`writable_schema` set = destructive; `journal_mode`
  is no longer read-only); DELETE/UPDATE with a WHERE part without a column (`WHERE 1`, `1=1`, `?`, `… OR 'a'='a'`) or a self-comparison (`id = id`) are destructive; the
  top-level WHERE counts (a selective subquery no longer hides `WHERE 1 OR …`); triggers that delete or update are destructive.
* **M-6:** `Dns.SafeUpsertAsync` (and `UpdateAsync`) keep the current `proxied` value when `Proxied` is null (the PUT made the record DNS-only before).
* **M-7:** `ApiTokens.UpdateAsync` refuses to change the token the client uses unless `allowSelf` (one verify call).
* **M-8 new switches** (each refuses locally without a request; the previews name the risk): `ApiShield.RevokeClientCertificateAsync` (`allowRevoke`),
  `ReplaceTokenValidationKeysAsync` (a key set that drops a current key, read first: `allowKeyRemoval`), `SetOverrideActionAsync("none")` (`allowLoosen`),
  `DeleteTokenValidationConfigAsync`/`DeleteTokenValidationRuleAsync` (`allowRemoval`); `Workers.AttachDomainAsync` (`allowDeploy`); `Waf.RemoveCustomRuleAsync` (`allowLoosen`);
  `Tls.SetSwitchAsync` off for `tls_1_3`, `always_use_https`, `opportunistic_encryption` (`allowWeaken`); minimum TLS 1.0/1.1 in `CustomHostnames.Create/Ensure/Update…`
  and `R2.EnsureCustomDomainAsync` (`allowWeaken`); `Logpush.SetJobEnabledAsync(false)`/`DeleteJobAsync` (`allowRemoval`).
* **N-1:** `PUT …/tokens/{id}/value` (rolling a token) is never retried (`CloudflareWritePolicy.IsIdempotent(method, path)`, also in the generated client's retry handler).
* **N-2:** in the last-healthy-pool check a pool without monitor or health report is "unknown" and no longer counts as healthy fallback; origins with weight 0 or without
  address count as unusable (also in `UpsertOriginAsync`).
* **N-3:** upserts (`Dns.SafeUpsertAsync`, the ruleset phase clients) check the allow-list again with the method and path of the actual plan before writing;
  `Dns.SafeUpsertAsync` checks the two possible plans (POST of a new record, PUT below `dns_records/`) before the read.
* **N-4:** `MatchesAll` recognises `not false`, `!false`, `1 == 1`, `"a" eq "a"`, `http.host ne ""`, `len(…) ge 0`, `starts_with(http.request.uri.path, "/")`,
  `matches ".*"`, `ip.src in {0.0.0.0/0 ::/0}` and these behind a top-level `or`. Limit documented: syntactic, no evaluation.
* **N-5:** `ApiTokenSecret`, `WorkerSecretText`, `OriginPullKeyPair` and `JwtKeySet` carry `[DebuggerDisplay]` without the value, hide their buffer from the debugger
  (`[DebuggerBrowsable(Never)]`) and overwrite it on `Dispose`/`TakeValue` (the last three are now `IDisposable`).
* **N-6:** Logpush redaction also replaces query parameters without `=` and the path of every destination except r2/s3/gs/azure (for example `splunk://`, `datadog://`).
* **N-7:** `Kv.ListKeysAsync` stops on an empty page, a repeated cursor and after a page limit; `ListAllAsync` stops on a repeated cursor.
* **N-8:** `CloudflareOptions.Validate()` (called by `CloudflareClient.Create`, `CloudflareOpenApi.CreateClient` and the DI registration): absolute HTTPS base address
  (HTTP only for loopback; `http://localhost.evil…` no longer passes), no user info, `MaxRetries` 0 to 10 (`MaxRetriesLimit`), `RetryBaseDelay` not negative. New
  `MaxResponseBytes` (default 32 MiB): larger answers fail with `CloudflareApiException`.
* **N-9:** documented: `CloudflareNotEntitledException`/`CloudflareConflictException` are recognised from status and message text; use them for messages, not for
  security decisions.
* **N-10:** `Workers.PreviewAttachDomain` takes `accountId` (it always used the default account); the README lists which previews read (the `Preview…Async` ones).
* Also found by the new reflective guard test: `Lists.EnsureAsync` read before the write guard; it now checks the guard first.
* Tests: 107 new (317 in total): `PathTraversalTests`, `SecurityHardeningTests` (all findings), the guard tests the review missed (`SetDiscoveryStatesAsync`,
  `UpdateTokenValidationConfigAsync`, `DeleteTokenValidationConfigAsync`, `UpdateTokenValidationRuleAsync`, user labels, `RemoveLabelsFromOperationsAsync`,
  `ReactivateClientCertificateAsync`, `SetDefaultActionAsync`, `SetOperationActionAsync`, Page Shield `Create/UpdatePolicyAsync`, Bots leaked credential detection,
  `CustomHostnames.UpdateAsync`, `OriginPulls.DeleteHostnameCertificateAsync`, `ApiTokens.UpdateAsync`) and a reflective test: every public method of every curated
  client, called with sample arguments and `AllowWrites = false`, sends no write, and a method that hits the guard has sent nothing before.
* **Breaking (behaviour):** the methods listed under M-1 refuse what they wrote before (always-refused ones: `Zones.PurgeEverythingAsync`, `R2.DeleteBucketAsync`,
  `Workers.UploadModuleAsync`, `Workers.DeleteScriptAsync`, `Monitoring.DeleteLogpushJobAsync`); the M-8 methods need their switch; `Dns.UpsertAsync` writes only on change;
  ids with `/` are refused instead of encoded (`CloudflarePath.Append` for names); `journal_mode` and other PRAGMAs now need `allowWriteSql`; pools without monitor block
  the last-healthy check (pass `allowLastHealthyPool` after checking); invalid options throw at creation.
* **Breaking (source, rare):** new optional parameters, each placed after the zone/account/scope parameter and before the `CancellationToken`, so positional calls keep
  compiling unless they pass the token positionally: `Tls.SetSwitchAsync(…, allowWeaken)`, `ApiTokens.UpdateAsync(…, allowSelf)`, `Logpush.SetJobEnabledAsync`/`DeleteJobAsync(…, allowRemoval)`,
  `ApiShield.SetOverrideActionAsync(…, allowLoosen)`, `ReplaceTokenValidationKeysAsync(…, allowKeyRemoval)`, `DeleteTokenValidationConfigAsync`/`DeleteTokenValidationRuleAsync(…, allowRemoval)`,
  `RevokeClientCertificateAsync(…, allowRevoke)`, `Workers.AttachDomainAsync(…, allowDeploy)`, `Waf.RemoveCustomRuleAsync(…, allowLoosen)`,
  `R2.EnsureCustomDomainAsync(…, allowWeaken)`, `CustomHostnames.PreviewCreate/CreateAsync/EnsureAsync/PreviewUpdate/UpdateAsync(…, allowWeaken)`,
  `Workers.PreviewAttachDomain(…, accountId)`. `Zones.SetSettingAsync`/`SetSettingsAsync`, `Dns.UpdateAsync`/`PatchAsync`, `Rulesets.PutPhaseEntrypointAsync` and the other
  ruleset writes are now `async` (same return types). `Monitoring.DeleteLogpushJobAsync` is obsolete.

## 0.7.0 – unreleased

Priority 2: Workers, KV, D1, Queues, R2, cache, load balancing, Spectrum and Argo as typed clients, with the patterns of 0.5.0/0.6.0: every write checks
`AllowWrites`/`WriteFilter` (methods that read before writing check it **before** the read, so with `AllowWrites = false` nothing is sent), has a `Preview…` sister that
sends nothing, validates input locally, and risky options need an explicit `allow…` switch. POST is never repeated after a server error. Endpoints from the API schema
`cloudflare/api-schemas@650bd71`; plans and limits from developers.cloudflare.com (retrieved 17.11.2026, sources in the XML documentation of each client).

* `Workers` (extended): `ListSecretsAsync` (names and types only), `GetScriptSettingsAsync`, `ListSchedulesAsync`, `ListVersionsAsync`, `GetVersionAsync`, `ListDeploymentsAsync`,
  `ListDomainsAsync`. Writes: `UploadScriptAsync` (needs `allowDeploy`; the preview shows size and SHA-256, never the source; `keep_bindings` defaults to the secret types so a
  redeploy does not drop secrets; secret bindings in metadata are refused), `RemoveScriptAsync` (`allowDelete`, `force` needs `allowForce`), `EnsureRouteAsync` (wildcard host needs
  `allowBroadRoute`; a pattern of another Worker is a `CloudflareConflictException`), `RemoveRouteAsync`, `AttachDomainAsync`/`DetachDomainAsync` (`allowRemoval`),
  `SetSchedulesAsync` (cron checked locally, written only on change, an empty list needs `allowClear`), `DeployVersionsAsync` (one version or a 90/10 style split, percentages
  checked, `allowDeploy`), `PutSecretAsync`/`RemoveSecretAsync` (`allowDeploy`: Cloudflare deploys a secret change at once).
  **Secret values** exist only in the new `WorkerSecretText` (`ToString` and JSON write `[redacted]`) and in the request body; no model has a value, `text` is stripped from
  every answer, previews show `[redacted]`.
* New `Kv` (`KvClient`): namespaces (list, get, `EnsureNamespaceAsync`, rename, `RemoveNamespaceAsync` with `allowDelete` and, for a namespace with keys, `allowNonEmpty`), keys
  (`ListKeysAsync` with prefix and cursor paging, `GetValueAsync`, `GetMetadataAsync`, `PutValueAsync` text/binary with TTL, expiration, metadata and `allowOverwrite: false`,
  `DeleteKeyAsync`), bulk (`PutBulkAsync`, `GetBulkAsync`, `DeleteBulkAsync` with `allowBulkDelete`). Limits checked locally: key 512 bytes, value 25 MiB, metadata 1024 bytes,
  TTL at least 60 s, 10 000 pairs and 100 MB per bulk write, 100 keys per bulk read.
* New `D1` (`D1Client`): databases (list, get, `EnsureDatabaseAsync`, `RemoveDatabaseAsync` with `allowDelete`), Time Travel bookmark, `QueryAsync`/`PreviewQuery` with **bound
  parameters**. The SQL is classified locally (`D1Sql.Classify`: read-only, write, destructive; comments and string literals are ignored): by default only reads are sent,
  writes need `allowWriteSql`, DROP/ALTER/VACUUM/ATTACH and DELETE or UPDATE without WHERE need `allowDestructiveSql`; previews show the SQL and the parameter count, not the values.
  The query endpoint is a POST, so the write guard applies to SELECT too. Export, import and restore are not included.
* New `Queues` (`QueuesClient`): list, find, `EnsureAsync`, `UpdateSettingsAsync` (pausing needs `allowPause`), `RemoveAsync` (`allowDelete`), `PurgeAsync` (`allowPurge`), backlog,
  consumers (`EnsureConsumerAsync`, `RemoveConsumerAsync`), `PushAsync`/`PushBatchAsync` (128 KB per message, 100 per batch, delay up to 24 h; previews show sizes only).
* `R2` (extended): `EnsureBucketAsync`, `RemoveBucketAsync` (`allowDelete` and the bucket must be empty), custom domains (`EnsureCustomDomainAsync` needs `allowPublicAccess`,
  `RemoveCustomDomainAsync` needs `allowRemoval`), r2.dev address (`SetManagedDomainAsync`, enabling needs `allowPublicAccess`), CORS typed (`GetCorsRulesAsync`, `SetCorsAsync`
  with origin check, `*` needs `allowAnyOrigin`, `DeleteCorsAsync`), lifecycle typed (`GetLifecycleRulesAsync`, `SetLifecycleAsync`, deleting rules need `allowDeletion`).
* New `Cache` (`CacheClient`, based on `RulesetPhaseClient`): cache rules of phase `http_request_cache_settings` (`UpsertRuleAsync` changes one rule; caching a match-all
  expression needs `allowBroadCache`, an edge TTL override above one day `allowLongTtl`), purge by URL, hostname, tag and prefix (split into requests of 100, at most 1000 per
  call, inputs checked), `PurgeEverythingAsync` (`allowPurgeAll`), Cache Reserve (enabling needs `allowBilling`), regional tiered cache.
* New `Argo` (`ArgoClient`): smart routing (enabling needs `allowBilling`) and tiered caching.
* New `LoadBalancing` (`LoadBalancingClient`): monitors (header values **redacted** in models and previews, `allowInsecureTls` for a monitor without certificate check, a monitor in
  use is not deleted), pools (`EnsurePoolAsync`, `SetPoolEnabledAsync`, `SetOriginEnabledAsync`, `UpsertOriginAsync`, `RemoveOriginAsync`, `RemovePoolAsync` refuses a pool in use),
  load balancers (`EnsureLoadBalancerAsync`, `SetLoadBalancerEnabledAsync` and `RemoveLoadBalancerAsync` need `allowDisableActive`/`allowDeleteActive` for an enabled one).
  **Outage protection:** taking the last healthy pool of a load balancer out (disable the pool, disable or remove its last enabled origin) is refused unless
  `allowLastHealthyPool` is true; the check reads the load balancers of the zone and the pool's references and refuses when a load balancer outside the zone cannot be checked.
* New `Spectrum` (`SpectrumClient`): list, get, `EnsureAppAsync`, `UpdateAppAsync`, `RemoveAppAsync` (`allowDelete`); management and database ports (SSH, RDP, SMB, SQL, Redis …,
  also inside a port range) need `allowSensitivePort`. Custom TCP/UDP applications need Enterprise with the add-on: Cloudflare answers with `CloudflareNotEntitledException`.
* **Obsolete** (still working, removed in 1.0): `Workers.UploadModuleAsync`, `DeleteScriptAsync`, `CreateRouteAsync`, `DeleteRouteAsync`; `R2.CreateBucketAsync`, `DeleteBucketAsync`,
  `PutLifecycleAsync`, `PutCorsAsync`; `Zones.PurgeEverythingAsync`. With `TreatWarningsAsErrors` callers have to switch to the guarded replacements or suppress CS0618.
* **Breaking (source, rare):** `ICloudflareClient` has the new members `Kv`, `D1`, `Queues`, `Cache`, `Argo`, `LoadBalancing`, `Spectrum` (own implementations of the interface, in
  practice test doubles, must add them). `WorkerMetadata` has the new optional property `KeepBindings`. `WorkersClient` and `R2Client` are now `partial`. No other public signature changed.
* Not included (reachable through `OpenApi`): Durable Objects, Secrets Store, Hyperdrive, Workflows, Pages, D1 export/import and Time Travel restore, Queues pull/acknowledge,
  R2 buckets with a jurisdiction, bucket locks, event notifications, Cache Reserve clear, Argo analytics, account-level load balancers and monitor groups.
* Tests: 55 new (`Priority2Tests`, 210 in total) with the fake handler: success, errors, rate limit (429 retried), not entitled, conflict, previews send nothing,
  `AllowWrites = false` sends nothing (64 write methods), `WriteFilter` before the preparing read, every allow switch refuses locally without a request, secret values, KV values,
  D1 parameters, queue messages, monitor headers and Worker source never in previews, models or errors, last-healthy-pool protection (five scenarios), POST not repeated after a server error.

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
