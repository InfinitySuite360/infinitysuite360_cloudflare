using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>The Zero Trust account of Gateway (tag, provider).</summary>
public sealed class GatewayAccount : CloudflareModel
{
    public string? Id { get; init; }
    public string? GatewayTag { get; init; }
    public string? ProviderName { get; init; }
}

/// <summary>A Gateway rule (DNS, HTTP, network/L4, egress or resolver policy).</summary>
public sealed class GatewayRule : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    /// <summary>For example "allow", "block", "isolate", "scan", "noscan", "off" (do not inspect), "on", "override", "l4_override", "egress", "resolve".</summary>
    public string Action { get; init; } = "";
    public bool Enabled { get; init; }
    /// <summary>"dns", "http", "l4", "egress", "dns_resolver".</summary>
    public List<string> Filters { get; init; } = [];
    public int? Precedence { get; init; }
    public string? Traffic { get; init; }
    public string? Identity { get; init; }
    public string? DevicePosture { get; init; }
    public JsonElement? RuleSettings { get; init; }
    public JsonElement? Schedule { get; init; }
    public JsonElement? Expiration { get; init; }
    public bool? ReadOnly { get; init; }
    public int? Version { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>A new or changed Gateway rule. There is deliberately no default action: name it.</summary>
public sealed class GatewayRuleInput
{
    public required string Name { get; init; }
    public required string Action { get; init; }
    /// <summary>Exactly one of "dns", "http", "l4", "egress", "dns_resolver".</summary>
    public required IReadOnlyList<string> Filters { get; init; }
    /// <summary>Wirefilter expression of the traffic, for example <c>any(dns.domains[*] in $&lt;list id&gt;)</c>.</summary>
    public string? Traffic { get; init; }
    public string? Identity { get; init; }
    public string? DevicePosture { get; init; }
    public bool Enabled { get; init; } = true;
    public int? Precedence { get; init; }
    public string? Description { get; init; }
    public JsonObject? RuleSettings { get; init; }
}

/// <summary>A Gateway list (domains, URLs, IPs, e-mail addresses, serial numbers …).</summary>
public sealed class GatewayList : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"DOMAIN", "URL", "IP", "EMAIL", "SERIAL", "CATEGORY", "LOCATION", "DEVICE", "AAGUID".</summary>
    public string Type { get; init; } = "";
    public string? Description { get; init; }
    public double? Count { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

public sealed class GatewayListItem : CloudflareModel
{
    public string Value { get; init; } = "";
    public string? Description { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
}

/// <summary>A DNS location (resolver endpoints and source networks).</summary>
public sealed class GatewayLocation : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public bool ClientDefault { get; init; }
    public bool? EcsSupport { get; init; }
    public bool? Dns64Enabled { get; init; }
    public string? DohSubdomain { get; init; }
    public string? Ip { get; init; }
    public string? Ipv4Destination { get; init; }
    public string? Ipv4DestinationBackup { get; init; }
    public List<GatewayLocationNetwork> Networks { get; init; } = [];
    public JsonElement? Endpoints { get; init; }
}

public sealed class GatewayLocationNetwork : CloudflareModel
{
    public string Network { get; init; } = "";
}

/// <summary>The Gateway account configuration (TLS decryption, antivirus, activity log, block page, browser isolation, FIPS, certificate …).</summary>
public sealed class GatewayConfiguration : CloudflareModel
{
    public JsonElement? Settings { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }

    private bool? Flag(string section, string name) =>
        Settings is { ValueKind: JsonValueKind.Object } s && s.TryGetProperty(section, out var sec) && sec.ValueKind == JsonValueKind.Object
        && sec.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;

    public bool? TlsDecryptEnabled => Flag("tls_decrypt", "enabled");
    public bool? ActivityLogEnabled => Flag("activity_log", "enabled");
    public bool? AntivirusDownloadScan => Flag("antivirus", "enabled_download_phase");
    public bool? AntivirusUploadScan => Flag("antivirus", "enabled_upload_phase");
    public bool? AntivirusFailClosed => Flag("antivirus", "fail_closed");
    public bool? ProtocolDetectionEnabled => Flag("protocol_detection", "enabled");
    public bool? BlockPageEnabled => Flag("block_page", "enabled");
}

/// <summary>A change of the Gateway configuration; only set fields are sent (PATCH of the changed sections).</summary>
public sealed class GatewaySettingsChange
{
    /// <summary>On breaks applications with certificate pinning (needs <c>allowTlsDecrypt</c>); off ends HTTP inspection (needs <c>allowLoosen</c>).</summary>
    public bool? TlsDecrypt { get; init; }
    /// <summary>Off ends the activity log (needs <c>allowLoosen</c>).</summary>
    public bool? ActivityLog { get; init; }
    public bool? AntivirusDownloadScan { get; init; }
    public bool? AntivirusUploadScan { get; init; }
    /// <summary>On blocks files that cannot be scanned (needs <c>allowBlock</c>).</summary>
    public bool? AntivirusFailClosed { get; init; }
    public bool? ProtocolDetection { get; init; }
    public bool? BlockPageEnabled { get; init; }
    /// <summary>Id of the Gateway certificate used for TLS inspection (needs <c>allowTlsDecrypt</c>: devices must trust it).</summary>
    public string? CertificateId { get; init; }
}

/// <summary>Gateway logging: PII redaction and what is logged per rule type.</summary>
public sealed class GatewayLogging : CloudflareModel
{
    public bool? RedactPii { get; init; }
    public JsonElement? SettingsByRuleType { get; init; }
}

/// <summary>A proxy endpoint (PAC file target).</summary>
public sealed class GatewayProxyEndpoint : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"ip" or "identity".</summary>
    public string? Kind { get; init; }
    public List<string> Ips { get; init; } = [];
    public string? Subdomain { get; init; }
}

/// <summary>A Gateway (inspection) certificate. Only metadata and the public certificate; Cloudflare never returns a private key.</summary>
public sealed class GatewayCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"pending_deployment", "available", "pending_deletion", "inactive".</summary>
    public string? BindingStatus { get; init; }
    public bool? InUse { get; init; }
    /// <summary>"gateway_managed" or "custom".</summary>
    public string? Type { get; init; }
    public string? Fingerprint { get; init; }
    public string? IssuerOrg { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
}

/// <summary>A content or security category of Gateway.</summary>
public sealed class GatewayCategory : CloudflareModel
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string? Class { get; init; }
    public string? Description { get; init; }
    public bool? Beta { get; init; }
    public List<GatewayCategory> Subcategories { get; init; } = [];
}

/// <summary>
/// Zero Trust Gateway: rules (DNS, HTTP, network), lists, DNS locations, account configuration (TLS decryption, antivirus, …), logging, proxy endpoints,
/// inspection certificates, categories. Endpoints from cloudflare/api-schemas@650bd71 (<c>zero-trust-gateway-*</c>, <c>zero-trust-lists-*</c>,
/// <c>zero-trust-accounts-*</c>, <c>zero-trust-certificates-*</c>); limits from developers.cloudflare.com/cloudflare-one/account-limits/ (retrieved 17.11.2026:
/// 500 rules per type, 250 DNS locations, 100 lists, 1000 entries per list (Enterprise 5000), 10 active certificates, 3 generated per day).
/// </summary>
/// <remarks>
/// <para>Write rules: every write checks <c>AllowWrites</c>/<c>WriteFilter</c> first (before any preparing read), has a <c>Preview…</c> sister and is sent
/// only on change. A rule has no default action. Protective actions (block, isolate, scan, quarantine, safesearch, ytrestricted, on, redirect) on a rule
/// without any selector need <c>allowBroadMatch</c>; turning an enabled protective rule into a permissive one, disabling, deleting or re-matching it needs
/// <c>allowLoosen</c>; turning a permissive rule into a blocking one or enabling a block rule needs <c>allowBlock</c>.</para>
/// <para>Token permissions: "Zero Trust: Read" for reading, "Zero Trust: Edit" for writes.</para>
/// </remarks>
public sealed class ZeroTrustGatewayClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly HashSet<string> Actions = ["on", "off", "allow", "block", "scan", "noscan", "safesearch", "ytrestricted", "isolate", "noisolate", "override", "l4_override", "egress", "resolve", "quarantine", "redirect", "forward"];
    private static readonly HashSet<string> Protective = ["block", "isolate", "scan", "quarantine", "safesearch", "ytrestricted", "on", "redirect"];
    /// <summary>Actions that let traffic past protective rules or out of inspection (H3, 0.8.1).</summary>
    private static readonly HashSet<string> Permissive = ["allow", "off", "noscan", "noisolate", "override", "l4_override", "resolve", "egress"];
    /// <summary>Members of a rule that Cloudflare sets itself; they are not sent back with a PUT.</summary>
    private static readonly string[] ReadOnlyRuleMembers = ["id", "created_at", "updated_at", "deleted_at", "version", "read_only", "source_account", "sharable", "warning_status", "not_sharable"];
    private static readonly HashSet<string> Filters = ["dns", "http", "l4", "egress", "dns_resolver"];
    private static readonly HashSet<string> ListTypes = ["SERIAL", "URL", "DOMAIN", "EMAIL", "IP", "CATEGORY", "LOCATION", "DEVICE", "AAGUID"];
    private const int MaxListItems = 5000;

    public Task<GatewayAccount> GetAccountAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<GatewayAccount>(AccountPath(accountId, "gateway"), ct);

    public async Task<List<GatewayCategory>> ListCategoriesAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<GatewayCategory>>(AccountPath(accountId, "gateway", "categories"), ct).ConfigureAwait(false) ?? [];

    public async Task<List<JsonElement>> ListAppTypesAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<JsonElement>>(AccountPath(accountId, "gateway", "app_types"), ct).ConfigureAwait(false) ?? [];

    // ------------------------------------------------------------------ rules

    /// <summary>Rules, optionally only of one filter ("dns", "http", "l4", …), ordered by precedence.</summary>
    public async Task<List<GatewayRule>> ListRulesAsync(string? filter = null, string? accountId = null, CancellationToken ct = default)
    {
        var rules = await ZT.GetListAsync<GatewayRule>(Api, AccountPath(accountId, "gateway", "rules"), ct).ConfigureAwait(false);
        return rules.Where(r => filter is null || r.Filters.Contains(filter)).OrderBy(r => r.Precedence ?? int.MaxValue).ToList();
    }

    public Task<GatewayRule> GetRuleAsync(string ruleId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<GatewayRule>(Api, HttpMethod.Get, AccountPath(accountId, "gateway", "rules", ruleId), null, ct);

    public CloudflareChangePreview PreviewEnsureRule(GatewayRuleInput rule, bool allowBroadMatch = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "gateway", "rules"), RuleBody(rule, allowBroadMatch), Describe("Create", rule));

    /// <summary>
    /// Returns the rule with this name or creates it (POST, not retried after a server error); an existing rule is not changed. H3 (0.8.1): an enabled
    /// permissive rule (allow, off, noscan, noisolate, override, l4_override, resolve, egress) that matches all traffic, or that would be evaluated before an
    /// enabled protective rule of the same filter, needs <paramref name="allowLoosen"/> (the rules are read first, fail-closed).
    /// </summary>
    public async Task<(GatewayRule Rule, bool Created)> EnsureRuleAsync(GatewayRuleInput rule, bool allowBroadMatch = false, string? accountId = null, bool allowLoosen = false,
        CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "rules");
        EnsureWritable(HttpMethod.Post, path);
        var body = RuleBody(rule, allowBroadMatch);
        var all = await ListRulesAsync(null, accountId, ct).ConfigureAwait(false);
        var existing = all.FirstOrDefault(r => r.Name == rule.Name);
        if (existing is not null) return (existing, false);
        if (PermissiveRisk(rule.Action, rule.Enabled, rule.Filters[0], rule.Traffic, rule.Identity, rule.DevicePosture, rule.Precedence, all, null) is { } why)
            P2.Allow(allowLoosen, $"rule \"{rule.Name}\" {why}", nameof(allowLoosen));
        try { return (await ZT.SendAsync<GatewayRule>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListRulesAsync(null, accountId, ct).ConfigureAwait(false)).FirstOrDefault(r => r.Name == rule.Name);
            return again is null ? throw ZT.Conflict("POST", path, $"Rule \"{rule.Name}\" is reported as existing but was not found.") : (again, false);
        }
    }

    /// <summary>Plan of a rule change: reads the rule and names loosening or tightening (sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewChangeRuleAsync(string ruleId, GatewayRuleInput rule, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetRuleAsync(ruleId, accountId, ct).ConfigureAwait(false);
        var (loosen, block) = Compare(current, rule);
        return new("PUT", AccountPath(accountId, "gateway", "rules", ruleId), RuleBody(rule, true),
            Describe($"Change rule \"{current.Name}\" to", rule) + (loosen is null ? "" : $" WARNING: loosens ({loosen}).") + (block is null ? "" : $" WARNING: tightens ({block})."));
    }

    /// <summary>
    /// Replaces a rule after a fresh read (written only on change). Read-only rules (managed by a parent account) are refused. Loosening needs
    /// <paramref name="allowLoosen"/>, tightening to block needs <paramref name="allowBlock"/>, a protective rule without selector <paramref name="allowBroadMatch"/>.
    /// H3 (0.8.1): loosening also covers a protective rule that moves later (precedence) or to another filter, changed rule settings of an enabled rule, and a
    /// permissive rule that newly matches all traffic or moves before an enabled protective rule. The PUT keeps every member the input does not set
    /// (<c>schedule</c>, <c>expiration</c>, <c>rule_settings</c>, <c>precedence</c>, <c>description</c>, …) instead of resetting it.
    /// </summary>
    public async Task<(GatewayRule Rule, bool Changed)> ChangeRuleAsync(string ruleId, GatewayRuleInput rule, bool allowLoosen = false, bool allowBlock = false, bool allowBroadMatch = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "rules", P1.Required(ruleId, nameof(ruleId)));
        EnsureWritable(HttpMethod.Put, path);
        var body = RuleBody(rule, allowBroadMatch);
        var raw = await ZT.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<GatewayRule>(raw);
        if (current.ReadOnly == true) throw new InvalidOperationException($"Refused: rule \"{current.Name}\" is read-only (managed by another account).");
        var (loosen, block) = Compare(current, rule);
        if (loosen is not null) P2.Allow(allowLoosen, $"the change loosens rule \"{current.Name}\": {loosen}", nameof(allowLoosen));
        if (block is not null) P2.Allow(allowBlock, $"the change tightens rule \"{current.Name}\": {block}", nameof(allowBlock));
        if (P1.Covers(P1.Node(raw), body)) return (current, false);
        var widens = !(current.Enabled && Permissive.Contains(current.Action)) || Selector(current) != Selector(rule)
                     || (rule.Precedence is { } np && current.Precedence is { } cp && np < cp) || !current.Filters.SequenceEqual(rule.Filters);
        if (widens && rule.Enabled && Permissive.Contains(rule.Action))
        {
            var all = await ListRulesAsync(null, accountId, ct).ConfigureAwait(false);
            if (PermissiveRisk(rule.Action, rule.Enabled, rule.Filters[0], rule.Traffic, rule.Identity, rule.DevicePosture, rule.Precedence ?? current.Precedence, all, current.Id) is { } why)
                P2.Allow(allowLoosen, $"rule \"{current.Name}\" {why}", nameof(allowLoosen));
        }
        var merged = ZT.Merge(raw, body, ReadOnlyRuleMembers);
        return (await ZT.SendAsync<GatewayRule>(Api, HttpMethod.Put, path, merged, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewSetRuleEnabled(string ruleId, bool enabled, string? accountId = null) =>
        new("PATCH", AccountPath(accountId, "gateway", "rules", ruleId), new JsonObject { ["enabled"] = enabled },
            enabled ? $"Enable Gateway rule {ruleId} (refused for a permissive rule without allowLoosen and a block rule without allowBlock)."
                : $"Disable Gateway rule {ruleId} (refused for a protective rule without allowLoosen).");

    /// <summary>
    /// Enables or disables a rule (PATCH, only on change). Disabling a protective rule needs <paramref name="allowLoosen"/>, enabling a block rule
    /// <paramref name="allowBlock"/>; H3 (0.8.1): enabling a permissive rule (allow, off, noscan, noisolate, override, l4_override, resolve, egress) needs
    /// <paramref name="allowLoosen"/>.
    /// </summary>
    public async Task<(GatewayRule Rule, bool Changed)> SetRuleEnabledAsync(string ruleId, bool enabled, bool allowLoosen = false, bool allowBlock = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "rules", P1.Required(ruleId, nameof(ruleId)));
        EnsureWritable(HttpMethod.Patch, path);
        var current = await GetRuleAsync(ruleId, accountId, ct).ConfigureAwait(false);
        if (current.Enabled == enabled) return (current, false);
        if (current.ReadOnly == true) throw new InvalidOperationException($"Refused: rule \"{current.Name}\" is read-only (managed by another account).");
        if (!enabled && Protective.Contains(current.Action)) P2.Allow(allowLoosen, $"disabling {current.Action} rule \"{current.Name}\" loosens Gateway", nameof(allowLoosen));
        if (enabled && Permissive.Contains(current.Action)) P2.Allow(allowLoosen, $"enabling {current.Action} rule \"{current.Name}\" lets matching traffic past the protective rules", nameof(allowLoosen));
        if (enabled && current.Action == "block") P2.Allow(allowBlock, $"enabling block rule \"{current.Name}\" tightens Gateway", nameof(allowBlock));
        return (await ZT.SendAsync<GatewayRule>(Api, HttpMethod.Patch, path, new JsonObject { ["enabled"] = enabled }, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveRule(string ruleId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "gateway", "rules", ruleId), null, $"Delete Gateway rule {ruleId} (refused for an enabled protective rule without allowLoosen).");

    /// <summary>Deletes a rule after a fresh read; an enabled protective rule needs <paramref name="allowLoosen"/>. False when it did not exist.</summary>
    public async Task<bool> RemoveRuleAsync(string ruleId, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "rules", P1.Required(ruleId, nameof(ruleId)));
        EnsureWritable(HttpMethod.Delete, path);
        var current = await ZT.GetOrNullAsync<GatewayRule>(Api, path, ct).ConfigureAwait(false);
        if (current is null) return false;
        if (current.ReadOnly == true) throw new InvalidOperationException($"Refused: rule \"{current.Name}\" is read-only (managed by another account).");
        if (current.Enabled && Protective.Contains(current.Action)) P2.Allow(allowLoosen, $"deleting enabled {current.Action} rule \"{current.Name}\" loosens Gateway", nameof(allowLoosen));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Loosening and tightening of a rule change (H3, 0.8.1: also precedence, filters and rule settings): a protective rule that becomes permissive, is
    /// disabled, gets another selector or filter or moves later; changed rule settings of an enabled rule; a rule that starts to block.
    /// </summary>
    private static (string? Loosen, string? Block) Compare(GatewayRule current, GatewayRuleInput next)
    {
        string? loosen = null, block = null;
        var wasProtective = current.Enabled && Protective.Contains(current.Action);
        var isProtective = next.Enabled && Protective.Contains(next.Action);
        if (wasProtective && !isProtective) loosen = next.Enabled ? $"action {current.Action} → {next.Action}" : "it would be disabled";
        else if (wasProtective && Selector(current) != Selector(next))
            loosen = "the selector of a protective rule would change and may match less";
        else if (wasProtective && !current.Filters.SequenceEqual(next.Filters))
            loosen = $"a protective rule would move from filter {string.Join("/", current.Filters)} to {string.Join("/", next.Filters)}";
        else if (wasProtective && next.Precedence is { } np && current.Precedence is { } cp && np > cp)
            loosen = $"a protective rule would be evaluated later (precedence {cp} → {np})";
        else if (current.Enabled && next.Enabled && next.RuleSettings is not null && !SameSettings(current.RuleSettings, next.RuleSettings))
            loosen = "the rule settings of an enabled rule would change (block page, isolation, untrusted certificates, overrides, …)";
        var wasBlocking = current.Enabled && current.Action == "block";
        if (next.Enabled && next.Action == "block" && !wasBlocking) block = current.Enabled ? $"action {current.Action} → block" : "a disabled rule would block";
        return (loosen, block);
    }

    private static bool SameSettings(JsonElement? current, JsonObject next) => P1.Covers(P1.Node(current) ?? new JsonObject(), next);

    private static string Selector(GatewayRule r) => $"{Norm(r.Traffic)}\n{Norm(r.Identity)}\n{Norm(r.DevicePosture)}";

    private static string Selector(GatewayRuleInput r) => $"{Norm(r.Traffic)}\n{Norm(r.Identity)}\n{Norm(r.DevicePosture)}";

    private static string Norm(string? s) => (s ?? "").Trim();

    /// <summary>True when the selectors are empty or tautologies (<see cref="ZT.MatchesAll"/>): the rule applies to all traffic of its filter.</summary>
    private static bool IsBroad(string? traffic, string? identity, string? posture) => ZT.MatchesAll(traffic) && ZT.MatchesAll(identity) && ZT.MatchesAll(posture);

    /// <summary>
    /// Why an enabled permissive rule is risky, or null: it matches all traffic of its filter, or its precedence puts it before an enabled protective rule of the
    /// same filter (the first matching rule wins).
    /// </summary>
    private static string? PermissiveRisk(string action, bool enabled, string filter, string? traffic, string? identity, string? posture, int? precedence,
        IReadOnlyList<GatewayRule> all, string? selfId)
    {
        if (!enabled || !Permissive.Contains(action)) return null;
        if (IsBroad(traffic, identity, posture)) return $"would {action} all {filter} traffic (no effective selector)";
        if (precedence is { } p)
        {
            var shadowed = all.Where(r => r.Id != selfId && r.Enabled && Protective.Contains(r.Action) && r.Filters.Contains(filter) && r.Precedence is { } rp && rp > p)
                .Select(r => $"\"{r.Name}\" ({r.Action})").ToList();
            if (shadowed.Count > 0) return $"would {action} matching traffic before protective rule(s) {string.Join(", ", shadowed)} (precedence {p})";
        }
        return null;
    }

    private static string Describe(string what, GatewayRuleInput r)
    {
        var broad = IsBroad(r.Traffic, r.Identity, r.DevicePosture);
        return $"{what} Gateway {string.Join("/", r.Filters)} rule \"{r.Name}\": {r.Action}{(r.Enabled ? "" : " (disabled)")}"
               + (broad ? ", matches all traffic" : "") + "."
               + (r.Action == "block" && r.Enabled ? " WARNING: blocks matching traffic." : "")
               + (Permissive.Contains(r.Action) && r.Enabled ? $" WARNING: {r.Action} lets matching traffic past the protective rules (allowLoosen when broad or placed before them)." : "");
    }

    private static JsonObject RuleBody(GatewayRuleInput r, bool allowBroadMatch)
    {
        P1.Required(r.Name, nameof(r), 255);
        if (!Actions.Contains(r.Action)) throw new ArgumentException($"Unknown action \"{r.Action}\".", nameof(r));
        if (r.Filters is not { Count: 1 } || !Filters.Contains(r.Filters[0])) throw new ArgumentException("Exactly one filter: dns, http, l4, egress or dns_resolver.", nameof(r));
        var broad = IsBroad(r.Traffic, r.Identity, r.DevicePosture);
        if (broad && r.Enabled && Protective.Contains(r.Action))
            P2.Allow(allowBroadMatch, $"rule \"{r.Name}\" would {r.Action} all {r.Filters[0]} traffic (no traffic, identity or device posture selector)", nameof(allowBroadMatch));
        var body = new JsonObject
        {
            ["name"] = r.Name, ["action"] = r.Action, ["enabled"] = r.Enabled, ["filters"] = P1.Arr(r.Filters),
            ["traffic"] = r.Traffic ?? "", ["identity"] = r.Identity ?? "", ["device_posture"] = r.DevicePosture ?? "",
        };
        if (r.Precedence is { } p) body["precedence"] = p;
        if (r.Description is not null) body["description"] = r.Description;
        if (r.RuleSettings is not null) body["rule_settings"] = r.RuleSettings.DeepClone();
        return body;
    }

    // ------------------------------------------------------------------ lists

    public async Task<List<GatewayList>> ListListsAsync(string? type = null, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<GatewayList>>(CloudflarePath.WithQuery(AccountPath(accountId, "gateway", "lists"), ("type", type)), ct).ConfigureAwait(false) ?? [];

    public Task<GatewayList> GetListAsync(string listId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<GatewayList>(AccountPath(accountId, "gateway", "lists", listId), ct);

    public Task<IReadOnlyList<GatewayListItem>> ListItemsAsync(string listId, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<GatewayListItem>(AccountPath(accountId, "gateway", "lists", P1.Required(listId, nameof(listId)), "items"), 50, ct);

    public CloudflareChangePreview PreviewEnsureList(string name, string type, IEnumerable<string>? values = null, string? description = null, string? accountId = null)
    {
        var body = ListBody(name, type, values, description);
        return new("POST", AccountPath(accountId, "gateway", "lists"), body, $"Create Gateway {type} list \"{name}\" with {body["items"]!.AsArray().Count} entries.");
    }

    /// <summary>Returns the list with this name or creates it (entries checked locally per type, at most 5000); an existing list is not changed.</summary>
    public async Task<(GatewayList List, bool Created)> EnsureListAsync(string name, string type, IEnumerable<string>? values = null, string? description = null,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "lists");
        EnsureWritable(HttpMethod.Post, path);
        var body = ListBody(name, type, values, description);
        var existing = (await ListListsAsync(null, accountId, ct).ConfigureAwait(false)).FirstOrDefault(l => l.Name == name);
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<GatewayList>(path, body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewAddListItems(string listId, string type, IEnumerable<string> values, string? accountId = null)
    {
        var items = Items(type, values);
        return new("PATCH", AccountPath(accountId, "gateway", "lists", listId), new JsonObject { ["append"] = items }, $"Append {items.Count} entries to Gateway list {listId}.");
    }

    /// <summary>
    /// Appends entries (PATCH <c>append</c>; values checked against the list type from a fresh read). M6 (0.8.1): when a rule uses the list, new entries
    /// change what it matches (an allow list admits more, a block list blocks more), so this needs <paramref name="allowInUse"/> (rules read, fail-closed).
    /// </summary>
    public async Task<GatewayList> AddListItemsAsync(string listId, IEnumerable<string> values, string? accountId = null, bool allowInUse = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "lists", P1.Required(listId, nameof(listId)));
        EnsureWritable(HttpMethod.Patch, path);
        var list = await GetListAsync(listId, accountId, ct).ConfigureAwait(false);
        var items = Items(list.Type, values);
        if (items.Count == 0) return list;
        if ((list.Count ?? 0) + items.Count > MaxListItems) throw new ArgumentException($"A list holds at most {MaxListItems} entries (Enterprise).", nameof(values));
        await RefuseInUseAsync(listId, allowInUse, "adding entries to", accountId, ct).ConfigureAwait(false);
        return await Api.PatchAsync<GatewayList>(path, new JsonObject { ["append"] = items }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Removes entries (PATCH <c>remove</c>). When an enabled rule uses the list, the rule changes its effect (a block rule blocks less), so this needs
    /// <paramref name="allowInUse"/>; the check reads the rules and fails when they cannot be read.
    /// </summary>
    public async Task<GatewayList> RemoveListItemsAsync(string listId, IEnumerable<string> values, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "lists", P1.Required(listId, nameof(listId)));
        EnsureWritable(HttpMethod.Patch, path);
        var remove = values.Select(v => P1.Required(v, nameof(values)).Trim()).Distinct().ToList();
        if (remove.Count == 0) throw new ArgumentException("At least one value.", nameof(values));
        await RefuseInUseAsync(listId, allowInUse, "removing entries from", accountId, ct).ConfigureAwait(false);
        return await Api.PatchAsync<GatewayList>(path, new JsonObject { ["remove"] = P1.Arr(remove) }, ct).ConfigureAwait(false);
    }

    /// <summary>Deletes a list. A list used by a rule needs <paramref name="allowInUse"/> (fresh read of the rules, fail-closed). False when it did not exist.</summary>
    public async Task<bool> RemoveListAsync(string listId, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "lists", P1.Required(listId, nameof(listId)));
        EnsureWritable(HttpMethod.Delete, path);
        await RefuseInUseAsync(listId, allowInUse, "deleting", accountId, ct).ConfigureAwait(false);
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private async Task RefuseInUseAsync(string listId, bool allowInUse, string what, string? accountId, CancellationToken ct)
    {
        if (allowInUse) return;
        // M6 (0.8.1): disabled rules count as well – they take the changed list with them when they are enabled again.
        var users = (await ListRulesAsync(null, accountId, ct).ConfigureAwait(false))
            .Where(r => $"{r.Traffic} {r.Identity} {r.DevicePosture}".Contains("$" + listId, StringComparison.OrdinalIgnoreCase))
            .Select(r => $"\"{r.Name}\" ({r.Action}{(r.Enabled ? "" : ", disabled")})").ToList();
        if (users.Count > 0)
            throw new InvalidOperationException($"Refused: {what} list {listId} changes rule(s) {string.Join(", ", users)}. Pass allowInUse: true deliberately.");
    }

    private static JsonObject ListBody(string name, string type, IEnumerable<string>? values, string? description)
    {
        P1.Required(name, nameof(name), 255);
        var body = new JsonObject { ["name"] = name, ["type"] = CheckType(type), ["items"] = Items(type, values ?? []) };
        if (description is not null) body["description"] = description;
        return body;
    }

    private static string CheckType(string type) => ListTypes.Contains(type) ? type : throw new ArgumentException($"Unknown list type \"{type}\".", nameof(type));

    private static JsonArray Items(string type, IEnumerable<string> values)
    {
        CheckType(type);
        var list = values.Select(v => (v ?? "").Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (list.Count > MaxListItems) throw new ArgumentException($"At most {MaxListItems} entries.", nameof(values));
        foreach (var v in list)
        {
            switch (type)
            {
                case "IP": ZT.Cidr(v, nameof(values)); break;
                case "DOMAIN": P1.Hostname(v, nameof(values), allowWildcard: true); break;
                case "EMAIL" when !v.Contains('@'): throw new ArgumentException($"\"{v}\" is not an e-mail address.", nameof(values));
                case "URL" when v.Contains("://", StringComparison.Ordinal): throw new ArgumentException($"\"{v}\": URL entries without scheme.", nameof(values));
            }
        }
        return new JsonArray(list.Select(v => (JsonNode?)new JsonObject { ["value"] = v }).ToArray());
    }

    // ------------------------------------------------------------------ locations

    public async Task<List<GatewayLocation>> ListLocationsAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<GatewayLocation>>(AccountPath(accountId, "gateway", "locations"), ct).ConfigureAwait(false) ?? [];

    public Task<GatewayLocation> GetLocationAsync(string locationId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<GatewayLocation>(AccountPath(accountId, "gateway", "locations", locationId), ct);

    public CloudflareChangePreview PreviewEnsureLocation(string name, IEnumerable<string>? networks = null, bool ecsSupport = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "gateway", "locations"), LocationBody(name, networks, ecsSupport), $"Create DNS location \"{name}\".");

    /// <summary>Returns the DNS location with this name or creates it (never as client default); source networks are checked as CIDR.</summary>
    public async Task<(GatewayLocation Location, bool Created)> EnsureLocationAsync(string name, IEnumerable<string>? networks = null, bool ecsSupport = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "locations");
        EnsureWritable(HttpMethod.Post, path);
        var body = LocationBody(name, networks, ecsSupport);
        var existing = (await ListLocationsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(l => l.Name == name);
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<GatewayLocation>(path, body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveLocation(string locationId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "gateway", "locations", locationId), null,
            $"Delete DNS location {locationId}. WARNING: resolvers pointed at it are no longer filtered.");

    /// <summary>Deletes a DNS location; resolvers using it lose filtering, so this always needs <paramref name="allowDelete"/>. False when it did not exist.</summary>
    public Task<bool> RemoveLocationAsync(string locationId, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "locations", P1.Required(locationId, nameof(locationId)));
        EnsureWritable(HttpMethod.Delete, path);
        P2.Allow(allowDelete, "deleting a DNS location ends the filtering of every resolver pointed at it", nameof(allowDelete));
        return DeleteIfExistsAsync(path, null, ct);
    }

    private static JsonObject LocationBody(string name, IEnumerable<string>? networks, bool ecs)
    {
        P1.Required(name, nameof(name), 255);
        var nets = (networks ?? []).Select(n => ZT.Cidr(n, nameof(networks)).Cidr).Distinct().ToList();
        if (nets.Count > 1500) throw new ArgumentException("At most 1500 source networks per location.", nameof(networks));
        return new JsonObject
        {
            ["name"] = name, ["client_default"] = false, ["ecs_support"] = ecs,
            ["networks"] = new JsonArray(nets.Select(n => (JsonNode?)new JsonObject { ["network"] = n }).ToArray()),
        };
    }

    // ------------------------------------------------------------------ configuration

    public Task<GatewayConfiguration> GetConfigurationAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<GatewayConfiguration>(Api, HttpMethod.Get, AccountPath(accountId, "gateway", "configuration"), null, ct);

    /// <summary>Plan of a configuration change (reads the configuration; sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewUpdateConfigurationAsync(GatewaySettingsChange change, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetConfigurationAsync(accountId, ct).ConfigureAwait(false);
        var (body, notes) = ConfigurationBody(current, change);
        var sections = body["settings"]!.AsObject().Select(p => p.Key).ToList();
        return new("PATCH", AccountPath(accountId, "gateway", "configuration"), body,
            sections.Count == 0 ? "No change." : $"Change Gateway settings {string.Join(", ", sections)}." + (notes.Count > 0 ? " WARNING: " + string.Join("; ", notes.Select(n => n.Text)) + "." : ""));
    }

    /// <summary>
    /// Changes the Gateway configuration (PATCH of the changed sections only, each merged with a fresh read). Switching inspection, antivirus or the activity log
    /// off needs <paramref name="allowLoosen"/>; TLS decryption on or another inspection certificate needs <paramref name="allowTlsDecrypt"/>; antivirus fail-closed on
    /// needs <paramref name="allowBlock"/>.
    /// </summary>
    public async Task<(GatewayConfiguration Configuration, bool Changed)> UpdateConfigurationAsync(GatewaySettingsChange change, bool allowLoosen = false, bool allowTlsDecrypt = false,
        bool allowBlock = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "configuration");
        EnsureWritable(HttpMethod.Patch, path);
        var current = await GetConfigurationAsync(accountId, ct).ConfigureAwait(false);
        var (body, notes) = ConfigurationBody(current, change);
        foreach (var (flag, text) in notes)
            P2.Allow(flag switch { "allowTlsDecrypt" => allowTlsDecrypt, "allowBlock" => allowBlock, _ => allowLoosen }, text, flag);
        if (body["settings"]!.AsObject().Count == 0) return (current, false);
        return (await ZT.SendAsync<GatewayConfiguration>(Api, HttpMethod.Patch, path, body, ct).ConfigureAwait(false), true);
    }

    private static (JsonObject Body, List<(string Flag, string Text)> Notes) ConfigurationBody(GatewayConfiguration current, GatewaySettingsChange c)
    {
        var settings = new JsonObject();
        var notes = new List<(string, string)>();
        var now = current.Settings is { ValueKind: JsonValueKind.Object } s ? (JsonObject)JsonNode.Parse(s.GetRawText())! : new JsonObject();

        void Set(string section, string name, bool? next, bool? was, string? offNote, string? onNote, string onFlag = "allowLoosen")
        {
            if (next is not { } n || n == (was ?? false)) return;
            var sec = settings[section] as JsonObject ?? (now[section]?.DeepClone() as JsonObject) ?? new JsonObject();
            sec[name] = n;
            settings[section] = sec;
            if (!n && offNote is not null) notes.Add(("allowLoosen", offNote));
            if (n && onNote is not null) notes.Add((onFlag, onNote));
        }

        Set("tls_decrypt", "enabled", c.TlsDecrypt, current.TlsDecryptEnabled, "turning TLS decryption off ends HTTP inspection",
            "turning TLS decryption on breaks applications with certificate pinning and needs the certificate on every device", "allowTlsDecrypt");
        Set("activity_log", "enabled", c.ActivityLog, current.ActivityLogEnabled, "turning the activity log off ends Gateway logging", null);
        Set("antivirus", "enabled_download_phase", c.AntivirusDownloadScan, current.AntivirusDownloadScan, "turning the download scan off", null);
        Set("antivirus", "enabled_upload_phase", c.AntivirusUploadScan, current.AntivirusUploadScan, "turning the upload scan off", null);
        Set("antivirus", "fail_closed", c.AntivirusFailClosed, current.AntivirusFailClosed, "turning antivirus fail-closed off lets unscanned files through",
            "antivirus fail-closed blocks every file that cannot be scanned", "allowBlock");
        Set("protocol_detection", "enabled", c.ProtocolDetection, current.ProtocolDetectionEnabled, "turning protocol detection off", null);
        Set("block_page", "enabled", c.BlockPageEnabled, current.BlockPageEnabled, null, null);
        if (c.CertificateId is { } certId)
        {
            var was = now["certificate"]?["id"]?.GetValue<string>();
            if (!string.Equals(was, P1.Required(certId, nameof(c)), StringComparison.Ordinal))
            {
                settings["certificate"] = new JsonObject { ["id"] = certId };
                notes.Add(("allowTlsDecrypt", "another inspection certificate must be trusted by every device first"));
            }
        }
        return (new JsonObject { ["settings"] = settings }, notes);
    }

    // ------------------------------------------------------------------ logging

    public Task<GatewayLogging> GetLoggingAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<GatewayLogging>(AccountPath(accountId, "gateway", "logging"), ct);

    /// <summary>
    /// Sets logging (PUT, merged with a fresh read, written only on change). Turning PII redaction off needs <paramref name="allowPii"/>; turning off logging of
    /// all requests or of blocks for a rule type ("dns", "http", "l4") needs <paramref name="allowLoosen"/>.
    /// </summary>
    public async Task<(GatewayLogging Logging, bool Changed)> SetLoggingAsync(bool? redactPii = null, IReadOnlyDictionary<string, (bool LogAll, bool LogBlocks)>? byRuleType = null,
        bool allowPii = false, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "logging");
        EnsureWritable(HttpMethod.Put, path);
        var current = await GetLoggingAsync(accountId, ct).ConfigureAwait(false);
        var body = new JsonObject { ["redact_pii"] = redactPii ?? current.RedactPii ?? false };
        var types = P1.Node(current.SettingsByRuleType) as JsonObject ?? new JsonObject();
        if (redactPii == false && current.RedactPii == true) P2.Allow(allowPii, "turning PII redaction off writes personal data into the Gateway logs", nameof(allowPii));
        foreach (var (type, (all, blocks)) in byRuleType ?? new Dictionary<string, (bool, bool)>())
        {
            if (type is not ("dns" or "http" or "l4")) throw new ArgumentException("Rule types: dns, http, l4.", nameof(byRuleType));
            var was = types[type] as JsonObject;
            var wasAll = was?["log_all"]?.GetValue<bool>() ?? false;
            var wasBlocks = was?["log_blocks"]?.GetValue<bool>() ?? false;
            if ((wasAll && !all) || (wasBlocks && !blocks)) P2.Allow(allowLoosen, $"less {type} logging", nameof(allowLoosen));
            types[type] = new JsonObject { ["log_all"] = all, ["log_blocks"] = blocks };
        }
        body["settings_by_rule_type"] = types;
        if (P1.Covers(P1.Node(ToElement(current)), body)) return (current, false);
        return (await Api.PutAsync<GatewayLogging>(path, body, ct).ConfigureAwait(false), true);
    }

    // ------------------------------------------------------------------ proxy endpoints

    public async Task<List<GatewayProxyEndpoint>> ListProxyEndpointsAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<GatewayProxyEndpoint>>(AccountPath(accountId, "gateway", "proxy_endpoints"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Returns the IP proxy endpoint with this name or creates it (source ranges checked as CIDR, at most 2000).</summary>
    public async Task<(GatewayProxyEndpoint Endpoint, bool Created)> EnsureProxyEndpointAsync(string name, IEnumerable<string> ips, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "proxy_endpoints");
        EnsureWritable(HttpMethod.Post, path);
        var ranges = ips.Select(i => ZT.Cidr(i, nameof(ips)).Cidr).Distinct().ToList();
        if (ranges.Count is 0 or > 2000) throw new ArgumentException("1 to 2000 source ranges.", nameof(ips));
        var body = new JsonObject { ["name"] = P1.Required(name, nameof(name), 255), ["kind"] = "ip", ["ips"] = P1.Arr(ranges) };
        var existing = (await ListProxyEndpointsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(e => e.Name == name);
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<GatewayProxyEndpoint>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>Deletes a proxy endpoint; browsers configured with it lose their proxy, so this always needs <paramref name="allowDelete"/>.</summary>
    public Task<bool> RemoveProxyEndpointAsync(string endpointId, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "proxy_endpoints", P1.Required(endpointId, nameof(endpointId)));
        EnsureWritable(HttpMethod.Delete, path);
        P2.Allow(allowDelete, "deleting a proxy endpoint ends filtering for every browser that uses it", nameof(allowDelete));
        return DeleteIfExistsAsync(path, null, ct);
    }

    // ------------------------------------------------------------------ certificates

    public async Task<List<GatewayCertificate>> ListCertificatesAsync(string? accountId = null, CancellationToken ct = default) =>
        await ZT.GetListAsync<GatewayCertificate>(Api, AccountPath(accountId, "gateway", "certificates"), ct).ConfigureAwait(false);

    public Task<GatewayCertificate> GetCertificateAsync(string certificateId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<GatewayCertificate>(Api, HttpMethod.Get, AccountPath(accountId, "gateway", "certificates", certificateId), null, ct);

    public CloudflareChangePreview PreviewCreateCertificate(int validityDays = 1826, string? accountId = null) =>
        new("POST", AccountPath(accountId, "gateway", "certificates"), new JsonObject { ["validity_period_days"] = CheckDays(validityDays) },
            $"Generate a Cloudflare-managed inspection certificate valid for {validityDays} days (at most 3 per day, 10 active).");

    /// <summary>Generates a Cloudflare-managed certificate (POST, not retried after a server error). It is inactive until <see cref="ActivateCertificateAsync"/>.</summary>
    public Task<GatewayCertificate> CreateCertificateAsync(int validityDays = 1826, string? accountId = null, CancellationToken ct = default)
    {
        var preview = PreviewCreateCertificate(validityDays, accountId);
        return ZT.SendAsync<GatewayCertificate>(Api, HttpMethod.Post, preview.Path, preview.Body, ct);
    }

    /// <summary>Deploys a certificate to the edge (POST). Using it for inspection is a separate configuration change (<see cref="GatewaySettingsChange.CertificateId"/>).</summary>
    public Task<GatewayCertificate> ActivateCertificateAsync(string certificateId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<GatewayCertificate>(Api, HttpMethod.Post, AccountPath(accountId, "gateway", "certificates", P1.Required(certificateId, nameof(certificateId)), "activate"), null, ct);

    /// <summary>Takes a certificate off the edge after a fresh read; one in use for inspection needs <paramref name="allowDisable"/> (devices then see certificate errors).</summary>
    public async Task<GatewayCertificate> DeactivateCertificateAsync(string certificateId, bool allowDisable = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "certificates", P1.Required(certificateId, nameof(certificateId)), "deactivate");
        EnsureWritable(HttpMethod.Post, path);
        var current = await GetCertificateAsync(certificateId, accountId, ct).ConfigureAwait(false);
        if (current.InUse == true) P2.Allow(allowDisable, $"certificate {certificateId} is used for TLS inspection", nameof(allowDisable));
        return await ZT.SendAsync<GatewayCertificate>(Api, HttpMethod.Post, path, null, ct).ConfigureAwait(false);
    }

    /// <summary>Deletes a certificate after a fresh read; one in use or deployed (<c>available</c>) needs <paramref name="allowDisable"/>. False when it did not exist.</summary>
    public async Task<bool> RemoveCertificateAsync(string certificateId, bool allowDisable = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "gateway", "certificates", P1.Required(certificateId, nameof(certificateId)));
        EnsureWritable(HttpMethod.Delete, path);
        var current = await ZT.GetOrNullAsync<GatewayCertificate>(Api, path, ct).ConfigureAwait(false);
        if (current is null) return false;
        if (current.InUse == true || current.BindingStatus == "available")
            P2.Allow(allowDisable, $"certificate {certificateId} is deployed{(current.InUse == true ? " and used for TLS inspection" : "")}", nameof(allowDisable));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private static int CheckDays(int days) => days is >= 1 and <= 10950 ? days : throw new ArgumentOutOfRangeException(nameof(days), "1 to 10950 days.");
}
