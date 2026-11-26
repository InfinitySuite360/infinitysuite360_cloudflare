using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>TTL setting of a cache rule: <c>Mode</c> and, for the override modes, the seconds.</summary>
/// <param name="Mode">Edge TTL: respect_origin, override_origin or bypass_by_default. Browser TTL: respect_origin, override_origin or bypass.</param>
/// <param name="Seconds">Seconds (0 to 31 536 000), required for override_origin.</param>
public sealed record CacheTtl(string Mode, int? Seconds = null);

/// <summary>A cache rule (phase <c>http_request_cache_settings</c>, action <c>set_cache_settings</c>).</summary>
public sealed class CacheRuleInput
{
    public required string Ref { get; init; }
    public string? Description { get; init; }
    public required string Expression { get; init; }
    public bool Enabled { get; init; } = true;
    /// <summary>true = eligible for the cache (also for content Cloudflare does not cache by default), false = bypass the cache, null = unchanged.</summary>
    public bool? Cache { get; init; }
    public CacheTtl? EdgeTtl { get; init; }
    public CacheTtl? BrowserTtl { get; init; }
    /// <summary>
    /// Extra members of <c>action_parameters</c> (for example <c>cache_key</c>, <c>serve_stale</c>, <c>respect_strong_etags</c>), merged into the typed ones.
    /// <c>cache</c>, <c>edge_ttl</c> and <c>browser_ttl</c> are refused here (0.7.1): set them with the typed members, which carry the checks.
    /// </summary>
    public JsonElement? ExtraParameters { get; init; }
}

public sealed class CacheSetting : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"on" or "off" (regional tiered cache and cache reserve).</summary>
    public string? Value { get; init; }
    public bool? Editable { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>
/// Cache rules, purging and cache settings (developers.cloudflare.com/cache/, retrieved 17.11.2026). Cache rules are changed one rule at a time (see
/// <see cref="RulesetPhaseClient"/>); caching everything (an expression that matches every request) needs <c>allowBroadCache</c> (cached private pages are a
/// data leak), an edge TTL override of more than a day <c>allowLongTtl</c>. Purging by URL, hostname, tag and prefix is available on all plans (100 items per
/// request, token bucket per plan); <c>PurgeEverythingAsync</c> needs <c>allowPurgeAll</c> (the origin gets the whole load at once). Cache Reserve is billed,
/// so enabling it needs <c>allowBilling</c>. Token permissions "Zone: Cache Purge: Purge", "Zone: Cache Rules: Edit", "Zone: Zone Settings: Edit".
/// Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class CacheClient(ICloudflareApiConnection api) : RulesetPhaseClient(api)
{
    private const int PurgeBatch = 100;
    private const int MaxPurgeItems = 1000;

    // ---- cache rules ----

    public async Task<IReadOnlyList<RulesetRule>> ListRulesAsync(string? zoneId = null, CancellationToken ct = default) =>
        (await EntrypointAsync(RulesetPhases.CacheSettings, zoneId, ct).ConfigureAwait(false))?.Rules ?? [];

    public Task<CloudflareChangePreview?> PreviewUpsertRuleAsync(CacheRuleInput rule, bool allowBroadCache = false, bool allowLongTtl = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = Build(rule, allowBroadCache, allowLongTtl);
        return PlanUpsertAsync(RulesetPhases.CacheSettings, built, summary, zoneId, ct);
    }

    /// <summary>Creates or changes the cache rule with this ref (only this rule; writes only on change).</summary>
    public Task<(Ruleset? Ruleset, bool Changed)> UpsertRuleAsync(CacheRuleInput rule, bool allowBroadCache = false, bool allowLongTtl = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = Build(rule, allowBroadCache, allowLongTtl);
        return UpsertAsync(RulesetPhases.CacheSettings, built, summary, zoneId, ct);
    }

    public Task<CloudflareChangePreview?> PreviewRemoveRuleAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        PlanRemoveAsync(RulesetPhases.CacheSettings, CheckRef(reference), "", zoneId, ct);

    /// <summary>Removes the cache rule with this ref. False when it did not exist.</summary>
    public Task<bool> RemoveRuleAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        RemoveAsync(RulesetPhases.CacheSettings, CheckRef(reference), zoneId, ct);

    // ---- purge ----

    public CloudflareChangePreview PreviewPurgeUrls(IEnumerable<string> urls, string? zoneId = null) =>
        PurgePreview("files", CheckUrls(urls), zoneId, "URL");

    /// <summary>Purges single URLs (absolute http/https, no credentials; split into requests of 100; at most 1000 per call). Returns the ids of the requests.</summary>
    public Task<IReadOnlyList<IdResult>> PurgeUrlsAsync(IEnumerable<string> urls, string? zoneId = null, CancellationToken ct = default) =>
        PurgeAsync("files", CheckUrls(urls), zoneId, ct);

    public CloudflareChangePreview PreviewPurgeHosts(IEnumerable<string> hosts, string? zoneId = null) =>
        PurgePreview("hosts", CheckHosts(hosts), zoneId, "hostname");

    /// <summary>Purges everything cached for hostnames (bare hostnames, no wildcard).</summary>
    public Task<IReadOnlyList<IdResult>> PurgeHostsAsync(IEnumerable<string> hosts, string? zoneId = null, CancellationToken ct = default) =>
        PurgeAsync("hosts", CheckHosts(hosts), zoneId, ct);

    public CloudflareChangePreview PreviewPurgeTags(IEnumerable<string> tags, string? zoneId = null) =>
        PurgePreview("tags", CheckTags(tags), zoneId, "tag");

    /// <summary>Purges by Cache-Tag.</summary>
    public Task<IReadOnlyList<IdResult>> PurgeTagsAsync(IEnumerable<string> tags, string? zoneId = null, CancellationToken ct = default) =>
        PurgeAsync("tags", CheckTags(tags), zoneId, ct);

    public CloudflareChangePreview PreviewPurgePrefixes(IEnumerable<string> prefixes, string? zoneId = null) =>
        PurgePreview("prefixes", CheckPrefixes(prefixes), zoneId, "prefix");

    /// <summary>Purges by URL prefix (host and path without scheme, for example <c>example.com/assets/</c>).</summary>
    public Task<IReadOnlyList<IdResult>> PurgePrefixesAsync(IEnumerable<string> prefixes, string? zoneId = null, CancellationToken ct = default) =>
        PurgeAsync("prefixes", CheckPrefixes(prefixes), zoneId, ct);

    public CloudflareChangePreview PreviewPurgeEverything(string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "purge_cache"), new JsonObject { ["purge_everything"] = true }, "Purge the whole cache of the zone. WARNING: every request goes to the origin until the cache is warm again.");

    /// <summary>Purges the whole cache. Refused unless <paramref name="allowPurgeAll"/> is true. POST is never repeated automatically.</summary>
    public async Task<IdResult> PurgeEverythingAsync(bool allowPurgeAll = false, string? zoneId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowPurgeAll, "purging everything sends the full load to the origin at once", nameof(allowPurgeAll));
        return await Api.PostAsync<IdResult>(ZonePath(zoneId, "purge_cache"), new JsonObject { ["purge_everything"] = true }, ct).ConfigureAwait(false);
    }

    // ---- settings ----

    public Task<CacheSetting> GetCacheReserveAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<CacheSetting>(ZonePath(zoneId, "cache", "cache_reserve"), ct);

    public CloudflareChangePreview PreviewSetCacheReserve(bool enabled, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "cache", "cache_reserve"), new JsonObject { ["value"] = enabled ? "on" : "off" },
            enabled ? "Enable Cache Reserve. WARNING: billed by storage and operations (plan Paid or Enterprise)." : "Disable Cache Reserve.");

    /// <summary>Switches Cache Reserve. Enabling is billed and needs <paramref name="allowBilling"/>.</summary>
    public Task<CacheSetting> SetCacheReserveAsync(bool enabled, bool allowBilling = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (enabled) ResourceKit.Allow(allowBilling, "Cache Reserve is billed for storage and operations", nameof(allowBilling));
        return Api.PatchAsync<CacheSetting>(ZonePath(zoneId, "cache", "cache_reserve"), new JsonObject { ["value"] = enabled ? "on" : "off" }, ct);
    }

    public Task<CacheSetting> GetRegionalTieredCacheAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<CacheSetting>(ZonePath(zoneId, "cache", "regional_tiered_cache"), ct);

    /// <summary>Switches Regional Tiered Cache (Enterprise).</summary>
    public Task<CacheSetting> SetRegionalTieredCacheAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<CacheSetting>(ZonePath(zoneId, "cache", "regional_tiered_cache"), new JsonObject { ["value"] = enabled ? "on" : "off" }, ct);

    // ---- helpers ----

    private static (RulesetRule Rule, string Summary) Build(CacheRuleInput r, bool allowBroadCache, bool allowLongTtl)
    {
        var reference = CheckRef(r.Ref);
        ResourceKit.Required(r.Expression, nameof(r), 4096);
        var ap = new JsonObject();
        if (r.Cache is { } cache) ap["cache"] = cache;
        if (r.EdgeTtl is { } e) ap["edge_ttl"] = Ttl(e, edge: true);
        if (r.BrowserTtl is { } b) ap["browser_ttl"] = Ttl(b, edge: false);
        if (ResourceKit.Node(r.ExtraParameters) is JsonObject extra)
            foreach (var (k, v) in extra)
            {
                // M-2 (0.7.1): the typed members carry the guards (allowBroadCache, allowLongTtl); ExtraParameters must not override them.
                if (k is "cache" or "edge_ttl" or "browser_ttl")
                    throw new ArgumentException($"ExtraParameters must not set \"{k}\"; use Cache, EdgeTtl or BrowserTtl (they carry the checks).", nameof(r));
                ap[k] = v?.DeepClone();
            }
        else if (r.ExtraParameters is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) })
            throw new ArgumentException("ExtraParameters must be a JSON object.", nameof(r));
        if (ap.Count == 0) throw new ArgumentException("A cache rule sets at least one of cache, edge TTL or browser TTL.", nameof(r));
        if (r.Cache == true && MatchesAll(r.Expression))
            ResourceKit.Allow(allowBroadCache, "caching every request also caches HTML, API answers and logged-in pages (data leak between visitors)", nameof(allowBroadCache));
        if (r.EdgeTtl is { Mode: "override_origin", Seconds: > 86_400 })
            ResourceKit.Allow(allowLongTtl, "an edge TTL above one day keeps stale content for visitors after changes", nameof(allowLongTtl));
        var rule = new RulesetRule { Ref = reference, Action = "set_cache_settings", Expression = r.Expression, Description = r.Description, Enabled = r.Enabled, ActionParameters = El(ap) };
        return (rule, $"set cache settings when {(r.Expression.Length <= 120 ? r.Expression : r.Expression[..117] + "...")}.");
    }

    private static JsonObject Ttl(CacheTtl t, bool edge)
    {
        string[] modes = edge ? ["respect_origin", "override_origin", "bypass_by_default"] : ["respect_origin", "override_origin", "bypass"];
        if (Array.IndexOf(modes, t.Mode) < 0) throw new ArgumentException($"Mode must be {string.Join(", ", modes)}.", nameof(t));
        var o = new JsonObject { ["mode"] = t.Mode };
        if (t.Mode == "override_origin")
        {
            if (t.Seconds is not { } s || s is < 0 or > 31_536_000) throw new ArgumentOutOfRangeException(nameof(t), "Seconds 0 to 31536000.");
            o["default"] = s;
        }
        return o;
    }

    private static List<string> CheckUrls(IEnumerable<string> urls)
    {
        var list = Items(urls, "URLs");
        foreach (var u in list)
            if (!Uri.TryCreate(u, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo) || u.Length > 4096)
                throw new ArgumentException($"\"{u}\" is not an absolute http(s) URL without credentials.", nameof(urls));
        return list;
    }

    private static List<string> CheckHosts(IEnumerable<string> hosts) => Items(hosts, "hostnames").Select(h => ResourceKit.Hostname(h, nameof(hosts))).ToList();

    private static List<string> CheckTags(IEnumerable<string> tags)
    {
        var list = Items(tags, "tags");
        foreach (var t in list)
            if (t.Length > 1024 || t.Contains(',') || t.Any(char.IsControl)) throw new ArgumentException("A tag has at most 1024 characters, no comma and no control characters.", nameof(tags));
        return list;
    }

    private static List<string> CheckPrefixes(IEnumerable<string> prefixes)
    {
        var list = Items(prefixes, "prefixes");
        foreach (var p in list)
            if (p.Contains("://", StringComparison.Ordinal) || p.Length > 4096 || p.StartsWith('/') || p.Any(char.IsWhiteSpace))
                throw new ArgumentException($"\"{p}\" is not a prefix (host and path without scheme, for example example.com/assets/).", nameof(prefixes));
        return list;
    }

    private static List<string> Items(IEnumerable<string> values, string what)
    {
        var list = (values ?? throw new ArgumentNullException(nameof(values))).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.Ordinal).ToList();
        if (list.Count == 0) throw new ArgumentException($"At least one of the {what} is required.", nameof(values));
        if (list.Count > MaxPurgeItems) throw new ArgumentException($"At most {MaxPurgeItems} {what} per call.", nameof(values));
        return list;
    }

    private CloudflareChangePreview PurgePreview(string kind, List<string> items, string? zoneId, string noun) =>
        new("POST", ZonePath(zoneId, "purge_cache"), new JsonObject { [kind] = ResourceKit.Arr(items.Take(PurgeBatch)) },
            $"Purge {items.Count} {noun}(s) from the cache{(items.Count > PurgeBatch ? $" in {(items.Count + PurgeBatch - 1) / PurgeBatch} requests (the body shows the first)" : "")}.");

    private async Task<IReadOnlyList<IdResult>> PurgeAsync(string kind, List<string> items, string? zoneId, CancellationToken ct)
    {
        var path = ZonePath(zoneId, "purge_cache");
        EnsureWritable(HttpMethod.Post, path);
        var ids = new List<IdResult>();
        foreach (var chunk in ResourceKit.Chunk(items, PurgeBatch))
            ids.Add(await Api.PostAsync<IdResult>(path, new JsonObject { [kind] = ResourceKit.Arr(chunk) }, ct).ConfigureAwait(false));
        return ids;
    }
}

/// <summary>
/// Argo Smart Routing and Argo tiered caching of a zone (developers.cloudflare.com/argo-smart-routing/, retrieved 17.11.2026: billed by traffic). Switching Argo
/// Smart Routing on needs <c>allowBilling</c>. Token permission "Zone: Zone Settings: Edit" (reading "Read"). Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class ArgoClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<CacheSetting> GetSmartRoutingAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<CacheSetting>(ZonePath(zoneId, "argo", "smart_routing"), ct);

    public CloudflareChangePreview PreviewSetSmartRouting(bool enabled, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "argo", "smart_routing"), new JsonObject { ["value"] = enabled ? "on" : "off" },
            enabled ? "Enable Argo Smart Routing. WARNING: billed per gigabyte of traffic." : "Disable Argo Smart Routing.");

    /// <summary>Switches Argo Smart Routing. Enabling is billed and needs <paramref name="allowBilling"/>.</summary>
    public Task<CacheSetting> SetSmartRoutingAsync(bool enabled, bool allowBilling = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (enabled) ResourceKit.Allow(allowBilling, "Argo Smart Routing is billed per gigabyte", nameof(allowBilling));
        return Api.PatchAsync<CacheSetting>(ZonePath(zoneId, "argo", "smart_routing"), new JsonObject { ["value"] = enabled ? "on" : "off" }, ct);
    }

    public Task<CacheSetting> GetTieredCachingAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<CacheSetting>(ZonePath(zoneId, "argo", "tiered_caching"), ct);

    /// <summary>Switches Argo tiered caching.</summary>
    public Task<CacheSetting> SetTieredCachingAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<CacheSetting>(ZonePath(zoneId, "argo", "tiered_caching"), new JsonObject { ["value"] = enabled ? "on" : "off" }, ct);
}
