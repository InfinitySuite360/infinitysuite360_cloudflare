using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class Zone : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Status { get; init; } = "";
    public bool Paused { get; init; }
    public string? Type { get; init; }
    public List<string> NameServers { get; init; } = [];
    public ZonePlan? Plan { get; init; }
    public ZoneAccount? Account { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

public sealed class ZonePlan : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? LegacyId { get; init; }
}

public sealed class ZoneAccount : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
}

/// <summary>A zone setting (for example "ssl", "min_tls_version", "always_use_https", "security_level").</summary>
public sealed class ZoneSetting : CloudflareModel
{
    public string Id { get; init; } = "";
    public JsonElement Value { get; init; }
    public bool Editable { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }

    /// <summary>Value as text (the string content, otherwise the raw JSON).</summary>
    public string ValueText => Value.ValueKind == JsonValueKind.String ? Value.GetString() ?? "" : Value.ValueKind == JsonValueKind.Undefined ? "" : Value.GetRawText();
}

public sealed class DnssecStatus : CloudflareModel
{
    /// <summary>"active", "pending", "disabled", "pending-disabled", "error".</summary>
    public string Status { get; init; } = "";
    public string? Ds { get; init; }
    public string? Digest { get; init; }
    public string? KeyTag { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>Frequently used zone setting IDs.</summary>
public static class ZoneSettingIds
{
    public const string Ssl = "ssl";
    public const string MinTlsVersion = "min_tls_version";
    public const string Tls13 = "tls_1_3";
    public const string AlwaysUseHttps = "always_use_https";
    public const string AutomaticHttpsRewrites = "automatic_https_rewrites";
    public const string SecurityLevel = "security_level";
    public const string SecurityHeader = "security_header";
    public const string BrowserCheck = "browser_check";
    public const string OpportunisticEncryption = "opportunistic_encryption";
    public const string Http3 = "http3";
    public const string Brotli = "brotli";
    public const string EarlyHints = "early_hints";
    public const string Ipv6 = "ipv6";
    public const string AlwaysOnline = "always_online";
    public const string DevelopmentMode = "development_mode";
    public const string CacheLevel = "cache_level";
    public const string BrowserCacheTtl = "browser_cache_ttl";
    public const string EmailObfuscation = "email_obfuscation";
    public const string HotlinkProtection = "hotlink_protection";
    public const string WebSockets = "websockets";
    /// <summary>How long a visitor who passed a challenge is not challenged again (seconds).</summary>
    public const string ChallengeTtl = "challenge_ttl";
    /// <summary>0-RTT connection resumption ("on"/"off"); requests can be replayed, so "off" is the safer value for APIs.</summary>
    public const string ZeroRtt = "0rtt";
    /// <summary>Encrypted Client Hello ("on"/"off").</summary>
    public const string Ech = "ech";
    /// <summary>SSL/TLS Recommender: Cloudflare suggests the strictest SSL mode the origin supports.</summary>
    public const string SslRecommender = "ssl_recommender";
}

/// <summary>Zones, zone settings, cache purge, DNSSEC and Tiered Cache.</summary>
public sealed class ZonesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<Zone>> ListAsync(string? name = null, string? status = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<Zone>(CloudflarePath.WithQuery("zones", ("name", name), ("status", status), ("account.id", accountId)), 50, ct);

    public Task<Zone> GetAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<Zone>(ZonePath(zoneId), ct);

    public async Task<Zone?> FindByNameAsync(string name, CancellationToken ct = default) =>
        (await ListAsync(name, ct: ct).ConfigureAwait(false)).FirstOrDefault(z => string.Equals(z.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Creates a zone. <paramref name="type"/>: "full" or "partial".</summary>
    public Task<Zone> CreateAsync(string name, string? accountId = null, string type = "full", CancellationToken ct = default) =>
        Api.PostAsync<Zone>("zones", new JsonObject { ["name"] = name, ["account"] = new JsonObject { ["id"] = Account(accountId) }, ["type"] = type }, ct);

    public Task DeleteAsync(string zoneId, CancellationToken ct = default) => Api.DeleteAsync(CloudflarePath.Of("zones", zoneId), ct);

    /// <summary>Triggers a new activation check.</summary>
    public Task<IdResult> ActivationCheckAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<IdResult>(ZonePath(zoneId, "activation_check"), null, ct);

    // ---- Settings ----

    public Task<List<ZoneSetting>> GetSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<ZoneSetting>>(ZonePath(zoneId, "settings"), ct);

    public Task<ZoneSetting> GetSettingAsync(string settingId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<ZoneSetting>(ZonePath(zoneId, "settings", settingId), ct);

    /// <summary>
    /// Sets one setting. <paramref name="value"/> for example "on", "strict", "1.2" or an object (security_header).
    /// Since 0.7.1 the TLS guards of <see cref="TlsSettingsClient"/> apply with their safe defaults: a weaker <c>ssl</c> mode or <c>min_tls_version</c>, TLS 1.3
    /// only, and switching <c>tls_1_3</c>, <c>always_use_https</c> or <c>opportunistic_encryption</c> off are refused (use <c>Tls</c> with <c>allowWeaken</c>).
    /// </summary>
    public async Task<ZoneSetting> SetSettingAsync(string settingId, object value, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        var node = JsonSerializer.SerializeToNode(value, value.GetType(), CloudflareJson.Options);
        var path = ZonePath(zoneId, "settings", settingId);
        if (TlsSettingsClient.IsGuarded(settingId))
        {
            EnsureWritable(HttpMethod.Patch, path);
            await new TlsSettingsClient(Api).RefuseWeakeningAsync([(settingId, node)], zoneId, ct).ConfigureAwait(false);
        }
        return await Api.PatchAsync<ZoneSetting>(path, new JsonObject { ["value"] = node }, ct).ConfigureAwait(false);
    }

    /// <summary>Sets several settings in one call. The TLS guards of <see cref="SetSettingAsync"/> apply to every item (one read of the settings).</summary>
    public async Task<List<ZoneSetting>> SetSettingsAsync(IReadOnlyDictionary<string, object> values, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(values);
        var nodes = values.Select(kv => (Id: kv.Key, Value: JsonSerializer.SerializeToNode(kv.Value, kv.Value.GetType(), CloudflareJson.Options))).ToList();
        var path = ZonePath(zoneId, "settings");
        if (nodes.Any(n => TlsSettingsClient.IsGuarded(n.Id)))
        {
            EnsureWritable(HttpMethod.Patch, path);
            await new TlsSettingsClient(Api).RefuseWeakeningAsync(nodes, zoneId, ct).ConfigureAwait(false);
        }
        var items = new JsonArray(nodes.Select(n => (JsonNode)new JsonObject { ["id"] = n.Id, ["value"] = n.Value?.DeepClone() }).ToArray());
        return await Api.PatchAsync<List<ZoneSetting>>(path, new JsonObject { ["items"] = items }, ct).ConfigureAwait(false);
    }

    // ---- Cache ----

    /// <summary>Always refused since 0.7.1 (no switch in this signature): use <c>Cache.PurgeEverythingAsync(allowPurgeAll: true)</c>.</summary>
    [Obsolete("Always refused since 0.7.1: purging everything needs an explicit switch. Use Cache.PurgeEverythingAsync(allowPurgeAll: true). Removed in 1.0.")]
    public async Task<IdResult> PurgeEverythingAsync(string? zoneId = null, CancellationToken ct = default) =>
        await new CacheClient(Api).PurgeEverythingAsync(allowPurgeAll: false, zoneId, ct).ConfigureAwait(false);

    /// <summary>Same checks as <see cref="CacheClient.PurgeUrlsAsync"/> (since 0.7.1); returns the id of the first request.</summary>
    public async Task<IdResult> PurgeFilesAsync(IEnumerable<string> urls, string? zoneId = null, CancellationToken ct = default) =>
        First(await new CacheClient(Api).PurgeUrlsAsync(urls, zoneId, ct).ConfigureAwait(false));

    /// <summary>Same checks as <see cref="CacheClient.PurgeTagsAsync"/> (since 0.7.1); returns the id of the first request.</summary>
    public async Task<IdResult> PurgeTagsAsync(IEnumerable<string> tags, string? zoneId = null, CancellationToken ct = default) =>
        First(await new CacheClient(Api).PurgeTagsAsync(tags, zoneId, ct).ConfigureAwait(false));

    /// <summary>Same checks as <see cref="CacheClient.PurgeHostsAsync"/> (bare hostnames, since 0.7.1); returns the id of the first request.</summary>
    public async Task<IdResult> PurgeHostsAsync(IEnumerable<string> hosts, string? zoneId = null, CancellationToken ct = default) =>
        First(await new CacheClient(Api).PurgeHostsAsync(hosts, zoneId, ct).ConfigureAwait(false));

    /// <summary>Same checks as <see cref="CacheClient.PurgePrefixesAsync"/> (host and path, since 0.7.1); returns the id of the first request.</summary>
    public async Task<IdResult> PurgePrefixesAsync(IEnumerable<string> prefixes, string? zoneId = null, CancellationToken ct = default) =>
        First(await new CacheClient(Api).PurgePrefixesAsync(prefixes, zoneId, ct).ConfigureAwait(false));

    private static IdResult First(IReadOnlyList<IdResult> ids) => ids.Count > 0 ? ids[0] : new IdResult();

    public Task<ZoneSetting> GetTieredCacheSmartTopologyAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<ZoneSetting>(ZonePath(zoneId, "cache", "tiered_cache_smart_topology_enable"), ct);

    public Task<ZoneSetting> SetTieredCacheSmartTopologyAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<ZoneSetting>(ZonePath(zoneId, "cache", "tiered_cache_smart_topology_enable"), new JsonObject { ["value"] = enabled ? "on" : "off" }, ct);

    // ---- DNSSEC ----

    public Task<DnssecStatus> GetDnssecAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<DnssecStatus>(ZonePath(zoneId, "dnssec"), ct);

    public Task<DnssecStatus> SetDnssecAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<DnssecStatus>(ZonePath(zoneId, "dnssec"), new JsonObject { ["status"] = enabled ? "active" : "disabled" }, ct);
}
