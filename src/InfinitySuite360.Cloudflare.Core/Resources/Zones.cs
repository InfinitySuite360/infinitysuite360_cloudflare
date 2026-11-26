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

    /// <summary>Sets one setting. <paramref name="value"/> for example "on", "strict", "1.2" or an object (security_header).</summary>
    public Task<ZoneSetting> SetSettingAsync(string settingId, object value, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<ZoneSetting>(ZonePath(zoneId, "settings", settingId), new JsonObject { ["value"] = JsonSerializer.SerializeToNode(value, value.GetType(), CloudflareJson.Options) }, ct);

    /// <summary>Sets several settings in one call.</summary>
    public Task<List<ZoneSetting>> SetSettingsAsync(IReadOnlyDictionary<string, object> values, string? zoneId = null, CancellationToken ct = default)
    {
        var items = new JsonArray(values.Select(kv => (JsonNode)new JsonObject
        {
            ["id"] = kv.Key,
            ["value"] = JsonSerializer.SerializeToNode(kv.Value, kv.Value.GetType(), CloudflareJson.Options),
        }).ToArray());
        return Api.PatchAsync<List<ZoneSetting>>(ZonePath(zoneId, "settings"), new JsonObject { ["items"] = items }, ct);
    }

    // ---- Cache ----

    public Task<IdResult> PurgeEverythingAsync(string? zoneId = null, CancellationToken ct = default) =>
        Purge(new JsonObject { ["purge_everything"] = true }, zoneId, ct);

    public Task<IdResult> PurgeFilesAsync(IEnumerable<string> urls, string? zoneId = null, CancellationToken ct = default) => PurgeList("files", urls, zoneId, ct);
    public Task<IdResult> PurgeTagsAsync(IEnumerable<string> tags, string? zoneId = null, CancellationToken ct = default) => PurgeList("tags", tags, zoneId, ct);
    public Task<IdResult> PurgeHostsAsync(IEnumerable<string> hosts, string? zoneId = null, CancellationToken ct = default) => PurgeList("hosts", hosts, zoneId, ct);
    public Task<IdResult> PurgePrefixesAsync(IEnumerable<string> prefixes, string? zoneId = null, CancellationToken ct = default) => PurgeList("prefixes", prefixes, zoneId, ct);

    private Task<IdResult> PurgeList(string kind, IEnumerable<string> values, string? zoneId, CancellationToken ct)
    {
        var list = values.Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
        if (list.Count == 0) throw new ArgumentException("At least one entry is required.", nameof(values));
        return Purge(new JsonObject { [kind] = new JsonArray(list.Select(v => (JsonNode)JsonValue.Create(v)!).ToArray()) }, zoneId, ct);
    }

    private Task<IdResult> Purge(JsonObject body, string? zoneId, CancellationToken ct) =>
        Api.PostAsync<IdResult>(ZonePath(zoneId, "purge_cache"), body, ct);

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
