using System.Globalization;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed record ZoneTrafficSummary(long Requests, long Threats, long CachedRequests, long Bytes)
{
    public double ThreatShare => Requests == 0 ? 0 : Threats * 100.0 / Requests;
    public double CacheHitRatio => Requests == 0 ? 0 : CachedRequests * 100.0 / Requests;
}

public sealed record SecurityEvent(DateTimeOffset Time, string Action, string Source, string RuleId, string Country, string Host, string Path, string ClientIp)
{
    /// <summary>Shortened address for logs (IPv4: last octet hidden, IPv6: everything after the third group hidden).</summary>
    public string MaskedIp => MaskIp(ClientIp);

    public static string MaskIp(string ip)
    {
        if (ip.Contains('.') && !ip.Contains(':'))
        {
            var p = ip.Split('.');
            return p.Length == 4 ? $"{p[0]}.{p[1]}.{p[2]}.x" : "?";
        }
        var g = ip.Split(':');
        return g.Length >= 3 ? $"{g[0]}:{g[1]}:{g[2]}::" : "?";
    }
}

public sealed class WebAnalyticsSite : CloudflareModel
{
    public string SiteTag { get; init; } = "";
    public string? SiteToken { get; init; }
    public string? Host { get; init; }
    public string? ZoneTag { get; init; }
    public bool AutoInstall { get; init; }
    public string? Snippet { get; init; }
}

/// <summary>GraphQL Analytics and Web Analytics (RUM).</summary>
public sealed class AnalyticsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Any GraphQL query against the Analytics schema.</summary>
    public Task<JsonElement> QueryAsync(string query, object? variables = null, CancellationToken ct = default) =>
        Api.GraphQlAsync(query, variables, ct);

    /// <summary>Totals of requests, threats, cached requests and bytes over the last <paramref name="days"/> days (token needs "Analytics: Read").</summary>
    public async Task<ZoneTrafficSummary> GetTrafficSummaryAsync(int days = 1, string? zoneId = null, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        const string q = "query($zone:String!,$from:Date!){viewer{zones(filter:{zoneTag:$zone}){httpRequests1dGroups(limit:100,filter:{date_geq:$from}){sum{requests threats cachedRequests bytes}}}}}";
        var from = (now ?? DateTimeOffset.UtcNow).UtcDateTime.Date.AddDays(-Math.Max(1, days)).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var root = await Api.GraphQlAsync(q, new Dictionary<string, object> { ["zone"] = Zone(zoneId), ["from"] = from }, ct).ConfigureAwait(false);
        return ParseTraffic(root);
    }

    internal static ZoneTrafficSummary ParseTraffic(JsonElement root)
    {
        long requests = 0, threats = 0, cached = 0, bytes = 0;
        foreach (var g in Zones(root, "httpRequests1dGroups"))
        {
            if (!g.TryGetProperty("sum", out var sum)) continue;
            requests += Long(sum, "requests");
            threats += Long(sum, "threats");
            cached += Long(sum, "cachedRequests");
            bytes += Long(sum, "bytes");
        }
        return new ZoneTrafficSummary(requests, threats, cached, bytes);
    }

    /// <summary>Security events (WAF, rate limiting, bots, …) in a time window; an alternative to Logpush on non-Enterprise plans.</summary>
    public async Task<IReadOnlyList<SecurityEvent>> GetSecurityEventsAsync(DateTimeOffset from, DateTimeOffset to, int limit = 100, string? zoneId = null, CancellationToken ct = default)
    {
        const string q = "query($zone:String!,$from:Time!,$to:Time!,$limit:Int!){viewer{zones(filter:{zoneTag:$zone}){firewallEventsAdaptive(filter:{datetime_geq:$from,datetime_leq:$to},limit:$limit,orderBy:[datetime_ASC]){action clientCountryName clientIP clientRequestHTTPHost clientRequestPath datetime ruleId source}}}}";
        var vars = new Dictionary<string, object>
        {
            ["zone"] = Zone(zoneId),
            ["from"] = from.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["to"] = to.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["limit"] = Math.Clamp(limit, 1, 10_000),
        };
        return ParseEvents(await Api.GraphQlAsync(q, vars, ct).ConfigureAwait(false));
    }

    internal static IReadOnlyList<SecurityEvent> ParseEvents(JsonElement root) =>
        Zones(root, "firewallEventsAdaptive").Select(e => new SecurityEvent(
            DateTimeOffset.TryParse(Str(e, "datetime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) ? t : DateTimeOffset.MinValue,
            Str(e, "action"), Str(e, "source"), Str(e, "ruleId"), Str(e, "clientCountryName"),
            Str(e, "clientRequestHTTPHost"), Str(e, "clientRequestPath"), Str(e, "clientIP"))).ToList();

    // ---- Web Analytics (RUM) ----
    public Task<IReadOnlyList<WebAnalyticsSite>> ListWebAnalyticsSitesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<WebAnalyticsSite>(AccountPath(accountId, "rum", "site_info", "list"), 100, ct);

    /// <summary>Enables Web Analytics for a proxied zone (<paramref name="autoInstall"/> injects the beacon automatically).</summary>
    public Task<WebAnalyticsSite> CreateWebAnalyticsSiteAsync(string? zoneId = null, bool autoInstall = true, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<WebAnalyticsSite>(AccountPath(accountId, "rum", "site_info"), new { zone_tag = Zone(zoneId), auto_install = autoInstall }, ct);

    private static IEnumerable<JsonElement> Zones(JsonElement root, string dataset)
    {
        if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object) yield break;
        if (!data.TryGetProperty("viewer", out var viewer) || !viewer.TryGetProperty("zones", out var zones) || zones.ValueKind != JsonValueKind.Array) yield break;
        foreach (var z in zones.EnumerateArray())
            if (z.TryGetProperty(dataset, out var rows) && rows.ValueKind == JsonValueKind.Array)
                foreach (var r in rows.EnumerateArray()) yield return r;
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static long Long(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : 0;
}
