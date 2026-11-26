using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>HTTP Strict Transport Security of a zone (part of the zone setting <c>security_header</c>).</summary>
public sealed class HstsSettings
{
    public bool Enabled { get; init; }
    /// <summary>max-age in seconds.</summary>
    public int MaxAge { get; init; }
    public bool IncludeSubdomains { get; init; }
    public bool Preload { get; init; }
    /// <summary>Adds <c>X-Content-Type-Options: nosniff</c>.</summary>
    public bool Nosniff { get; init; }
}

/// <summary>TLS-related settings of a zone, read with one request.</summary>
public sealed class TlsOverview
{
    /// <summary>"off", "flexible", "full" or "strict".</summary>
    public string? SslMode { get; init; }
    public string? MinTlsVersion { get; init; }
    /// <summary>"on", "off" or "zrt" (with 0-RTT).</summary>
    public string? Tls13 { get; init; }
    public string? AlwaysUseHttps { get; init; }
    public string? AutomaticHttpsRewrites { get; init; }
    public string? OpportunisticEncryption { get; init; }
    public string? Ech { get; init; }
    public string? Http3 { get; init; }
    public string? ZeroRtt { get; init; }
    public HstsSettings? Hsts { get; init; }
}

/// <summary>
/// SSL/TLS settings of a zone with previews and guards (zone settings API, developers.cloudflare.com/ssl/edge-certificates/additional-options/, 17.11.2026).
/// Weakening the SSL mode or the minimum TLS version needs <c>allowWeaken: true</c>; TLS 1.3 only (old clients fail) needs <c>allowTls13Only</c>;
/// HSTS that browsers keep longer than one day, with subdomains or preload needs <c>allowLongLivedHsts</c> (HTTPS can then not be switched off
/// for the max-age). Token permission: "Zone: Zone Settings: Edit" (reading "Read"). Per-hostname TLS settings (Advanced Certificate Manager) are
/// reachable through <c>OpenApi</c>.
/// </summary>
public sealed class TlsSettingsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] SslModes = ["off", "flexible", "full", "strict"];
    private static readonly string[] TlsVersions = ["1.0", "1.1", "1.2", "1.3"];
    private static readonly HashSet<string> Switches =
    [
        ZoneSettingIds.Tls13, ZoneSettingIds.AlwaysUseHttps, ZoneSettingIds.AutomaticHttpsRewrites, ZoneSettingIds.OpportunisticEncryption,
        ZoneSettingIds.Ech, ZoneSettingIds.Http3, ZoneSettingIds.ZeroRtt,
    ];

    public async Task<TlsOverview> GetOverviewAsync(string? zoneId = null, CancellationToken ct = default)
    {
        var settings = (await Api.GetAsync<List<ZoneSetting>>(ZonePath(zoneId, "settings"), ct).ConfigureAwait(false) ?? []).ToDictionary(s => s.Id, s => s);
        string? Text(string id) => settings.TryGetValue(id, out var s) ? s.ValueText : null;
        return new TlsOverview
        {
            SslMode = Text(ZoneSettingIds.Ssl), MinTlsVersion = Text(ZoneSettingIds.MinTlsVersion), Tls13 = Text(ZoneSettingIds.Tls13),
            AlwaysUseHttps = Text(ZoneSettingIds.AlwaysUseHttps), AutomaticHttpsRewrites = Text(ZoneSettingIds.AutomaticHttpsRewrites),
            OpportunisticEncryption = Text(ZoneSettingIds.OpportunisticEncryption), Ech = Text(ZoneSettingIds.Ech), Http3 = Text(ZoneSettingIds.Http3),
            ZeroRtt = Text(ZoneSettingIds.ZeroRtt),
            Hsts = settings.TryGetValue(ZoneSettingIds.SecurityHeader, out var sh) ? ReadHsts(sh.Value) : null,
        };
    }

    // ---- SSL mode ----

    /// <summary>Reads the current mode and plans the change (read-only).</summary>
    public async Task<CloudflareChangePreview> PreviewSetSslModeAsync(string mode, string? zoneId = null, CancellationToken ct = default)
    {
        var current = (await Api.GetAsync<ZoneSetting>(ZonePath(zoneId, "settings", ZoneSettingIds.Ssl), ct).ConfigureAwait(false)).ValueText;
        return new("PATCH", ZonePath(zoneId, "settings", ZoneSettingIds.Ssl), Value(CheckMode(mode)), ModeSummary(current, mode));
    }

    /// <summary>Sets the SSL/TLS encryption mode. A weaker mode than the current one (strict → full → flexible → off) needs <paramref name="allowWeaken"/>.</summary>
    public async Task<ZoneSetting> SetSslModeAsync(string mode, bool allowWeaken = false, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "settings", ZoneSettingIds.Ssl);
        CheckMode(mode);
        EnsureWritable(HttpMethod.Patch, path);
        if (!allowWeaken)
        {
            var current = (await Api.GetAsync<ZoneSetting>(path, ct).ConfigureAwait(false)).ValueText;
            if (Rank(SslModes, mode) < Rank(SslModes, current))
                throw new InvalidOperationException($"Refused: SSL mode {current} → {mode} weakens the encryption to the origin. Pass allowWeaken: true deliberately.");
        }
        return await Api.PatchAsync<ZoneSetting>(path, Value(mode), ct).ConfigureAwait(false);
    }

    // ---- minimum TLS version ----

    public async Task<CloudflareChangePreview> PreviewSetMinTlsVersionAsync(string version, string? zoneId = null, CancellationToken ct = default)
    {
        var current = (await Api.GetAsync<ZoneSetting>(ZonePath(zoneId, "settings", ZoneSettingIds.MinTlsVersion), ct).ConfigureAwait(false)).ValueText;
        return new("PATCH", ZonePath(zoneId, "settings", ZoneSettingIds.MinTlsVersion), Value(CustomHostnamesClient.Tls(version)),
            $"Minimum TLS version {current} → {version}." +
            (Rank(TlsVersions, version) < Rank(TlsVersions, current) ? " WARNING: weaker, older protocol versions are accepted again." : "") +
            (version == "1.3" ? " WARNING: clients without TLS 1.3 can no longer connect." : ""));
    }

    /// <summary>
    /// Sets the minimum TLS version. Lowering it needs <paramref name="allowWeaken"/>; "1.3" needs <paramref name="allowTls13Only"/> because clients
    /// without TLS 1.3 (older operating systems, embedded HTTP stacks) are locked out.
    /// </summary>
    public async Task<ZoneSetting> SetMinTlsVersionAsync(string version, bool allowWeaken = false, bool allowTls13Only = false, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "settings", ZoneSettingIds.MinTlsVersion);
        CustomHostnamesClient.Tls(version);
        if (version == "1.3" && !allowTls13Only)
            throw new ArgumentException("TLS 1.3 only locks out clients without TLS 1.3. Pass allowTls13Only: true deliberately.", nameof(version));
        EnsureWritable(HttpMethod.Patch, path);
        if (!allowWeaken)
        {
            var current = (await Api.GetAsync<ZoneSetting>(path, ct).ConfigureAwait(false)).ValueText;
            if (Rank(TlsVersions, version) < Rank(TlsVersions, current))
                throw new InvalidOperationException($"Refused: minimum TLS version {current} → {version} accepts weaker protocol versions. Pass allowWeaken: true deliberately.");
        }
        return await Api.PatchAsync<ZoneSetting>(path, Value(version), ct).ConfigureAwait(false);
    }

    // ---- HSTS ----

    public CloudflareChangePreview PreviewSetHsts(HstsSettings hsts, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "settings", ZoneSettingIds.SecurityHeader), HstsBody(hsts), HstsSummary(hsts));

    /// <summary>Sets HSTS. max-age above one day, includeSubDomains or preload need <paramref name="allowLongLivedHsts"/> (browsers keep it, HTTPS cannot be dropped).</summary>
    public Task<ZoneSetting> SetHstsAsync(HstsSettings hsts, bool allowLongLivedHsts = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (hsts.Enabled && (hsts.MaxAge > 86400 || hsts.IncludeSubdomains || hsts.Preload) && !allowLongLivedHsts)
            throw new ArgumentException("HSTS with max-age above one day, includeSubDomains or preload binds browsers to HTTPS for that time (also subdomains). Start short and pass allowLongLivedHsts: true deliberately.", nameof(hsts));
        return Api.PatchAsync<ZoneSetting>(ZonePath(zoneId, "settings", ZoneSettingIds.SecurityHeader), HstsBody(hsts), ct);
    }

    // ---- on/off switches ----

    public CloudflareChangePreview PreviewSetSwitch(string settingId, bool on, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "settings", CheckSwitch(settingId)), Value(on ? "on" : "off"), SwitchSummary(settingId, on));

    /// <summary>Switches tls_1_3, always_use_https, automatic_https_rewrites, opportunistic_encryption, ech, http3 or 0rtt on or off.</summary>
    public Task<ZoneSetting> SetSwitchAsync(string settingId, bool on, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<ZoneSetting>(ZonePath(zoneId, "settings", CheckSwitch(settingId)), Value(on ? "on" : "off"), ct);

    private static string CheckSwitch(string id) =>
        Switches.Contains(id) ? id : throw new ArgumentException($"Setting must be one of {string.Join(", ", Switches)}.", nameof(id));

    private static string SwitchSummary(string id, bool on) => $"Switch {id} {(on ? "on" : "off")}." + (id, on) switch
    {
        (ZoneSettingIds.ZeroRtt, true) => " WARNING: 0-RTT requests can be replayed; keep it off for APIs that change state.",
        (ZoneSettingIds.Tls13, false) or (ZoneSettingIds.AlwaysUseHttps, false) or (ZoneSettingIds.OpportunisticEncryption, false) => " Loosening.",
        _ => "",
    };

    private static string CheckMode(string mode) =>
        SslModes.Contains(mode) ? mode : throw new ArgumentException("SSL mode must be off, flexible, full or strict.", nameof(mode));

    private static string ModeSummary(string current, string mode) =>
        $"SSL mode {current} → {mode}." + (Rank(SslModes, mode) < Rank(SslModes, current) ? " WARNING: weaker encryption to the origin." : "")
        + (mode is "off" or "flexible" ? " Authenticated Origin Pulls do not apply in this mode." : "");

    private static int Rank(string[] order, string? value) => Array.IndexOf(order, value ?? "");

    private static JsonObject Value(string value) => new() { ["value"] = value };

    private static JsonObject HstsBody(HstsSettings h)
    {
        if (h.MaxAge < 0) throw new ArgumentException("max-age must not be negative.", nameof(h));
        return new JsonObject
        {
            ["value"] = new JsonObject
            {
                ["strict_transport_security"] = new JsonObject
                {
                    ["enabled"] = h.Enabled, ["max_age"] = h.MaxAge, ["include_subdomains"] = h.IncludeSubdomains, ["preload"] = h.Preload, ["nosniff"] = h.Nosniff,
                },
            },
        };
    }

    private static string HstsSummary(HstsSettings h) => !h.Enabled
        ? "Switch HSTS off (browsers keep the last max-age until it expires)."
        : string.Create(CultureInfo.InvariantCulture, $"Switch HSTS on with max-age {h.MaxAge} s{(h.IncludeSubdomains ? ", includeSubDomains" : "")}{(h.Preload ? ", preload" : "")}.")
          + (h.MaxAge > 86400 || h.IncludeSubdomains || h.Preload ? " WARNING: browsers keep HTTPS-only for that time; preload lists are hard to leave." : "");

    private static HstsSettings? ReadHsts(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("strict_transport_security", out var sts) || sts.ValueKind != JsonValueKind.Object) return null;
        bool B(string n) => sts.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
        return new HstsSettings
        {
            Enabled = B("enabled"), IncludeSubdomains = B("include_subdomains"), Preload = B("preload"), Nosniff = B("nosniff"),
            MaxAge = sts.TryGetProperty("max_age", out var m) && m.TryGetInt32(out var age) ? age : 0,
        };
    }
}
