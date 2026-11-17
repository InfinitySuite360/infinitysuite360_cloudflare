using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class SpectrumApp : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>For example "tcp/22", "tcp/443", "udp/53".</summary>
    public string Protocol { get; init; } = "";
    public JsonElement? Dns { get; init; }
    public JsonElement? OriginDirect { get; init; }
    public JsonElement? OriginDns { get; init; }
    public JsonElement? OriginPort { get; init; }
    public bool? IpFirewall { get; init; }
    public string? ProxyProtocol { get; init; }
    public string? Tls { get; init; }
    public string? TrafficType { get; init; }
    public bool? ArgoSmartRouting { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>A Spectrum application that proxies a TCP or UDP port of an origin.</summary>
public sealed class SpectrumAppInput
{
    /// <summary>The hostname clients connect to.</summary>
    public required string Hostname { get; init; }
    /// <summary>"tcp/PORT" or "udp/PORT" (or a port range "tcp/8000-8100").</summary>
    public required string Protocol { get; init; }
    /// <summary>Origin IP addresses, for example <c>tcp://203.0.113.10:22</c>. Exactly one of this and <see cref="OriginDnsName"/>.</summary>
    public IReadOnlyList<string>? OriginDirect { get; init; }
    public string? OriginDnsName { get; init; }
    public int? OriginPort { get; init; }
    /// <summary>Cloudflare's IP firewall for this application (default true).</summary>
    public bool IpFirewall { get; init; } = true;
    /// <summary>"off", "v1", "v2" or "simple".</summary>
    public string ProxyProtocol { get; init; } = "off";
    /// <summary>"off", "flexible", "full" or "strict".</summary>
    public string Tls { get; init; } = "off";
    /// <summary>"direct", "http" or "https".</summary>
    public string TrafficType { get; init; } = "direct";
}

/// <summary>
/// Spectrum (TCP/UDP proxy; developers.cloudflare.com/spectrum/, retrieved 17.11.2026: paid plans, custom TCP/UDP applications only on Enterprise with the add-on,
/// so Cloudflare may answer with <see cref="CloudflareNotEntitledException"/>). Publishing a management or database port (SSH, RDP, Telnet, SMB, VNC, SQL, Redis,
/// MongoDB, …) to the internet needs <c>allowSensitivePort</c>; deleting an application <c>allowDelete</c>. Token permission "Zone: Zone Settings: Edit"
/// (reading "Read"). Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class SpectrumClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly HashSet<int> SensitivePorts = [21, 22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017];
    private static readonly Regex ProtocolPattern = P2.Rx(@"^(tcp|udp)/([0-9]{1,5})(-([0-9]{1,5}))?$");
    private static readonly HashSet<string> ProxyProtocols = ["off", "v1", "v2", "simple"];
    private static readonly HashSet<string> TlsModes = ["off", "flexible", "full", "strict"];
    private static readonly HashSet<string> TrafficTypes = ["direct", "http", "https"];

    public Task<IReadOnlyList<SpectrumApp>> ListAppsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<SpectrumApp>(ZonePath(zoneId, "spectrum", "apps"), 50, ct);

    public Task<SpectrumApp> GetAppAsync(string appId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<SpectrumApp>(ZonePath(zoneId, "spectrum", "apps", appId), ct);

    public CloudflareChangePreview PreviewCreateApp(SpectrumAppInput app, bool allowSensitivePort = false, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "spectrum", "apps"), Body(app, allowSensitivePort), $"Proxy {app.Protocol} for {app.Hostname} to the origin.");

    /// <summary>Returns the application for this hostname and protocol or creates it; an existing one is not changed.</summary>
    public async Task<(SpectrumApp App, bool Created)> EnsureAppAsync(SpectrumAppInput app, bool allowSensitivePort = false, string? zoneId = null, CancellationToken ct = default)
    {
        var body = Body(app, allowSensitivePort);
        var path = ZonePath(zoneId, "spectrum", "apps");
        EnsureWritable(HttpMethod.Post, path);
        bool Same(SpectrumApp a) => a.Protocol == app.Protocol && a.Dns is { } d && string.Equals(P2.Str(d, "name"), body["dns"]!["name"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
        var existing = (await ListAppsAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(Same);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<SpectrumApp>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListAppsAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(Same);
            return again is null ? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = "The application is reported as existing but was not found." }]) : (again, false);
        }
    }

    /// <summary>Replaces an application (PUT, idempotent).</summary>
    public Task<SpectrumApp> UpdateAppAsync(string appId, SpectrumAppInput app, bool allowSensitivePort = false, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<SpectrumApp>(ZonePath(zoneId, "spectrum", "apps", P1.Required(appId, nameof(appId))), Body(app, allowSensitivePort), ct);

    public CloudflareChangePreview PreviewRemoveApp(string appId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "spectrum", "apps", appId), null, $"Delete Spectrum application {appId}. WARNING: clients can no longer connect through it.");

    /// <summary>Deletes an application. Refused unless <paramref name="allowDelete"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveAppAsync(string appId, bool allowDelete = false, string? zoneId = null, CancellationToken ct = default)
    {
        P2.Allow(allowDelete, "deleting the application cuts every client that connects through it", nameof(allowDelete));
        return DeleteIfExistsAsync(ZonePath(zoneId, "spectrum", "apps", P1.Required(appId, nameof(appId))), null, ct);
    }

    // M-3 (0.7.1): an origin port that is a management, file-sharing or database port exposes that service through Spectrum, too.
    private static void CheckOriginPorts(IEnumerable<int> ports, bool allowSensitivePort)
    {
        var sensitive = ports.Where(SensitivePorts.Contains).Distinct().ToList();
        if (sensitive.Count > 0) P2.Allow(allowSensitivePort, $"origin port {string.Join(", ", sensitive)} is a management, file-sharing or database port", nameof(allowSensitivePort));
    }

    private static JsonObject Body(SpectrumAppInput a, bool allowSensitivePort)
    {
        var m = ProtocolPattern.Match(a.Protocol ?? "");
        if (!m.Success) throw new ArgumentException("Protocol is tcp/PORT, udp/PORT or tcp/FIRST-LAST.", nameof(a));
        var first = int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
        var last = m.Groups[4].Success ? int.Parse(m.Groups[4].Value, System.Globalization.CultureInfo.InvariantCulture) : first;
        if (first is < 1 or > 65535 || last is < 1 or > 65535 || last < first) throw new ArgumentException("Ports are 1 to 65535, the range ascending.", nameof(a));
        var sensitive = SensitivePorts.Where(p => p >= first && p <= last).ToList();
        if (sensitive.Count > 0) P2.Allow(allowSensitivePort, $"port {string.Join(", ", sensitive)} is a management, file-sharing or database port that attackers scan for", nameof(allowSensitivePort));
        if ((a.OriginDirect is { Count: > 0 }) == (a.OriginDnsName is not null)) throw new ArgumentException("Pass exactly one of OriginDirect and OriginDnsName.", nameof(a));
        if (!ProxyProtocols.Contains(a.ProxyProtocol)) throw new ArgumentException("Proxy protocol: off, v1, v2 or simple.", nameof(a));
        if (!TlsModes.Contains(a.Tls)) throw new ArgumentException("TLS: off, flexible, full or strict.", nameof(a));
        if (!TrafficTypes.Contains(a.TrafficType)) throw new ArgumentException("Traffic type: direct, http or https.", nameof(a));
        var body = new JsonObject
        {
            ["protocol"] = a.Protocol,
            ["dns"] = new JsonObject { ["type"] = "CNAME", ["name"] = P1.Hostname(a.Hostname, nameof(a)) },
            ["ip_firewall"] = a.IpFirewall, ["proxy_protocol"] = a.ProxyProtocol, ["tls"] = a.Tls, ["traffic_type"] = a.TrafficType,
        };
        if (a.OriginDirect is { Count: > 0 } direct)
        {
            var originPorts = new List<int>();
            foreach (var d in direct)
            {
                if (!Uri.TryCreate(d, UriKind.Absolute, out var u) || u.Scheme is not ("tcp" or "udp") || u.Port < 1 || !string.IsNullOrEmpty(u.UserInfo)) throw new ArgumentException($"\"{d}\" is not an origin like tcp://203.0.113.10:22.", nameof(a));
                originPorts.Add(u.Port);
            }
            CheckOriginPorts(originPorts, allowSensitivePort);
            body["origin_direct"] = P1.Arr(direct);
        }
        else
        {
            body["origin_dns"] = new JsonObject { ["name"] = P1.Hostname(a.OriginDnsName, nameof(a)) };
            var port = a.OriginPort ?? throw new ArgumentException("OriginPort is required with OriginDnsName.", nameof(a));
            if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(a), "OriginPort 1 to 65535.");
            CheckOriginPorts([port], allowSensitivePort);
            body["origin_port"] = port;
        }
        return body;
    }
}
