using System.Net;
using System.Net.Sockets;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class IpsResult : CloudflareModel
{
    public List<string> Ipv4Cidrs { get; init; } = [];
    public List<string> Ipv6Cidrs { get; init; } = [];
    public string? Etag { get; init; }

    /// <summary>All ranges, IPv4 first (for trusted proxy settings and firewall rule sets).</summary>
    public IReadOnlyList<string> AllCidrs => [.. Ipv4Cidrs, .. Ipv6Cidrs];

    /// <summary>True when <paramref name="address"/> lies in one of the ranges (IPv4-mapped IPv6 addresses count as IPv4).</summary>
    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var ranges = address.AddressFamily == AddressFamily.InterNetwork ? Ipv4Cidrs : Ipv6Cidrs;
        return ranges.Any(r => InRange(address, r));
    }

    private static bool InRange(IPAddress address, string cidr)
    {
        var slash = cidr.IndexOf('/');
        if (slash <= 0 || !IPAddress.TryParse(cidr.AsSpan(0, slash), out var network) || !int.TryParse(cidr.AsSpan(slash + 1), out var bits)) return false;
        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length || bits < 0 || bits > a.Length * 8) return false;
        var whole = bits / 8;
        for (var i = 0; i < whole; i++) if (a[i] != n[i]) return false;
        var rest = bits % 8;
        if (rest == 0) return true;
        var mask = (byte)(0xFF << (8 - rest));
        return (a[whole] & mask) == (n[whole] & mask);
    }
}

/// <summary>Current IP ranges of the Cloudflare network (GET /ips, no token needed but sent anyway).</summary>
public sealed class IpsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IpsResult> GetAsync(CancellationToken ct = default) => Api.GetAsync<IpsResult>("ips", ct);
}
