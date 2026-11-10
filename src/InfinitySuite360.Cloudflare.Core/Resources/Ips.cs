using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class IpsResult : CloudflareModel
{
    public List<string> Ipv4Cidrs { get; init; } = [];
    public List<string> Ipv6Cidrs { get; init; } = [];
    public string? Etag { get; init; }
}

/// <summary>Current IP ranges of the Cloudflare network (GET /ips).</summary>
public sealed class IpsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IpsResult> GetAsync(CancellationToken ct = default) => Api.GetAsync<IpsResult>("ips", ct);
}
