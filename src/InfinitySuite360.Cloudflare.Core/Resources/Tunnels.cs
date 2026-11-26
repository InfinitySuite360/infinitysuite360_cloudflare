using System.Text.Json;
using System.Text.Json.Serialization;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class Tunnel : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"inactive", "degraded", "healthy" or "down".</summary>
    public string Status { get; init; } = "";
    public string? TunType { get; init; }
    public bool RemoteConfig { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? DeletedAt { get; init; }
    public DateTimeOffset? ConnsActiveAt { get; init; }
    public List<JsonElement> Connections { get; init; } = [];
}

/// <summary>Ingress rule. Note: the tunnel configuration uses camelCase (originRequest), not snake_case.</summary>
public sealed class TunnelIngressRule
{
    [JsonPropertyName("hostname")] public string? Hostname { get; init; }
    [JsonPropertyName("path")] public string? Path { get; init; }
    /// <summary>For example "http://localhost:8080" or "http_status:404".</summary>
    [JsonPropertyName("service")] public string Service { get; init; } = "";
    [JsonPropertyName("originRequest")] public JsonElement? OriginRequest { get; init; }
}

public sealed class TunnelConfigurationBody
{
    [JsonPropertyName("ingress")] public List<TunnelIngressRule> Ingress { get; init; } = [];
    [JsonPropertyName("originRequest")] public JsonElement? OriginRequest { get; init; }
    [JsonPropertyName("warp-routing")] public JsonElement? WarpRouting { get; init; }
}

public sealed class TunnelConfiguration : CloudflareModel
{
    public string TunnelId { get; init; } = "";
    public int Version { get; init; }
    public TunnelConfigurationBody? Config { get; init; }
    public string? Source { get; init; }
}

/// <summary>One connection of a connector to a Cloudflare data centre.</summary>
public sealed class TunnelConnection : CloudflareModel
{
    public string? Id { get; init; }
    public string? Uuid { get; init; }
    public string? ColoName { get; init; }
    public string? ClientId { get; init; }
    public string? ClientVersion { get; init; }
    public string? OriginIp { get; init; }
    public bool IsPendingReconnect { get; init; }
    public DateTimeOffset? OpenedAt { get; init; }
}

/// <summary>A running cloudflared instance (replica) of a tunnel with its connections.</summary>
public sealed class TunnelConnector : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Version { get; init; }
    public string? Arch { get; init; }
    public string? OriginIp { get; init; }
    public DateTimeOffset? RunAt { get; init; }
    public List<string> Features { get; init; } = [];
    public List<TunnelConnection> Conns { get; init; } = [];

    /// <summary>Connections that are not waiting to reconnect.</summary>
    public int ActiveConnections => Conns.Count(c => !c.IsPendingReconnect);
}

/// <summary>Cloudflare Tunnel (cloudflared) management.</summary>
public sealed class TunnelsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public const string CatchAllService = "http_status:404";

    public Task<IReadOnlyList<Tunnel>> ListAsync(string? name = null, bool includeDeleted = false, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<Tunnel>(CloudflarePath.WithQuery(AccountPath(accountId, "cfd_tunnel"), ("name", name), ("is_deleted", includeDeleted ? null : "false")), 50, ct);

    public Task<Tunnel> GetAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<Tunnel>(AccountPath(accountId, "cfd_tunnel", tunnelId), ct);

    /// <summary>Creates a remotely managed tunnel (config_src "cloudflare"): ingress is managed through the API.</summary>
    public Task<Tunnel> CreateAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<Tunnel>(AccountPath(accountId, "cfd_tunnel"), new { name, config_src = "cloudflare" }, ct);

    public Task DeleteAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "cfd_tunnel", tunnelId), ct);

    /// <summary>Disconnects the tunnel's connections (for example before deleting it).</summary>
    public Task CleanupConnectionsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "cfd_tunnel", tunnelId, "connections"), ct);

    /// <summary>Connectors (replicas) of the tunnel with their connections; empty when no cloudflared is connected.</summary>
    public async Task<List<TunnelConnector>> ListConnectionsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<TunnelConnector>>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connections"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Connectors of the tunnel (newer endpoint for the same information, with version and features).</summary>
    public async Task<List<TunnelConnector>> ListConnectorsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<TunnelConnector>>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connectors"), ct).ConfigureAwait(false) ?? [];

    public Task<TunnelConnector> GetConnectorAsync(string tunnelId, string connectorId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TunnelConnector>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connectors", connectorId), ct);

    /// <summary>Token for <c>cloudflared tunnel run --token …</c>. Treat it as a secret.</summary>
    public Task<string> GetTokenAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<string>(AccountPath(accountId, "cfd_tunnel", tunnelId, "token"), ct);

    public Task<TunnelConfiguration> GetConfigurationAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TunnelConfiguration>(AccountPath(accountId, "cfd_tunnel", tunnelId, "configurations"), ct);

    /// <summary>Sets the ingress rules. A final catch-all "http_status:404" is added when missing (cloudflared rejects configurations without one).</summary>
    public Task<TunnelConfiguration> PutConfigurationAsync(string tunnelId, IEnumerable<TunnelIngressRule> ingress, string? accountId = null, CancellationToken ct = default)
    {
        var rules = ingress.ToList();
        if (rules.Count == 0 || rules[^1].Hostname is not null || rules[^1].Path is not null)
            rules.Add(new TunnelIngressRule { Service = CatchAllService });
        return Api.PutAsync<TunnelConfiguration>(AccountPath(accountId, "cfd_tunnel", tunnelId, "configurations"),
            new { config = new TunnelConfigurationBody { Ingress = rules } }, ct);
    }

    /// <summary>
    /// Publishes a public hostname: adds or replaces the ingress rule and creates a proxied CNAME to &lt;tunnel&gt;.cfargotunnel.com.
    /// </summary>
    public async Task PublishHostnameAsync(string tunnelId, string hostname, string service, DnsClient dns, string? zoneId = null, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false);
        var rules = current.Config?.Ingress
            .Where(r => r.Service != CatchAllService || r.Hostname is not null)
            .Where(r => !string.Equals(r.Hostname, hostname, StringComparison.OrdinalIgnoreCase))
            .ToList() ?? [];
        rules.Add(new TunnelIngressRule { Hostname = hostname, Service = service });
        await PutConfigurationAsync(tunnelId, rules, accountId, ct).ConfigureAwait(false);
        await dns.UpsertAsync(new DnsRecordInput { Type = "CNAME", Name = hostname, Content = $"{tunnelId}.cfargotunnel.com", Proxied = true }, zoneId, ct).ConfigureAwait(false);
    }
}
