using System.ComponentModel;
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

/// <summary>
/// Cloudflare Tunnel (cloudflared) management. The guarded methods of 0.8.0 (ingress, routes, virtual networks, run token, removal with outage
/// protection) are in <c>Tunnels.ZeroTrust.cs</c>; the older unguarded write methods here are obsolete. Since 0.8.0 secret members (<c>token</c>,
/// <c>tunnel_secret</c>, <c>credentials_file</c>) are removed from every answer before a model is built.
/// </summary>
public sealed partial class TunnelsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public const string CatchAllService = "http_status:404";

    public Task<IReadOnlyList<Tunnel>> ListAsync(string? name = null, bool includeDeleted = false, string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<Tunnel>(Api, CloudflarePath.WithQuery(AccountPath(accountId, "cfd_tunnel"), ("name", name), ("is_deleted", includeDeleted ? null : "false")), 50, ct);

    public Task<Tunnel> GetAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<Tunnel>(Api, HttpMethod.Get, AccountPath(accountId, "cfd_tunnel", tunnelId), null, ct);

    // M7 (0.8.1): the obsolete write methods go through their guarded replacements with every allow switch off, or are always refused; none of them
    // hands out the run token.

    /// <summary>
    /// Since 0.8.1 <see cref="EnsureAsync"/>: returns the tunnel with this name or creates a remotely managed one. The run token is not returned (read it
    /// deliberately with <c>GetRunTokenAsync(…, allowReadSecret: true)</c>).
    /// </summary>
    [Obsolete("Use EnsureAsync (0.8.0); since 0.8.1 this is EnsureAsync without the run token. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task<Tunnel> CreateAsync(string name, string? accountId = null, CancellationToken ct = default)
    {
        var (ensured, _) = await EnsureAsync(name, accountId, ct).ConfigureAwait(false);
        ensured.RunToken?.Dispose();
        return ensured.Tunnel;
    }

    /// <summary>Since 0.8.1 <see cref="RemoveAsync"/> without <c>allowDeleteActive</c>.</summary>
    [Obsolete("Use RemoveAsync(tunnelId, allowDeleteActive) (0.8.0); since 0.8.1 this applies its checks with the switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveAsync(tunnelId, allowDeleteActive: false, accountId, ct).ConfigureAwait(false);

    /// <summary>Since 0.8.1 <see cref="DisconnectAsync"/> without <c>allowDisconnect</c>: always refused.</summary>
    [Obsolete("Always refused since 0.8.1. Use DisconnectAsync(tunnelId, allowDisconnect: true) (0.8.0). Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task CleanupConnectionsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        DisconnectAsync(tunnelId, null, allowDisconnect: false, accountId, ct);

    /// <summary>Connectors (replicas) of the tunnel with their connections; empty when no cloudflared is connected.</summary>
    public async Task<List<TunnelConnector>> ListConnectionsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<TunnelConnector>>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connections"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Connectors of the tunnel (newer endpoint for the same information, with version and features).</summary>
    public async Task<List<TunnelConnector>> ListConnectorsAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<TunnelConnector>>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connectors"), ct).ConfigureAwait(false) ?? [];

    public Task<TunnelConnector> GetConnectorAsync(string tunnelId, string connectorId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TunnelConnector>(AccountPath(accountId, "cfd_tunnel", tunnelId, "connectors", connectorId), ct);

    /// <summary>Always refused since 0.8.1: it returned the run token as a plain string.</summary>
    [Obsolete("Always refused since 0.8.1. Use GetRunTokenAsync(tunnelId, allowReadSecret: true) (0.8.0), which returns a CloudflareOneTimeSecret. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<string> GetTokenAsync(string tunnelId, string? accountId = null, CancellationToken ct = default)
    {
        AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "token");
        return Task.FromException<string>(new InvalidOperationException(
            "Refused: GetTokenAsync is obsolete and always refused since 0.8.1 (it returned the run token as a plain string). Use GetRunTokenAsync(tunnelId, allowReadSecret: true)."));
    }

    public Task<TunnelConfiguration> GetConfigurationAsync(string tunnelId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TunnelConfiguration>(AccountPath(accountId, "cfd_tunnel", tunnelId, "configurations"), ct);

    /// <summary>Sets the ingress rules; since 0.8.1 <see cref="SetIngressAsync"/> with every allow switch off (originRequest and warp-routing are kept).</summary>
    [Obsolete("Use SetIngressAsync (0.8.0); since 0.8.1 this applies its checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task<TunnelConfiguration> PutConfigurationAsync(string tunnelId, IEnumerable<TunnelIngressRule> ingress, string? accountId = null, CancellationToken ct = default) =>
        (await SetIngressAsync(tunnelId, ingress, allowDisconnect: false, allowCatchAllService: false, accountId, ct: ct).ConfigureAwait(false)).Configuration;

    /// <summary>Publishes a public hostname; since 0.8.1 <see cref="PublishAsync"/> without <c>allowDisconnect</c> (no re-pointing, DNS through SafeUpsertAsync).</summary>
    [Obsolete("Use PublishAsync (0.8.0); since 0.8.1 this applies its checks with the switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task PublishHostnameAsync(string tunnelId, string hostname, string service, DnsClient dns, string? zoneId = null, string? accountId = null, CancellationToken ct = default) =>
        PublishAsync(tunnelId, hostname, service, dns, allowDisconnect: false, zoneId, accountId, ct);
}
