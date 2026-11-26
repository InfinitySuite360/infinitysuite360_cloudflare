using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Result of <see cref="TunnelsClient.EnsureAsync"/>: the tunnel and, for a new tunnel, the run token Cloudflare returned once.</summary>
public sealed class EnsuredTunnel
{
    internal EnsuredTunnel(Tunnel tunnel, CloudflareOneTimeSecret? runToken)
    {
        Tunnel = tunnel;
        RunToken = runToken;
    }

    public Tunnel Tunnel { get; }
    /// <summary>The token for <c>cloudflared tunnel run --token</c> when Cloudflare returned it with the new tunnel (otherwise read it with <c>GetRunTokenAsync</c>).</summary>
    public CloudflareOneTimeSecret? RunToken { get; }

    public override string ToString() => $"EnsuredTunnel({Tunnel.Id}, \"{Tunnel.Name}\", run token {(RunToken is null ? "none" : P1.Redacted)})";
}

/// <summary>A private network route (CIDR) through a tunnel, reachable for WARP clients.</summary>
public sealed class TunnelRoute : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Network { get; init; } = "";
    public string? TunnelId { get; init; }
    public string? TunnelName { get; init; }
    public string? VirtualNetworkId { get; init; }
    public string? Comment { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? DeletedAt { get; init; }
}

/// <summary>A virtual network (separates overlapping private address ranges).</summary>
public sealed class VirtualNetwork : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Comment { get; init; }
    public bool IsDefaultNetwork { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? DeletedAt { get; init; }
}

/// <summary>
/// Guarded tunnel writes (0.8.0). Endpoints from cloudflare/api-schemas@650bd71 (<c>cloudflare-tunnel-*</c>, <c>tunnel-route-*</c>, <c>tunnel-virtual-network-*</c>);
/// token handling from developers.cloudflare.com/tunnel/reference/tunnel-tokens/ ("Anyone with the token can run the tunnel"; reading it needs a write
/// permission such as "Cloudflare Tunnel Write"; after rotation cloudflared cannot open new connections with the old token), limits from
/// …/cloudflare-one/account-limits/ (1000 tunnels, 25 replicas, 1 MB configuration, 1000 virtual networks), retrieved 17.11.2026.
/// </summary>
/// <remarks>
/// Lock-out protection: ingress changes that remove a hostname or point it elsewhere (this can be the hostname of the very application that calls this
/// package) need <c>allowDisconnect</c>; a catch-all that forwards instead of answering 404 needs <c>allowCatchAllService</c>; deleting a tunnel with active
/// connectors or routes needs <c>allowDeleteActive</c>; every check reads the current state first and fails if it cannot (fail-closed).
/// </remarks>
public sealed partial class TunnelsClient
{
    // ------------------------------------------------------------------ tunnels

    public CloudflareChangePreview PreviewEnsure(string name, string? accountId = null) =>
        new("POST", AccountPath(accountId, "cfd_tunnel"), new JsonObject { ["name"] = P1.Required(name, nameof(name), 255), ["config_src"] = "cloudflare" },
            $"Create remotely managed tunnel \"{name}\"; the run token is shown once in the result.");

    /// <summary>
    /// Returns the (not deleted) tunnel with this name or creates a remotely managed one (POST, not retried after a server error). The run token of a new
    /// tunnel is moved into <see cref="EnsuredTunnel.RunToken"/>; <c>token</c>, <c>tunnel_secret</c> and <c>credentials_file</c> never reach a model.
    /// </summary>
    public async Task<(EnsuredTunnel Tunnel, bool Created)> EnsureAsync(string name, string? accountId = null, CancellationToken ct = default)
    {
        var preview = PreviewEnsure(name, accountId);
        EnsureWritable(HttpMethod.Post, preview.Path);
        var existing = (await ListAsync(name, false, accountId, ct).ConfigureAwait(false)).FirstOrDefault(t => t.Name == name && t.DeletedAt is null);
        if (existing is not null) return (new EnsuredTunnel(existing, null), false);
        var result = await P2.ResultAsync(Api, HttpMethod.Post, preview.Path, preview.Body, ct).ConfigureAwait(false);
        var token = P2.Str(result, "token") is { Length: > 0 } t ? new CloudflareOneTimeSecret(t, "tunnel-run-token") : null;
        return (new EnsuredTunnel(P1.As<Tunnel>(ZT.Strip(result)), token), true);
    }

    /// <summary>
    /// The run token of a tunnel as a <see cref="CloudflareOneTimeSecret"/>. Reading it is a GET, but Cloudflare requires a write permission for it; anyone
    /// with the token can run the tunnel. L4 (0.8.1): reading a secret needs <paramref name="allowReadSecret"/> (refused locally, nothing sent).
    /// </summary>
    public async Task<CloudflareOneTimeSecret> GetRunTokenAsync(string tunnelId, string? accountId = null, bool allowReadSecret = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "token");
        P2.Allow(allowReadSecret, $"reading the run token of tunnel {tunnelId} hands out a secret that lets anybody run the tunnel", nameof(allowReadSecret));
        var result = await P2.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (result.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(result.GetString()))
            throw new CloudflareApiException(HttpStatusCode.OK, "GET", CloudflarePath.Normalize(path), [new CloudflareError { Message = "The answer carries no run token." }]);
        return new CloudflareOneTimeSecret(result.GetString()!, "tunnel-run-token");
    }

    public CloudflareChangePreview PreviewRotateRunToken(string tunnelId, string? accountId = null) =>
        new("PATCH", AccountPath(accountId, "cfd_tunnel", tunnelId), new JsonObject { ["tunnel_secret"] = P1.Redacted },
            $"Rotate the run token of tunnel {tunnelId}: a new random tunnel secret is generated locally. WARNING: cloudflared cannot open new connections with the old token.");

    /// <summary>
    /// Rotates the run token: generates a new 32-byte tunnel secret locally (never logged, never in a preview), sets it (PATCH) and returns the new token.
    /// Replicas must be reinstalled with the new token, so this always needs <paramref name="allowDisconnect"/>.
    /// </summary>
    public async Task<CloudflareOneTimeSecret> RotateRunTokenAsync(string tunnelId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)));
        EnsureWritable(HttpMethod.Patch, path);
        P2.Allow(allowDisconnect, "after rotating, cloudflared replicas with the old token cannot reconnect", nameof(allowDisconnect));
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await Api.SendAsync<JsonElement>(HttpMethod.Patch, path, new JsonObject { ["tunnel_secret"] = secret }, ct).ConfigureAwait(false);
        return await GetRunTokenAsync(tunnelId, accountId, allowReadSecret: true, ct).ConfigureAwait(false);
    }

    public CloudflareChangePreview PreviewRemove(string tunnelId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "cfd_tunnel", tunnelId), null, $"Delete tunnel {tunnelId} (refused while connectors are connected or routes use it).");

    /// <summary>
    /// Deletes a tunnel after a fresh read of the tunnel, its connectors, its routes and its ingress. A tunnel that is connected (status healthy/degraded
    /// or active connections), that private routes use or (L7, 0.8.1) whose ingress still serves hostnames – their CNAMEs point at it, also while it is
    /// "down" – needs <paramref name="allowDeleteActive"/>; if the state cannot be read the call fails. False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveAsync(string tunnelId, bool allowDeleteActive = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)));
        EnsureWritable(HttpMethod.Delete, path);
        var tunnel = await ZT.GetOrNullAsync<Tunnel>(Api, path, ct).ConfigureAwait(false);
        if (tunnel is null || tunnel.DeletedAt is not null) return false;
        if (!allowDeleteActive)
        {
            var connectors = await ListConnectionsAsync(tunnelId, accountId, ct).ConfigureAwait(false);
            var active = connectors.Sum(c => c.ActiveConnections);
            if (tunnel.Status is "healthy" or "degraded" || active > 0)
                throw new InvalidOperationException($"Refused: tunnel \"{tunnel.Name}\" is {tunnel.Status} with {active} active connection(s); deleting it cuts every hostname and route it serves. Pass allowDeleteActive: true deliberately.");
            var routes = await ListRoutesAsync(tunnelId, null, accountId, ct).ConfigureAwait(false);
            if (routes.Count > 0)
                throw new InvalidOperationException($"Refused: {ZT.Plural(routes.Count, "private route uses", "private routes use")} tunnel \"{tunnel.Name}\". Remove them first or pass allowDeleteActive: true deliberately.");
            TunnelConfiguration? config;
            try { config = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false); }
            catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { config = null; }
            var hosts = (config?.Config?.Ingress ?? []).Where(r => r.Hostname is not null).Select(r => r.Hostname!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (hosts.Count > 0)
                throw new InvalidOperationException($"Refused: tunnel \"{tunnel.Name}\" ({tunnel.Status}) still serves {P1.Join(hosts)}; their DNS records point at it. Remove the ingress rules and records first or pass allowDeleteActive: true deliberately.");
        }
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    public CloudflareChangePreview PreviewDisconnect(string tunnelId, string? clientId = null, string? accountId = null) =>
        new("DELETE", CloudflarePath.WithQuery(AccountPath(accountId, "cfd_tunnel", tunnelId, "connections"), ("client_id", clientId)), null,
            clientId is null ? $"Disconnect every connector of tunnel {tunnelId}." : $"Disconnect connector {clientId} of tunnel {tunnelId}.");

    /// <summary>Disconnects all connectors (or one, <paramref name="clientId"/>) of a tunnel; always needs <paramref name="allowDisconnect"/>.</summary>
    public async Task DisconnectAsync(string tunnelId, string? clientId = null, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "connections"), ("client_id", clientId));
        EnsureWritable(HttpMethod.Delete, path);
        P2.Allow(allowDisconnect, "disconnecting connectors interrupts every hostname the tunnel serves", nameof(allowDisconnect));
        await Api.SendAsync<JsonElement>(HttpMethod.Delete, path, null, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ ingress

    /// <summary>Plan of an ingress change: reads the configuration and lists added, removed and re-pointed hostnames (sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewSetIngressAsync(string tunnelId, IEnumerable<TunnelIngressRule> ingress, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false);
        var rules = Normalize(ingress, true);
        var diff = Diff(current.Config?.Ingress ?? [], rules);
        return new("PUT", AccountPath(accountId, "cfd_tunnel", tunnelId, "configurations"), ConfigBody(current, rules),
            $"Set {rules.Count} ingress rule(s) of tunnel {tunnelId}: added {P1.Join(diff.Added)}, removed {P1.Join(diff.Removed)}, re-pointed or shadowed {P1.Join(diff.Changed)}."
            + (diff.Removed.Count + diff.Changed.Count > 0 ? " WARNING: removed, re-pointed or shadowed hostnames lose their current service or origin settings." : ""));
    }

    /// <summary>
    /// Sets the ingress rules after a fresh read; <c>originRequest</c> and <c>warp-routing</c> of the current configuration are kept and a final catch-all
    /// <c>http_status:404</c> is added when missing. Removing a hostname, pointing it to another service, changing its <c>originRequest</c> or letting another
    /// rule (a wildcard, a rule without hostname, a new order) answer it first needs <paramref name="allowDisconnect"/>; a catch-all or a path rule without
    /// hostname that forwards to a service needs <paramref name="allowCatchAllService"/>. Written only on change; the configuration version is read again
    /// right before the PUT and a concurrent change is a <see cref="CloudflareConflictException"/> (M1, 0.8.1).
    /// </summary>
    public async Task<(TunnelConfiguration Configuration, bool Changed)> SetIngressAsync(string tunnelId, IEnumerable<TunnelIngressRule> ingress, bool allowDisconnect = false,
        bool allowCatchAllService = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "configurations");
        EnsureWritable(HttpMethod.Put, path);
        var rules = Normalize(ingress, allowCatchAllService);
        var current = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false);
        var (config, changed) = await WriteIngressAsync(path, current, rules, allowDisconnect, ct).ConfigureAwait(false);
        return (config, changed);
    }

    /// <summary>
    /// Adds an ingress rule or replaces the one with the same hostname and path (before the catch-all). Changing the service or <c>originRequest</c> of an
    /// existing hostname needs <paramref name="allowDisconnect"/>; a rule without <c>OriginRequest</c> keeps the origin settings of the rule it replaces.
    /// </summary>
    public async Task<(TunnelConfiguration Configuration, bool Changed)> UpsertIngressRuleAsync(string tunnelId, TunnelIngressRule rule, bool allowDisconnect = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "configurations");
        EnsureWritable(HttpMethod.Put, path);
        var (config, changed, _) = await UpsertCoreAsync(path, tunnelId, rule, allowDisconnect, accountId, ct).ConfigureAwait(false);
        return (config, changed);
    }

    private async Task<(TunnelConfiguration Configuration, bool Changed, TunnelConfiguration Before)> UpsertCoreAsync(string path, string tunnelId, TunnelIngressRule rule,
        bool allowDisconnect, string? accountId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rule.Hostname)) throw new ArgumentException("An ingress rule needs a hostname (the catch-all is managed for you).", nameof(rule));
        var host = P1.Hostname(rule.Hostname, nameof(rule), allowWildcard: true);
        var service = CheckService(rule.Service);
        var current = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false);
        var rules = (current.Config?.Ingress ?? []).Where(r => !IsCatchAll(r)).ToList();
        var index = rules.FindIndex(r => SameKey(r, host, rule.Path));
        var next = new TunnelIngressRule { Hostname = host, Path = rule.Path, Service = service, OriginRequest = rule.OriginRequest ?? (index >= 0 ? rules[index].OriginRequest : null) };
        if (index >= 0) rules[index] = next; else rules.Add(next);
        var (config, changed) = await WriteIngressAsync(path, current, Normalize(rules.Concat(Tail(current)), true), allowDisconnect, ct).ConfigureAwait(false);
        return (config, changed, current);
    }

    /// <summary>Removes the ingress rule of a hostname. This cuts the hostname off, so it always needs <paramref name="allowDisconnect"/>. False when there was no such rule.</summary>
    public async Task<bool> RemoveIngressRuleAsync(string tunnelId, string hostname, string? path = null, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var configPath = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "configurations");
        EnsureWritable(HttpMethod.Put, configPath);
        var host = P1.Hostname(hostname, nameof(hostname), allowWildcard: true);
        P2.Allow(allowDisconnect, $"removing the ingress rule of {host} cuts that hostname off", nameof(allowDisconnect));
        var current = await GetConfigurationAsync(tunnelId, accountId, ct).ConfigureAwait(false);
        var rules = (current.Config?.Ingress ?? []).ToList();
        if (rules.RemoveAll(r => SameKey(r, host, path)) == 0) return false;
        await WriteIngressAsync(configPath, current, Normalize(rules, true), true, ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Publishes a hostname through the tunnel: <see cref="UpsertIngressRuleAsync"/> plus a proxied CNAME to <c>&lt;tunnel&gt;.cfargotunnel.com</c> via
    /// <see cref="DnsClient.SafeUpsertAsync"/>. Re-pointing an existing hostname – in the ingress or a DNS record that points elsewhere – needs
    /// <paramref name="allowDisconnect"/>. L8 (0.8.1): the zone must belong to the tunnel's account (read first), the DNS plan is read before the ingress is
    /// written, and when the DNS write fails the ingress change is rolled back, so the call does not leave half a publication behind.
    /// </summary>
    public async Task PublishAsync(string tunnelId, string hostname, string service, DnsClient dns, bool allowDisconnect = false, string? zoneId = null, string? accountId = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(dns);
        var path = AccountPath(accountId, "cfd_tunnel", P1.Required(tunnelId, nameof(tunnelId)), "configurations");
        EnsureWritable(HttpMethod.Put, path);
        var host = P1.Hostname(hostname, nameof(hostname), allowWildcard: true);
        CheckService(service);
        var record = new DnsRecordInput { Type = "CNAME", Name = host, Content = $"{tunnelId}.cfargotunnel.com", Proxied = true };
        var dnsPath = dns.PreviewCreate(record, zoneId).Path;
        EnsureAnyWritable((HttpMethod.Post, dnsPath), (HttpMethod.Put, dnsPath + "/"));

        var zonePath = dnsPath[..dnsPath.LastIndexOf('/')];
        var zone = await P2.ResultAsync(Api, HttpMethod.Get, zonePath, null, ct).ConfigureAwait(false);
        var zoneAccount = zone.ValueKind == JsonValueKind.Object && zone.TryGetProperty("account", out var acc) ? P2.Str(acc, "id") : null;
        if (!string.Equals(zoneAccount, Account(accountId), StringComparison.Ordinal))
            throw new InvalidOperationException($"Refused: zone {P2.Str(zone, "name") ?? zonePath} belongs to account {zoneAccount ?? "(unknown)"}, not to the account of tunnel {tunnelId}; a CNAME there would not reach the tunnel.");
        var plan = await dns.PreviewUpsertAsync(record, zoneId, ct).ConfigureAwait(false);
        if (plan is { Method: "PUT" })
            P2.Allow(allowDisconnect, $"{host} already has a CNAME that points elsewhere; publishing re-points it to tunnel {tunnelId}", nameof(allowDisconnect));

        var (_, changed, before) = await UpsertCoreAsync(path, tunnelId, new TunnelIngressRule { Hostname = host, Service = service }, allowDisconnect, accountId, ct).ConfigureAwait(false);
        try
        {
            await dns.SafeUpsertAsync(record, false, zoneId, ct).ConfigureAwait(false);
        }
        catch (Exception dnsError) when (changed)
        {
            try { await Api.PutAsync<TunnelConfiguration>(path, ConfigBody(before, [.. before.Config?.Ingress ?? []]), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception rollbackError)
            {
                throw new AggregateException($"Publishing {host} failed at the DNS step and the ingress rollback failed as well; check the ingress of tunnel {tunnelId}.", dnsError, rollbackError);
            }
            throw;
        }
    }

    private async Task<(TunnelConfiguration, bool)> WriteIngressAsync(string path, TunnelConfiguration current, List<TunnelIngressRule> rules, bool allowDisconnect, CancellationToken ct)
    {
        var before = current.Config?.Ingress ?? [];
        var diff = Diff(before, rules);
        if (diff.Removed.Count + diff.Changed.Count > 0)
            P2.Allow(allowDisconnect, $"the ingress change removes {P1.Join(diff.Removed)} and re-points or shadows {P1.Join(diff.Changed)}", nameof(allowDisconnect));
        if (JsonNode.DeepEquals(ZT.ToNode(before), ZT.ToNode(rules))) return (current, false);
        // L6/M1 (0.8.1): the API has no If-Match for tunnel configurations; the version is read again right before the PUT.
        var again = await Api.GetAsync<TunnelConfiguration>(path, ct).ConfigureAwait(false);
        if (again.Version != current.Version)
            throw ZT.Conflict("PUT", path, $"The tunnel configuration changed while it was checked (version {current.Version} → {again.Version}). Read it again and repeat the change.");
        return (await Api.PutAsync<TunnelConfiguration>(path, ConfigBody(current, rules), ct).ConfigureAwait(false), true);
    }

    private static JsonObject ConfigBody(TunnelConfiguration current, List<TunnelIngressRule> rules)
    {
        var config = new JsonObject { ["ingress"] = new JsonArray(rules.Select(r => JsonSerializer.SerializeToNode(r, CloudflareJson.Options)).ToArray()) };
        if (P1.Node(current.Config?.OriginRequest) is { } origin) config["originRequest"] = origin;
        if (P1.Node(current.Config?.WarpRouting) is { } warp) config["warp-routing"] = warp;
        return new JsonObject { ["config"] = config };
    }

    private static IEnumerable<TunnelIngressRule> Tail(TunnelConfiguration current) =>
        (current.Config?.Ingress ?? []).Where(IsCatchAll).Take(1);

    private static bool IsCatchAll(TunnelIngressRule r) => r.Hostname is null && r.Path is null;

    private static bool SameKey(TunnelIngressRule r, string host, string? path) =>
        string.Equals(r.Hostname, host, StringComparison.OrdinalIgnoreCase) && (r.Path ?? "") == (path ?? "");

    private static string Key(TunnelIngressRule r) => r.Hostname + (string.IsNullOrEmpty(r.Path) ? "" : " " + r.Path);

    /// <summary>
    /// Added and removed hostname/path keys, and (M1, 0.8.1) every key of <paramref name="before"/> whose first matching rule – as cloudflared evaluates
    /// the list from the top – answers differently afterwards: another service, other <c>originRequest</c> settings, or another rule (a wildcard, a rule
    /// without hostname, a new order) that now comes first.
    /// </summary>
    private static (List<string> Added, List<string> Removed, List<string> Changed) Diff(IReadOnlyList<TunnelIngressRule> before, IReadOnlyList<TunnelIngressRule> after)
    {
        var b = before.Where(r => !IsCatchAll(r)).GroupBy(Key, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var a = after.Where(r => !IsCatchAll(r)).GroupBy(Key, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var changed = b.Where(kv => a.ContainsKey(kv.Key) && Answer(before, kv.Value) != Answer(after, kv.Value)).Select(kv => kv.Key).ToList();
        return (a.Keys.Where(k => !b.ContainsKey(k)).ToList(), b.Keys.Where(k => !a.ContainsKey(k)).ToList(), changed);
    }

    /// <summary>Service and origin settings of the first rule in <paramref name="rules"/> that can answer requests of <paramref name="target"/>.</summary>
    private static string Answer(IReadOnlyList<TunnelIngressRule> rules, TunnelIngressRule target)
    {
        var first = rules.FirstOrDefault(r => Overlaps(r, target));
        return first is null ? "(none)" : first.Service + "|" + (P1.Node(first.OriginRequest)?.ToJsonString() ?? "");
    }

    /// <summary>
    /// True when <paramref name="rule"/> can take requests meant for <paramref name="target"/>: no hostname or an overlapping hostname (equal, or one is a
    /// wildcard that covers the other), and no path, the same path, or a target without path. Different path expressions are not evaluated (regex).
    /// </summary>
    private static bool Overlaps(TunnelIngressRule rule, TunnelIngressRule target)
    {
        var hostOverlap = rule.Hostname is null || target.Hostname is null || Covers(rule.Hostname, target.Hostname) || Covers(target.Hostname, rule.Hostname);
        var pathOverlap = string.IsNullOrEmpty(rule.Path) || string.IsNullOrEmpty(target.Path) || rule.Path == target.Path;
        return hostOverlap && pathOverlap;
    }

    private static bool Covers(string pattern, string host) =>
        string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase)
        || (pattern.StartsWith("*.", StringComparison.Ordinal) && host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase) && host.Length > pattern.Length - 1);

    private static List<TunnelIngressRule> Normalize(IEnumerable<TunnelIngressRule> ingress, bool allowCatchAllService)
    {
        var rules = new List<TunnelIngressRule>();
        TunnelIngressRule? catchAll = null;
        foreach (var r in ingress)
        {
            CheckService(r.Service);
            if (IsCatchAll(r)) { catchAll ??= r; continue; }
            // M1 (0.8.1): a path rule without hostname answers that path for every hostname of the tunnel, like a catch-all.
            if (r.Hostname is null && !r.Service.StartsWith("http_status:", StringComparison.Ordinal))
                P2.Allow(allowCatchAllService, $"the rule for path {r.Path} has no hostname and would forward that path of every hostname to {r.Service}", nameof(allowCatchAllService));
            rules.Add(r.Hostname is null ? r : new TunnelIngressRule { Hostname = P1.Hostname(r.Hostname, nameof(ingress), allowWildcard: true), Path = r.Path, Service = r.Service, OriginRequest = r.OriginRequest });
        }
        if (catchAll is not null && catchAll.Service != CatchAllService && !catchAll.Service.StartsWith("http_status:", StringComparison.Ordinal))
            P2.Allow(allowCatchAllService, $"the catch-all rule would forward every unmatched hostname to {catchAll.Service}", nameof(allowCatchAllService));
        rules.Add(catchAll ?? new TunnelIngressRule { Service = CatchAllService });
        if (rules.Select(Key).Where(k => k.Length > 0).GroupBy(k => k, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            throw new ArgumentException("Each hostname/path may appear only once.", nameof(ingress));
        if (System.Text.Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(rules, CloudflareJson.Options)) > 1_000_000)
            throw new ArgumentException("The tunnel configuration is limited to 1 MB.", nameof(ingress));
        return rules;
    }

    private static string CheckService(string? service)
    {
        var s = P1.Required(service, nameof(service));
        if (!(s.StartsWith("http://", StringComparison.Ordinal) || s.StartsWith("https://", StringComparison.Ordinal) || s.StartsWith("http_status:", StringComparison.Ordinal)
              || s.StartsWith("tcp://", StringComparison.Ordinal) || s.StartsWith("ssh://", StringComparison.Ordinal) || s.StartsWith("rdp://", StringComparison.Ordinal)
              || s.StartsWith("smb://", StringComparison.Ordinal) || s.StartsWith("unix:", StringComparison.Ordinal) || s.StartsWith("unix+tls:", StringComparison.Ordinal)
              || s == "hello_world" || s == "bastion" || s == "socks5"))
            throw new ArgumentException($"\"{s}\" is not a cloudflared service (http://, https://, tcp://, ssh://, rdp://, smb://, unix:, http_status:NNN, hello_world, bastion).", nameof(service));
        return s;
    }

    // ------------------------------------------------------------------ private network routes

    public Task<IReadOnlyList<TunnelRoute>> ListRoutesAsync(string? tunnelId = null, string? virtualNetworkId = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<TunnelRoute>(CloudflarePath.WithQuery(AccountPath(accountId, "teamnet", "routes"),
            ("tunnel_id", tunnelId), ("virtual_network_id", virtualNetworkId), ("is_deleted", "false")), 50, ct);

    public CloudflareChangePreview PreviewEnsureRoute(string network, string tunnelId, string? virtualNetworkId = null, string? comment = null, bool allowBroadRoute = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "teamnet", "routes"), RouteBody(network, tunnelId, virtualNetworkId, comment, allowBroadRoute),
            $"Route {ZT.Cidr(network, nameof(network)).Cidr} through tunnel {tunnelId}{(virtualNetworkId is null ? "" : $" in virtual network {virtualNetworkId}")}.");

    /// <summary>
    /// Returns the route for this network (and virtual network) or creates it. A range shorter than /8 (IPv4) or /16 (IPv6) sends a large part of all traffic
    /// into the tunnel and needs <paramref name="allowBroadRoute"/>. A route of the same network through another tunnel is a <see cref="CloudflareConflictException"/>
    /// (moving it is <see cref="MoveRouteAsync"/>).
    /// </summary>
    public async Task<(TunnelRoute Route, bool Created)> EnsureRouteAsync(string network, string tunnelId, string? virtualNetworkId = null, string? comment = null, bool allowBroadRoute = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "routes");
        EnsureWritable(HttpMethod.Post, path);
        var body = RouteBody(network, tunnelId, virtualNetworkId, comment, allowBroadRoute);
        var cidr = body["network"]!.GetValue<string>();
        var existing = (await ListRoutesAsync(null, virtualNetworkId, accountId, ct).ConfigureAwait(false))
            .FirstOrDefault(r => string.Equals(r.Network, cidr, StringComparison.OrdinalIgnoreCase) && (virtualNetworkId is null || r.VirtualNetworkId == virtualNetworkId));
        if (existing is not null)
            return existing.TunnelId == tunnelId ? (existing, false)
                : throw ZT.Conflict("POST", path, $"Network {cidr} is already routed through tunnel {existing.TunnelName ?? existing.TunnelId}. Use MoveRouteAsync deliberately.");
        return (await Api.PostAsync<TunnelRoute>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>Points a route at another tunnel (PATCH). Clients lose the path through the old tunnel, so this always needs <paramref name="allowDisconnect"/>.</summary>
    public Task<TunnelRoute> MoveRouteAsync(string routeId, string tunnelId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "routes", P1.Required(routeId, nameof(routeId)));
        EnsureWritable(HttpMethod.Patch, path);
        P2.Allow(allowDisconnect, "moving a route sends its traffic through another tunnel", nameof(allowDisconnect));
        return Api.PatchAsync<TunnelRoute>(path, new JsonObject { ["tunnel_id"] = P1.Required(tunnelId, nameof(tunnelId)) }, ct);
    }

    public CloudflareChangePreview PreviewRemoveRoute(string routeId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "teamnet", "routes", routeId), null, $"Delete private route {routeId}. WARNING: WARP clients can no longer reach that network.");

    /// <summary>Deletes a private route; clients lose access to the network, so this always needs <paramref name="allowDisconnect"/>. False when it did not exist.</summary>
    public Task<bool> RemoveRouteAsync(string routeId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "routes", P1.Required(routeId, nameof(routeId)));
        EnsureWritable(HttpMethod.Delete, path);
        P2.Allow(allowDisconnect, "deleting a private route cuts WARP clients off that network", nameof(allowDisconnect));
        return DeleteIfExistsAsync(path, null, ct);
    }

    private static JsonObject RouteBody(string network, string tunnelId, string? vnet, string? comment, bool allowBroadRoute)
    {
        var cidr = ZT.Cidr(network, nameof(network));
        if (ZT.IsBroad(cidr)) P2.Allow(allowBroadRoute, $"route {cidr.Cidr} covers a large part of the address space", nameof(allowBroadRoute));
        var body = new JsonObject { ["network"] = cidr.Cidr, ["tunnel_id"] = P1.Required(tunnelId, nameof(tunnelId)) };
        if (vnet is not null) body["virtual_network_id"] = vnet;
        if (comment is not null) body["comment"] = comment;
        return body;
    }

    // ------------------------------------------------------------------ virtual networks

    public Task<IReadOnlyList<VirtualNetwork>> ListVirtualNetworksAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<VirtualNetwork>(CloudflarePath.WithQuery(AccountPath(accountId, "teamnet", "virtual_networks"), ("is_deleted", "false")), 50, ct);

    /// <summary>Returns the virtual network with this name or creates it (never as the default network).</summary>
    public async Task<(VirtualNetwork Network, bool Created)> EnsureVirtualNetworkAsync(string name, string? comment = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "virtual_networks");
        EnsureWritable(HttpMethod.Post, path);
        var body = new JsonObject { ["name"] = P1.Required(name, nameof(name), 256), ["is_default"] = false };
        if (comment is not null) body["comment"] = comment;
        var existing = (await ListVirtualNetworksAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(v => v.Name == name);
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<VirtualNetwork>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>Makes a virtual network the account default (every client without a choice uses it); always needs <paramref name="allowDefaultChange"/>.</summary>
    public Task<VirtualNetwork> SetDefaultVirtualNetworkAsync(string virtualNetworkId, bool allowDefaultChange = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "virtual_networks", P1.Required(virtualNetworkId, nameof(virtualNetworkId)));
        EnsureWritable(HttpMethod.Patch, path);
        P2.Allow(allowDefaultChange, "changing the default virtual network changes the routing of every client", nameof(allowDefaultChange));
        return Api.PatchAsync<VirtualNetwork>(path, new JsonObject { ["is_default_network"] = true }, ct);
    }

    /// <summary>
    /// Deletes a virtual network after a fresh read: the default network is refused, one with routes needs <paramref name="allowDisconnect"/> (fail-closed when
    /// the routes cannot be read). False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveVirtualNetworkAsync(string virtualNetworkId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "teamnet", "virtual_networks", P1.Required(virtualNetworkId, nameof(virtualNetworkId)));
        EnsureWritable(HttpMethod.Delete, path);
        var vnet = (await ListVirtualNetworksAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(v => v.Id == virtualNetworkId);
        if (vnet is null) return false;
        if (vnet.IsDefaultNetwork) throw new InvalidOperationException($"Refused: \"{vnet.Name}\" is the default virtual network. Make another one the default first.");
        var routes = await ListRoutesAsync(null, virtualNetworkId, accountId, ct).ConfigureAwait(false);
        if (routes.Count > 0) P2.Allow(allowDisconnect, $"virtual network \"{vnet.Name}\" still has {ZT.Plural(routes.Count, "route", "routes")}", nameof(allowDisconnect));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }
}
