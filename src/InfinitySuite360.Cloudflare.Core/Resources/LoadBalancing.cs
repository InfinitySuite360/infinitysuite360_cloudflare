using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class LbOrigin : CloudflareModel
{
    public string Name { get; init; } = "";
    public string Address { get; init; } = "";
    public bool Enabled { get; init; } = true;
    public double? Weight { get; init; }
    public int? Port { get; init; }
    public JsonElement? Header { get; init; }
}

public sealed class LbPool : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public bool Enabled { get; init; } = true;
    public int? MinimumOrigins { get; init; }
    /// <summary>Id of the monitor; null = no health checks (the pool counts as healthy).</summary>
    public string? Monitor { get; init; }
    public string? NotificationEmail { get; init; }
    /// <summary>Health as Cloudflare reports it on the pool object (not in every schema version).</summary>
    public bool? Healthy { get; init; }
    public List<LbOrigin> Origins { get; init; } = [];
    public List<string>? CheckRegions { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>
/// A health monitor. Header values are <b>redacted</b> (<c>[redacted]</c>) in every model and preview because monitors often carry an Authorization header;
/// only the header names are visible.
/// </summary>
public sealed class LbMonitor : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Type { get; init; } = "";
    public string? Description { get; init; }
    public string? Method { get; init; }
    public string? Path { get; init; }
    public int? Port { get; init; }
    public int? Interval { get; init; }
    public int? Timeout { get; init; }
    public int? Retries { get; init; }
    public string? ExpectedCodes { get; init; }
    public string? ExpectedBody { get; init; }
    public bool? FollowRedirects { get; init; }
    public bool? AllowInsecure { get; init; }
    public int? ConsecutiveUp { get; init; }
    public int? ConsecutiveDown { get; init; }
    public JsonElement? Header { get; init; }
}

public sealed class LoadBalancer : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public bool Enabled { get; init; } = true;
    public bool Proxied { get; init; }
    public int? Ttl { get; init; }
    public string? SteeringPolicy { get; init; }
    public string? SessionAffinity { get; init; }
    public List<string> DefaultPools { get; init; } = [];
    public string? FallbackPool { get; init; }
    public JsonElement? RegionPools { get; init; }
    public JsonElement? PopPools { get; init; }
    public JsonElement? CountryPools { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

public sealed record LbOriginInput(string Name, string Address, bool Enabled = true, double Weight = 1, int? Port = null, string? HostHeader = null);

public sealed class LbPoolInput
{
    /// <summary>Letters, digits, '-' and '_' (Cloudflare's rule).</summary>
    public required string Name { get; init; }
    public required IReadOnlyList<LbOriginInput> Origins { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; } = true;
    /// <summary>The pool counts as unhealthy when fewer origins are healthy (1 to the number of origins).</summary>
    public int? MinimumOrigins { get; init; }
    public string? MonitorId { get; init; }
    public string? NotificationEmail { get; init; }
}

public sealed class LbMonitorInput
{
    /// <summary>http, https, tcp, udp_icmp, icmp_ping or smtp.</summary>
    public string Type { get; init; } = "https";
    public string? Description { get; init; }
    public string? Method { get; init; }
    public string? Path { get; init; }
    public int? Port { get; init; }
    /// <summary>Seconds between checks (5 to 3600; the plan sets the minimum).</summary>
    public int Interval { get; init; } = 60;
    /// <summary>Seconds to wait for an answer (1 to 60, below the interval).</summary>
    public int Timeout { get; init; } = 5;
    public int Retries { get; init; } = 2;
    public string? ExpectedCodes { get; init; } = "200";
    public string? ExpectedBody { get; init; }
    public bool FollowRedirects { get; init; }
    /// <summary>Skips the certificate check of the origin; needs <c>allowInsecureTls</c>.</summary>
    public bool AllowInsecure { get; init; }
    /// <summary>Extra request headers (values may be secrets; never shown by this package).</summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }
}

public sealed class LoadBalancerInput
{
    /// <summary>The hostname that is balanced, for example <c>lb.example.com</c>.</summary>
    public required string Name { get; init; }
    public required IReadOnlyList<string> DefaultPools { get; init; }
    public required string FallbackPool { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; } = true;
    public bool Proxied { get; init; } = true;
    /// <summary>DNS TTL in seconds (30 to 600); only for <c>Proxied = false</c>.</summary>
    public int? Ttl { get; init; }
    /// <summary>off, geo, random, dynamic_latency, proximity, least_outstanding_requests or least_connections.</summary>
    public string SteeringPolicy { get; init; } = "off";
    /// <summary>none, cookie, ip_cookie or header.</summary>
    public string SessionAffinity { get; init; } = "none";
}

/// <summary>
/// Load balancing: monitors and pools (account scope), load balancers (zone scope). Cloudflare Load Balancing is a paid add-on and the limits (origins,
/// monitors, intervals, regions) depend on the plan: Cloudflare answers, nothing is guessed here (developers.cloudflare.com/load-balancing/, retrieved 17.11.2026).
/// <para>Outage protection: switching off or removing the <b>last healthy pool</b> of a load balancer (<see cref="SetPoolEnabledAsync"/>, <see cref="SetOriginEnabledAsync"/>,
/// <see cref="RemoveOriginAsync"/>) is refused unless <c>allowLastHealthyPool</c> is true; the check reads the load balancers of the zone (pass the zone or configure
/// a default zone) and refuses when a load balancer outside it uses the pool and cannot be checked. Disabling or deleting an <b>enabled</b> load balancer needs
/// <c>allowDisableActive</c> / <c>allowDeleteActive</c>, a monitor that skips the certificate check <c>allowInsecureTls</c>. A pool in use and a monitor in use are not deleted.</para>
/// Token permission "Account: Load Balancing: Monitors and Pools: Edit", "Zone: Load Balancers: Edit". Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class LoadBalancingClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly Regex PoolNamePattern = P2.Rx(@"^[A-Za-z0-9_-]{1,100}$");
    private static readonly HashSet<string> MonitorTypes = ["http", "https", "tcp", "udp_icmp", "icmp_ping", "smtp"];
    private static readonly HashSet<string> Steering = ["off", "geo", "random", "dynamic_latency", "proximity", "least_outstanding_requests", "least_connections"];
    private static readonly HashSet<string> Affinity = ["none", "cookie", "ip_cookie", "header"];

    // ---- monitors ----

    public async Task<IReadOnlyList<LbMonitor>> ListMonitorsAsync(string? accountId = null, CancellationToken ct = default)
    {
        var list = new List<LbMonitor>();
        foreach (var e in await Api.GetAsync<List<JsonElement>>(AccountPath(accountId, "load_balancers", "monitors"), ct).ConfigureAwait(false) ?? []) list.Add(ToMonitor(e));
        return list;
    }

    public async Task<LbMonitor> GetMonitorAsync(string monitorId, string? accountId = null, CancellationToken ct = default) =>
        ToMonitor(await Api.GetAsync<JsonElement>(AccountPath(accountId, "load_balancers", "monitors", monitorId), ct).ConfigureAwait(false));

    public CloudflareChangePreview PreviewCreateMonitor(LbMonitorInput monitor, bool allowInsecureTls = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "load_balancers", "monitors"), MonitorBody(monitor, allowInsecureTls, redact: true),
            $"Create a {monitor.Type} health monitor ({monitor.Interval} s interval).");

    /// <summary>Creates a monitor (POST, not repeated automatically). Header values go to Cloudflare but come back redacted.</summary>
    public async Task<LbMonitor> CreateMonitorAsync(LbMonitorInput monitor, bool allowInsecureTls = false, string? accountId = null, CancellationToken ct = default) =>
        ToMonitor(await Api.PostAsync<JsonElement>(AccountPath(accountId, "load_balancers", "monitors"), MonitorBody(monitor, allowInsecureTls, redact: false), ct).ConfigureAwait(false));

    /// <summary>Replaces a monitor (PUT, idempotent).</summary>
    public async Task<LbMonitor> UpdateMonitorAsync(string monitorId, LbMonitorInput monitor, bool allowInsecureTls = false, string? accountId = null, CancellationToken ct = default) =>
        ToMonitor(await Api.PutAsync<JsonElement>(AccountPath(accountId, "load_balancers", "monitors", P1.Required(monitorId, nameof(monitorId))), MonitorBody(monitor, allowInsecureTls, redact: false), ct).ConfigureAwait(false));

    public CloudflareChangePreview PreviewRemoveMonitor(string monitorId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "load_balancers", "monitors", monitorId), null, $"Delete health monitor {monitorId} (refused while a pool uses it).");

    /// <summary>Deletes a monitor that no pool uses (one read of its references after the guard check). False when it did not exist.</summary>
    public async Task<bool> RemoveMonitorAsync(string monitorId, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "load_balancers", "monitors", P1.Required(monitorId, nameof(monitorId)));
        EnsureWritable(HttpMethod.Delete, path);
        var uses = await ReferencesAsync(AccountPath(accountId, "load_balancers", "monitors", monitorId, "references"), ct).ConfigureAwait(false);
        if (uses is null) return false;
        if (uses.Count > 0) throw new InvalidOperationException($"Refused: monitor {monitorId} is used by {string.Join(", ", uses.Select(u => u.Name))}. Detach it first.");
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ---- pools ----

    public Task<List<LbPool>> ListPoolsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<LbPool>>(AccountPath(accountId, "load_balancers", "pools"), ct);

    public Task<LbPool> GetPoolAsync(string poolId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<LbPool>(AccountPath(accountId, "load_balancers", "pools", poolId), ct);

    /// <summary>The health report of a pool (per Cloudflare location and origin) as Cloudflare returns it.</summary>
    public Task<JsonElement> GetPoolHealthAsync(string poolId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "load_balancers", "pools", poolId, "health"), ct);

    public CloudflareChangePreview PreviewCreatePool(LbPoolInput pool, string? accountId = null) =>
        new("POST", AccountPath(accountId, "load_balancers", "pools"), PoolBody(pool), $"Create pool \"{pool.Name}\" with {pool.Origins.Count} origin(s).");

    /// <summary>Returns the pool with this name or creates it; an existing pool is not changed.</summary>
    public async Task<(LbPool Pool, bool Created)> EnsurePoolAsync(LbPoolInput pool, string? accountId = null, CancellationToken ct = default)
    {
        var body = PoolBody(pool);
        var path = AccountPath(accountId, "load_balancers", "pools");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await ListPoolsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == pool.Name);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<LbPool>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListPoolsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == pool.Name);
            return again is null ? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"Pool \"{pool.Name}\" is reported as existing but was not found." }]) : (again, false);
        }
    }

    /// <summary>Enables or disables a pool (PATCH, idempotent; only written on change). Disabling the last healthy pool of a load balancer needs <paramref name="allowLastHealthyPool"/>.</summary>
    public async Task<(LbPool Pool, bool Changed)> SetPoolEnabledAsync(string poolId, bool enabled, bool allowLastHealthyPool = false, string? zoneId = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "load_balancers", "pools", P1.Required(poolId, nameof(poolId)));
        EnsureWritable(HttpMethod.Patch, path);
        var pool = await GetPoolAsync(poolId, accountId, ct).ConfigureAwait(false);
        if (pool.Enabled == enabled) return (pool, false);
        if (!enabled) await AssertNotLastHealthyAsync(pool, allowLastHealthyPool, zoneId, accountId, ct).ConfigureAwait(false);
        return (await Api.PatchAsync<LbPool>(path, new JsonObject { ["enabled"] = enabled }, ct).ConfigureAwait(false), true);
    }

    /// <summary>Enables or disables one origin of a pool. When the pool is left without enough enabled origins (below <c>minimum_origins</c>, at least one) the last-healthy-pool check applies.</summary>
    public Task<(LbPool Pool, bool Changed)> SetOriginEnabledAsync(string poolId, string originName, bool enabled, bool allowLastHealthyPool = false, string? zoneId = null, string? accountId = null, CancellationToken ct = default) =>
        ChangeOriginsAsync(poolId, originName, o => o.Enabled == enabled ? null : new LbOriginInput(o.Name, o.Address, enabled, o.Weight ?? 1, o.Port), allowLastHealthyPool, zoneId, accountId, ct, mustExist: true);

    /// <summary>Adds an origin or replaces the one with the same name (PATCH of the origin list).</summary>
    public Task<(LbPool Pool, bool Changed)> UpsertOriginAsync(string poolId, LbOriginInput origin, bool allowLastHealthyPool = false, string? zoneId = null, string? accountId = null, CancellationToken ct = default)
    {
        CheckOrigin(origin);
        return ChangeOriginsAsync(poolId, origin.Name, _ => origin, allowLastHealthyPool, zoneId, accountId, ct, mustExist: false);
    }

    /// <summary>Removes an origin from a pool (same protection as <see cref="SetOriginEnabledAsync"/>). False when the pool has no such origin.</summary>
    public async Task<bool> RemoveOriginAsync(string poolId, string originName, bool allowLastHealthyPool = false, string? zoneId = null, string? accountId = null, CancellationToken ct = default) =>
        (await ChangeOriginsAsync(poolId, originName, _ => null, allowLastHealthyPool, zoneId, accountId, ct, mustExist: true, remove: true).ConfigureAwait(false)).Changed;

    public CloudflareChangePreview PreviewRemovePool(string poolId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "load_balancers", "pools", poolId), null, $"Delete pool {poolId} (refused while a load balancer or monitor group uses it).");

    /// <summary>Deletes a pool that no load balancer uses (one read of its references after the guard check). False when it did not exist.</summary>
    public async Task<bool> RemovePoolAsync(string poolId, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "load_balancers", "pools", P1.Required(poolId, nameof(poolId)));
        EnsureWritable(HttpMethod.Delete, path);
        var uses = await ReferencesAsync(AccountPath(accountId, "load_balancers", "pools", poolId, "references"), ct).ConfigureAwait(false);
        if (uses is null) return false;
        if (uses.Count > 0) throw new InvalidOperationException($"Refused: pool {poolId} is used by {string.Join(", ", uses.Select(u => u.Name))}. Remove it from them first.");
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ---- load balancers ----

    public Task<List<LoadBalancer>> ListLoadBalancersAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<LoadBalancer>>(ZonePath(zoneId, "load_balancers"), ct);

    public Task<LoadBalancer> GetLoadBalancerAsync(string loadBalancerId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<LoadBalancer>(ZonePath(zoneId, "load_balancers", loadBalancerId), ct);

    public CloudflareChangePreview PreviewCreateLoadBalancer(LoadBalancerInput lb, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "load_balancers"), LoadBalancerBody(lb), $"Create load balancer {lb.Name} over {lb.DefaultPools.Count} pool(s), steering {lb.SteeringPolicy}{(lb.Enabled ? "" : ", created disabled")}.");

    /// <summary>Returns the load balancer for this hostname or creates it; an existing one is not changed.</summary>
    public async Task<(LoadBalancer LoadBalancer, bool Created)> EnsureLoadBalancerAsync(LoadBalancerInput lb, string? zoneId = null, CancellationToken ct = default)
    {
        var body = LoadBalancerBody(lb);
        var path = ZonePath(zoneId, "load_balancers");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await ListLoadBalancersAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(l => string.Equals(l.Name, lb.Name, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<LoadBalancer>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListLoadBalancersAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(l => string.Equals(l.Name, lb.Name, StringComparison.OrdinalIgnoreCase));
            return again is null ? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"Load balancer \"{lb.Name}\" is reported as existing but was not found." }]) : (again, false);
        }
    }

    public CloudflareChangePreview PreviewSetLoadBalancerEnabled(string loadBalancerId, bool enabled, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "load_balancers", loadBalancerId), new JsonObject { ["enabled"] = enabled },
            enabled ? $"Enable load balancer {loadBalancerId}." : $"Disable load balancer {loadBalancerId}. WARNING: its hostname stops being balanced.");

    /// <summary>Enables or disables a load balancer (PATCH; only written on change). Disabling an enabled one needs <paramref name="allowDisableActive"/>.</summary>
    public async Task<(LoadBalancer LoadBalancer, bool Changed)> SetLoadBalancerEnabledAsync(string loadBalancerId, bool enabled, bool allowDisableActive = false, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "load_balancers", P1.Required(loadBalancerId, nameof(loadBalancerId)));
        EnsureWritable(HttpMethod.Patch, path);
        var current = await GetLoadBalancerAsync(loadBalancerId, zoneId, ct).ConfigureAwait(false);
        if (current.Enabled == enabled) return (current, false);
        if (!enabled) P2.Allow(allowDisableActive, $"load balancer {current.Name} is enabled and serving traffic", nameof(allowDisableActive));
        return (await Api.PatchAsync<LoadBalancer>(path, new JsonObject { ["enabled"] = enabled }, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveLoadBalancer(string loadBalancerId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "load_balancers", loadBalancerId), null, $"Delete load balancer {loadBalancerId}. WARNING: its hostname stops resolving to the pools.");

    /// <summary>Deletes a load balancer. An enabled one needs <paramref name="allowDeleteActive"/> (disable it first to see the effect). False when it did not exist.</summary>
    public async Task<bool> RemoveLoadBalancerAsync(string loadBalancerId, bool allowDeleteActive = false, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "load_balancers", P1.Required(loadBalancerId, nameof(loadBalancerId)));
        EnsureWritable(HttpMethod.Delete, path);
        LoadBalancer current;
        try { current = await GetLoadBalancerAsync(loadBalancerId, zoneId, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return false; }
        if (current.Enabled) P2.Allow(allowDeleteActive, $"load balancer {current.Name} is enabled and serving traffic", nameof(allowDeleteActive));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ---- outage protection ----

    private async Task<(LbPool Pool, bool Changed)> ChangeOriginsAsync(string poolId, string originName, Func<LbOrigin, LbOriginInput?> change, bool allowLast, string? zoneId, string? accountId, CancellationToken ct, bool mustExist, bool remove = false)
    {
        var path = AccountPath(accountId, "load_balancers", "pools", P1.Required(poolId, nameof(poolId)));
        EnsureWritable(HttpMethod.Patch, path);
        var pool = await GetPoolAsync(poolId, accountId, ct).ConfigureAwait(false);
        var current = pool.Origins.FirstOrDefault(o => o.Name == originName);
        if (current is null && mustExist) return (pool, false);
        var origins = new List<LbOriginInput>();
        var changed = false;
        foreach (var o in pool.Origins)
        {
            if (o.Name != originName) { origins.Add(new(o.Name, o.Address, o.Enabled, o.Weight ?? 1, o.Port)); continue; }
            if (remove) { changed = true; continue; }
            var next = change(o);
            if (next is null) { origins.Add(new(o.Name, o.Address, o.Enabled, o.Weight ?? 1, o.Port)); continue; }
            changed |= next != new LbOriginInput(o.Name, o.Address, o.Enabled, o.Weight ?? 1, o.Port);
            origins.Add(next);
        }
        if (current is null && !remove) { var added = change(new LbOrigin { Name = originName }); if (added is not null) { origins.Add(added); changed = true; } }
        if (!changed) return (pool, false);

        var needed = Math.Max(1, pool.MinimumOrigins ?? 1);
        var wasUsable = pool.Origins.Count(o => o.Enabled) >= needed;
        if (pool.Enabled && wasUsable && origins.Count(o => o.Enabled) < needed)
            await AssertNotLastHealthyAsync(pool, allowLast, zoneId, accountId, ct).ConfigureAwait(false);
        var body = new JsonObject { ["origins"] = new JsonArray(origins.Select(OriginJson).ToArray()) };
        return (await Api.PatchAsync<LbPool>(path, body, ct).ConfigureAwait(false), true);
    }

    private async Task AssertNotLastHealthyAsync(LbPool pool, bool allow, string? zoneId, string? accountId, CancellationToken ct)
    {
        if (allow) return;
        if (string.IsNullOrWhiteSpace(zoneId) && string.IsNullOrWhiteSpace(Api.Options.ZoneId))
            throw new CloudflareConfigurationException("Cloudflare: the last-healthy-pool check needs the zone of the load balancers (pass zoneId or configure CloudflareOptions.ZoneId), or pass allowLastHealthyPool: true after checking yourself.");
        var zone = Zone(zoneId);
        var balancers = await ListLoadBalancersAsync(zone, ct).ConfigureAwait(false);
        var pools = (await ListPoolsAsync(accountId, ct).ConfigureAwait(false)).ToDictionary(p => p.Id);
        var references = await ReferencesAsync(AccountPath(accountId, "load_balancers", "pools", pool.Id, "references"), ct).ConfigureAwait(false) ?? [];
        var unchecked_ = references.Where(r => r.Type == "load_balancer" && balancers.All(b => b.Id != r.Id)).ToList();
        if (unchecked_.Count > 0)
            throw new InvalidOperationException($"Refused: pool \"{pool.Name}\" is also used by load balancers outside zone {zone} ({string.Join(", ", unchecked_.Select(u => u.Name))}), which cannot be checked. Pass allowLastHealthyPool: true deliberately.");

        var atRisk = new List<string>();
        foreach (var lb in balancers)
        {
            var ids = PoolIds(lb);
            if (!ids.Contains(pool.Id)) continue;
            var healthyOthers = 0;
            foreach (var id in ids.Where(i => i != pool.Id))
                if (pools.TryGetValue(id, out var other) && await IsHealthyAsync(other, accountId, ct).ConfigureAwait(false)) healthyOthers++;
            if (healthyOthers == 0) atRisk.Add(lb.Name);
        }
        if (atRisk.Count > 0)
            throw new InvalidOperationException($"Refused: pool \"{pool.Name}\" is the last healthy pool of {string.Join(", ", atRisk)}; taking it out ends the traffic of those load balancers. Pass allowLastHealthyPool: true deliberately.");
    }

    private async Task<bool> IsHealthyAsync(LbPool pool, string? accountId, CancellationToken ct)
    {
        if (!pool.Enabled) return false;
        if (pool.Healthy is { } h) return h;
        if (pool.Monitor is null) return true;
        var health = await GetPoolHealthAsync(pool.Id, accountId, ct).ConfigureAwait(false);
        if (!P2.TryGet(health, "pop_health", out var pops) || pops.ValueKind != JsonValueKind.Object) return true;
        var any = false;
        foreach (var p in pops.EnumerateObject())
        {
            if (p.Value.ValueKind != JsonValueKind.Object || !p.Value.TryGetProperty("healthy", out var ok) || ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) continue;
            any = true;
            if (ok.GetBoolean()) return true;
        }
        return !any;
    }

    private static HashSet<string> PoolIds(LoadBalancer lb)
    {
        var ids = new HashSet<string>(lb.DefaultPools);
        if (!string.IsNullOrEmpty(lb.FallbackPool)) ids.Add(lb.FallbackPool);
        foreach (var map in new[] { lb.RegionPools, lb.PopPools, lb.CountryPools })
            if (map is { ValueKind: JsonValueKind.Object } m)
                foreach (var entry in m.EnumerateObject())
                    if (entry.Value.ValueKind == JsonValueKind.Array)
                        foreach (var id in entry.Value.EnumerateArray()) if (id.ValueKind == JsonValueKind.String) ids.Add(id.GetString()!);
        return ids;
    }

    private async Task<List<(string Type, string Id, string Name)>?> ReferencesAsync(string path, CancellationToken ct)
    {
        try
        {
            var result = await Api.GetAsync<List<JsonElement>>(path, ct).ConfigureAwait(false) ?? [];
            return result.Select(r => (P2.Str(r, "resource_type") ?? "", P2.Str(r, "resource_id") ?? "", P2.Str(r, "resource_name") ?? P2.Str(r, "resource_id") ?? "")).ToList();
        }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return null; }
    }

    // ---- bodies and checks ----

    private static LbMonitor ToMonitor(JsonElement e)
    {
        var node = JsonNode.Parse(e.GetRawText())!.AsObject();
        if (node["header"] is JsonObject headers)
            foreach (var name in headers.Select(p => p.Key).ToList()) headers[name] = new JsonArray(P1.Redacted);
        return P1.As<LbMonitor>(JsonSerializer.SerializeToElement(node, CloudflareJson.Options));
    }

    private static JsonObject MonitorBody(LbMonitorInput m, bool allowInsecureTls, bool redact)
    {
        if (!MonitorTypes.Contains(m.Type)) throw new ArgumentException("Type: http, https, tcp, udp_icmp, icmp_ping or smtp.", nameof(m));
        if (m.Interval is < 5 or > 3600) throw new ArgumentOutOfRangeException(nameof(m), "Interval 5 to 3600 seconds.");
        if (m.Timeout < 1 || m.Timeout > 60 || m.Timeout >= m.Interval) throw new ArgumentOutOfRangeException(nameof(m), "Timeout 1 to 60 seconds and below the interval.");
        if (m.Retries is < 0 or > 5) throw new ArgumentOutOfRangeException(nameof(m), "Retries 0 to 5.");
        if (m.Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(m), "Port 1 to 65535.");
        if (m.AllowInsecure) P2.Allow(allowInsecureTls, "a monitor that skips the certificate check cannot see an origin with a broken or foreign certificate", nameof(allowInsecureTls));
        var body = new JsonObject { ["type"] = m.Type, ["interval"] = m.Interval, ["timeout"] = m.Timeout, ["retries"] = m.Retries };
        if (m.Description is not null) body["description"] = m.Description;
        if (m.Type is "http" or "https")
        {
            body["method"] = m.Method ?? "GET";
            body["path"] = m.Path ?? "/";
            if (m.ExpectedCodes is not null) body["expected_codes"] = m.ExpectedCodes;
            if (m.ExpectedBody is not null) body["expected_body"] = m.ExpectedBody;
            body["follow_redirects"] = m.FollowRedirects;
            body["allow_insecure"] = m.AllowInsecure;
        }
        if (m.Port is { } port) body["port"] = port;
        if (m.Headers is { Count: > 0 })
        {
            var headers = new JsonObject();
            foreach (var (name, value) in m.Headers)
            {
                if (string.IsNullOrWhiteSpace(name) || name.Any(c => c is ' ' or ':' or '\r' or '\n')) throw new ArgumentException("Invalid header name.", nameof(m));
                if (value.Any(c => c is '\r' or '\n')) throw new ArgumentException($"The value of header {name} has a line break.", nameof(m));
                headers[name] = new JsonArray(redact ? P1.Redacted : value);
            }
            body["header"] = headers;
        }
        return body;
    }

    private static void CheckOrigin(LbOriginInput o)
    {
        P2.Match(o.Name, "origin name", PoolNamePattern, "letters, digits, '-' and '_'");
        if (!System.Net.IPAddress.TryParse(o.Address, out _)) P1.Hostname(o.Address, "origin address");
        if (o.Weight is < 0 or > 1) throw new ArgumentOutOfRangeException(nameof(o), "Weight 0 to 1.");
        if (o.Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(o), "Port 1 to 65535.");
    }

    private static JsonNode OriginJson(LbOriginInput o)
    {
        var json = new JsonObject { ["name"] = o.Name, ["address"] = o.Address, ["enabled"] = o.Enabled, ["weight"] = o.Weight };
        if (o.Port is { } p) json["port"] = p;
        if (o.HostHeader is not null) json["header"] = new JsonObject { ["Host"] = new JsonArray(o.HostHeader) };
        return json;
    }

    private static JsonObject PoolBody(LbPoolInput p)
    {
        P2.Match(p.Name, nameof(p), PoolNamePattern, "letters, digits, '-' and '_'");
        if (p.Origins is null || p.Origins.Count is < 1 or > 100) throw new ArgumentException("Between 1 and 100 origins.", nameof(p));
        foreach (var o in p.Origins) CheckOrigin(o);
        if (p.Origins.Select(o => o.Name).Distinct().Count() != p.Origins.Count) throw new ArgumentException("Origin names must be unique.", nameof(p));
        if (!p.Origins.Any(o => o.Enabled)) throw new ArgumentException("At least one origin must be enabled.", nameof(p));
        if (p.MinimumOrigins is { } min && (min < 1 || min > p.Origins.Count)) throw new ArgumentOutOfRangeException(nameof(p), "Minimum origins: 1 to the number of origins.");
        var body = new JsonObject { ["name"] = p.Name, ["enabled"] = p.Enabled, ["origins"] = new JsonArray(p.Origins.Select(OriginJson).ToArray()) };
        if (p.Description is not null) body["description"] = p.Description;
        if (p.MinimumOrigins is { } m) body["minimum_origins"] = m;
        if (p.MonitorId is not null) body["monitor"] = p.MonitorId;
        if (p.NotificationEmail is not null) body["notification_email"] = p.NotificationEmail.Contains('@') && !p.NotificationEmail.Any(char.IsWhiteSpace) ? p.NotificationEmail : throw new ArgumentException("Invalid notification email.", nameof(p));
        return body;
    }

    private static JsonObject LoadBalancerBody(LoadBalancerInput l)
    {
        var name = P1.Hostname(l.Name, nameof(l));
        if (l.DefaultPools is null || l.DefaultPools.Count == 0 || l.DefaultPools.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("At least one default pool.", nameof(l));
        if (!Steering.Contains(l.SteeringPolicy)) throw new ArgumentException($"Steering policy: {string.Join(", ", Steering)}.", nameof(l));
        if (!Affinity.Contains(l.SessionAffinity)) throw new ArgumentException($"Session affinity: {string.Join(", ", Affinity)}.", nameof(l));
        var body = new JsonObject
        {
            ["name"] = name, ["default_pools"] = P1.Arr(l.DefaultPools), ["fallback_pool"] = P1.Required(l.FallbackPool, nameof(l)),
            ["enabled"] = l.Enabled, ["proxied"] = l.Proxied, ["steering_policy"] = l.SteeringPolicy, ["session_affinity"] = l.SessionAffinity,
        };
        if (l.Description is not null) body["description"] = l.Description;
        if (l.Ttl is { } ttl)
        {
            if (l.Proxied) throw new ArgumentException("A TTL is only used for DNS-only (not proxied) load balancers.", nameof(l));
            body["ttl"] = ttl is >= 30 and <= 600 ? ttl : throw new ArgumentOutOfRangeException(nameof(l), "TTL 30 to 600 seconds.");
        }
        return body;
    }
}
