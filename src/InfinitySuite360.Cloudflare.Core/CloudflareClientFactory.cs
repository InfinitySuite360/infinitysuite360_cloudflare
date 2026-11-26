using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare;

/// <summary>
/// Clients for several tenants (0.9.0): one <see cref="ICloudflareClient"/> per tenant with its own <see cref="CloudflareOptions"/> (token, account, zone,
/// write guard), a shared HTTP connection pool and a shared request budget per token (<see cref="CloudflareRateBudgetRegistry"/>).
/// <list type="bullet">
/// <item>A client is never handed to another tenant, and a cached client is replaced as soon as the tenant's token or settings change: a client always
/// sends exactly the token it was created with.</item>
/// <item>The token is only sent in the <c>Authorization</c> header of each request (never in <c>DefaultRequestHeaders</c> of the shared pool), never in
/// <see cref="object.ToString"/>, exceptions or events.</item>
/// <item>Every tenant gets a copy of its options (<see cref="CloudflareOptions.Clone"/>); later changes at the source create a new client instead of
/// changing a running one.</item>
/// </list>
/// </summary>
public interface ICloudflareClientFactory : IDisposable
{
    /// <summary>The client of a configured tenant (cached while the tenant's token and settings stay the same).</summary>
    /// <exception cref="CloudflareConfigurationException">The tenant is unknown, has no token or invalid settings.</exception>
    /// <exception cref="ArgumentException">The name is not a valid tenant name (letters, digits, <c>.</c>, <c>_</c>, <c>-</c>; at most 64).</exception>
    ICloudflareClient GetClient(string tenant);

    /// <summary>A new client for ad-hoc options (not cached; same pool and budget rules). The options are copied.</summary>
    ICloudflareClient CreateClient(CloudflareOptions options);

    /// <summary>The names of the configured tenants.</summary>
    IReadOnlyCollection<string> Tenants { get; }
}

/// <summary>The tenant names known to dependency injection (filled by <c>AddCloudflareTenant</c>).</summary>
public sealed class CloudflareTenantCatalog
{
    /// <summary>Configured tenant names (case-sensitive).</summary>
    public ISet<string> Names { get; } = new HashSet<string>(StringComparer.Ordinal);
}

/// <inheritdoc cref="ICloudflareClientFactory"/>
public sealed class CloudflareClientFactory : ICloudflareClientFactory
{
    private static readonly Regex TenantName = new("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private readonly Func<string, CloudflareOptions?> _resolve;
    private readonly Func<IReadOnlyCollection<string>> _names;
    private readonly Func<CloudflareOptions, HttpClient> _http;
    private readonly HttpMessageHandler? _ownedHandler;
    private readonly CloudflareRateBudgetRegistry _budgets;
    private readonly ConcurrentDictionary<string, Entry> _clients = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private volatile bool _disposed;

    private sealed record Entry(string Fingerprint, string Settings, Func<HttpMethod, string, bool>? WriteFilter, ICloudflareClient Client);

    /// <summary>
    /// Without dependency injection: <paramref name="tenants"/> maps names to options. All clients share one <see cref="SocketsHttpHandler"/> (connection
    /// pool, renewed every five minutes for DNS changes) unless <paramref name="sharedHandler"/> is passed (tests: a fake handler; it is not disposed here).
    /// </summary>
    public CloudflareClientFactory(IReadOnlyDictionary<string, CloudflareOptions> tenants, HttpMessageHandler? sharedHandler = null, CloudflareRateBudgetRegistry? budgets = null)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        foreach (var name in tenants.Keys) CheckName(name);
        var snapshot = tenants.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        _resolve = name => snapshot.TryGetValue(name, out var o) ? o : null;
        _names = () => snapshot.Keys.ToList();
        var handler = sharedHandler;
        if (handler is null)
        {
            handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5), AllowAutoRedirect = false };
            _ownedHandler = handler;
        }
        _http = o => new HttpClient(handler, disposeHandler: false) { Timeout = o.Timeout };
        _budgets = budgets ?? new CloudflareRateBudgetRegistry();
    }

    /// <summary>
    /// For dependency injection: tenants are named options (<c>AddCloudflareTenant</c>), the HTTP clients come from <see cref="IHttpClientFactory"/>
    /// (pooled handlers of the client <c>InfinitySuite360.Cloudflare.Api</c>), the budgets from the registered <see cref="CloudflareRateBudgetRegistry"/>.
    /// </summary>
    public CloudflareClientFactory(IOptionsMonitor<CloudflareOptions> options, IHttpClientFactory httpClientFactory, CloudflareRateBudgetRegistry budgets, IOptions<CloudflareTenantCatalog> catalog)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(catalog);
        var names = catalog.Value.Names;
        _resolve = name => names.Contains(name) ? options.Get(name) : null;
        _names = () => names.ToList();
        _http = o =>
        {
            var http = httpClientFactory.CreateClient(Microsoft.Extensions.DependencyInjection.CloudflareServiceCollectionExtensions.ApiHttpClientName);
            http.Timeout = o.Timeout;
            return http;
        };
        _budgets = budgets ?? throw new ArgumentNullException(nameof(budgets));
    }

    public IReadOnlyCollection<string> Tenants => _names();

    /// <summary>The budgets used by this factory (status pages; labels and counters only).</summary>
    public CloudflareRateBudgetRegistry Budgets => _budgets;

    public ICloudflareClient GetClient(string tenant)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CheckName(tenant);
        var source = _resolve(tenant) ?? throw new CloudflareConfigurationException($"Cloudflare: tenant \"{tenant}\" is not configured.");
        var options = Prepare(source, tenant);
        var fingerprint = _budgets.Fingerprint(options.ApiToken);
        // M-3 (0.9.1): every setting counts (keyed hash of all option values except the token, see CloudflareOptions.SettingsText), not only ToString.
        var settings = _budgets.Fingerprint(options.SettingsText());
        // A cached client is reused only for the same tenant with the same token and the same settings; otherwise a new one replaces it. One lock for
        // the compare-and-build, so parallel first calls get the same client instead of each building one (M-3/L-8 race).
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_clients.TryGetValue(tenant, out var old) && old.Fingerprint == fingerprint && old.Settings == settings && ReferenceEquals(old.WriteFilter, options.WriteFilter))
                return old.Client;
            var entry = new Entry(fingerprint, settings, options.WriteFilter, Build(options));
            _clients[tenant] = entry;
            return entry.Client;
        }
    }

    public ICloudflareClient CreateClient(CloudflareOptions options)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(options);
        return Build(Prepare(options, null));
    }

    public override string ToString() => $"CloudflareClientFactory({_clients.Count} cached clients, {_budgets.Count} budgets)";

    /// <summary>Drops the cached clients and disposes the own connection pool (not a handler passed in, not the <see cref="IHttpClientFactory"/>).</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _clients.Clear();
        _ownedHandler?.Dispose();
    }

    private static CloudflareOptions Prepare(CloudflareOptions source, string? tenant)
    {
        var options = source.Clone();
        if (tenant is not null && string.IsNullOrWhiteSpace(options.RateBudget.Name)) options.RateBudget.Name = tenant;
        options.Validate();
        if (string.IsNullOrWhiteSpace(options.ApiToken))
            throw new CloudflareConfigurationException(tenant is null ? "Cloudflare: no API token configured." : $"Cloudflare: tenant \"{tenant}\" has no API token.");
        return options;
    }

    private ICloudflareClient Build(CloudflareOptions options) =>
        new CloudflareClient(new CloudflareApiConnection(_http(options), options) { RateBudget = _budgets.For(options) });

    internal static void CheckName(string? tenant)
    {
        if (tenant is null || !TenantName.IsMatch(tenant))
            throw new ArgumentException("A tenant name has 1 to 64 characters: letters, digits, '.', '_' or '-', starting with a letter or digit.", nameof(tenant));
    }
}
