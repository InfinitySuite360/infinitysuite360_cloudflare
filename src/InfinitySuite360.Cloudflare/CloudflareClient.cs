using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare;

/// <summary>
/// Single entry point to the Cloudflare API.
/// <list type="bullet">
/// <item><see cref="OpenApi"/>: every operation of the official OpenAPI schema, generated and fully typed.</item>
/// <item>Curated clients (<see cref="Zones"/>, <see cref="Dns"/>, …): hand-written convenience for common tasks.</item>
/// <item><see cref="Api"/>: raw access to any endpoint with the same write guard, retries and error handling.</item>
/// </list>
/// Use it through dependency injection (<c>AddCloudflareInfinitySuite360</c>) or create it with <see cref="CloudflareClient.Create"/>.
/// </summary>
public interface ICloudflareClient
{
    /// <summary>Raw access to any API v4 endpoint (write guard, retries, error handling).</summary>
    ICloudflareApiConnection Api { get; }

    /// <summary>Complete generated client: all operations and models of the official Cloudflare OpenAPI schema.</summary>
    CloudflareApiClient OpenApi { get; }

    AccountsClient Accounts { get; }
    ZonesClient Zones { get; }
    DnsClient Dns { get; }
    RulesetsClient Rulesets { get; }
    TurnstileWidgetsClient Turnstile { get; }
    TunnelsClient Tunnels { get; }
    AccessClient Access { get; }
    EmailRoutingClient EmailRouting { get; }
    R2Client R2 { get; }
    WorkersClient Workers { get; }
    MonitoringClient Monitoring { get; }
    SecurityClient Security { get; }
    CertificatesClient Certificates { get; }
    AnalyticsClient Analytics { get; }
    IpsClient Ips { get; }
}

public sealed class CloudflareClient : ICloudflareClient
{
    private readonly Lazy<CloudflareApiClient> _openApi;

    public CloudflareClient(ICloudflareApiConnection api, Func<CloudflareApiClient>? openApiFactory = null)
    {
        Api = api;
        _openApi = new Lazy<CloudflareApiClient>(openApiFactory ?? (() => CloudflareOpenApi.CreateClient(api.Options)));
        Accounts = new(api);
        Zones = new(api);
        Dns = new(api);
        Rulesets = new(api);
        Turnstile = new(api);
        Tunnels = new(api);
        Access = new(api);
        EmailRouting = new(api);
        R2 = new(api);
        Workers = new(api);
        Monitoring = new(api);
        Security = new(api);
        Certificates = new(api);
        Analytics = new(api);
        Ips = new(api);
    }

    /// <summary>Creates a client without dependency injection (console tools, scripts, tests).</summary>
    public static CloudflareClient Create(CloudflareOptions options, HttpClient? httpClient = null)
    {
        var http = httpClient ?? new HttpClient { Timeout = options.Timeout };
        return new CloudflareClient(new CloudflareApiConnection(http, options));
    }

    public ICloudflareApiConnection Api { get; }
    public CloudflareApiClient OpenApi => _openApi.Value;
    public AccountsClient Accounts { get; }
    public ZonesClient Zones { get; }
    public DnsClient Dns { get; }
    public RulesetsClient Rulesets { get; }
    public TurnstileWidgetsClient Turnstile { get; }
    public TunnelsClient Tunnels { get; }
    public AccessClient Access { get; }
    public EmailRoutingClient EmailRouting { get; }
    public R2Client R2 { get; }
    public WorkersClient Workers { get; }
    public MonitoringClient Monitoring { get; }
    public SecurityClient Security { get; }
    public CertificatesClient Certificates { get; }
    public AnalyticsClient Analytics { get; }
    public IpsClient Ips { get; }
}
