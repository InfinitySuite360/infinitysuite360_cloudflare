using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare;

/// <summary>
/// Single entry point to the Cloudflare API.
/// <list type="bullet">
/// <item><c>OpenApi</c>: every operation of the official OpenAPI schema, generated and fully typed — only with the package
/// <c>InfinitySuite360.Cloudflare</c>, which adds it as an extension property (<c>CloudflareClientOpenApiExtensions</c>).</item>
/// <item>Curated clients (<see cref="Zones"/>, <see cref="Dns"/>, …): hand-written convenience for common tasks.</item>
/// <item><see cref="Api"/>: raw access to any endpoint with the same write guard, retries and error handling.</item>
/// </list>
/// Use it through dependency injection (<c>AddCloudflareInfinitySuite360</c>) or create it with <see cref="CloudflareClient.Create"/>.
/// </summary>
public interface ICloudflareClient
{
    /// <summary>Raw access to any API v4 endpoint (write guard, retries, error handling).</summary>
    ICloudflareApiConnection Api { get; }

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
    ListsClient Lists { get; }
    IpAccessClient IpAccess { get; }
    /// <summary>Page Shield (client-side security): settings, scripts, connections, cookies, content security rules.</summary>
    PageShieldClient PageShield { get; }
    /// <summary>API Shield: operations, API Discovery, schema validation, token validation, labels, mTLS client certificates.</summary>
    ApiShieldClient ApiShield { get; }
    /// <summary>Rate limiting rules (phase http_ratelimit) and the deprecated classic rate limits.</summary>
    RateLimitingClient RateLimiting { get; }
    /// <summary>WAF custom rules and managed rules (deployments, overrides).</summary>
    WafClient Waf { get; }
    /// <summary>Bot Fight Mode, Super Bot Fight Mode, Bot Management, leaked credential checks.</summary>
    BotsClient Bots { get; }
    /// <summary>Custom hostnames (Cloudflare for SaaS) and their fallback origin.</summary>
    CustomHostnamesClient CustomHostnames { get; }
    /// <summary>Authenticated Origin Pulls (zone-level and per-hostname).</summary>
    OriginPullsClient OriginPulls { get; }
    /// <summary>SSL mode, minimum TLS version, HSTS and TLS switches of a zone.</summary>
    TlsSettingsClient Tls { get; }
    /// <summary>Logpush jobs with redacted destinations.</summary>
    LogpushClient Logpush { get; }
    /// <summary>API token management (create, roll, revoke; the value only once in the result).</summary>
    ApiTokensClient ApiTokens { get; }
    /// <summary>Workers KV: namespaces, keys, values, bulk operations.</summary>
    KvClient Kv { get; }
    /// <summary>D1 databases and SQL (read-only unless <c>allowWriteSql</c>).</summary>
    D1Client D1 { get; }
    /// <summary>Cloudflare Queues: queues, consumers, publishing.</summary>
    QueuesClient Queues { get; }
    /// <summary>Cache rules, purging and cache settings.</summary>
    CacheClient Cache { get; }
    /// <summary>Argo Smart Routing and Argo tiered caching.</summary>
    ArgoClient Argo { get; }
    /// <summary>Load balancing: monitors, pools, load balancers with outage protection.</summary>
    LoadBalancingClient LoadBalancing { get; }
    /// <summary>Spectrum applications (TCP/UDP proxy).</summary>
    SpectrumClient Spectrum { get; }
}

public sealed class CloudflareClient : ICloudflareClient
{
    public CloudflareClient(ICloudflareApiConnection api)
    {
        Api = api;
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
        Lists = new(api);
        IpAccess = new(api);
        PageShield = new(api);
        ApiShield = new(api);
        RateLimiting = new(api);
        Waf = new(api);
        Bots = new(api);
        CustomHostnames = new(api);
        OriginPulls = new(api);
        Tls = new(api);
        Logpush = new(api);
        ApiTokens = new(api);
        Kv = new(api);
        D1 = new(api);
        Queues = new(api);
        Cache = new(api);
        Argo = new(api);
        LoadBalancing = new(api);
        Spectrum = new(api);
    }

    /// <summary>Creates a client without dependency injection (console tools, scripts, tests).</summary>
    public static CloudflareClient Create(CloudflareOptions options, HttpClient? httpClient = null)
    {
        var http = httpClient ?? new HttpClient { Timeout = options.Timeout };
        return new CloudflareClient(new CloudflareApiConnection(http, options));
    }

    public ICloudflareApiConnection Api { get; }
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
    public ListsClient Lists { get; }
    public IpAccessClient IpAccess { get; }
    public PageShieldClient PageShield { get; }
    public ApiShieldClient ApiShield { get; }
    public RateLimitingClient RateLimiting { get; }
    public WafClient Waf { get; }
    public BotsClient Bots { get; }
    public CustomHostnamesClient CustomHostnames { get; }
    public OriginPullsClient OriginPulls { get; }
    public TlsSettingsClient Tls { get; }
    public LogpushClient Logpush { get; }
    public ApiTokensClient ApiTokens { get; }
    public KvClient Kv { get; }
    public D1Client D1 { get; }
    public QueuesClient Queues { get; }
    public CacheClient Cache { get; }
    public ArgoClient Argo { get; }
    public LoadBalancingClient LoadBalancing { get; }
    public SpectrumClient Spectrum { get; }
}
