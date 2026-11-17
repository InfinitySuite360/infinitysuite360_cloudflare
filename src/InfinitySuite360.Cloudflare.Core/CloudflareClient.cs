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
    /// <summary>Zero Trust Gateway: DNS/HTTP/network rules, lists, DNS locations, configuration, logging, proxy endpoints, inspection certificates.</summary>
    ZeroTrustGatewayClient Gateway { get; }
    /// <summary>WARP device profiles, Split Tunnel, posture rules, devices (read-only) and registration revocation.</summary>
    DevicesClient Devices { get; }
    /// <summary>Data Loss Prevention, read-only: profiles, datasets, payload log settings.</summary>
    DlpClient Dlp { get; }
    /// <summary>Zero Trust risk scoring, read-only: behaviors and user summary.</summary>
    RiskScoringClient RiskScoring { get; }
    /// <summary>Cloudflare Images (0.9.0, narrow): images, usage, variants; delete with preview.</summary>
    ImagesClient Images { get; }
    /// <summary>Cloudflare Stream (0.9.0, narrow): videos, storage usage; delete with preview.</summary>
    StreamClient Stream { get; }
    /// <summary>Cloudflare Registrar (0.9.0, narrow): registrations, status, auto-renew with preview.</summary>
    RegistrarClient Registrar { get; }
    /// <summary>Account members and roles (0.9.0, narrow): read; remove with preview and lock-out protection.</summary>
    MembersClient Members { get; }
    /// <summary>Account audit log v2 (0.9.0, read-only; v1 in Monitoring).</summary>
    AuditLogsClient AuditLogs { get; }
    /// <summary>Cloudflare Radar (0.9.0, read-only): domain ranking, ASNs, any dataset.</summary>
    RadarClient Radar { get; }
    /// <summary>Cloudflare Pages (0.9.0, narrow): projects, deployments; rollback with preview.</summary>
    PagesClient Pages { get; }
    /// <summary>Hyperdrive (0.9.0, narrow): configurations without passwords; delete with preview.</summary>
    HyperdriveClient Hyperdrive { get; }
    /// <summary>Workflows (0.9.0, narrow): workflows, instances; pause/resume/terminate with preview.</summary>
    WorkflowsClient Workflows { get; }
    /// <summary>Durable Objects (0.9.0, read-only): namespaces and objects.</summary>
    DurableObjectsClient DurableObjects { get; }
    /// <summary>Secrets Store (0.9.0, narrow): stores and secret metadata, never values; delete with preview.</summary>
    SecretsStoreClient SecretsStore { get; }
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
        Gateway = new(api);
        Devices = new(api);
        Dlp = new(api);
        RiskScoring = new(api);
        Images = new(api);
        Stream = new(api);
        Registrar = new(api);
        Members = new(api);
        AuditLogs = new(api);
        Radar = new(api);
        Pages = new(api);
        Hyperdrive = new(api);
        Workflows = new(api);
        DurableObjects = new(api);
        SecretsStore = new(api);
    }

    /// <summary>Creates a client without dependency injection (console tools, scripts, tests).</summary>
    /// <exception cref="CloudflareConfigurationException">The options are invalid (see <see cref="CloudflareOptions.Validate"/>).</exception>
    public static CloudflareClient Create(CloudflareOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
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
    public ZeroTrustGatewayClient Gateway { get; }
    public DevicesClient Devices { get; }
    public DlpClient Dlp { get; }
    public RiskScoringClient RiskScoring { get; }
    public ImagesClient Images { get; }
    public StreamClient Stream { get; }
    public RegistrarClient Registrar { get; }
    public MembersClient Members { get; }
    public AuditLogsClient AuditLogs { get; }
    public RadarClient Radar { get; }
    public PagesClient Pages { get; }
    public HyperdriveClient Hyperdrive { get; }
    public WorkflowsClient Workflows { get; }
    public DurableObjectsClient DurableObjects { get; }
    public SecretsStoreClient SecretsStore { get; }
}
