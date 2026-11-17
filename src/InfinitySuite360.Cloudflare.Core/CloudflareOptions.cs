namespace InfinitySuite360.Cloudflare;

/// <summary>
/// Settings for the Cloudflare client. Bindable from configuration (section <see cref="SectionName"/>).
/// Write calls are disabled by default (<see cref="AllowWrites"/>): a client must opt in before it can change anything.
/// </summary>
public sealed class CloudflareOptions
{
    public const string SectionName = "Cloudflare";
    public const string DefaultBaseAddress = "https://api.cloudflare.com/client/v4/";

    /// <summary>API token (Bearer). Never written to exception messages or logs.</summary>
    public string ApiToken { get; set; } = "";

    /// <summary>Default account ID for account-scoped calls when none is passed.</summary>
    public string? AccountId { get; set; }

    /// <summary>Default zone ID for zone-scoped calls when none is passed.</summary>
    public string? ZoneId { get; set; }

    /// <summary>API base address (override for tests or proxies).</summary>
    public string BaseAddress { get; set; } = DefaultBaseAddress;

    /// <summary>Timeout per request.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Allow write calls (POST/PUT/PATCH/DELETE). Default: <c>false</c>.</summary>
    public bool AllowWrites { get; set; }

    /// <summary>
    /// Optional allow-list for write calls (method, relative path without query). When set, only matching write calls are sent;
    /// everything else is rejected locally with <see cref="CloudflareWriteNotAllowedException"/>.
    /// </summary>
    public Func<HttpMethod, string, bool>? WriteFilter { get; set; }

    /// <summary>Upper bound of <see cref="MaxRetries"/> (checked by <see cref="Validate"/>; the connection never retries more often).</summary>
    public const int MaxRetriesLimit = 10;

    /// <summary>Retries for HTTP 429 and transient server errors (502/503/504, idempotent methods only). 0 to <see cref="MaxRetriesLimit"/>.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Largest answer body the curated client reads (default 32 MiB); a larger answer fails with <see cref="CloudflareApiException"/> instead of filling the memory.</summary>
    public long MaxResponseBytes { get; set; } = 32L * 1024 * 1024;

    /// <summary>Base delay for exponential back-off when Cloudflare sends no <c>Retry-After</c>.</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    public string UserAgent { get; set; } = "InfinitySuite360.Cloudflare";

    public TurnstileOptions Turnstile { get; set; } = new();

    /// <summary>Checking the token that Cloudflare Access adds to requests (<c>Cf-Access-Jwt-Assertion</c>); off until team domain and audiences are set.</summary>
    public InfinitySuite360.Cloudflare.AccessJwt.CloudflareAccessJwtOptions AccessJwt { get; set; } = new();

    /// <summary>
    /// Checks the settings that protect the token and the process (0.7.1): <see cref="BaseAddress"/> must be an absolute <c>https</c> URI (plain <c>http</c> only
    /// for loopback hosts such as a local test proxy), <see cref="MaxRetries"/> 0 to <see cref="MaxRetriesLimit"/>, <see cref="RetryBaseDelay"/> not negative,
    /// <see cref="MaxResponseBytes"/> positive. Called by <see cref="CloudflareClient.Create"/> and the dependency injection registration.
    /// </summary>
    /// <exception cref="CloudflareConfigurationException">A setting is out of range.</exception>
    public void Validate()
    {
        if (!Uri.TryCreate(BaseAddress, UriKind.Absolute, out var uri) || !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            throw new CloudflareConfigurationException("Cloudflare: BaseAddress must be an absolute https URI (http only for loopback); otherwise the API token would travel in clear text.");
        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new CloudflareConfigurationException("Cloudflare: BaseAddress must not contain user info, query or fragment.");
        if (MaxRetries is < 0 or > MaxRetriesLimit)
            throw new CloudflareConfigurationException($"Cloudflare: MaxRetries must be 0 to {MaxRetriesLimit}.");
        if (RetryBaseDelay < TimeSpan.Zero)
            throw new CloudflareConfigurationException("Cloudflare: RetryBaseDelay must not be negative.");
        if (MaxResponseBytes <= 0)
            throw new CloudflareConfigurationException("Cloudflare: MaxResponseBytes must be positive.");
    }
}

/// <summary>Settings for server-side Turnstile validation (siteverify).</summary>
public sealed class TurnstileOptions
{
    public const string DefaultVerifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    public string SiteKey { get; set; } = "";
    public string SecretKey { get; set; } = "";

    /// <summary>When set, the widget must have been solved on exactly this hostname (rejects tokens minted on other sites).</summary>
    public string? ExpectedHostname { get; set; }

    /// <summary>When set, the widget's <c>action</c> must match.</summary>
    public string? ExpectedAction { get; set; }

    public string VerifyUrl { get; set; } = DefaultVerifyUrl;

    public bool IsConfigured => SiteKey.Length > 0 && SecretKey.Length > 0;
}
