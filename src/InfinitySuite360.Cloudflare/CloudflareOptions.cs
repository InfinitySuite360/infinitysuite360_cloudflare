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

    /// <summary>Retries for HTTP 429 and transient server errors (502/503/504, idempotent methods only).</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Base delay for exponential back-off when Cloudflare sends no <c>Retry-After</c>.</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    public string UserAgent { get; set; } = "InfinitySuite360.Cloudflare";

    public TurnstileOptions Turnstile { get; set; } = new();

    /// <summary>Checking the token that Cloudflare Access adds to requests (<c>Cf-Access-Jwt-Assertion</c>); off until team domain and audiences are set.</summary>
    public InfinitySuite360.Cloudflare.AccessJwt.CloudflareAccessJwtOptions AccessJwt { get; set; } = new();
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
