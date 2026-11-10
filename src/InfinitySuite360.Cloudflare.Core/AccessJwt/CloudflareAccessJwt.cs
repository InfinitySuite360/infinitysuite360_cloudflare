using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace InfinitySuite360.Cloudflare.AccessJwt;

/// <summary>
/// Settings for checking the token that Cloudflare Access adds to every request (<c>Cf-Access-Jwt-Assertion</c>). Bindable from configuration
/// (<c>Cloudflare:AccessJwt</c>). Off until <see cref="TeamDomain"/> and <see cref="Audiences"/> are set.
/// </summary>
public sealed class CloudflareAccessJwtOptions
{
    /// <summary>Header Cloudflare sets on every request that passed Access.</summary>
    public const string HeaderName = "Cf-Access-Jwt-Assertion";

    /// <summary>Cookie that carries the same token.</summary>
    public const string CookieName = "CF_Authorization";

    /// <summary>Your Zero Trust team domain, for example <c>myteam.cloudflareaccess.com</c> (no scheme, no path).</summary>
    public string TeamDomain { get; set; } = "";

    /// <summary>
    /// Application audience tags (Zero Trust → Access → Applications → your application → Overview → "Application Audience (AUD) Tag"). The token must carry one of them,
    /// which ties it to <i>your</i> application: a token minted for another application of the same team is refused.
    /// </summary>
    public List<string> Audiences { get; set; } = [];

    /// <summary>
    /// Accept a team domain that is not <c>*.cloudflareaccess.com</c> (a custom Access domain). Default: <c>false</c>. The domain is used to fetch the signing keys, so it must never be
    /// influenced by a request.
    /// </summary>
    public bool AllowCustomTeamDomain { get; set; }

    /// <summary>The signing keys are used from memory for this long before they are fetched again.</summary>
    public TimeSpan KeyCacheTime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>A token with an unknown key id triggers a new fetch at most this often (forged tokens must not flood Cloudflare).</summary>
    public TimeSpan MinRefetchInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// If the keys cannot be fetched, keys that are already known are still used for this long after they were fetched (Cloudflare rotates keys with an overlap of weeks,
    /// so a short outage must not lock everybody out). <see cref="TimeSpan.Zero"/> = fail closed.
    /// </summary>
    public TimeSpan MaxStaleKeyAge { get; set; } = TimeSpan.FromHours(12);

    /// <summary>Allowed difference between the clocks of Cloudflare and this server.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Tokens longer than this are refused before they are parsed.</summary>
    public int MaxTokenLength { get; set; } = 8192;

    /// <summary>Keys with a shorter modulus are ignored.</summary>
    public int MinKeyBits { get; set; } = 2048;

    public TimeSpan FetchTimeout { get; set; } = TimeSpan.FromSeconds(8);

    public bool IsConfigured => TeamDomain.Length > 0 && Audiences.Count > 0;

    /// <summary>The domain as a key: trimmed and lower case.</summary>
    internal static string Normalize(string teamDomain) => (teamDomain ?? "").Trim().ToLowerInvariant();

    private static readonly Regex CloudflareDomain = new(@"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex AnyHost = new(@"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Is this an acceptable team domain? Never a URL, an IP address, a port or a path.</summary>
    public static bool ValidTeamDomain(string? teamDomain, bool allowCustom)
    {
        var d = Normalize(teamDomain ?? "");
        return d.Length is > 0 and <= 253 && (CloudflareDomain.IsMatch(d) || (allowCustom && AnyHost.IsMatch(d) && !IPAddressLike(d)));
    }

    private static bool IPAddressLike(string host) => System.Net.IPAddress.TryParse(host, out _) || host.All(c => char.IsAsciiDigit(c) || c == '.');

    /// <summary>Error in the settings, or <c>null</c>. Unconfigured settings are valid (the check is simply off).</summary>
    public string? Validate()
    {
        if (TeamDomain.Length == 0 && Audiences.Count == 0) return null;
        if (!ValidTeamDomain(TeamDomain, AllowCustomTeamDomain)) return "Cloudflare:AccessJwt:TeamDomain must be a team domain such as myteam.cloudflareaccess.com (no scheme, port or path).";
        if (Audiences.Count == 0 || Audiences.Any(a => string.IsNullOrWhiteSpace(a) || a.Length > 128 || a.Any(char.IsWhiteSpace))) return "Cloudflare:AccessJwt:Audiences needs at least one application audience tag.";
        if (KeyCacheTime < TimeSpan.FromMinutes(1) || KeyCacheTime > TimeSpan.FromDays(1)) return "Cloudflare:AccessJwt:KeyCacheTime: 1 minute to 1 day.";
        if (MinRefetchInterval < TimeSpan.FromSeconds(1)) return "Cloudflare:AccessJwt:MinRefetchInterval: at least 1 second.";
        if (MaxStaleKeyAge < TimeSpan.Zero || MaxStaleKeyAge > TimeSpan.FromDays(2)) return "Cloudflare:AccessJwt:MaxStaleKeyAge: 0 to 2 days.";
        if (ClockSkew < TimeSpan.Zero || ClockSkew > TimeSpan.FromMinutes(5)) return "Cloudflare:AccessJwt:ClockSkew: 0 to 5 minutes.";
        if (MaxTokenLength is < 512 or > 65_536) return "Cloudflare:AccessJwt:MaxTokenLength: 512 to 65536.";
        if (MinKeyBits < 2048) return "Cloudflare:AccessJwt:MinKeyBits: at least 2048.";
        return null;
    }
}

/// <summary>Why a token was refused. Use it for logs and metrics; do not show it to the caller (it tells an attacker how far they got).</summary>
public enum CloudflareAccessFailure
{
    None,
    NotConfigured,
    MissingToken,
    TokenTooLong,
    Malformed,
    UnsupportedAlgorithm,
    MissingKeyId,
    UnknownKey,
    KeysUnavailable,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    MissingExpiry,
    Expired,
    NotYetValid,
}

/// <summary>Who Cloudflare Access let in.</summary>
/// <param name="Subject">Stable user id (<c>sub</c>); for a service token its client id.</param>
/// <param name="Email">E-mail of a user; <c>null</c> for service tokens.</param>
/// <param name="CommonName">Client id of a service token; <c>null</c> for users.</param>
/// <param name="IdentityNonce">Use it with <c>/cdn-cgi/access/get-identity</c> to fetch the full identity (groups, device).</param>
/// <param name="Type"><c>app</c> for users, <c>service-token</c> for machine tokens (when Cloudflare says so).</param>
public sealed record CloudflareAccessIdentity(string Subject, string? Email, string? CommonName, string? IdentityNonce, string? Type, string? Country,
    IReadOnlyList<string> Audiences, DateTimeOffset? IssuedAt, DateTimeOffset ExpiresAt, IReadOnlyList<string> Groups);

/// <summary>Result of checking a token.</summary>
public sealed record CloudflareAccessResult(bool Ok, CloudflareAccessFailure Failure, string? Message, CloudflareAccessIdentity? Identity)
{
    public static CloudflareAccessResult Fail(CloudflareAccessFailure failure, string message) => new(false, failure, message, null);

    public static CloudflareAccessResult Success(CloudflareAccessIdentity identity) => new(true, CloudflareAccessFailure.None, null, identity);
}

public interface ICloudflareAccessJwtValidator
{
    /// <summary>Checks a token with the configured team domain and audiences.</summary>
    Task<CloudflareAccessResult> ValidateAsync(string? jwt, CancellationToken cancellationToken = default);

    /// <summary>Checks a token against a given team domain and audiences (for servers that sit behind several Access applications).</summary>
    Task<CloudflareAccessResult> ValidateAsync(string? jwt, string teamDomain, IReadOnlyCollection<string> audiences, CancellationToken cancellationToken = default);

    /// <summary>Fetches the team's keys now and returns how many usable keys there are (for a settings page: "is the team domain right?").</summary>
    Task<int> ProbeAsync(string? teamDomain = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Checks the JWT that Cloudflare Access signs and adds to every request (<c>Cf-Access-Jwt-Assertion</c>), at the origin server: signature, issuer, audience and validity.
/// Do this even behind a tunnel — anyone who can reach the origin directly could send the header with any content, and an application that trusts it without checking
/// the signature is open to the world.
/// <list type="bullet">
/// <item>Only <b>RS256</b> is accepted: no <c>none</c>, no HS256 (a public key must never be usable as an HMAC secret).</item>
/// <item>The <b>team domain</b> is checked against a strict pattern before keys are fetched from it, so a request can never point the server at another host.</item>
/// <item>Keys come from <c>https://&lt;team&gt;/cdn-cgi/access/certs</c>, are cached, and are refetched for an unknown key id at most every 30 seconds.</item>
/// <item>If the fetch fails, known keys are used for a while longer (<see cref="CloudflareAccessJwtOptions.MaxStaleKeyAge"/>); otherwise the check fails closed.</item>
/// </list>
/// Thread-safe. Register it as a singleton (it holds the key cache).
/// </summary>
public sealed class CloudflareAccessJwtValidator : ICloudflareAccessJwtValidator
{
    public const int MaxKeyDocumentBytes = 64 * 1024;

    private sealed record KeySet(Dictionary<string, RSAParameters> Keys, DateTimeOffset FetchedAt);

    private readonly CloudflareAccessJwtOptions _options;
    private readonly Func<string, CancellationToken, Task<string>> _fetch;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, KeySet> _cache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _lastAttempt = new(StringComparer.Ordinal);

    /// <param name="fetch">Downloads a document (the key set). Default: a plain HTTPS client without redirects and with a size limit.</param>
    public CloudflareAccessJwtValidator(CloudflareAccessJwtOptions options, Func<string, CancellationToken, Task<string>>? fetch = null, TimeProvider? clock = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _clock = clock ?? TimeProvider.System;
        _fetch = fetch ?? DefaultFetchAsync;
    }

    public Task<CloudflareAccessResult> ValidateAsync(string? jwt, CancellationToken cancellationToken = default)
    {
        if (!_options.IsConfigured) return Task.FromResult(CloudflareAccessResult.Fail(CloudflareAccessFailure.NotConfigured, "Cloudflare Access is not configured (TeamDomain and Audiences)."));
        return ValidateAsync(jwt, _options.TeamDomain, _options.Audiences, cancellationToken);
    }

    public async Task<CloudflareAccessResult> ValidateAsync(string? jwt, string teamDomain, IReadOnlyCollection<string> audiences, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(audiences);
        var team = CloudflareAccessJwtOptions.Normalize(teamDomain);
        if (!CloudflareAccessJwtOptions.ValidTeamDomain(team, _options.AllowCustomTeamDomain))
            throw new CloudflareConfigurationException("The team domain must be a domain such as myteam.cloudflareaccess.com (no scheme, port or path).");
        if (audiences.Count == 0 || audiences.Any(string.IsNullOrWhiteSpace)) throw new CloudflareConfigurationException("At least one application audience tag is required.");

        if (string.IsNullOrWhiteSpace(jwt)) return CloudflareAccessResult.Fail(CloudflareAccessFailure.MissingToken, "The Cloudflare Access token is missing.");
        if (jwt.Length > _options.MaxTokenLength) return CloudflareAccessResult.Fail(CloudflareAccessFailure.TokenTooLong, "The token is too long.");
        var parts = jwt.Split('.');
        if (parts.Length != 3 || parts.Any(p => p.Length == 0)) return CloudflareAccessResult.Fail(CloudflareAccessFailure.Malformed, "The token is not a JWT.");

        JsonDocument header, payload;
        byte[] signature;
        try
        {
            header = JsonDocument.Parse(Base64Url(parts[0]));
            payload = JsonDocument.Parse(Base64Url(parts[1]));
            signature = Base64Url(parts[2]);
        }
        catch (Exception ex) when (ex is JsonException or FormatException) { return CloudflareAccessResult.Fail(CloudflareAccessFailure.Malformed, "The token cannot be read."); }

        using (header)
        using (payload)
        {
            if (header.RootElement.ValueKind != JsonValueKind.Object || payload.RootElement.ValueKind != JsonValueKind.Object)
                return CloudflareAccessResult.Fail(CloudflareAccessFailure.Malformed, "The token cannot be read.");
            if (Str(header.RootElement, "alg") != "RS256") return CloudflareAccessResult.Fail(CloudflareAccessFailure.UnsupportedAlgorithm, "Only RS256 is allowed.");
            var kid = Str(header.RootElement, "kid");
            if (string.IsNullOrEmpty(kid)) return CloudflareAccessResult.Fail(CloudflareAccessFailure.MissingKeyId, "The key id (kid) is missing.");

            RSAParameters? key;
            try { key = await GetKeyAsync(team, kid, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException or IOException or FormatException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
            {
                return CloudflareAccessResult.Fail(CloudflareAccessFailure.KeysUnavailable, "The signing keys of the team could not be fetched: " + ex.Message);
            }
            if (key is null) return CloudflareAccessResult.Fail(CloudflareAccessFailure.UnknownKey, "Unknown signing key.");

            using var rsa = RSA.Create();
            rsa.ImportParameters(key.Value);
            if (!rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                return CloudflareAccessResult.Fail(CloudflareAccessFailure.BadSignature, "The signature is invalid.");

            var root = payload.RootElement;
            if (Str(root, "iss") != "https://" + team) return CloudflareAccessResult.Fail(CloudflareAccessFailure.WrongIssuer, "The issuer does not match the team.");
            var tokenAudiences = Audiences(root);
            if (!tokenAudiences.Any(a => audiences.Contains(a, StringComparer.Ordinal))) return CloudflareAccessResult.Fail(CloudflareAccessFailure.WrongAudience, "The audience does not match the application.");

            var now = _clock.GetUtcNow();
            if (Time(root, "exp") is not { } exp) return CloudflareAccessResult.Fail(CloudflareAccessFailure.MissingExpiry, "The expiry (exp) is missing.");
            if (exp + _options.ClockSkew < now) return CloudflareAccessResult.Fail(CloudflareAccessFailure.Expired, "The token has expired.");
            if (Time(root, "nbf") is { } nbf && nbf - _options.ClockSkew > now) return CloudflareAccessResult.Fail(CloudflareAccessFailure.NotYetValid, "The token is not valid yet.");

            // Cloudflare sends service tokens with "sub": "" and the client id in common_name: an empty claim counts as missing
            var email = NonEmpty(Str(root, "email"));
            var common = NonEmpty(Str(root, "common_name"));
            var subject = NonEmpty(Str(root, "sub")) ?? common ?? email;
            if (string.IsNullOrEmpty(subject)) return CloudflareAccessResult.Fail(CloudflareAccessFailure.Malformed, "The token names nobody (no sub, common_name or email).");
            return CloudflareAccessResult.Success(new CloudflareAccessIdentity(subject, email, common, Str(root, "identity_nonce"), Str(root, "type"), Str(root, "country"),
                tokenAudiences, Time(root, "iat"), exp, StringList(root, "groups")));
        }
    }

    public async Task<int> ProbeAsync(string? teamDomain = null, CancellationToken cancellationToken = default)
    {
        var team = CloudflareAccessJwtOptions.Normalize(string.IsNullOrWhiteSpace(teamDomain) ? _options.TeamDomain : teamDomain);
        if (!CloudflareAccessJwtOptions.ValidTeamDomain(team, _options.AllowCustomTeamDomain))
            throw new CloudflareConfigurationException("The team domain must be a domain such as myteam.cloudflareaccess.com (no scheme, port or path).");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return (await RefreshAsync(team, cancellationToken).ConfigureAwait(false)).Keys.Count; }
        finally { _gate.Release(); }
    }

    private async Task<RSAParameters?> GetKeyAsync(string team, string kid, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _clock.GetUtcNow();
            _cache.TryGetValue(team, out var entry);
            if (entry is not null && now - entry.FetchedAt < _options.KeyCacheTime && entry.Keys.TryGetValue(kid, out var cached)) return cached;

            // Unknown key id (or expired keys): fetch again — but never more often than the minimum interval, however many forged tokens arrive.
            var lastTry = _lastAttempt.TryGetValue(team, out var t) ? t : DateTimeOffset.MinValue;
            if (now - lastTry >= _options.MinRefetchInterval)
            {
                try { entry = await RefreshAsync(team, ct).ConfigureAwait(false); }
                catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested) && entry is not null && _options.MaxStaleKeyAge > TimeSpan.Zero && now - entry.FetchedAt < _options.MaxStaleKeyAge)
                {
                    // The fetch failed but the keys we know are still young enough: use them.
                }
            }
            return entry is not null && entry.Keys.TryGetValue(kid, out var key) && (now - entry.FetchedAt < _options.KeyCacheTime || (_options.MaxStaleKeyAge > TimeSpan.Zero && now - entry.FetchedAt < _options.MaxStaleKeyAge))
                ? key : null;
        }
        finally { _gate.Release(); }
    }

    private async Task<KeySet> RefreshAsync(string team, CancellationToken ct)
    {
        _lastAttempt[team] = _clock.GetUtcNow();
        var json = await _fetch($"https://{team}/cdn-cgi/access/certs", ct).ConfigureAwait(false);
        var set = new KeySet(ParseKeys(json, _options.MinKeyBits), _clock.GetUtcNow());
        _cache[team] = set;
        return set;
    }

    /// <summary>The RSA signing keys of a key document (<c>{"keys":[…]}</c>), by key id. Keys of other types or with a short modulus are skipped.</summary>
    public static Dictionary<string, RSAParameters> ParseKeys(string json, int minKeyBits = 2048)
    {
        var result = new Dictionary<string, RSAParameters>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array) return result;
        foreach (var k in keys.EnumerateArray())
        {
            if (k.ValueKind != JsonValueKind.Object || Str(k, "kty") != "RSA" || Str(k, "kid") is not { Length: > 0 } kid || Str(k, "n") is not { } n || Str(k, "e") is not { } e) continue;
            if (Str(k, "use") is { } use && use != "sig") continue;
            try
            {
                var modulus = Base64Url(n);
                var bits = (modulus.Length - (modulus.Length > 0 && modulus[0] == 0 ? 1 : 0)) * 8;
                if (bits < minKeyBits) continue;
                result[kid] = new RSAParameters { Modulus = modulus, Exponent = Base64Url(e) };
            }
            catch (FormatException) { /* a broken entry is skipped */ }
        }
        return result;
    }

    internal static byte[] Base64Url(string s)
    {
        if (s.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) throw new FormatException("not base64url");
        var t = s.Replace('-', '+').Replace('_', '/');
        t = t.PadRight(t.Length + (4 - t.Length % 4) % 4, '=');
        return Convert.FromBase64String(t);
    }

    private static List<string> Audiences(JsonElement root)
    {
        if (!root.TryGetProperty("aud", out var aud)) return [];
        return aud.ValueKind switch
        {
            JsonValueKind.String => [aud.GetString()!],
            JsonValueKind.Array => [.. aud.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!)],
            _ => [],
        };
    }

    private static List<string> StringList(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? [.. v.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!).Take(200)] : [];

    private static DateTimeOffset? Time(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var s) && s is > 0 and < 253_402_300_799
            ? DateTimeOffset.FromUnixTimeSeconds(s) : null;

    private static string? NonEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static async Task<string> DefaultFetchAsync(string url, CancellationToken ct)
    {
        using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(5) }) { Timeout = TimeSpan.FromSeconds(8) };
        return await ReadLimitedAsync(http, url, ct).ConfigureAwait(false);
    }

    /// <summary>GET with a size limit; only HTTPS, no redirect followed.</summary>
    internal static async Task<string> ReadLimitedAsync(HttpClient http, string url, CancellationToken ct)
    {
        if (!url.StartsWith("https://", StringComparison.Ordinal)) throw new InvalidOperationException("Only https addresses are fetched.");
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException($"The key document answered HTTP {(int)response.StatusCode}.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[MaxKeyDocumentBytes + 1];
        var read = 0;
        int n;
        while (read < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(read), ct).ConfigureAwait(false)) > 0) read += n;
        if (read > MaxKeyDocumentBytes) throw new InvalidOperationException("The key document is too large.");
        return Encoding.UTF8.GetString(buffer, 0, read);
    }
}
