using System.Text.Json;
using System.Text.Json.Serialization;
using InfinitySuite360.Cloudflare.Http;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class TurnstileWidget : CloudflareModel
{
    public string Sitekey { get; init; } = "";
    /// <summary>Only returned on create and secret rotation.</summary>
    public string? Secret { get; init; }
    public string Name { get; init; } = "";
    public List<string> Domains { get; init; } = [];
    /// <summary>"managed", "non-interactive" or "invisible".</summary>
    public string Mode { get; init; } = "";
    public bool BotFightMode { get; init; }
    public string? Region { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

public sealed class TurnstileWidgetInput
{
    public required string Name { get; init; }
    public required List<string> Domains { get; init; }
    public string Mode { get; init; } = "managed";
    public bool? BotFightMode { get; init; }
    public string? Region { get; init; }
}

/// <summary>Turnstile widget management.</summary>
public sealed class TurnstileWidgetsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<TurnstileWidget>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<TurnstileWidget>(AccountPath(accountId, "challenges", "widgets"), 50, ct);

    public Task<TurnstileWidget> GetAsync(string sitekey, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TurnstileWidget>(AccountPath(accountId, "challenges", "widgets", sitekey), ct);

    public Task<TurnstileWidget> CreateAsync(TurnstileWidgetInput widget, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<TurnstileWidget>(AccountPath(accountId, "challenges", "widgets"), widget, ct);

    public Task<TurnstileWidget> UpdateAsync(string sitekey, TurnstileWidgetInput widget, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<TurnstileWidget>(AccountPath(accountId, "challenges", "widgets", sitekey), widget, ct);

    public Task DeleteAsync(string sitekey, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "challenges", "widgets", sitekey), ct);

    /// <summary>Creates a new secret. With <paramref name="invalidateImmediately"/> = false the old one stays valid for two hours.</summary>
    public Task<TurnstileWidget> RotateSecretAsync(string sitekey, bool invalidateImmediately = false, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<TurnstileWidget>(AccountPath(accountId, "challenges", "widgets", sitekey, "rotate_secret"), new { invalidate_immediately = invalidateImmediately }, ct);
}

/// <summary>siteverify response.</summary>
public sealed class TurnstileVerifyResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("challenge_ts")] public DateTimeOffset? ChallengeTimestamp { get; init; }
    [JsonPropertyName("hostname")] public string? Hostname { get; init; }
    [JsonPropertyName("error-codes")] public List<string> ErrorCodes { get; init; } = [];
    [JsonPropertyName("action")] public string? Action { get; init; }
    [JsonPropertyName("cdata")] public string? CData { get; init; }

    /// <summary>Local rejection reason (for example hostname mismatch) in addition to Cloudflare's error codes.</summary>
    [JsonIgnore] public string? RejectReason { get; init; }

    /// <summary>True only when Cloudflare confirmed the token and all local checks passed.</summary>
    [JsonIgnore] public bool Accepted => Success && RejectReason is null;

    internal static TurnstileVerifyResult Rejected(string reason) => new() { Success = false, RejectReason = reason };
}

public interface ITurnstileVerifier
{
    /// <summary>Validates a Turnstile token server-side. Fails closed: never accepted when the service is unavailable.</summary>
    Task<TurnstileVerifyResult> VerifyAsync(string? token, string? remoteIp = null, CancellationToken ct = default);
}

/// <summary>Server-side Turnstile validation (siteverify) with optional hostname and action checks.</summary>
public sealed class TurnstileVerifier : ITurnstileVerifier
{
    public const int MaxTokenLength = 2048;
    private readonly HttpClient _http;
    private readonly TurnstileOptions _options;

    public TurnstileVerifier(HttpClient http, IOptions<CloudflareOptions> options) : this(http, options.Value.Turnstile) { }

    public TurnstileVerifier(HttpClient http, TurnstileOptions options)
    {
        _http = http;
        _options = options;
    }

    public async Task<TurnstileVerifyResult> VerifyAsync(string? token, string? remoteIp = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_options.SecretKey)) return TurnstileVerifyResult.Rejected("not-configured");
        if (string.IsNullOrWhiteSpace(token)) return TurnstileVerifyResult.Rejected("missing-input-response");
        if (token.Length > MaxTokenLength) return TurnstileVerifyResult.Rejected("invalid-input-response");

        var form = new List<KeyValuePair<string, string>> { new("secret", _options.SecretKey), new("response", token) };
        if (!string.IsNullOrEmpty(remoteIp)) form.Add(new("remoteip", remoteIp));

        TurnstileVerifyResult? result;
        try
        {
            using var content = new FormUrlEncodedContent(form);
            using var response = await _http.PostAsync(_options.VerifyUrl, content, ct).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            result = JsonSerializer.Deserialize<TurnstileVerifyResult>(text);
        }
        catch (Exception ex) when ((ex is HttpRequestException or JsonException or TaskCanceledException) && !ct.IsCancellationRequested)
        {
            return TurnstileVerifyResult.Rejected("verify-unavailable");
        }

        if (result is null) return TurnstileVerifyResult.Rejected("verify-unavailable");
        if (!result.Success) return result;

        if (_options.ExpectedHostname is { Length: > 0 } host && result.Hostname is { } h && !string.Equals(h, host, StringComparison.OrdinalIgnoreCase))
            return CopyWith(result, "hostname-mismatch");
        if (_options.ExpectedAction is { Length: > 0 } action && !string.Equals(result.Action, action, StringComparison.Ordinal))
            return CopyWith(result, "action-mismatch");
        return result;
    }

    private static TurnstileVerifyResult CopyWith(TurnstileVerifyResult r, string reason) => new()
    {
        Success = r.Success, ChallengeTimestamp = r.ChallengeTimestamp, Hostname = r.Hostname, ErrorCodes = r.ErrorCodes,
        Action = r.Action, CData = r.CData, RejectReason = reason,
    };
}
