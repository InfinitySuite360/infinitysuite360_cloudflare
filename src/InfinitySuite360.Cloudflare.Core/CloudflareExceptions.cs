using System.Net;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare;

/// <summary>The API reported an error. The message never contains the API token.</summary>
public class CloudflareApiException : Exception
{
    public CloudflareApiException(HttpStatusCode statusCode, string method, string path, IReadOnlyList<CloudflareError> errors, Exception? inner = null)
        : base(BuildMessage(statusCode, method, path, errors), inner)
    {
        StatusCode = statusCode;
        Method = method;
        Path = path;
        Errors = errors;
    }

    public HttpStatusCode StatusCode { get; }
    public string Method { get; }
    public string Path { get; }
    public IReadOnlyList<CloudflareError> Errors { get; }

    /// <summary>True when one of the Cloudflare error codes matches.</summary>
    public bool HasErrorCode(int code) => Errors.Any(e => e.Code == code);

    private static string BuildMessage(HttpStatusCode status, string method, string path, IReadOnlyList<CloudflareError> errors)
    {
        var detail = errors.Count > 0 ? string.Join("; ", errors) : "no error details";
        return $"Cloudflare API error ({method} {path}, HTTP {(int)status}): {detail}";
    }

    /// <summary>
    /// Creates the most specific exception for an error response: <see cref="CloudflareNotEntitledException"/> when Cloudflare says the plan or add-on
    /// does not include the feature, <see cref="CloudflareConflictException"/> for HTTP 409 or an "already exists" error, otherwise <see cref="CloudflareApiException"/>.
    /// All of them derive from <see cref="CloudflareApiException"/>, so existing <c>catch</c> blocks keep working.
    /// </summary>
    public static CloudflareApiException Create(HttpStatusCode statusCode, string method, string path, IReadOnlyList<CloudflareError> errors, Exception? inner = null)
    {
        if (CloudflareNotEntitledException.Matches(statusCode, errors)) return new CloudflareNotEntitledException(statusCode, method, path, errors, inner);
        if (CloudflareConflictException.Matches(statusCode, errors)) return new CloudflareConflictException(statusCode, method, path, errors, inner);
        return new CloudflareApiException(statusCode, method, path, errors, inner);
    }
}

/// <summary>
/// Cloudflare refused the call because the zone's plan or add-on does not include the feature (for example API Shield JWT validation without the
/// Enterprise add-on, Page Shield content security rules without "Advanced"). This is <b>not</b> a missing token permission: an authentication or
/// permission error (code 10000, "Authentication error") stays a plain <see cref="CloudflareApiException"/>.
/// </summary>
/// <remarks>
/// Detection is based on Cloudflare's error text ("not entitled", "entitlement", "upgrade your plan", "not available on your plan", …) because the error
/// codes are not documented per product. <see cref="CloudflareApiException.Errors"/> carries the literal text; show it rather than guessing the plan.
/// </remarks>
public sealed class CloudflareNotEntitledException(HttpStatusCode statusCode, string method, string path, IReadOnlyList<CloudflareError> errors, Exception? inner = null)
    : CloudflareApiException(statusCode, method, path, errors, inner)
{
    private static readonly string[] Markers =
    [
        "not entitled", "entitlement", "upgrade your plan", "not available on your plan", "not available for your plan", "not available on this plan",
        "not available for this plan", "not included in your plan", "plan does not", "requires an enterprise", "requires enterprise", "requires a paid",
        "not enabled for this zone", "not enabled for your account",
    ];

    internal static bool Matches(HttpStatusCode status, IReadOnlyList<CloudflareError> errors) =>
        (int)status is 400 or 402 or 403 or 422
        && errors.Any(e => !string.IsNullOrEmpty(e.Message) && Markers.Any(m => e.Message.Contains(m, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>
/// The change conflicts with the current state (HTTP 409, or an "already exists"/"duplicate" error), for example a label or schema name that is taken.
/// Retrying the same request does not help; read the current state and decide (the <c>Ensure…</c> methods do this for you).
/// </summary>
public sealed class CloudflareConflictException(HttpStatusCode statusCode, string method, string path, IReadOnlyList<CloudflareError> errors, Exception? inner = null)
    : CloudflareApiException(statusCode, method, path, errors, inner)
{
    internal static bool Matches(HttpStatusCode status, IReadOnlyList<CloudflareError> errors) =>
        status == HttpStatusCode.Conflict
        || ((int)status is 400 or 422 && errors.Any(e => e.Message?.Contains("already exist", StringComparison.OrdinalIgnoreCase) == true
                                                          || e.Message?.Contains("duplicate", StringComparison.OrdinalIgnoreCase) == true));
}

/// <summary>A write call was rejected locally (writes disabled or not on the allow-list). Nothing was sent.</summary>
public sealed class CloudflareWriteNotAllowedException(string method, string path, string reason)
    : InvalidOperationException($"Cloudflare write call rejected ({method} {path}): {reason}")
{
    public string Method { get; } = method;
    public string Path { get; } = path;
}

/// <summary>Required setting missing (for example a zone or account ID without default).</summary>
public sealed class CloudflareConfigurationException(string message) : InvalidOperationException(message);
