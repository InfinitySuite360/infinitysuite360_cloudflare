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
