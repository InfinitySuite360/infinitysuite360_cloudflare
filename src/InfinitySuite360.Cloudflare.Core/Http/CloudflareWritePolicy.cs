using System.Text.RegularExpressions;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Shared write guard for the curated client and the generated OpenAPI client.</summary>
public static class CloudflareWritePolicy
{
    private static readonly HashSet<string> ReadMethods = new(StringComparer.OrdinalIgnoreCase) { "GET", "HEAD", "OPTIONS" };

    // PUT …/tokens/{id}/value rolls a token: a repeat after a lost answer would roll again and invalidate the value the first call returned.
    private static readonly Regex NeverRetried = new(@"(^|/)tokens/[^/]+/value$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

    /// <summary>True for methods that never change state.</summary>
    public static bool IsRead(HttpMethod method) => ReadMethods.Contains(method.Method);

    /// <summary>True when a retry cannot duplicate side effects (by method only; prefer <see cref="IsIdempotent(HttpMethod, string)"/>).</summary>
    public static bool IsIdempotent(HttpMethod method) =>
        IsRead(method) || method == HttpMethod.Put || method == HttpMethod.Delete;

    /// <summary>
    /// True when a retry cannot duplicate side effects. Like <see cref="IsIdempotent(HttpMethod)"/>, but PUTs that are not idempotent on Cloudflare (rolling an
    /// API token, <c>PUT …/tokens/{id}/value</c>) are never repeated (0.7.1).
    /// </summary>
    public static bool IsIdempotent(HttpMethod method, string relativePath) =>
        IsIdempotent(method) && !(method == HttpMethod.Put && NeverRetried.IsMatch(CloudflarePath.Normalize(relativePath ?? "")));

    /// <summary>
    /// Throws <see cref="CloudflareWriteNotAllowedException"/> when <paramref name="method"/> writes and the options do not allow it.
    /// The GraphQL Analytics endpoint is read-only despite using POST and is always allowed. Since 0.7.1 the path is also checked as Cloudflare would see it:
    /// dot segments are refused (<see cref="CloudflarePath.EnsureSafe"/>, <see cref="ArgumentException"/>) and the allow-list sees the resolved path.
    /// </summary>
    public static void EnsureAllowed(HttpMethod method, string relativePath, CloudflareOptions options)
    {
        if (IsRead(method)) return;
        CloudflarePath.EnsureSafe(relativePath);
        var path = CloudflarePath.Normalize(relativePath);
        var resolved = RelativePath(ResolveUri(relativePath, options), options);
        if (!string.Equals(Unescape(resolved), Unescape(path), StringComparison.Ordinal))
            throw new CloudflareWriteNotAllowedException(method.Method, path, "the path resolves to a different endpoint.");
        if (path == "graphql") return;
        if (!options.AllowWrites)
            throw new CloudflareWriteNotAllowedException(method.Method, path, "writes are disabled (CloudflareOptions.AllowWrites = false).");
        if (options.WriteFilter is { } filter && !filter(method, resolved))
            throw new CloudflareWriteNotAllowedException(method.Method, path, "not on the allow-list (CloudflareOptions.WriteFilter).");
    }

    /// <summary>The absolute request URI for a relative path, as the connection sends it.</summary>
    public static Uri ResolveUri(string relativePath, CloudflareOptions options)
    {
        var baseAddress = options.BaseAddress.EndsWith('/') ? options.BaseAddress : options.BaseAddress + "/";
        return new Uri(new Uri(baseAddress), relativePath.TrimStart('/'));
    }

    /// <summary>Path of <paramref name="uri"/> relative to the configured base address (for absolute request URIs).</summary>
    public static string RelativePath(Uri uri, CloudflareOptions options)
    {
        var basePath = new Uri(options.BaseAddress.EndsWith('/') ? options.BaseAddress : options.BaseAddress + "/").AbsolutePath;
        var path = uri.AbsolutePath;
        return path.StartsWith(basePath, StringComparison.OrdinalIgnoreCase) ? path[basePath.Length..] : path.TrimStart('/');
    }

    private static string Unescape(string s)
    {
        try { return Uri.UnescapeDataString(s); }
        catch (UriFormatException) { return s; }
    }
}
