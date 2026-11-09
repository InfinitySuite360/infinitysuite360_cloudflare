namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Shared write guard for the curated client and the generated OpenAPI client.</summary>
public static class CloudflareWritePolicy
{
    private static readonly HashSet<string> ReadMethods = new(StringComparer.OrdinalIgnoreCase) { "GET", "HEAD", "OPTIONS" };

    /// <summary>True for methods that never change state.</summary>
    public static bool IsRead(HttpMethod method) => ReadMethods.Contains(method.Method);

    /// <summary>True when a retry cannot duplicate side effects.</summary>
    public static bool IsIdempotent(HttpMethod method) =>
        IsRead(method) || method == HttpMethod.Put || method == HttpMethod.Delete;

    /// <summary>
    /// Throws <see cref="CloudflareWriteNotAllowedException"/> when <paramref name="method"/> writes and the options do not allow it.
    /// The GraphQL Analytics endpoint is read-only despite using POST and is always allowed.
    /// </summary>
    public static void EnsureAllowed(HttpMethod method, string relativePath, CloudflareOptions options)
    {
        if (IsRead(method)) return;
        var path = CloudflarePath.Normalize(relativePath);
        if (path == "graphql") return;
        if (!options.AllowWrites)
            throw new CloudflareWriteNotAllowedException(method.Method, path, "writes are disabled (CloudflareOptions.AllowWrites = false).");
        if (options.WriteFilter is { } filter && !filter(method, path))
            throw new CloudflareWriteNotAllowedException(method.Method, path, "not on the allow-list (CloudflareOptions.WriteFilter).");
    }

    /// <summary>Path of <paramref name="uri"/> relative to the configured base address (for absolute request URIs).</summary>
    public static string RelativePath(Uri uri, CloudflareOptions options)
    {
        var basePath = new Uri(options.BaseAddress.EndsWith('/') ? options.BaseAddress : options.BaseAddress + "/").AbsolutePath;
        var path = uri.AbsolutePath;
        return path.StartsWith(basePath, StringComparison.OrdinalIgnoreCase) ? path[basePath.Length..] : path.TrimStart('/');
    }
}
