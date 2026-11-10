using InfinitySuite360.Cloudflare.Http;

// Namespace kept from 0.2 (the handler lived next to CloudflareOpenApi before the core was split off).
namespace InfinitySuite360.Cloudflare;

/// <summary>
/// For own <see cref="HttpClient"/> pipelines (for example the generated OpenAPI client): rejects write calls locally according to <see cref="CloudflareOptions.AllowWrites"/> and <see cref="CloudflareOptions.WriteFilter"/>.
/// </summary>
public sealed class CloudflareWriteGuardHandler(CloudflareOptions options) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is { } uri)
            CloudflareWritePolicy.EnsureAllowed(request.Method, CloudflareWritePolicy.RelativePath(uri, options), options);
        return base.SendAsync(request, cancellationToken);
    }
}
