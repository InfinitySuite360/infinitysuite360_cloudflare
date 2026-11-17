namespace InfinitySuite360.Cloudflare.Http;

/// <summary>
/// For own <see cref="HttpClient"/> pipelines (for example the generated OpenAPI client, 0.9.0): takes a slot of the shared token budget before every
/// attempt and reports a 429 to it, so the curated client, the generated client and other tools on the same token draw from one budget.
/// </summary>
public sealed class CloudflareRateBudgetHandler(CloudflareRateBudget budget) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var kind = CloudflareWritePolicy.IsRead(request.Method) || request.RequestUri?.AbsolutePath.EndsWith("/graphql", StringComparison.Ordinal) == true
            ? CloudflareRequestKind.Read
            : CloudflareRequestKind.Write;
        await budget.AcquireAsync(kind, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        {
            try { budget.ReportThrottled(CloudflareRetryAfter.Of(response, budget.Time), kind); }
            catch
            {
                response.Dispose();
                throw;
            }
        }
        return response;
    }
}

/// <summary>Reads <c>Retry-After</c> as seconds or as an HTTP date (0.9.1, L-7).</summary>
internal static class CloudflareRetryAfter
{
    /// <summary>The wait the answer asks for; null without the header; never negative.</summary>
    public static TimeSpan? Of(HttpResponseMessage response, TimeProvider time)
    {
        var header = response.Headers.RetryAfter;
        if (header is null) return null;
        var wait = header.Delta ?? (header.Date is { } date ? date - time.GetUtcNow() : null);
        return wait is { } w && w < TimeSpan.Zero ? TimeSpan.Zero : wait;
    }
}
