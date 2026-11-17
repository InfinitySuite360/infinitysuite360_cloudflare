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
            budget.ReportThrottled(response.Headers.RetryAfter?.Delta, kind);
        return response;
    }
}
