using System.Net;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;
using Microsoft.Kiota.Bundle;
using Microsoft.Kiota.Http.HttpClientLibrary;
using Microsoft.Kiota.Http.HttpClientLibrary.Middleware.Options;

namespace InfinitySuite360.Cloudflare;

/// <summary>
/// Creates the complete, generated Cloudflare API client (<see cref="CloudflareApiClient"/>), which covers every operation of
/// Cloudflare's official OpenAPI schema. It shares <see cref="CloudflareOptions"/> with the curated client: same token,
/// same base address, same write guard and the same retry rules.
/// </summary>
public static class CloudflareOpenApi
{
    /// <summary>Creates a client. Without <paramref name="httpClient"/> a client with the full handler chain is built.</summary>
    public static CloudflareApiClient CreateClient(CloudflareOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var http = httpClient ?? new HttpClient(CreateHandler(options)) { Timeout = options.Timeout };
        var auth = new BaseBearerTokenAuthenticationProvider(new OptionsTokenProvider(options));
        var adapter = new DefaultRequestAdapter(auth, httpClient: http) { BaseUrl = options.BaseAddress.TrimEnd('/') };
        return new CloudflareApiClient(adapter);
    }

    /// <summary>
    /// Handler chain for the generated client: write guard first, then Kiota's default handlers (retry, redirect, …).
    /// Retries only happen for HTTP 429 or idempotent methods.
    /// </summary>
    public static HttpMessageHandler CreateHandler(CloudflareOptions options, HttpMessageHandler? innerHandler = null)
    {
        var retry = new RetryHandlerOption
        {
            MaxRetry = Math.Clamp(options.MaxRetries, 0, 10),
            ShouldRetry = (_, _, response) =>
                response.StatusCode == HttpStatusCode.TooManyRequests
                || (response.RequestMessage is { } request && CloudflareWritePolicy.IsIdempotent(request.Method)),
        };
        var handlers = KiotaClientFactory.CreateDefaultHandlers([retry]);
        handlers.Insert(0, new CloudflareWriteGuardHandler(options));
        return KiotaClientFactory.ChainHandlersCollectionAndGetFirstLink(innerHandler ?? KiotaClientFactory.GetDefaultHttpMessageHandler(), [.. handlers])
            ?? throw new InvalidOperationException("Could not build the handler chain.");
    }

    private sealed class OptionsTokenProvider(CloudflareOptions options) : IAccessTokenProvider
    {
        public AllowedHostsValidator AllowedHostsValidator { get; } = new([new Uri(options.BaseAddress).Host]);

        public Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(options.ApiToken))
                throw new CloudflareConfigurationException("Cloudflare: no API token configured (CloudflareOptions.ApiToken).");
            return Task.FromResult(options.ApiToken);
        }
    }
}
