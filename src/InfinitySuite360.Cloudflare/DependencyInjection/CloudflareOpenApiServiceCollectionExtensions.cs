using InfinitySuite360.Cloudflare;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// Deliberately in the IServiceCollection namespace so the extension is found without an extra using.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registration of the full package: the core plus the generated OpenAPI client.</summary>
public static class CloudflareOpenApiServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ICloudflareClient"/> (with <c>OpenApi</c>), <see cref="ICloudflareApiConnection"/>, the generated <see cref="CloudflareApiClient"/>,
    /// the Access token validator and the Turnstile verifier. Settings are read from the <c>Cloudflare</c> section (or <paramref name="section"/>).
    /// Without the generated client: <c>AddCloudflareInfinitySuite360Core</c> (package InfinitySuite360.Cloudflare.Core).
    /// </summary>
    public static IServiceCollection AddCloudflareInfinitySuite360(this IServiceCollection services, IConfiguration configuration, string section = CloudflareOptions.SectionName, Action<CloudflareOptions>? configure = null) =>
        services.AddCloudflareOpenApi().AddCloudflareInfinitySuite360Core(configuration, section, configure);

    /// <summary>Registration with settings from code.</summary>
    public static IServiceCollection AddCloudflareInfinitySuite360(this IServiceCollection services, Action<CloudflareOptions> configure) =>
        services.AddCloudflareOpenApi().AddCloudflareInfinitySuite360Core(configure);

    // Before the core: its TryAdd of ICloudflareClient then keeps this registration, which ties OpenApi to the registered generated client.
    private static IServiceCollection AddCloudflareOpenApi(this IServiceCollection services)
    {
        services.AddHttpClient(CloudflareServiceCollectionExtensions.OpenApiHttpClientName, (sp, http) => http.Timeout = sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.Timeout)
            .ConfigurePrimaryHttpMessageHandler(sp => CloudflareOpenApi.CreateHandler(sp.GetRequiredService<IOptions<CloudflareOptions>>().Value));
        services.TryAddTransient(sp => CloudflareOpenApi.CreateClient(
            sp.GetRequiredService<IOptions<CloudflareOptions>>().Value,
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(CloudflareServiceCollectionExtensions.OpenApiHttpClientName)));
        services.TryAddTransient<ICloudflareClient>(sp => new CloudflareClient(sp.GetRequiredService<ICloudflareApiConnection>())
            .WithOpenApi(() => sp.GetRequiredService<CloudflareApiClient>()));
        return services;
    }
}
