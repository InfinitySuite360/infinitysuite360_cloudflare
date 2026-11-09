using InfinitySuite360.Cloudflare;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;
using InfinitySuite360.Cloudflare.Resources;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// Deliberately in the IServiceCollection namespace so the extension is found without an extra using.
namespace Microsoft.Extensions.DependencyInjection;

public static class CloudflareServiceCollectionExtensions
{
    public const string ApiHttpClientName = "InfinitySuite360.Cloudflare.Api";
    public const string OpenApiHttpClientName = "InfinitySuite360.Cloudflare.OpenApi";
    public const string TurnstileHttpClientName = "InfinitySuite360.Cloudflare.Turnstile";

    /// <summary>
    /// Registers <see cref="ICloudflareClient"/>, <see cref="ICloudflareApiConnection"/>, the generated <see cref="CloudflareApiClient"/>
    /// and <see cref="ITurnstileVerifier"/>. Settings are read from the <c>Cloudflare</c> section (or <paramref name="section"/>).
    /// </summary>
    public static IServiceCollection AddCloudflareInfinitySuite360(this IServiceCollection services, IConfiguration configuration, string section = CloudflareOptions.SectionName, Action<CloudflareOptions>? configure = null)
    {
        services.AddOptions<CloudflareOptions>().Bind(configuration.GetSection(section));
        if (configure is not null) services.Configure(configure);
        return services.AddCloudflareCore();
    }

    /// <summary>Registration with settings from code.</summary>
    public static IServiceCollection AddCloudflareInfinitySuite360(this IServiceCollection services, Action<CloudflareOptions> configure)
    {
        services.AddOptions<CloudflareOptions>().Configure(configure);
        return services.AddCloudflareCore();
    }

    private static IServiceCollection AddCloudflareCore(this IServiceCollection services)
    {
        services.AddOptions<CloudflareOptions>()
            .Validate(o => (Uri.TryCreate(o.BaseAddress, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps) || o.BaseAddress.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase),
                "Cloudflare:BaseAddress must be an HTTPS address.")
            .Validate(o => o.MaxRetries is >= 0 and <= 10, "Cloudflare:MaxRetries must be between 0 and 10.");

        services.AddHttpClient(ApiHttpClientName, (sp, http) => http.Timeout = sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.Timeout);
        services.AddHttpClient(OpenApiHttpClientName, (sp, http) => http.Timeout = sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.Timeout)
            .ConfigurePrimaryHttpMessageHandler(sp => CloudflareOpenApi.CreateHandler(sp.GetRequiredService<IOptions<CloudflareOptions>>().Value));
        services.AddHttpClient(TurnstileHttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10));

        services.TryAddTransient<ICloudflareApiConnection>(sp => new CloudflareApiConnection(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(ApiHttpClientName),
            sp.GetRequiredService<IOptions<CloudflareOptions>>()));
        services.TryAddTransient(sp => CloudflareOpenApi.CreateClient(
            sp.GetRequiredService<IOptions<CloudflareOptions>>().Value,
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(OpenApiHttpClientName)));
        services.TryAddTransient<ICloudflareClient>(sp => new CloudflareClient(
            sp.GetRequiredService<ICloudflareApiConnection>(),
            () => sp.GetRequiredService<CloudflareApiClient>()));
        services.TryAddTransient<ITurnstileVerifier>(sp => new TurnstileVerifier(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(TurnstileHttpClientName),
            sp.GetRequiredService<IOptions<CloudflareOptions>>()));
        return services;
    }
}
