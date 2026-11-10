using InfinitySuite360.Cloudflare;
using InfinitySuite360.Cloudflare.AccessJwt;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// Deliberately in the IServiceCollection namespace so the extension is found without an extra using.
namespace Microsoft.Extensions.DependencyInjection;

public static class CloudflareServiceCollectionExtensions
{
    public const string ApiHttpClientName = "InfinitySuite360.Cloudflare.Api";
    /// <summary>Name of the HTTP client of the generated OpenAPI client (registered by <c>AddCloudflareInfinitySuite360</c> in the package InfinitySuite360.Cloudflare).</summary>
    public const string OpenApiHttpClientName = "InfinitySuite360.Cloudflare.OpenApi";
    public const string TurnstileHttpClientName = "InfinitySuite360.Cloudflare.Turnstile";
    public const string AccessKeysHttpClientName = "InfinitySuite360.Cloudflare.AccessKeys";

    /// <summary>
    /// Registers the core without the generated OpenAPI client: <see cref="ICloudflareClient"/>, <see cref="ICloudflareApiConnection"/>,
    /// <see cref="ICloudflareAccessJwtValidator"/> and <see cref="ITurnstileVerifier"/>. Settings are read from the <c>Cloudflare</c> section
    /// (or <paramref name="section"/>). With the package InfinitySuite360.Cloudflare use <c>AddCloudflareInfinitySuite360</c>, which also registers the generated client.
    /// </summary>
    public static IServiceCollection AddCloudflareInfinitySuite360Core(this IServiceCollection services, IConfiguration configuration, string section = CloudflareOptions.SectionName, Action<CloudflareOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddOptions<CloudflareOptions>().Bind(configuration.GetSection(section));
        if (configure is not null) services.Configure(configure);
        return services.AddCloudflareCoreServices();
    }

    /// <summary>Registration of the core with settings from code.</summary>
    public static IServiceCollection AddCloudflareInfinitySuite360Core(this IServiceCollection services, Action<CloudflareOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        services.AddOptions<CloudflareOptions>().Configure(configure);
        return services.AddCloudflareCoreServices();
    }

    private static IServiceCollection AddCloudflareCoreServices(this IServiceCollection services)
    {
        services.AddOptions<CloudflareOptions>()
            .Validate(o => (Uri.TryCreate(o.BaseAddress, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps) || o.BaseAddress.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase),
                "Cloudflare:BaseAddress must be an HTTPS address.")
            .Validate(o => o.MaxRetries is >= 0 and <= 10, "Cloudflare:MaxRetries must be between 0 and 10.")
            .Validate(o => o.AccessJwt.Validate() is null, "Cloudflare:AccessJwt is invalid (team domain such as myteam.cloudflareaccess.com, application audience tags).");

        services.AddHttpClient(ApiHttpClientName, (sp, http) => http.Timeout = sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.Timeout);
        services.AddHttpClient(TurnstileHttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10));
        // The signing keys come from the team domain: no redirects, so that a key document can never send the server somewhere else.
        services.AddHttpClient(AccessKeysHttpClientName, http => http.Timeout = TimeSpan.FromSeconds(8))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(5) });

        services.TryAddTransient<ICloudflareApiConnection>(sp => new CloudflareApiConnection(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(ApiHttpClientName),
            sp.GetRequiredService<IOptions<CloudflareOptions>>()));
        services.TryAddTransient<ICloudflareClient>(sp => new CloudflareClient(sp.GetRequiredService<ICloudflareApiConnection>()));
        // One instance: it holds the cache of signing keys.
        services.TryAddSingleton<ICloudflareAccessJwtValidator>(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new CloudflareAccessJwtValidator(sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.AccessJwt,
                (url, ct) => CloudflareAccessJwtValidator.ReadLimitedAsync(factory.CreateClient(AccessKeysHttpClientName), url, ct), sp.GetService<TimeProvider>());
        });
        services.TryAddTransient<ITurnstileVerifier>(sp => new TurnstileVerifier(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(TurnstileHttpClientName),
            sp.GetRequiredService<IOptions<CloudflareOptions>>()));
        return services;
    }
}
