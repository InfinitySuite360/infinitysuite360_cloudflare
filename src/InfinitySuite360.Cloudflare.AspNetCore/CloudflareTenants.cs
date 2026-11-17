using InfinitySuite360.Cloudflare;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.AspNetCore;

/// <summary>How a request is mapped to its Cloudflare tenant (0.9.0).</summary>
public sealed class CloudflareTenantResolutionOptions
{
    /// <summary>
    /// Returns the tenant of a request, or null when the request has none. Derive it from something the server trusts (an authenticated claim, the
    /// host name the server serves), never from a header or query value the caller can choose: otherwise a caller could act with another tenant's token.
    /// Default: no resolver (<see cref="CloudflareTenantHttpContextExtensions.GetCloudflareClient"/> throws).
    /// </summary>
    public Func<HttpContext, string?>? Resolve { get; set; }
}

/// <summary>Registration of several Cloudflare tenants in an ASP.NET Core application (0.9.0).</summary>
public static class CloudflareTenantServiceCollectionExtensions
{
    /// <summary>
    /// Registers every child of <paramref name="tenants"/> (for example the section <c>Cloudflare:Tenants</c> with children <c>shop-a</c>, <c>shop-b</c>)
    /// as a tenant with its own <see cref="CloudflareOptions"/>, plus <see cref="ICloudflareClientFactory"/>. The settings of every tenant are checked when the
    /// host starts (<c>ValidateOnStart</c>): a missing token or an http base address stops the start instead of failing on the first request.
    /// Keep the tokens in a secret store (user secrets, environment, key vault), not in <c>appsettings.json</c>.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <param name="tenants">The section whose children are the tenants.</param>
    /// <param name="resolve">Optional: maps a request to its tenant (see <see cref="CloudflareTenantResolutionOptions.Resolve"/>).</param>
    public static IServiceCollection AddCloudflareTenants(this IServiceCollection services, IConfiguration tenants, Func<HttpContext, string?>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(tenants);
        foreach (var child in tenants.GetChildren())
        {
            services.AddCloudflareTenant(child.Key, child);
            services.AddOptions<CloudflareOptions>(child.Key).ValidateOnStart();
        }
        services.AddCloudflareClientFactory();
        services.AddHttpContextAccessor();
        if (resolve is not null) services.Configure<CloudflareTenantResolutionOptions>(o => o.Resolve = resolve);
        else services.AddOptions<CloudflareTenantResolutionOptions>();
        return services;
    }
}

/// <summary>The client of the current request's tenant (0.9.0).</summary>
public static class CloudflareTenantHttpContextExtensions
{
    /// <summary>
    /// The client of the tenant that <see cref="CloudflareTenantResolutionOptions.Resolve"/> returns for <paramref name="context"/>.
    /// </summary>
    /// <exception cref="CloudflareConfigurationException">No resolver is configured, the request has no tenant, or the tenant is unknown.</exception>
    public static ICloudflareClient GetCloudflareClient(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var resolve = context.RequestServices.GetRequiredService<IOptions<CloudflareTenantResolutionOptions>>().Value.Resolve
            ?? throw new CloudflareConfigurationException("Cloudflare: no tenant resolver configured (AddCloudflareTenants(..., resolve)).");
        var tenant = resolve(context);
        if (string.IsNullOrWhiteSpace(tenant)) throw new CloudflareConfigurationException("Cloudflare: the request has no tenant.");
        return context.RequestServices.GetRequiredService<ICloudflareClientFactory>().GetClient(tenant);
    }
}
