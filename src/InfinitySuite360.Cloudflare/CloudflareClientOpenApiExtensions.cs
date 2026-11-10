using System.Runtime.CompilerServices;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;

namespace InfinitySuite360.Cloudflare;

/// <summary>
/// The generated client on <see cref="ICloudflareClient"/>. Up to 0.2 <c>OpenApi</c> was a member of the interface; since 0.3 the interface lives in
/// InfinitySuite360.Cloudflare.Core, which does not know the generated client, and this package adds it back: <c>client.OpenApi</c> (extension property,
/// C# 14) or <see cref="GetOpenApi"/> (any language version).
/// </summary>
public static class CloudflareClientOpenApiExtensions
{
    // One generated client per ICloudflareClient instance, created on first use like the former Lazy<> field; the entry dies with the client.
    private static readonly ConditionalWeakTable<ICloudflareClient, Lazy<CloudflareApiClient>> Clients = new();

    extension(ICloudflareClient client)
    {
        /// <summary>Complete generated client: all operations and models of the official Cloudflare OpenAPI schema.</summary>
        public CloudflareApiClient OpenApi => client.GetOpenApi();
    }

    /// <summary>
    /// The generated client for <paramref name="client"/>. From dependency injection (<c>AddCloudflareInfinitySuite360</c>) it uses the registered
    /// <see cref="CloudflareApiClient"/>; otherwise one is created from <see cref="ICloudflareApiConnection.Options"/> on first use.
    /// </summary>
    public static CloudflareApiClient GetOpenApi(this ICloudflareClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return Clients.GetValue(client, static c => new Lazy<CloudflareApiClient>(() => CloudflareOpenApi.CreateClient(c.Api.Options))).Value;
    }

    /// <summary>Sets where the generated client of <paramref name="client"/> comes from (called on first use of <c>OpenApi</c>).</summary>
    public static TClient WithOpenApi<TClient>(this TClient client, Func<CloudflareApiClient> factory) where TClient : ICloudflareClient
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(factory);
        Clients.AddOrUpdate(client, new Lazy<CloudflareApiClient>(factory));
        return client;
    }
}
