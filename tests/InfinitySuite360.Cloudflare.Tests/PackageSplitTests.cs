using System.Reflection;
using InfinitySuite360.Cloudflare.AccessJwt;
using InfinitySuite360.Cloudflare.AspNetCore;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.OpenApi;
using InfinitySuite360.Cloudflare.Resources;
using Microsoft.Extensions.DependencyInjection;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>InfinitySuite360.Cloudflare.Core must stay installable without the generated client (0.3.0).</summary>
public class PackageSplitTests
{
    private static readonly Assembly Core = typeof(ICloudflareClient).Assembly;

    [Fact]
    public void Core_is_its_own_assembly()
    {
        Assert.Equal("InfinitySuite360.Cloudflare.Core", Core.GetName().Name);
        Assert.Same(Core, typeof(CloudflareAccessJwtValidator).Assembly);
        Assert.Same(Core, typeof(DnsClient).Assembly);
        Assert.Same(Core, typeof(CloudflareApiConnection).Assembly);
        Assert.Same(Core, typeof(CloudflareWriteGuardHandler).Assembly);
    }

    [Fact]
    public void Core_references_only_the_framework_and_Microsoft_Extensions()
    {
        var foreign = Core.GetReferencedAssemblies().Select(a => a.Name!)
            .Where(n => !(n.StartsWith("System", StringComparison.Ordinal) || n.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal) || n is "netstandard" or "mscorlib"))
            .ToList();
        Assert.Empty(foreign);
    }

    [Fact]
    public void AspNetCore_package_needs_only_the_core()
    {
        var names = typeof(CloudflareAccessAuthenticationHandler).Assembly.GetReferencedAssemblies().Select(a => a.Name).ToList();
        Assert.Contains("InfinitySuite360.Cloudflare.Core", names);
        Assert.DoesNotContain("InfinitySuite360.Cloudflare", names);
        Assert.DoesNotContain("InfinitySuite360.Cloudflare.OpenApi", names);
        Assert.DoesNotContain(names, n => n!.StartsWith("Microsoft.Kiota", StringComparison.Ordinal));
    }

    [Fact]
    public void Core_registration_works_without_the_generated_client()
    {
        using var sp = new ServiceCollection()
            .AddCloudflareInfinitySuite360Core(o => { o.ApiToken = "t"; o.AccessJwt = new CloudflareAccessJwtOptions { TeamDomain = "team.cloudflareaccess.com", Audiences = ["aud"] }; })
            .BuildServiceProvider();
        Assert.NotNull(sp.GetRequiredService<ICloudflareClient>().Dns);
        Assert.NotNull(sp.GetRequiredService<ICloudflareAccessJwtValidator>());
        Assert.NotNull(sp.GetRequiredService<ITurnstileVerifier>());
        Assert.Null(sp.GetService<CloudflareApiClient>());
    }

    [Fact]
    public void OpenApi_of_a_client_without_dependency_injection_is_created_once()
    {
        var client = CloudflareClient.Create(new CloudflareOptions { ApiToken = "t" });
        Assert.Same(client.OpenApi, client.OpenApi);
        Assert.Same(client.OpenApi, client.GetOpenApi());
        Assert.NotSame(client.OpenApi, CloudflareClient.Create(new CloudflareOptions { ApiToken = "t" }).OpenApi);
    }

    [Fact]
    public void OpenApi_from_dependency_injection_is_the_registered_generated_client()
    {
        var registered = CloudflareOpenApi.CreateClient(new CloudflareOptions { ApiToken = "t" });
        using var sp = new ServiceCollection().AddSingleton(registered).AddCloudflareInfinitySuite360(o => o.ApiToken = "t").BuildServiceProvider();
        Assert.Same(registered, sp.GetRequiredService<ICloudflareClient>().OpenApi);
    }

    [Theory]
    [InlineData("InfinitySuite360.Cloudflare.CloudflareOptions")]
    [InlineData("InfinitySuite360.Cloudflare.ICloudflareClient")]
    [InlineData("InfinitySuite360.Cloudflare.AccessJwt.CloudflareAccessJwtValidator")]
    [InlineData("InfinitySuite360.Cloudflare.Http.CloudflareApiConnection")]
    [InlineData("InfinitySuite360.Cloudflare.Resources.DnsClient")]
    [InlineData("Microsoft.Extensions.DependencyInjection.CloudflareServiceCollectionExtensions")]
    public void Types_that_moved_to_the_core_are_forwarded(string type)
    {
        // Assemblies built against 0.2 (for example InfinitySuite360.Security.Edge 0.3.0) look for these types in InfinitySuite360.Cloudflare.
        var forwarded = Type.GetType($"{type}, InfinitySuite360.Cloudflare", throwOnError: true)!;
        Assert.Same(Core, forwarded.Assembly);
    }

    [Fact]
    public void Every_public_core_type_is_forwarded()
    {
        var forwarded = typeof(CloudflareOpenApi).Assembly.GetForwardedTypes().ToHashSet();
        var missing = Core.GetExportedTypes().Where(t => !t.IsNested && !forwarded.Contains(t)).Select(t => t.FullName).ToList();
        Assert.Empty(missing);
    }
}
