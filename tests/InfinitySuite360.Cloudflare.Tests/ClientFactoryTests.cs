using System.Security.Claims;
using InfinitySuite360.Cloudflare.AspNetCore;
using InfinitySuite360.Cloudflare.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>P6 (0.9.0): one client per tenant, shared pool, no reuse across tokens, token never in texts. Fake handler only, synthetic tokens.</summary>
public class ClientFactoryTests
{
    private static CloudflareOptions Tenant(string token, string zone) => new() { ApiToken = token, ZoneId = zone, RetryBaseDelay = TimeSpan.Zero };

    [Fact]
    public async Task Each_tenant_sends_its_own_token_over_the_shared_handler()
    {
        var h = new FakeHandler();
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions>
        {
            ["shop-a"] = Tenant("SYNTHETIC-TOKEN-A", "zone-a"),
            ["shop-b"] = Tenant("SYNTHETIC-TOKEN-B", "zone-b"),
        }, h);
        await factory.GetClient("shop-a").Api.GetRawAsync("zones/zone-a");
        await factory.GetClient("shop-b").Api.GetRawAsync("zones/zone-b");
        await factory.GetClient("shop-a").Api.GetRawAsync("zones/zone-a");
        Assert.Equal(["Bearer SYNTHETIC-TOKEN-A", "Bearer SYNTHETIC-TOKEN-B", "Bearer SYNTHETIC-TOKEN-A"], h.Requests.Select(r => r.Auth));
        Assert.Same(factory.GetClient("shop-a"), factory.GetClient("shop-a"));
        Assert.NotSame(factory.GetClient("shop-a"), factory.GetClient("shop-b"));
        Assert.Equal("zone-b", factory.GetClient("shop-b").Api.Options.ZoneId);
        Assert.Equal(["shop-a", "shop-b"], factory.Tenants.Order());
    }

    [Fact]
    public async Task A_changed_token_never_reuses_the_client_of_the_old_token()
    {
        var h = new FakeHandler();
        var source = Tenant("SYNTHETIC-TOKEN-OLD", "zone-a");
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["shop-a"] = source }, h);
        var first = factory.GetClient("shop-a");
        source.ApiToken = "SYNTHETIC-TOKEN-NEW";
        // The running client keeps its copy of the options …
        Assert.Equal("SYNTHETIC-TOKEN-OLD", first.Api.Options.ApiToken);
        // … and the factory hands out a new client for the new token.
        var second = factory.GetClient("shop-a");
        Assert.NotSame(first, second);
        await second.Api.GetRawAsync("zones");
        Assert.Equal("Bearer SYNTHETIC-TOKEN-NEW", Assert.Single(h.Requests).Auth);
        source.AllowWrites = true;
        Assert.NotSame(second, factory.GetClient("shop-a"));
    }

    [Fact]
    public void Ad_hoc_clients_are_never_cached_and_the_options_are_copied()
    {
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions>(), new FakeHandler());
        var o = Tenant("SYNTHETIC-TOKEN-X", "z");
        var a = factory.CreateClient(o);
        var b = factory.CreateClient(o);
        Assert.NotSame(a, b);
        Assert.NotSame(o, a.Api.Options);
        Assert.Throws<CloudflareConfigurationException>(() => factory.CreateClient(new CloudflareOptions()));
        Assert.Throws<CloudflareConfigurationException>(() => factory.CreateClient(new CloudflareOptions { ApiToken = "t", BaseAddress = "http://api.example.com/" }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("-x")]
    [InlineData("shop a")]
    public void Invalid_tenant_names_are_refused(string name)
    {
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions>(), new FakeHandler());
        Assert.Throws<ArgumentException>(() => factory.GetClient(name));
    }

    [Fact]
    public void Unknown_tenants_and_tenants_without_token_are_refused()
    {
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["empty"] = new() }, new FakeHandler());
        Assert.Throws<CloudflareConfigurationException>(() => factory.GetClient("unknown"));
        var ex = Assert.Throws<CloudflareConfigurationException>(() => factory.GetClient("empty"));
        Assert.Contains("empty", ex.Message);
    }

    [Fact]
    public void Texts_never_contain_the_token()
    {
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["shop-a"] = Tenant("SYNTHETIC-TOKEN-A", "zone-a") }, new FakeHandler());
        var client = factory.GetClient("shop-a");
        var text = string.Join("|", factory, client.Api, client.Api.Options, factory.Budgets, string.Join(",", factory.Budgets.Snapshots()));
        Assert.DoesNotContain("SYNTHETIC-TOKEN-A", text);
        Assert.Contains("[redacted]", client.Api.Options.ToString());
        Assert.Contains("shop-a", text); // the budget carries the tenant name
    }

    [Fact]
    public void Tenants_sharing_a_token_share_one_budget()
    {
        using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions>
        {
            ["a"] = Tenant("SYNTHETIC-SHARED", "z1"),
            ["b"] = Tenant("SYNTHETIC-SHARED", "z2"),
            ["c"] = Tenant("SYNTHETIC-OTHER", "z3"),
        }, new FakeHandler());
        var a = (CloudflareApiConnection)factory.GetClient("a").Api;
        var b = (CloudflareApiConnection)factory.GetClient("b").Api;
        var c = (CloudflareApiConnection)factory.GetClient("c").Api;
        Assert.Same(a.RateBudget, b.RateBudget);
        Assert.NotSame(a.RateBudget, c.RateBudget);
    }

    [Fact]
    public void After_Dispose_no_client_is_handed_out()
    {
        var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["a"] = Tenant("SYNTHETIC", "z") });
        factory.GetClient("a");
        factory.Dispose();
        factory.Dispose();
        Assert.Throws<ObjectDisposedException>(() => factory.GetClient("a"));
    }

    [Fact]
    public void Dependency_injection_registers_tenants_as_named_options_with_validation()
    {
        using var sp = new ServiceCollection()
            .AddCloudflareTenant("shop-a", o => { o.ApiToken = "SYNTHETIC-A"; o.ZoneId = "za"; })
            .AddCloudflareTenant("shop-b", o => o.ZoneId = "zb") // no token
            .BuildServiceProvider();
        var factory = sp.GetRequiredService<ICloudflareClientFactory>();
        Assert.Equal("za", factory.GetClient("shop-a").Api.Options.ZoneId);
        Assert.Throws<OptionsValidationException>(() => factory.GetClient("shop-b"));
        Assert.Throws<CloudflareConfigurationException>(() => factory.GetClient("shop-c"));
        Assert.Same(factory, sp.GetRequiredService<ICloudflareClientFactory>());
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddCloudflareTenant("a b", o => o.ApiToken = "x"));
    }

    [Fact]
    public void The_default_client_from_dependency_injection_counts_against_the_budget()
    {
        using var sp = new ServiceCollection().AddCloudflareInfinitySuite360Core(o => o.ApiToken = "SYNTHETIC").BuildServiceProvider();
        var connection = (CloudflareApiConnection)sp.GetRequiredService<ICloudflareApiConnection>();
        Assert.NotNull(connection.RateBudget);
        Assert.Same(connection.RateBudget, ((CloudflareApiConnection)sp.GetRequiredService<ICloudflareApiConnection>()).RateBudget);
    }

    [Fact]
    public void AspNetCore_registration_binds_the_tenant_section_and_validates_on_start()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Cloudflare:Tenants:shop-a:ApiToken"] = "SYNTHETIC-A",
            ["Cloudflare:Tenants:shop-a:ZoneId"] = "za",
            ["Cloudflare:Tenants:shop-b:ZoneId"] = "zb",
        }).Build();
        using var sp = new ServiceCollection().AddCloudflareTenants(config.GetSection("Cloudflare:Tenants")).BuildServiceProvider();
        // ValidateOnStart: the host runs this validator at start; a tenant without token stops the start.
        var ex = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IStartupValidator>().Validate());
        Assert.Contains("shop-b", ex.Message);
        Assert.DoesNotContain("SYNTHETIC-A", ex.Message);
        Assert.Equal("za", sp.GetRequiredService<ICloudflareClientFactory>().GetClient("shop-a").Api.Options.ZoneId);
    }

    [Fact]
    public void The_tenant_of_a_request_comes_from_the_configured_resolver_only()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["T:shop-a:ApiToken"] = "SYNTHETIC-A",
        }).Build();
        using var sp = new ServiceCollection()
            .AddCloudflareTenants(config.GetSection("T"), ctx => ctx.User.FindFirst("tenant")?.Value)
            .BuildServiceProvider();
        var ctx = new DefaultHttpContext { RequestServices = sp, User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant", "shop-a")], "test")) };
        Assert.Equal("SYNTHETIC-A", ctx.GetCloudflareClient().Api.Options.ApiToken);
        var anonymous = new DefaultHttpContext { RequestServices = sp };
        Assert.Throws<CloudflareConfigurationException>(() => anonymous.GetCloudflareClient());

        using var noResolver = new ServiceCollection().AddCloudflareTenants(config.GetSection("T")).BuildServiceProvider();
        Assert.Throws<CloudflareConfigurationException>(() => new DefaultHttpContext { RequestServices = noResolver }.GetCloudflareClient());
    }
}
