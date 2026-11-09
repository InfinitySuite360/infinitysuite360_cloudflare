using InfinitySuite360.Cloudflare.OpenApi;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace InfinitySuite360.Cloudflare.Tests;

public class OpenApiTests
{
    private static (CloudflareApiClient Client, FakeHandler Handler) Create(Action<CloudflareOptions>? configure = null)
    {
        var options = new CloudflareOptions { ApiToken = "secret-token-123", MaxRetries = 0 };
        configure?.Invoke(options);
        var handler = new FakeHandler();
        var http = new HttpClient(CloudflareOpenApi.CreateHandler(options, handler));
        return (CloudflareOpenApi.CreateClient(options, http), handler);
    }

    [Fact]
    public async Task Generated_client_calls_the_official_endpoint_with_bearer_token()
    {
        var (client, handler) = Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"zone1","name":"example.com","status":"active"}"""));
        await client.Zones["zone1"].GetAsync();
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://api.cloudflare.com/client/v4/zones/zone1", request.Url);
        Assert.Equal("Bearer secret-token-123", request.Auth);
    }

    [Fact]
    public async Task Generated_client_respects_the_write_guard()
    {
        var (client, handler) = Create();
        var ex = await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => client.Zones["zone1"].Dns_records["rec1"].DeleteAsync());
        Assert.Equal("zones/zone1/dns_records/rec1", ex.Path);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Write_filter_sees_the_relative_path()
    {
        string? seen = null;
        var (client, handler) = Create(o =>
        {
            o.AllowWrites = true;
            o.WriteFilter = (_, path) => { seen = path; return true; };
        });
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"rec1"}"""));
        await client.Zones["zone1"].Dns_records["rec1"].DeleteAsync();
        Assert.Equal("zones/zone1/dns_records/rec1", seen);
        Assert.Equal(HttpMethod.Delete, Assert.Single(handler.Requests).Method);
    }

    [Fact]
    public void Dependency_injection_exposes_the_generated_client()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Cloudflare:ApiToken"] = "t" }).Build();
        using var sp = new ServiceCollection().AddCloudflareInfinitySuite360(config).BuildServiceProvider();
        Assert.NotNull(sp.GetRequiredService<CloudflareApiClient>());
        Assert.NotNull(sp.GetRequiredService<ICloudflareClient>().OpenApi.Zones);
    }
}
