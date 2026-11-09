using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace InfinitySuite360.Cloudflare.Tests;

public class ConnectionTests
{
    [Fact]
    public async Task Writes_are_blocked_by_default_and_nothing_is_sent()
    {
        var (cf, handler, _) = FakeHandler.Create();
        var ex = await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Zones.PurgeEverythingAsync());
        Assert.Equal("zones/zone1/purge_cache", ex.Path);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task WriteFilter_rejects_paths_not_on_allow_list()
    {
        var (cf, handler, _) = FakeHandler.Create(o =>
        {
            o.AllowWrites = true;
            o.WriteFilter = (m, p) => m == HttpMethod.Post && p.EndsWith("/purge_cache", StringComparison.Ordinal);
        });
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"p1"}"""));
        Assert.Equal("p1", (await cf.Zones.PurgeEverythingAsync()).Id);
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Dns.DeleteAsync("r1"));
        Assert.Single(handler.Requests);
        Assert.Equal("""{"purge_everything":true}""", handler.Requests[0].Body);
    }

    [Fact]
    public async Task Bearer_token_is_sent_and_never_appears_in_error_messages()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Json("""{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}""", HttpStatusCode.Forbidden));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Zones.GetAsync());
        Assert.Equal("Bearer secret-token-123", handler.Requests[0].Auth);
        Assert.True(ex.HasErrorCode(10000));
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.DoesNotContain("secret-token-123", ex.Message);
        Assert.Contains("Authentication error", ex.Message);
    }

    [Fact]
    public async Task Missing_token_fails_before_sending()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.ApiToken = "");
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => cf.Zones.GetAsync());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Retries_429_then_succeeds()
    {
        var (cf, handler, _) = FakeHandler.Create();
        var limited = FakeHandler.Json("""{"success":false,"errors":[{"code":971,"message":"rate limited"}]}""", HttpStatusCode.TooManyRequests);
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(1));
        handler.Responses.Enqueue(limited);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"zone1","name":"example.com","status":"active"}"""));
        var zone = await cf.Zones.GetAsync();
        Assert.Equal("example.com", zone.Name);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Post_is_not_retried_on_503()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responder = (_, _) => FakeHandler.Json("""{"success":false,"errors":[]}""", HttpStatusCode.ServiceUnavailable);
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Zones.PurgeEverythingAsync());
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ListAll_reads_every_page()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"a","name":"a.com"},{"id":"b","name":"b.com"}]""", """{"page":1,"per_page":2,"count":2,"total_count":3,"total_pages":2}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"c","name":"c.com"}]""", """{"page":2,"per_page":2,"count":1,"total_count":3,"total_pages":2}"""));
        var zones = await cf.Api.ListAllToListAsync<Zone>("zones", 2);
        Assert.Equal(["a", "b", "c"], zones.Select(z => z.Id));
        Assert.Contains("page=2", handler.Requests[1].Url);
    }

    [Fact]
    public async Task Ids_are_url_encoded_to_prevent_path_injection()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"x"}"""));
        await cf.Dns.GetAsync("../../accounts/evil");
        Assert.Equal("https://api.cloudflare.com/client/v4/zones/zone1/dns_records/..%2F..%2Faccounts%2Fevil", handler.Requests[0].Url);
    }

    [Fact]
    public async Task GraphQl_is_allowed_in_read_only_mode_and_reports_errors()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Json("""{"data":null,"errors":[{"message":"zone not authorized"}]}"""));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Analytics.GetTrafficSummaryAsync());
        Assert.Contains("zone not authorized", ex.Message);
        Assert.EndsWith("/graphql", handler.Requests[0].Url);
    }

    [Fact]
    public async Task Unknown_fields_are_preserved()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"zone1","name":"example.com","status":"active","brand_new_field":42,"plan":{"id":"p","name":"Free Website"}}"""));
        var zone = await cf.Zones.GetAsync();
        Assert.Equal(42, zone.AdditionalData!["brand_new_field"].GetInt32());
        Assert.Equal("Free Website", zone.Plan!.Name);
    }

    [Fact]
    public async Task Missing_default_zone_gives_clear_error()
    {
        var (cf, _, _) = FakeHandler.Create(o => o.ZoneId = null);
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => cf.Zones.GetSettingsAsync());
    }

    [Fact]
    public void Dependency_injection_resolves_everything()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Cloudflare:ApiToken"] = "t",
            ["Cloudflare:ZoneId"] = "z",
            ["Cloudflare:AllowWrites"] = "true",
            ["Cloudflare:Turnstile:SiteKey"] = "site",
        }).Build();
        using var sp = new ServiceCollection().AddCloudflareInfinitySuite360(config).BuildServiceProvider();
        var cf = sp.GetRequiredService<ICloudflareClient>();
        Assert.Equal("z", cf.Api.Options.ZoneId);
        Assert.True(cf.Api.Options.AllowWrites);
        Assert.Equal("site", cf.Api.Options.Turnstile.SiteKey);
        Assert.NotNull(sp.GetRequiredService<ITurnstileVerifier>());
    }

    [Fact]
    public void Zone_setting_value_text()
    {
        var s = JsonSerializer.Deserialize<ZoneSetting>("""{"id":"ssl","value":"strict","editable":true}""", CloudflareJson.Options)!;
        Assert.Equal("strict", s.ValueText);
    }
}
