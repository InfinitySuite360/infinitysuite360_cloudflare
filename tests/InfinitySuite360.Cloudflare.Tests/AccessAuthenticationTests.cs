using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using InfinitySuite360.Cloudflare.AccessJwt;
using InfinitySuite360.Cloudflare.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.Tests;

public class AccessAuthenticationTests : IDisposable
{
    private readonly FakeTeam _team = new();
    private readonly JwtClock _clock = new();

    public void Dispose() => _team.Dispose();

    private async Task<HttpClient> StartAsync(Action<CloudflareAccessAuthenticationOptions>? configure = null)
    {
        var validator = new CloudflareAccessJwtValidator(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud] }, _team.FetchAsync, _clock);
        var host = await new HostBuilder().ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(s =>
            {
                s.AddRouting();
                s.AddLogging();
                s.AddSingleton<ICloudflareAccessJwtValidator>(validator);
                s.AddAuthentication(CloudflareAccessAuthenticationOptions.DefaultScheme).AddCloudflareAccess(configure);
                s.AddAuthorization();
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(e =>
                {
                    e.MapGet("/open", () => "open");
                    e.MapGet("/me", (ClaimsPrincipal user) =>
                    {
                        var who = user.CloudflareAccess()!;
                        return Results.Json(new { who.Subject, who.Email, who.CommonName, who.IdentityNonce, who.Type, who.Groups, who.IsServiceToken, name = user.Identity!.Name });
                    }).RequireAuthorization();
                });
            })).StartAsync();
        return host.GetTestServer().CreateClient();
    }

    private HttpRequestMessage Get(string path, string? token, string header = CloudflareAccessJwtOptions.HeaderName)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) request.Headers.TryAddWithoutValidation(header, token);
        return request;
    }

    [Fact]
    public async Task A_valid_token_signs_the_user_in()
    {
        var client = await StartAsync();
        var response = await client.SendAsync(Get("/me", _team.Token(_clock, p => p["groups"] = new[] { "admins" })));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"subject\":\"user-1\"", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ann@example.com", body);
        Assert.Contains("admins", body);
        Assert.Contains("\"isServiceToken\":false", body);
    }

    [Fact]
    public async Task A_service_token_is_recognised()
    {
        var client = await StartAsync();
        var token = _team.Token(_clock, p => { p.Remove("sub"); p.Remove("email"); p["common_name"] = "client-id.access"; p["type"] = "service-token"; });
        var body = await (await client.SendAsync(Get("/me", token))).Content.ReadAsStringAsync();
        Assert.Contains("\"isServiceToken\":true", body);
        Assert.Contains("client-id.access", body);
    }

    [Fact]
    public async Task A_service_token_with_an_empty_sub_as_Cloudflare_sends_it_is_recognised()
    {
        var client = await StartAsync();
        var token = _team.Token(_clock, p => { p["sub"] = ""; p.Remove("email"); p["common_name"] = "client-id.access"; p["type"] = "service-token"; });
        var answer = await client.SendAsync(Get("/me", token));
        Assert.Equal(HttpStatusCode.OK, answer.StatusCode);
        var body = await answer.Content.ReadAsStringAsync();
        Assert.Contains("\"isServiceToken\":true", body);
        Assert.Contains("\"subject\":\"client-id.access\"", body);
    }

    [Fact]
    public async Task No_token_is_anonymous_and_protected_endpoints_answer_401_without_a_redirect()
    {
        var client = await StartAsync();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/open")).StatusCode);
        var denied = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Null(denied.Headers.Location);
        Assert.Equal("", await denied.Content.ReadAsStringAsync());          // no hint about what is wrong
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("a.b.c")]
    public async Task A_bad_token_is_401_even_on_an_open_endpoint_with_authorization_but_never_a_success(string token)
    {
        var client = await StartAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/me", token))).StatusCode);
    }

    [Fact]
    public async Task Tokens_that_fail_the_check_are_refused()
    {
        var client = await StartAsync();
        using var other = RSA.Create(2048);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/me", _team.Token(_clock, signWith: other)))).StatusCode);                 // forged
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/me", _team.Token(_clock, p => p["aud"] = new[] { "another-app" })))).StatusCode);   // wrong application
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/me", _team.Token(_clock, p => p["exp"] = _clock.Unix(TimeSpan.FromHours(-1)))))).StatusCode);   // expired
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/me", _team.Token(_clock, header: h => h["alg"] = "none")))).StatusCode);
    }

    [Fact]
    public async Task The_cookie_is_only_read_when_allowed()
    {
        var token = _team.Token(_clock);
        var withoutCookie = await StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Add("Cookie", $"{CloudflareAccessJwtOptions.CookieName}={token}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await withoutCookie.SendAsync(request)).StatusCode);

        var withCookie = await StartAsync(o => o.AllowCookieFallback = true);
        var request2 = new HttpRequestMessage(HttpMethod.Get, "/me");
        request2.Headers.Add("Cookie", $"{CloudflareAccessJwtOptions.CookieName}={token}");
        Assert.Equal(HttpStatusCode.OK, (await withCookie.SendAsync(request2)).StatusCode);
    }

    [Fact]
    public async Task The_header_wins_over_the_cookie()
    {
        var client = await StartAsync(o => o.AllowCookieFallback = true);
        var request = Get("/me", "not-a-token");
        request.Headers.Add("Cookie", $"{CloudflareAccessJwtOptions.CookieName}={_team.Token(_clock)}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(request)).StatusCode);        // a bad header is not rescued by a good cookie
    }

    [Fact]
    public void Principal_helper_for_anyone_else_is_null() =>
        Assert.Null(new ClaimsPrincipal(new ClaimsIdentity()).CloudflareAccess());

    [Fact]
    public void Claims_are_built_from_the_identity()
    {
        var identity = CloudflareAccessAuthenticationHandler.ToIdentity(new CloudflareAccessIdentity("s", "a@b.c", null, "n", "app", "AT", ["x"], null, DateTimeOffset.UtcNow, ["g1", "g2"]), "scheme");
        Assert.True(identity.IsAuthenticated);
        Assert.Equal("a@b.c", identity.Name);
        Assert.Equal(["g1", "g2"], identity.FindAll(CloudflareAccessAuthenticationOptions.GroupClaim).Select(c => c.Value));
        Assert.Equal("AT", identity.FindFirst(CloudflareAccessAuthenticationOptions.CountryClaim)!.Value);
    }
}

public class AccessJwtRegistrationTests
{
    [Fact]
    public void The_validator_is_registered_as_a_singleton_that_shares_its_key_cache()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Cloudflare:AccessJwt:TeamDomain"] = FakeTeam.Domain,
            ["Cloudflare:AccessJwt:Audiences:0"] = FakeTeam.Aud,
        }).Build();
        var services = new ServiceCollection();
        services.AddCloudflareInfinitySuite360(config);
        using var sp = services.BuildServiceProvider();
        Assert.Same(sp.GetRequiredService<ICloudflareAccessJwtValidator>(), sp.GetRequiredService<ICloudflareAccessJwtValidator>());
        var options = sp.GetRequiredService<IOptions<CloudflareOptions>>().Value.AccessJwt;
        Assert.Equal(FakeTeam.Domain, options.TeamDomain);
        Assert.Equal([FakeTeam.Aud], options.Audiences);
        Assert.True(options.IsConfigured);
    }

    [Fact]
    public void Wrong_settings_stop_the_start_and_unset_settings_do_not()
    {
        var bad = new ServiceCollection();
        bad.AddCloudflareInfinitySuite360(o => o.AccessJwt = new CloudflareAccessJwtOptions { TeamDomain = "evil.com", Audiences = ["a"] });
        using var badProvider = bad.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => badProvider.GetRequiredService<IOptions<CloudflareOptions>>().Value);

        var off = new ServiceCollection();
        off.AddCloudflareInfinitySuite360(o => o.ApiToken = "x");
        using var offProvider = off.BuildServiceProvider();
        Assert.False(offProvider.GetRequiredService<IOptions<CloudflareOptions>>().Value.AccessJwt.IsConfigured);
    }

    [Fact]
    public async Task An_unconfigured_validator_refuses_everything()
    {
        var services = new ServiceCollection();
        services.AddCloudflareInfinitySuite360(o => o.ApiToken = "x");
        using var sp = services.BuildServiceProvider();
        var result = await sp.GetRequiredService<ICloudflareAccessJwtValidator>().ValidateAsync("a.b.c");
        Assert.Equal(CloudflareAccessFailure.NotConfigured, result.Failure);
    }
}
