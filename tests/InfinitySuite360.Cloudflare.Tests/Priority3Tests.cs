using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>P6 (0.9.0): the narrow priority-3 wrappers. Fake handler only, no network, synthetic values.</summary>
public class Priority3Tests
{
    private const string Token = "secret-token-123";

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    [Fact]
    public async Task Typed_reads_of_every_wrapper()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responder = (r, _) => r.RequestUri!.AbsolutePath switch
        {
            var p when p.EndsWith("/images/v1") => FakeHandler.Ok("""{"images":[{"id":"img1","filename":"a.png","requireSignedURLs":true,"variants":["https://imagedelivery.net/x/img1/public"]}]}"""),
            var p when p.EndsWith("/images/v1/stats") => FakeHandler.Ok("""{"count":{"allowed":100000,"current":12}}"""),
            var p when p.EndsWith("/stream") => FakeHandler.Ok("""[{"uid":"v1","readyToStream":true,"duration":12.5}]"""),
            var p when p.EndsWith("/stream/storage-usage") => FakeHandler.Ok("""{"totalStorageMinutes":12,"totalStorageMinutesLimit":1000,"videoCount":3}"""),
            var p when p.EndsWith("/registrar/registrations") => FakeHandler.Ok("""[{"domain_name":"example.com","auto_renew":true,"locked":true,"privacy_mode":"redaction"}]""", """{"page":1,"per_page":50,"total_pages":1}"""),
            var p when p.EndsWith("/members") => FakeHandler.Ok("""[{"id":"m1","email":"ops@example.com","status":"accepted","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}]}]""", """{"page":1,"per_page":50,"total_pages":1}"""),
            var p when p.EndsWith("/workers/durable_objects/namespaces") => FakeHandler.Ok("""[{"id":"ns1","name":"counter","class":"Counter","use_sqlite":true}]""", """{"page":1,"per_page":100,"total_pages":1}"""),
            var p when p.EndsWith("/workflows") => FakeHandler.Ok("""[{"id":"w1","name":"orders","class_name":"OrderFlow"}]""", """{"page":1,"per_page":50,"total_pages":1}"""),
            var p when p.Contains("/radar/ranking/domain/") => FakeHandler.Ok("""{"details_0":{"rank":42}}"""),
            _ => FakeHandler.Ok("null"),
        };

        Assert.True(Assert.Single(await cf.Images.ListAsync()).RequireSignedUrls);
        Assert.Equal(12, (await cf.Images.GetStatsAsync()).Count!.Current);
        Assert.True(Assert.Single(await cf.Stream.ListVideosAsync()).ReadyToStream);
        Assert.Equal(3, (await cf.Stream.GetStorageUsageAsync()).VideoCount);
        Assert.Equal("redaction", Assert.Single(await cf.Registrar.ListAsync()).PrivacyMode);
        Assert.Equal("ops@example.com", Assert.Single(await cf.Members.ListAsync()).Email);
        Assert.Equal("Counter", Assert.Single(await cf.DurableObjects.ListNamespacesAsync()).Class);
        Assert.Equal("OrderFlow", Assert.Single(await cf.Workflows.ListAsync()).ClassName);
        Assert.Equal(42, (await cf.Radar.GetDomainRankingAsync("example.com")).GetProperty("details_0").GetProperty("rank").GetInt32());
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    [Fact]
    public async Task Secrets_never_reach_a_model_or_AdditionalData()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responder = (r, _) => r.RequestUri!.AbsolutePath switch
        {
            var p when p.Contains("/hyperdrive/") => FakeHandler.Ok("""{"id":"hd1","name":"db","origin":{"host":"db.example.com","user":"app","password":"SYNTHETIC-PASSWORD","access_client_secret":"SYNTHETIC-ACCESS-SECRET"}}"""),
            var p when p.EndsWith("/pages/projects/site") => FakeHandler.Ok("""{"id":"p1","name":"site","deployment_configs":{"production":{"env_vars":{"API_KEY":{"type":"plain_text","value":"SYNTHETIC-PLAIN-VALUE"}}}}}"""),
            var p when p.EndsWith("/secrets") => FakeHandler.Ok("""[{"id":"s1","name":"STRIPE","store_id":"st1","status":"active","value":"SYNTHETIC-SECRET-VALUE"}]""", """{"page":1,"per_page":100,"total_pages":1}"""),
            _ => FakeHandler.Ok("null"),
        };
        var hd = await cf.Hyperdrive.GetAsync("hd1");
        var project = await cf.Pages.GetProjectAsync("site");
        var secrets = await cf.SecretsStore.ListSecretsAsync("st1");
        var all = JsonSerializer.Serialize(new object?[] { hd, project, secrets });
        foreach (var leaked in new[] { "SYNTHETIC-PASSWORD", "SYNTHETIC-ACCESS-SECRET", "SYNTHETIC-PLAIN-VALUE", "SYNTHETIC-SECRET-VALUE" })
            Assert.DoesNotContain(leaked, all);
        Assert.Equal("db.example.com", hd!.Origin!.Value.GetProperty("host").GetString());
        Assert.Equal("STRIPE", Assert.Single(secrets).Name);
    }

    [Fact]
    public async Task Errors_carry_no_token_and_map_to_the_known_exceptions()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 10000, "Authentication error"));
        var denied = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Images.GetStatsAsync());
        Assert.DoesNotContain(Token, denied.ToString());

        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 1001, "Stream is not available on your plan"));
        await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.Stream.GetStorageUsageAsync());

        // 429 with Retry-After: retried (reads), then success.
        var limited = Error(HttpStatusCode.TooManyRequests, 971, "Please wait and consider throttling your request speed");
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(1));
        h.Responses.Enqueue(limited);
        h.Responses.Enqueue(FakeHandler.Ok("""{"count":{"allowed":1,"current":1}}"""));
        Assert.Equal(1, (await cf.Images.GetStatsAsync()).Count!.Current);
    }

    [Fact]
    public async Task A_POST_is_not_repeated_after_a_server_error()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.ServiceUnavailable, 0, "unavailable"));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Pages.RollbackAsync("site", "d1", allowDeploy: true));
        Assert.Single(h.Requests);
    }

    [Fact]
    public async Task Previews_send_nothing_and_describe_the_risk()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var previews = new[]
        {
            cf.Images.PreviewDelete("img1"),
            cf.Stream.PreviewDeleteVideo("v1"),
            cf.Registrar.PreviewSetAutoRenew("example.com", false),
            cf.Members.PreviewRemove("m1"),
            cf.Pages.PreviewRollback("site", "d1"),
            cf.Hyperdrive.PreviewDelete("hd1"),
            cf.Workflows.PreviewChangeInstanceStatus("orders", "i1", WorkflowInstanceAction.Terminate),
            cf.SecretsStore.PreviewDeleteSecret("st1", "s1"),
        };
        Assert.Empty(h.Requests);
        Assert.All(previews, p => Assert.DoesNotContain(Token, p.ToString() + p.BodyJson));
        Assert.Contains("WARNING", previews[2].Summary);
        Assert.Equal("accounts/acc1/registrar/registrations/example.com", previews[2].Path);
        Assert.Contains("cannot be resumed", previews[6].Summary);
    }

    [Fact]
    public async Task Risky_writes_need_their_allow_switch_and_send_nothing_without_it()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Func<Task>[] refused =
        [
            () => cf.Images.DeleteAsync("img1"),
            () => cf.Stream.DeleteVideoAsync("v1"),
            () => cf.Registrar.SetAutoRenewAsync("example.com", false),
            () => cf.Members.RemoveAsync("m1"),
            () => cf.Pages.RollbackAsync("site", "d1"),
            () => cf.Hyperdrive.DeleteAsync("hd1"),
            () => cf.Workflows.ChangeInstanceStatusAsync("orders", "i1", WorkflowInstanceAction.Terminate),
            () => cf.SecretsStore.DeleteSecretAsync("st1", "s1"),
        ];
        foreach (var call in refused) await Assert.ThrowsAsync<InvalidOperationException>(call);
        Assert.Empty(h.Requests);

        // Switching auto-renew on and pausing need no switch.
        await cf.Registrar.SetAutoRenewAsync("example.com", true);
        await cf.Workflows.ChangeInstanceStatusAsync("orders", "i1", WorkflowInstanceAction.Pause);
        Assert.Equal([HttpMethod.Patch, HttpMethod.Patch], h.Requests.Select(r => r.Method));
        Assert.Contains("\"status\":\"pause\"", h.Requests[1].Body);
    }

    [Fact]
    public async Task The_last_super_administrator_is_never_removed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responder = (r, _) => r.Method == HttpMethod.Get
            ? FakeHandler.Ok("""[{"id":"m1","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}]},{"id":"m2","roles":[{"id":"r2","name":"Administrator Read Only"}]}]""", """{"page":1,"per_page":50,"total_pages":1}""")
            : FakeHandler.Ok("""{"id":"x"}""");
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Members.RemoveAsync("m1", allowRemoval: true));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
        Assert.True(await cf.Members.RemoveAsync("m2", allowRemoval: true));
        Assert.False(await cf.Members.RemoveAsync("m9", allowRemoval: true));
        Assert.Single(h.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task Inputs_are_checked_locally()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Registrar.GetAsync("https://example.com/x"));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => cf.Workflows.ChangeInstanceStatusAsync("orders", "i1", (WorkflowInstanceAction)99));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Pages.ListDeploymentsAsync("site", "staging"));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.AuditLogs.ListAsync(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(-1)));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Radar.GetAsync("../accounts"));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.SecretsStore.DeleteSecretAsync("st1", "..", allowDelete: true));
        Assert.Empty(h.Requests);
    }
}
