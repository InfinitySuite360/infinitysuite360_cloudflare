using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>
/// Priority-2 clients of 0.7.0 (Workers, KV, D1, Queues, R2, cache, load balancing, Spectrum, Argo). Fake handler only: no network, no real token.
/// Secret values in these tests are synthetic markers; the tests assert that they reach the wire where the call needs them and nowhere else.
/// </summary>
public class Priority2Tests
{
    private const string Token = "secret-token-123";
    private const string SecretMarker = "SYNTHETIC-SECRET-VALUE-7731";
    private const string Module = "export default { fetch() { return new Response('SOURCE-MARKER'); } };";

    private static HttpResponseMessage Ok(string result, string? info = null) => FakeHandler.Ok(result, info);

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    /// <summary>Answers by method and URL fragment; every other request is a test failure (404 with a marker).</summary>
    private static void Route(FakeHandler h, params (string Method, string Fragment, Func<string?, HttpResponseMessage> Reply)[] routes) =>
        h.Responder = (req, body) =>
        {
            var url = req.RequestUri!.ToString();
            foreach (var (method, fragment, reply) in routes)
                if (req.Method.Method == method && url.Contains(fragment, StringComparison.Ordinal)) return reply(body);
            return Error(HttpStatusCode.NotFound, 7003, "UNEXPECTED-REQUEST " + req.Method + " " + url);
        };

    private static (string Method, string Fragment, Func<string?, HttpResponseMessage> Reply) R(string method, string fragment, string result, string? info = null) =>
        (method, fragment, _ => Ok(result, info));

    /// <summary>A risky-option refusal: an <see cref="InvalidOperationException"/> that is not the write guard.</summary>
    private static async Task Refused(FakeHandler h, Func<Task> action)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.Empty(h.Requests);
    }

    // ---------------------------------------------------------------- guards

    [Fact]
    public async Task Every_new_write_is_refused_without_AllowWrites_and_nothing_is_sent()
    {
        var (cf, h, _) = FakeHandler.Create();
        var entries = new List<KvBulkEntry> { new() { Key = "k", Value = "v" } };
        var cors = new[] { new R2CorsRule(["https://app.example.com"], ["GET"]) };
        var lifecycle = new[] { new R2LifecycleRule("tmp", InfrequentAccessAfter: TimeSpan.FromDays(30)) };
        var pool = new LbPoolInput { Name = "eu", Origins = [new("o1", "203.0.113.10")] };
        var lb = new LoadBalancerInput { Name = "lb.example.com", DefaultPools = ["p1"], FallbackPool = "p1" };
        var spectrum = new SpectrumAppInput { Hostname = "tcp.example.com", Protocol = "tcp/8443", OriginDirect = ["tcp://203.0.113.10:8443"] };
        var cacheRule = new CacheRuleInput { Ref = "static", Expression = "(starts_with(http.request.uri.path, \"/static/\"))", Cache = true, EdgeTtl = new("override_origin", 3600) };
        const string version = "0123456789abcdef0123456789abcdef";
        Func<Task>[] writes =
        [
            () => cf.Workers.UploadScriptAsync("w", Module, allowDeploy: true),
            () => cf.Workers.RemoveScriptAsync("w", allowDelete: true),
            () => cf.Workers.EnsureRouteAsync("example.com/api/*", "w"),
            () => cf.Workers.RemoveRouteAsync("r1"),
            () => cf.Workers.AttachDomainAsync("app.example.com", "w"),
            () => cf.Workers.DetachDomainAsync("d1", allowRemoval: true),
            () => cf.Workers.SetSchedulesAsync("w", ["*/5 * * * *"]),
            () => cf.Workers.DeployVersionsAsync("w", [new(version, 100)], allowDeploy: true),
            () => cf.Workers.PutSecretAsync("w", "API_KEY", WorkerSecretText.From(SecretMarker), allowDeploy: true),
            () => cf.Workers.RemoveSecretAsync("w", "API_KEY", allowDeploy: true),
            () => cf.Kv.EnsureNamespaceAsync("cache"),
            () => cf.Kv.RenameNamespaceAsync("ns1", "cache2"),
            () => cf.Kv.RemoveNamespaceAsync("ns1", allowDelete: true),
            () => cf.Kv.PutValueAsync("ns1", "k", "v"),
            () => cf.Kv.PutValueAsync("ns1", "k", "v", allowOverwrite: false),
            () => cf.Kv.DeleteKeyAsync("ns1", "k"),
            () => cf.Kv.PutBulkAsync("ns1", entries),
            () => cf.Kv.GetBulkAsync("ns1", ["k"]),
            () => cf.Kv.DeleteBulkAsync("ns1", ["k"], allowBulkDelete: true),
            () => cf.D1.EnsureDatabaseAsync("main"),
            () => cf.D1.RemoveDatabaseAsync("db1", allowDelete: true),
            () => cf.D1.QueryAsync("db1", "select 1"),
            () => cf.Queues.EnsureAsync("jobs"),
            () => cf.Queues.UpdateSettingsAsync("q1", deliveryDelaySeconds: 5),
            () => cf.Queues.RemoveAsync("q1", allowDelete: true),
            () => cf.Queues.PurgeAsync("q1", allowPurge: true),
            () => cf.Queues.EnsureConsumerAsync("q1", new QueueConsumerInput { ScriptName = "w" }),
            () => cf.Queues.RemoveConsumerAsync("q1", "c1"),
            () => cf.Queues.PushAsync("q1", new { a = 1 }),
            () => cf.Queues.PushBatchAsync("q1", [new { a = 1 }]),
            () => cf.R2.EnsureBucketAsync("assets"),
            () => cf.R2.RemoveBucketAsync("assets", allowDelete: true),
            () => cf.R2.EnsureCustomDomainAsync("assets", "cdn.example.com", "zone1", allowPublicAccess: true),
            () => cf.R2.RemoveCustomDomainAsync("assets", "cdn.example.com", allowRemoval: true),
            () => cf.R2.SetManagedDomainAsync("assets", true, allowPublicAccess: true),
            () => cf.R2.SetCorsAsync("assets", cors),
            () => cf.R2.DeleteCorsAsync("assets"),
            () => cf.R2.SetLifecycleAsync("assets", lifecycle),
            () => cf.Cache.UpsertRuleAsync(cacheRule),
            () => cf.Cache.RemoveRuleAsync("static"),
            () => cf.Cache.PurgeUrlsAsync(["https://example.com/a.css"]),
            () => cf.Cache.PurgeHostsAsync(["example.com"]),
            () => cf.Cache.PurgeTagsAsync(["t1"]),
            () => cf.Cache.PurgePrefixesAsync(["example.com/assets/"]),
            () => cf.Cache.PurgeEverythingAsync(allowPurgeAll: true),
            () => cf.Cache.SetCacheReserveAsync(true, allowBilling: true),
            () => cf.Cache.SetRegionalTieredCacheAsync(true),
            () => cf.Argo.SetSmartRoutingAsync(true, allowBilling: true),
            () => cf.Argo.SetTieredCachingAsync(true),
            () => cf.LoadBalancing.CreateMonitorAsync(new LbMonitorInput()),
            () => cf.LoadBalancing.UpdateMonitorAsync("m1", new LbMonitorInput()),
            () => cf.LoadBalancing.RemoveMonitorAsync("m1"),
            () => cf.LoadBalancing.EnsurePoolAsync(pool),
            () => cf.LoadBalancing.SetPoolEnabledAsync("p1", false, allowLastHealthyPool: true),
            () => cf.LoadBalancing.SetOriginEnabledAsync("p1", "o1", false, allowLastHealthyPool: true),
            () => cf.LoadBalancing.UpsertOriginAsync("p1", new LbOriginInput("o2", "203.0.113.11")),
            () => cf.LoadBalancing.RemoveOriginAsync("p1", "o1", allowLastHealthyPool: true),
            () => cf.LoadBalancing.RemovePoolAsync("p1"),
            () => cf.LoadBalancing.EnsureLoadBalancerAsync(lb),
            () => cf.LoadBalancing.SetLoadBalancerEnabledAsync("lb1", false, allowDisableActive: true),
            () => cf.LoadBalancing.RemoveLoadBalancerAsync("lb1", allowDeleteActive: true),
            () => cf.Spectrum.EnsureAppAsync(spectrum),
            () => cf.Spectrum.UpdateAppAsync("a1", spectrum),
            () => cf.Spectrum.RemoveAppAsync("a1", allowDelete: true),
        ];
        foreach (var write in writes) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(write);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Risky_options_are_refused_locally_without_their_allow_switch()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string version = "0123456789abcdef0123456789abcdef";
        Func<Task>[] refused =
        [
            () => cf.Workers.UploadScriptAsync("w", Module),
            () => cf.Workers.RemoveScriptAsync("w"),
            () => cf.Workers.RemoveScriptAsync("w", allowDelete: true, force: true),
            () => cf.Workers.EnsureRouteAsync("*.example.com/*", "w"),
            () => cf.Workers.DetachDomainAsync("d1"),
            () => cf.Workers.SetSchedulesAsync("w", []),
            () => cf.Workers.DeployVersionsAsync("w", [new(version, 100)]),
            () => cf.Workers.PutSecretAsync("w", "API_KEY", WorkerSecretText.From(SecretMarker)),
            () => cf.Workers.RemoveSecretAsync("w", "API_KEY"),
            () => cf.Kv.RemoveNamespaceAsync("ns1"),
            () => cf.Kv.DeleteBulkAsync("ns1", ["k"]),
            () => cf.D1.RemoveDatabaseAsync("db1"),
            () => cf.D1.QueryAsync("db1", "insert into t values (1)"),
            () => cf.D1.QueryAsync("db1", "delete from t"),
            () => cf.D1.QueryAsync("db1", "drop table t", allowWriteSql: true),
            () => cf.Queues.RemoveAsync("q1"),
            () => cf.Queues.PurgeAsync("q1"),
            () => cf.Queues.UpdateSettingsAsync("q1", deliveryPaused: true),
            () => cf.R2.RemoveBucketAsync("assets"),
            () => cf.R2.EnsureCustomDomainAsync("assets", "cdn.example.com", "zone1"),
            () => cf.R2.RemoveCustomDomainAsync("assets", "cdn.example.com"),
            () => cf.R2.SetManagedDomainAsync("assets", true),
            () => cf.R2.SetCorsAsync("assets", [new R2CorsRule(["*"], ["GET"])]),
            () => cf.R2.SetLifecycleAsync("assets", [new R2LifecycleRule("purge", DeleteAfter: TimeSpan.FromDays(1))]),
            () => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "all", Expression = "true", Cache = true }),
            () => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "long", Expression = "http.host eq \"a.example.com\"", EdgeTtl = new("override_origin", 604800) }),
            () => cf.Cache.PurgeEverythingAsync(),
            () => cf.Cache.SetCacheReserveAsync(true),
            () => cf.Argo.SetSmartRoutingAsync(true),
            () => cf.LoadBalancing.CreateMonitorAsync(new LbMonitorInput { AllowInsecure = true }),
            () => cf.Spectrum.EnsureAppAsync(new SpectrumAppInput { Hostname = "ssh.example.com", Protocol = "tcp/22", OriginDirect = ["tcp://203.0.113.10:22"] }),
            () => cf.Spectrum.RemoveAppAsync("a1"),
        ];
        foreach (var call in refused) await Refused(h, call);
    }

    [Fact]
    public async Task WriteFilter_is_checked_before_the_preparing_read()
    {
        var (cf, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, path) => path.StartsWith("zones/zone1/dns_records", StringComparison.Ordinal); });
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Kv.EnsureNamespaceAsync("cache"));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Workers.EnsureRouteAsync("example.com/*", "w"));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.LoadBalancing.SetPoolEnabledAsync("p1", false));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "r", Expression = "http.host eq \"a\"", Cache = false }));
        Assert.Empty(h.Requests);
    }

    [Fact]
    public void Previews_send_nothing_and_never_contain_values_or_the_token()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var secret = cf.Workers.PreviewPutSecret("w", "API_KEY");
        var upload = cf.Workers.PreviewUploadScript("w", Module, new WorkerMetadata { Bindings = [new { type = "plain_text", name = "TITLE", text = "PLAIN-BINDING-VALUE" }] });
        var kv = cf.Kv.PreviewPutValue("ns1", "k", "KV-VALUE-MARKER");
        var query = cf.D1.PreviewQuery("db1", "select * from t where a = ?", parameterCount: 1);
        var push = cf.Queues.PreviewPush("q1", new { secret = "MESSAGE-MARKER" });
        var monitor = cf.LoadBalancing.PreviewCreateMonitor(new LbMonitorInput { Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer " + SecretMarker } });
        var all = new[] { secret, upload, kv, query, push, monitor,
            cf.Workers.PreviewRemoveScript("w"), cf.Workers.PreviewCreateRoute("example.com/*", "w"), cf.Kv.PreviewDeleteBulk("ns1", ["a", "b"]),
            cf.Cache.PreviewPurgeEverything(), cf.Cache.PreviewPurgeUrls(["https://example.com/a"]), cf.R2.PreviewSetManagedDomain("assets", true) };
        foreach (var p in all)
        {
            var text = p.Method + p.Path + p.BodyJson + p.Summary;
            foreach (var forbidden in new[] { Token, SecretMarker, "SOURCE-MARKER", "PLAIN-BINDING-VALUE", "KV-VALUE-MARKER", "MESSAGE-MARKER" }) Assert.DoesNotContain(forbidden, text);
        }
        Assert.Contains("[redacted]", secret.BodyJson);
        Assert.Contains("source_sha256", upload.BodyJson);
        Assert.Contains("plain_text TITLE", upload.BodyJson);
        Assert.Contains("1 bound values", query.BodyJson);
        Assert.Contains("WARNING", upload.Summary);
        Assert.Empty(h.Requests);
    }

    // ---------------------------------------------------------------- Workers

    [Fact]
    public async Task Upload_sends_one_multipart_PUT_with_keep_bindings_and_refuses_secret_bindings()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""{"id":"api-worker","etag":"e1"}"""));
        var response = await cf.Workers.UploadScriptAsync("api-worker", Module, new WorkerMetadata { Bindings = [new { type = "plain_text", name = "TITLE", text = "hi" }] }, allowDeploy: true);
        Assert.Equal("api-worker", response.Result!.Id);
        var request = Assert.Single(h.Requests);
        Assert.Equal(HttpMethod.Put, request.Method);
        Assert.EndsWith("/accounts/acc1/workers/scripts/api-worker", request.Url);
        Assert.Contains("keep_bindings", request.Body);
        Assert.Contains("secret_text", request.Body);
        Assert.Contains("SOURCE-MARKER", request.Body);

        var (cf2, h2, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => cf2.Workers.UploadScriptAsync("w", Module, new WorkerMetadata { Bindings = [new { type = "secret_text", name = "KEY", text = SecretMarker }] }, allowDeploy: true));
        Assert.DoesNotContain(SecretMarker, ex.Message);
        Assert.Empty(h2.Requests);
    }

    [Fact]
    public async Task Secret_value_goes_on_the_wire_only_and_never_into_models_output_or_errors()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok($$"""{"name":"API_KEY","type":"secret_text","text":"{{SecretMarker}}"}"""));
        var value = WorkerSecretText.From(SecretMarker);
        var info = await cf.Workers.PutSecretAsync("w", "API_KEY", value, allowDeploy: true);
        Assert.Contains(SecretMarker, h.Requests[0].Body);
        Assert.Equal("API_KEY", info.Name);
        Assert.Null(info.AdditionalData);
        foreach (var text in new[] { value.ToString(), JsonSerializer.Serialize(value), JsonSerializer.Serialize(info, CloudflareJson.Options), info.ToString() ?? "" })
            Assert.DoesNotContain(SecretMarker, text);

        h.Responses.Enqueue(Error(HttpStatusCode.BadRequest, 10021, "invalid secret"));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Workers.PutSecretAsync("w", "API_KEY", value, allowDeploy: true));
        Assert.DoesNotContain(SecretMarker, ex.Message);
        Assert.DoesNotContain(Token, ex.Message);

        h.Responses.Enqueue(Ok($$"""[{"name":"API_KEY","type":"secret_text","text":"{{SecretMarker}}"}]"""));
        var names = await cf.Workers.ListSecretsAsync("w");
        Assert.Equal("API_KEY", Assert.Single(names).Name);
        Assert.Null(names[0].AdditionalData);
    }

    [Fact]
    public async Task Schedules_are_written_only_on_change()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/schedules", """{"schedules":[{"cron":"*/5 * * * *"}]}"""), R("PUT", "/schedules", """{"schedules":[{"cron":"0 3 * * *"}]}"""));
        var same = await cf.Workers.SetSchedulesAsync("w", ["*/5 * * * *"]);
        Assert.False(same.Changed);
        Assert.Single(h.Requests);
        var changed = await cf.Workers.SetSchedulesAsync("w", ["0 3 * * *"]);
        Assert.True(changed.Changed);
        Assert.Equal(3, h.Requests.Count);
        Assert.Equal(HttpMethod.Put, h.Requests[2].Method);
        Assert.Contains("\"cron\":\"0 3 * * *\"", h.Requests[2].Body);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Workers.SetSchedulesAsync("w", ["every minute"]));
    }

    [Fact]
    public async Task Deploy_checks_percentages_and_is_not_repeated_after_a_server_error()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string v1 = "0123456789abcdef0123456789abcdef";
        const string v2 = "fedcba9876543210fedcba9876543210";
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Workers.DeployVersionsAsync("w", [new(v1, 60), new(v2, 30)], allowDeploy: true));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Workers.DeployVersionsAsync("w", [new(v1, 100), new(v1, 0.5)], allowDeploy: true));
        Assert.Empty(h.Requests);
        h.Responses.Enqueue(FakeHandler.Json("""{"success":false,"errors":[{"code":0,"message":"oops"}],"messages":[],"result":null}""", HttpStatusCode.BadGateway));
        h.Responses.Enqueue(Ok("""{"id":"d1"}"""));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Workers.DeployVersionsAsync("w", [new(v1, 90), new(v2, 10)], allowDeploy: true));
        var post = Assert.Single(h.Requests);
        Assert.Contains("\"strategy\":\"percentage\"", post.Body);
    }

    [Fact]
    public async Task Route_is_ensured_and_a_pattern_of_another_worker_is_a_conflict()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/workers/routes", """[{"id":"r1","pattern":"example.com/api/*","script":"other"},{"id":"r2","pattern":"example.com/web/*","script":"w"}]"""),
            R("POST", "/workers/routes", """{"id":"r3","pattern":"example.com/new/*","script":"w"}"""));
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Workers.EnsureRouteAsync("example.com/api/*", "w"));
        var (existing, created) = await cf.Workers.EnsureRouteAsync("example.com/web/*", "w");
        Assert.False(created);
        Assert.Equal("r2", existing.Id);
        var (route, createdNew) = await cf.Workers.EnsureRouteAsync("example.com/new/*", "w");
        Assert.True(createdNew);
        Assert.Equal("r3", route.Id);
        Assert.Equal(1, h.Requests.Count(r => r.Method == HttpMethod.Post));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Workers.EnsureRouteAsync("https://example.com/*", "w"));
    }

    [Fact]
    public async Task Worker_reads_are_typed()
    {
        var (cf, h, _) = FakeHandler.Create();
        Route(h,
            R("GET", "/versions", """{"items":[{"id":"0123456789abcdef0123456789abcdef","number":3}]}"""),
            R("GET", "/deployments", """{"deployments":[{"id":"d1","strategy":"percentage","versions":[{"version_id":"0123456789abcdef0123456789abcdef","percentage":100}]}]}"""),
            R("GET", "/workers/domains", """[{"id":"dom1","hostname":"app.example.com","service":"w","environment":"production","zone_id":"zone1"}]"""),
            R("GET", "/settings", """{"bindings":[{"type":"secret_text","name":"API_KEY"}],"compatibility_date":"2026-01-01"}"""));
        Assert.Equal(3, (await cf.Workers.ListVersionsAsync("w")).Single().Number);
        Assert.Equal(100, (await cf.Workers.ListDeploymentsAsync("w")).Single().Versions.Single().Percentage);
        Assert.Equal("app.example.com", (await cf.Workers.ListDomainsAsync()).Single().Hostname);
        Assert.Equal("2026-01-01", (await cf.Workers.GetScriptSettingsAsync("w")).CompatibilityDate);
    }

    // ---------------------------------------------------------------- KV

    [Fact]
    public async Task Kv_keys_are_listed_across_pages_and_values_are_written_as_multipart()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""[{"name":"a"},{"name":"b"}]""", """{"count":2,"cursor":"c1"}"""));
        h.Responses.Enqueue(Ok("""[{"name":"c","expiration":1900000000}]""", """{"count":1,"cursor":""}"""));
        var keys = await cf.Kv.ListKeysAsync("ns1", "pre", 1000);
        Assert.Equal(["a", "b", "c"], keys.Select(k => k.Name));
        Assert.Contains("prefix=pre", h.Requests[0].Url);
        Assert.Contains("cursor=c1", h.Requests[1].Url);

        h.Requests.Clear();
        h.Responses.Enqueue(Ok("null"));
        await cf.Kv.PutValueAsync("ns1", "my key/1", "VALUE-BODY", expirationTtl: 3600, metadata: JsonDocument.Parse("""{"src":"test"}""").RootElement);
        var put = Assert.Single(h.Requests);
        Assert.Equal(HttpMethod.Put, put.Method);
        Assert.Matches("/values/my(%20| )key%2F1", put.Url);
        Assert.Contains("expiration_ttl=3600", put.Url);
        Assert.Matches("name=\"?value\"?", put.Body);
        Assert.Contains("VALUE-BODY", put.Body);
        Assert.Matches("name=\"?metadata\"?", put.Body);
    }

    [Fact]
    public async Task Kv_overwrite_protection_and_limits()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""{"sample":1}"""));
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Kv.PutValueAsync("ns1", "k", "v", allowOverwrite: false));
        Assert.Single(h.Requests);
        h.Requests.Clear();
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Kv.PutValueAsync("ns1", new string('k', 513), "v"));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Kv.PutValueAsync("ns1", "..", "v"));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => cf.Kv.PutValueAsync("ns1", "k", "v", expirationTtl: 30));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Kv.PutBulkAsync("ns1", Enumerable.Range(0, 10_001).Select(i => new KvBulkEntry { Key = "k" + i, Value = "v" }).ToList()));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Kv.GetBulkAsync("ns1", Enumerable.Range(0, 101).Select(i => "k" + i).ToList()));
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Kv_namespace_is_only_deleted_when_empty_or_explicitly_allowed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/keys", """[{"name":"still-here"}]""", """{"count":1,"cursor":""}"""), R("DELETE", "/namespaces/ns1", "null"));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Kv.RemoveNamespaceAsync("ns1", allowDelete: true));
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
        Assert.True(await cf.Kv.RemoveNamespaceAsync("ns1", allowDelete: true, allowNonEmpty: true));
        Assert.Contains(h.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task Kv_bulk_get_and_ensure()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("POST", "/bulk/get", """{"values":{"a":"1","b":null}}"""),
            R("GET", "/storage/kv/namespaces", """[{"id":"ns1","title":"cache"}]"""));
        var map = await cf.Kv.GetBulkAsync("ns1", ["a", "b"]);
        Assert.Equal("1", map["a"]);
        Assert.Null(map["b"]);
        var (ns, created) = await cf.Kv.EnsureNamespaceAsync("cache");
        Assert.False(created);
        Assert.Equal("ns1", ns.Id);
    }

    // ---------------------------------------------------------------- D1

    [Theory]
    [InlineData("SELECT * FROM users WHERE id = ?", D1SqlKind.ReadOnly)]
    [InlineData("  -- comment\n select 1; ", D1SqlKind.ReadOnly)]
    [InlineData("WITH x AS (SELECT 1) SELECT * FROM x", D1SqlKind.ReadOnly)]
    [InlineData("PRAGMA table_info(users)", D1SqlKind.ReadOnly)]
    [InlineData("EXPLAIN QUERY PLAN SELECT 1", D1SqlKind.ReadOnly)]
    [InlineData("SELECT 'delete from t; drop table t'", D1SqlKind.ReadOnly)]
    [InlineData("INSERT INTO t VALUES (1)", D1SqlKind.Write)]
    [InlineData("UPDATE t SET a = 1 WHERE id = 2", D1SqlKind.Write)]
    [InlineData("DELETE FROM t WHERE id = 2", D1SqlKind.Write)]
    [InlineData("CREATE TABLE t (id integer)", D1SqlKind.Write)]
    [InlineData("PRAGMA foreign_keys = off", D1SqlKind.Write)]
    [InlineData("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", D1SqlKind.Write)]
    [InlineData("SELECT 1; INSERT INTO t VALUES (1)", D1SqlKind.Write)]
    [InlineData("DELETE FROM t", D1SqlKind.Destructive)]
    [InlineData("UPDATE t SET a = 1", D1SqlKind.Destructive)]
    [InlineData("DROP TABLE t", D1SqlKind.Destructive)]
    [InlineData("ALTER TABLE t ADD COLUMN b text", D1SqlKind.Destructive)]
    [InlineData("SELECT 1; DROP TABLE t", D1SqlKind.Destructive)]
    [InlineData("/* x */ DROP /* y */ TABLE t", D1SqlKind.Destructive)]
    public void Sql_is_classified_locally(string sql, D1SqlKind expected) => Assert.Equal(expected, D1Sql.Classify(sql));

    [Fact]
    public async Task D1_query_sends_bound_parameters_and_returns_rows()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""[{"results":[{"id":1,"name":"a"}],"success":true,"meta":{"duration":0.5}}]"""));
        var result = await cf.D1.QueryAsync("db1", "SELECT * FROM users WHERE name = ?", ["PARAM-MARKER"]);
        Assert.Equal(1, result[0].Results[0].GetProperty("id").GetInt32());
        Assert.True(result[0].Success);
        var request = Assert.Single(h.Requests);
        Assert.EndsWith("/accounts/acc1/d1/database/db1/query", request.Url);
        Assert.Contains("\"params\":[\"PARAM-MARKER\"]", request.Body);
        Assert.DoesNotContain("PARAM-MARKER", cf.D1.PreviewQuery("db1", "SELECT * FROM users WHERE name = ?", 1).BodyJson);
        h.Responses.Enqueue(Ok("""[{"results":[],"success":true}]"""));
        await cf.D1.QueryAsync("db1", "DELETE FROM users WHERE id = ?", [3], allowWriteSql: true);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.D1.QueryAsync("db1", new string('x', 100_001)));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.D1.QueryAsync("db1", "select 1", Enumerable.Repeat<object?>(1, 101).ToList()));
    }

    [Fact]
    public async Task D1_ensure_database_creates_once_and_survives_a_concurrent_create()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var lists = 0;
        h.Responder = (req, _) => req.Method == HttpMethod.Get
            ? Ok(++lists == 1 ? "[]" : """[{"uuid":"u1","name":"main"}]""")
            : Error(HttpStatusCode.Conflict, 7502, "database already exists");
        var (db, created) = await cf.D1.EnsureDatabaseAsync("main", "weur");
        Assert.False(created);
        Assert.Equal("u1", db.Uuid);
        Assert.Contains("\"primary_location_hint\":\"weur\"", h.Requests.Single(r => r.Method == HttpMethod.Post).Body);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.D1.EnsureDatabaseAsync("bad name"));
    }

    // ---------------------------------------------------------------- Queues

    [Fact]
    public async Task Queue_is_ensured_and_consumer_is_attached_once()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var posts = 0;
        h.Responder = (req, _) =>
        {
            var url = req.RequestUri!.ToString();
            if (req.Method == HttpMethod.Post && url.EndsWith("/queues", StringComparison.Ordinal)) { posts++; return Ok("""{"queue_id":"q1","queue_name":"jobs"}"""); }
            if (req.Method == HttpMethod.Get && url.EndsWith("/consumers", StringComparison.Ordinal)) return Ok("""[{"consumer_id":"c1","script_name":"w","type":"worker"}]""");
            if (req.Method == HttpMethod.Get) return Ok("[]");
            return Error(HttpStatusCode.NotFound, 7003, "UNEXPECTED");
        };
        var (queue, created) = await cf.Queues.EnsureAsync("jobs");
        Assert.True(created);
        Assert.Equal("q1", queue.QueueId);
        Assert.Equal(1, posts);
        var (consumer, attached) = await cf.Queues.EnsureConsumerAsync("q1", new QueueConsumerInput { ScriptName = "w", BatchSize = 10 });
        Assert.False(attached);
        Assert.Equal("c1", consumer.ConsumerId);
    }

    [Fact]
    public async Task Queue_ensure_survives_a_conflict_and_limits_are_checked()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var lists = 0;
        h.Responder = (req, _) => req.Method == HttpMethod.Get
            ? Ok(++lists == 1 ? "[]" : """[{"queue_id":"q1","queue_name":"jobs"}]""")
            : Error(HttpStatusCode.Conflict, 11009, "queue already exists");
        var (queue, created) = await cf.Queues.EnsureAsync("jobs");
        Assert.False(created);
        Assert.Equal("q1", queue.QueueId);
        h.Requests.Clear();
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Queues.PushAsync("q1", new { big = new string('x', 140_000) }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Queues.PushBatchAsync("q1", Enumerable.Range(0, 101).Select(i => (object)new { i }).ToList()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => cf.Queues.PushAsync("q1", new { a = 1 }, delaySeconds: 90_000));
        Assert.Empty(h.Requests);
        h.Responder = null;
        h.Responses.Enqueue(Ok("null"));
        await cf.Queues.PushBatchAsync("q1", [new { a = 1 }, new { a = 2 }], delaySeconds: 5);
        Assert.Contains("\"messages\":[", h.Requests[0].Body);
        Assert.Contains("\"delay_seconds\":5", h.Requests[0].Body);
    }

    // ---------------------------------------------------------------- R2

    [Fact]
    public async Task R2_bucket_is_ensured_and_only_an_empty_bucket_is_deleted()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/r2/buckets/assets/objects", """[{"key":"a.txt"}]"""), R("GET", "/r2/buckets/assets", """{"name":"assets"}"""), R("DELETE", "/r2/buckets/assets", "null"));
        var (bucket, created) = await cf.R2.EnsureBucketAsync("assets");
        Assert.False(created);
        Assert.Equal("assets", bucket.Name);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.R2.RemoveBucketAsync("assets", allowDelete: true));
        Assert.Contains("not empty", ex.Message);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.R2.EnsureBucketAsync("Bad_Name"));

        Route(h, R("GET", "/r2/buckets/assets/objects", "[]"), R("DELETE", "/r2/buckets/assets", "null"));
        Assert.True(await cf.R2.RemoveBucketAsync("assets", allowDelete: true));
    }

    [Fact]
    public async Task R2_creates_a_missing_bucket_with_camelCase_body()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("POST", "/r2/buckets", """{"name":"assets","location":"WEUR"}"""), (("GET", "/r2/buckets/assets", _ => Error(HttpStatusCode.NotFound, 10006, "The specified bucket does not exist."))));
        var (bucket, created) = await cf.R2.EnsureBucketAsync("assets", "weur", "InfrequentAccess");
        Assert.True(created);
        Assert.Equal("assets", bucket.Name);
        var post = h.Requests.Single(r => r.Method == HttpMethod.Post);
        Assert.Contains("\"locationHint\":\"weur\"", post.Body);
        Assert.Contains("\"storageClass\":\"InfrequentAccess\"", post.Body);
    }

    [Fact]
    public async Task R2_public_access_cors_and_lifecycle()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/domains/custom", """{"domains":[]}"""),
            R("POST", "/domains/custom", """{"domain":"cdn.example.com","enabled":true,"zoneId":"zone1","minTLS":"1.2"}"""),
            R("PUT", "/cors", "null"), R("PUT", "/lifecycle", "null"),
            (("GET", "/cors", _ => Error(HttpStatusCode.NotFound, 10059, "The CORS configuration does not exist."))));
        var (domain, created) = await cf.R2.EnsureCustomDomainAsync("assets", "cdn.example.com", "zone1", allowPublicAccess: true);
        Assert.True(created);
        Assert.Equal("zone1", domain.ZoneId);
        Assert.Equal("1.2", domain.MinTls);
        Assert.Contains("\"zoneId\":\"zone1\"", h.Requests.Single(r => r.Method == HttpMethod.Post).Body);

        Assert.Empty(await cf.R2.GetCorsRulesAsync("assets"));
        await cf.R2.SetCorsAsync("assets", [new R2CorsRule(["https://app.example.com"], ["GET", "HEAD"], ["Content-Type"], MaxAgeSeconds: 600)]);
        var cors = h.Requests.Last(r => r.Method == HttpMethod.Put).Body!;
        Assert.Contains("\"allowed\":{\"origins\":[\"https://app.example.com\"],\"methods\":[\"GET\",\"HEAD\"],\"headers\":[\"Content-Type\"]}", cors);
        Assert.Contains("\"maxAgeSeconds\":600", cors);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.R2.SetCorsAsync("assets", [new R2CorsRule(["https://app.example.com/path"], ["GET"])]));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.R2.SetCorsAsync("assets", [new R2CorsRule(["https://a.example.com"], ["TRACE"])]));

        await cf.R2.SetLifecycleAsync("assets", [new R2LifecycleRule("ia", Prefix: "logs/", InfrequentAccessAfter: TimeSpan.FromDays(30)), new R2LifecycleRule("old", DeleteAfter: TimeSpan.FromDays(90))], allowDeletion: true);
        var lifecycle = h.Requests.Last(r => r.Method == HttpMethod.Put).Body!;
        Assert.Contains("\"storageClassTransitions\":[{\"condition\":{\"type\":\"Age\",\"maxAge\":2592000},\"storageClass\":\"InfrequentAccess\"}]", lifecycle);
        Assert.Contains("\"deleteObjectsTransition\":{\"condition\":{\"type\":\"Age\",\"maxAge\":7776000}}", lifecycle);
    }

    // ---------------------------------------------------------------- cache

    [Fact]
    public async Task Cache_rule_changes_only_one_rule_and_only_on_change()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/rulesets/phases/http_request_cache_settings/entrypoint", """{"id":"rs1","name":"default","kind":"zone","phase":"http_request_cache_settings","rules":[{"id":"x1","ref":"other","action":"set_cache_settings","expression":"true","enabled":true,"action_parameters":{"cache":false}}]}"""),
            R("POST", "/rulesets/rs1/rules", """{"id":"rs1","name":"default","kind":"zone","phase":"http_request_cache_settings","rules":[]}"""));
        var rule = new CacheRuleInput { Ref = "static", Expression = "(starts_with(http.request.uri.path, \"/static/\"))", Cache = true, EdgeTtl = new("override_origin", 3600), BrowserTtl = new("respect_origin") };
        var (_, changed) = await cf.Cache.UpsertRuleAsync(rule);
        Assert.True(changed);
        var post = h.Requests.Single(r => r.Method == HttpMethod.Post);
        Assert.Contains("\"action\":\"set_cache_settings\"", post.Body);
        Assert.Contains("\"edge_ttl\":{\"mode\":\"override_origin\",\"default\":3600}", post.Body);
        Assert.Contains("\"browser_ttl\":{\"mode\":\"respect_origin\"}", post.Body);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Put);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "none", Expression = "http.host eq \"a\"" }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "ttl", Expression = "http.host eq \"a\"", EdgeTtl = new("override_origin") }));
    }

    [Fact]
    public async Task Purge_is_split_into_requests_of_100_and_inputs_are_checked()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responder = (_, _) => Ok("""{"id":"p1"}""");
        var urls = Enumerable.Range(0, 250).Select(i => $"https://example.com/a{i}.css").ToList();
        var ids = await cf.Cache.PurgeUrlsAsync(urls);
        Assert.Equal(3, ids.Count);
        Assert.Equal(3, h.Requests.Count);
        Assert.All(h.Requests, r => Assert.EndsWith("/zones/zone1/purge_cache", r.Url));
        Assert.Equal(100, JsonNode.Parse(h.Requests[0].Body!)!["files"]!.AsArray().Count);
        Assert.Equal(50, JsonNode.Parse(h.Requests[2].Body!)!["files"]!.AsArray().Count);
        h.Requests.Clear();
        foreach (var bad in new Func<Task>[]
                 {
                     () => cf.Cache.PurgeUrlsAsync(["https://user:pass@example.com/a"]), () => cf.Cache.PurgeUrlsAsync(["/relative"]),
                     () => cf.Cache.PurgeHostsAsync(["*.example.com"]), () => cf.Cache.PurgeTagsAsync(["a,b"]), () => cf.Cache.PurgePrefixesAsync(["https://example.com/x"]),
                     () => cf.Cache.PurgeUrlsAsync([]),
                 })
            await Assert.ThrowsAsync<ArgumentException>(bad);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Cache.PurgeUrlsAsync(Enumerable.Range(0, 1001).Select(i => $"https://example.com/{i}")));
        Assert.Empty(h.Requests);
        await cf.Cache.PurgeEverythingAsync(allowPurgeAll: true);
        Assert.Contains("\"purge_everything\":true", h.Requests.Single().Body);
    }

    [Fact]
    public async Task Cache_reserve_and_argo_billing_switches()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responder = (_, _) => Ok("""{"id":"cache_reserve","value":"off","editable":true}""");
        await cf.Cache.SetCacheReserveAsync(false);
        await cf.Argo.SetSmartRoutingAsync(false);
        Assert.Equal(2, h.Requests.Count);
        Assert.Contains("\"value\":\"off\"", h.Requests[0].Body);
        Assert.Contains("WARNING", cf.Argo.PreviewSetSmartRouting(true).Summary);
        Assert.Equal("off", (await cf.Cache.GetCacheReserveAsync()).Value);
    }

    // ---------------------------------------------------------------- load balancing

    private static string PoolJson(string id, string name, bool enabled = true, string? monitor = null, bool? healthy = null) =>
        $$"""{"id":"{{id}}","name":"{{name}}","enabled":{{(enabled ? "true" : "false")}},{{(monitor is null ? "" : $"\"monitor\":\"{monitor}\",")}}{{(healthy is null ? "" : $"\"healthy\":{(healthy.Value ? "true" : "false")},")}}"origins":[{"name":"o1","address":"203.0.113.10","enabled":true,"weight":1}]}""";

    private static string BalancerJson(string id, string name, bool enabled, params string[] pools) =>
        $$"""{"id":"{{id}}","name":"{{name}}","enabled":{{(enabled ? "true" : "false")}},"proxied":true,"default_pools":[{{string.Join(",", pools.Select(p => "\"" + p + "\""))}}],"fallback_pool":"{{pools[0]}}"}""";

    [Fact]
    public async Task Last_healthy_pool_is_protected_from_being_disabled()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            R("GET", "/load_balancers/pools/p1", PoolJson("p1", "eu")),
            R("GET", "/load_balancers/pools", $"[{PoolJson("p1", "eu")},{PoolJson("p2", "us", healthy: false)}]"),
            R("GET", "/zones/zone1/load_balancers", $"[{BalancerJson("lb1", "lb.example.com", true, "p1", "p2")}]"),
            R("PATCH", "/load_balancers/pools/p1", PoolJson("p1", "eu", enabled: false)));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.SetPoolEnabledAsync("p1", false));
        Assert.Contains("last healthy pool of lb.example.com", ex.Message);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);

        var (pool, changed) = await cf.LoadBalancing.SetPoolEnabledAsync("p1", false, allowLastHealthyPool: true);
        Assert.True(changed);
        Assert.False(pool.Enabled);
        Assert.Single(h.Requests, r => r.Method == HttpMethod.Patch);
    }

    [Fact]
    public async Task Pool_can_be_disabled_when_another_healthy_pool_remains()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            R("GET", "/load_balancers/pools/p2/health", """{"pool_id":"p2","pop_health":{"FRA":{"healthy":true}}}"""),
            R("GET", "/load_balancers/pools/p1", PoolJson("p1", "eu")),
            R("GET", "/load_balancers/pools", $"[{PoolJson("p1", "eu")},{PoolJson("p2", "us", monitor: "m1")}]"),
            R("GET", "/zones/zone1/load_balancers", $"[{BalancerJson("lb1", "lb.example.com", true, "p1", "p2")}]"),
            R("PATCH", "/load_balancers/pools/p1", PoolJson("p1", "eu", enabled: false)));
        var (_, changed) = await cf.LoadBalancing.SetPoolEnabledAsync("p1", false);
        Assert.True(changed);

        Route(h, R("GET", "/load_balancers/pools/p1", PoolJson("p1", "eu", enabled: false)));
        h.Requests.Clear();
        var (_, again) = await cf.LoadBalancing.SetPoolEnabledAsync("p1", false);
        Assert.False(again);
        Assert.Single(h.Requests);
    }

    [Fact]
    public async Task Pool_used_by_a_load_balancer_outside_the_zone_cannot_be_checked_and_is_refused()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb9","resource_name":"other-zone.example.net"}]"""),
            R("GET", "/load_balancers/pools/p1", PoolJson("p1", "eu")),
            R("GET", "/load_balancers/pools", $"[{PoolJson("p1", "eu")},{PoolJson("p2", "us")}]"),
            R("GET", "/zones/zone1/load_balancers", "[]"));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.SetPoolEnabledAsync("p1", false));
        Assert.Contains("outside zone zone1", ex.Message);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);
    }

    [Fact]
    public async Task Disabling_the_last_enabled_origin_counts_as_taking_the_pool_out()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            R("GET", "/load_balancers/pools/p1", PoolJson("p1", "eu")),
            R("GET", "/load_balancers/pools", $"[{PoolJson("p1", "eu")}]"),
            R("GET", "/zones/zone1/load_balancers", $"[{BalancerJson("lb1", "lb.example.com", true, "p1")}]"),
            R("PATCH", "/load_balancers/pools/p1", PoolJson("p1", "eu")));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.SetOriginEnabledAsync("p1", "o1", false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.RemoveOriginAsync("p1", "o1"));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);
        await cf.LoadBalancing.SetOriginEnabledAsync("p1", "o1", false, allowLastHealthyPool: true);
        var patch = h.Requests.Single(r => r.Method == HttpMethod.Patch);
        Assert.Contains("\"enabled\":false", patch.Body);
        Assert.Contains("\"name\":\"o1\"", patch.Body);
    }

    [Fact]
    public async Task Active_load_balancer_is_only_disabled_or_deleted_with_the_switch()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/zones/zone1/load_balancers/lb1", BalancerJson("lb1", "lb.example.com", true, "p1")),
            R("PATCH", "/zones/zone1/load_balancers/lb1", BalancerJson("lb1", "lb.example.com", false, "p1")), R("DELETE", "/zones/zone1/load_balancers/lb1", """{"id":"lb1"}"""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.SetLoadBalancerEnabledAsync("lb1", false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.RemoveLoadBalancerAsync("lb1"));
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        Assert.True(await cf.LoadBalancing.RemoveLoadBalancerAsync("lb1", allowDeleteActive: true));
        var (_, changed) = await cf.LoadBalancing.SetLoadBalancerEnabledAsync("lb1", false, allowDisableActive: true);
        Assert.True(changed);
    }

    [Fact]
    public async Task Pool_and_monitor_in_use_are_not_deleted()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            R("GET", "/monitors/m1/references", """[{"resource_type":"pool","resource_id":"p1","resource_name":"eu"}]"""),
            R("GET", "/monitors/m2/references", "[]"), R("DELETE", "/monitors/m2", """{"id":"m2"}"""));
        var pool = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.RemovePoolAsync("p1"));
        Assert.Contains("lb.example.com", pool.Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.LoadBalancing.RemoveMonitorAsync("m1"));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
        Assert.True(await cf.LoadBalancing.RemoveMonitorAsync("m2"));
    }

    [Fact]
    public async Task Monitor_header_values_are_redacted_in_models_and_previews()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var echo = $$$"""{"id":"m1","type":"https","interval":60,"header":{"Authorization":["Bearer {{{SecretMarker}}}"],"Host":["origin.example.com"]}}""";
        h.Responses.Enqueue(Ok(echo));
        var created = await cf.LoadBalancing.CreateMonitorAsync(new LbMonitorInput { Path = "/health", Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer " + SecretMarker } });
        Assert.Contains(SecretMarker, h.Requests[0].Body);
        var text = JsonSerializer.Serialize(created, CloudflareJson.Options);
        Assert.DoesNotContain(SecretMarker, text);
        Assert.DoesNotContain("origin.example.com", text);
        Assert.Contains("Authorization", text);
        h.Responses.Enqueue(Ok($"[{echo}]"));
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(await cf.LoadBalancing.ListMonitorsAsync(), CloudflareJson.Options));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => cf.LoadBalancing.CreateMonitorAsync(new LbMonitorInput { Interval = 60, Timeout = 60 }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.LoadBalancing.CreateMonitorAsync(new LbMonitorInput { Headers = new Dictionary<string, string> { ["X"] = "a\r\nInjected: 1" } }));
    }

    [Fact]
    public async Task Load_balancer_and_pool_inputs_are_checked_and_ensure_is_idempotent()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/zones/zone1/load_balancers", $"[{BalancerJson("lb1", "lb.example.com", true, "p1")}]"), R("GET", "/load_balancers/pools", $"[{PoolJson("p1", "eu")}]"));
        var (lb, created) = await cf.LoadBalancing.EnsureLoadBalancerAsync(new LoadBalancerInput { Name = "LB.example.com", DefaultPools = ["p1"], FallbackPool = "p1" });
        Assert.False(created);
        Assert.Equal("lb1", lb.Id);
        var (pool, poolCreated) = await cf.LoadBalancing.EnsurePoolAsync(new LbPoolInput { Name = "eu", Origins = [new("o1", "203.0.113.10")] });
        Assert.False(poolCreated);
        Assert.Equal("p1", pool.Id);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Post);
        foreach (var bad in new Func<Task>[]
                 {
                     () => cf.LoadBalancing.EnsureLoadBalancerAsync(new LoadBalancerInput { Name = "lb.example.com", DefaultPools = ["p1"], FallbackPool = "p1", SteeringPolicy = "chaos" }),
                     () => cf.LoadBalancing.EnsureLoadBalancerAsync(new LoadBalancerInput { Name = "lb.example.com", DefaultPools = ["p1"], FallbackPool = "p1", Ttl = 60 }),
                     () => cf.LoadBalancing.EnsureLoadBalancerAsync(new LoadBalancerInput { Name = "lb.example.com", DefaultPools = [], FallbackPool = "p1" }),
                     () => cf.LoadBalancing.EnsurePoolAsync(new LbPoolInput { Name = "eu", Origins = [new("o1", "203.0.113.10", Enabled: false)] }),
                     () => cf.LoadBalancing.EnsurePoolAsync(new LbPoolInput { Name = "eu", Origins = [new("o1", "not an address")] }),
                     () => cf.LoadBalancing.EnsurePoolAsync(new LbPoolInput { Name = "eu", Origins = [new("o1", "203.0.113.10", Weight: 2)] }),
                 })
        {
            h.Requests.Clear();
            await Assert.ThrowsAnyAsync<ArgumentException>(bad);
            Assert.Empty(h.Requests);
        }
    }

    // ---------------------------------------------------------------- Spectrum

    [Fact]
    public async Task Spectrum_app_is_ensured_and_management_ports_need_the_switch()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/spectrum/apps", """[{"id":"a1","protocol":"tcp/8443","dns":{"type":"CNAME","name":"tcp.example.com"}}]"""));
        var input = new SpectrumAppInput { Hostname = "tcp.example.com", Protocol = "tcp/8443", OriginDirect = ["tcp://203.0.113.10:8443"] };
        var (app, created) = await cf.Spectrum.EnsureAppAsync(input);
        Assert.False(created);
        Assert.Equal("a1", app.Id);
        h.Requests.Clear();
        await Refused(h, () => cf.Spectrum.EnsureAppAsync(new SpectrumAppInput { Hostname = "db.example.com", Protocol = "tcp/3306", OriginDirect = ["tcp://203.0.113.10:3306"] }));
        await Refused(h, () => cf.Spectrum.EnsureAppAsync(new SpectrumAppInput { Hostname = "range.example.com", Protocol = "tcp/20-30", OriginDirect = ["tcp://203.0.113.10:20"] }));
        Assert.Contains("tcp/8000-8100", cf.Spectrum.PreviewCreateApp(new SpectrumAppInput { Hostname = "range.example.com", Protocol = "tcp/8000-8100", OriginDirect = ["tcp://203.0.113.10:8000"] }).BodyJson);
        await Refused(h, () => cf.Spectrum.EnsureAppAsync(new SpectrumAppInput { Hostname = "x.example.com", Protocol = "tcp/8443" }));
    }

    // ---------------------------------------------------------------- errors, retries, secrets

    [Fact]
    public async Task Rate_limit_is_retried_and_plan_errors_become_NotEntitled()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.TooManyRequests, 971, "Too many requests"));
        h.Responses.Enqueue(Ok("""[{"id":"ns1","title":"cache"}]"""));
        Assert.Single(await cf.Kv.ListNamespacesAsync());
        Assert.Equal(2, h.Requests.Count);

        h.Requests.Clear();
        h.Responder = (req, _) => req.Method == HttpMethod.Get ? Ok("[]") : Error(HttpStatusCode.Forbidden, 1001, "Load balancing is not entitled on this zone");
        var ex = await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.LoadBalancing.EnsurePoolAsync(new LbPoolInput { Name = "eu", Origins = [new("o1", "203.0.113.10")] }));
        Assert.DoesNotContain(Token, ex.Message);

        h.Responder = (_, _) => Error(HttpStatusCode.BadRequest, 1004, "Spectrum is not available on your plan");
        await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.Spectrum.UpdateAppAsync("a1", new SpectrumAppInput { Hostname = "tcp.example.com", Protocol = "tcp/8443", OriginDirect = ["tcp://203.0.113.10:8443"] }));

        h.Responder = (_, _) => Error(HttpStatusCode.Forbidden, 10000, "Authentication error");
        var auth = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.D1.ListDatabasesAsync());
        Assert.IsNotType<CloudflareNotEntitledException>(auth);
        Assert.DoesNotContain(Token, auth.Message);
    }

    [Fact]
    public async Task Post_is_not_repeated_after_a_server_error_but_put_is()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.BadGateway, 0, "bad gateway"));
        h.Responses.Enqueue(Ok("""{"id":"p1"}"""));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Cache.PurgeEverythingAsync(allowPurgeAll: true));
        Assert.Single(h.Requests);

        h.Requests.Clear();
        h.Responses.Clear();
        h.Responses.Enqueue(Error(HttpStatusCode.BadGateway, 0, "bad gateway"));
        h.Responses.Enqueue(Ok("""{"name":"cache","id":"ns1","title":"renamed"}"""));
        await cf.Kv.RenameNamespaceAsync("ns1", "renamed");
        Assert.Equal(2, h.Requests.Count);
    }

    [Fact]
    public void Client_exposes_the_new_clients()
    {
        var (cf, _, _) = FakeHandler.Create();
        ICloudflareClient client = cf;
        Assert.NotNull(client.Kv);
        Assert.NotNull(client.D1);
        Assert.NotNull(client.Queues);
        Assert.NotNull(client.Cache);
        Assert.NotNull(client.Argo);
        Assert.NotNull(client.LoadBalancing);
        Assert.NotNull(client.Spectrum);
        Assert.Equal("https://acc.r2.cloudflarestorage.com", cf.R2.S3Endpoint("acc"));
    }
}
