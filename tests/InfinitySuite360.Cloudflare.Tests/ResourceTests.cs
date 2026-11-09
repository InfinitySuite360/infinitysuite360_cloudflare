using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

public class ResourceTests
{
    [Fact]
    public async Task Dns_upsert_creates_updates_or_refuses_ambiguity()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var input = new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = true };

        handler.Responses.Enqueue(FakeHandler.Ok("[]", """{"page":1,"per_page":500,"count":0,"total_count":0,"total_pages":0}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"new","type":"A","name":"app.example.com","content":"203.0.113.5","proxied":true}"""));
        Assert.Equal("new", (await cf.Dns.UpsertAsync(input)).Id);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Contains("\"proxied\":true", handler.Requests[1].Body);
        Assert.DoesNotContain("priority", handler.Requests[1].Body);

        handler.Requests.Clear();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"r1","type":"A","name":"app.example.com"}]""", """{"page":1,"per_page":500,"count":1,"total_count":1,"total_pages":1}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"r1"}"""));
        await cf.Dns.UpsertAsync(input);
        Assert.Equal(HttpMethod.Put, handler.Requests[1].Method);
        Assert.EndsWith("/dns_records/r1", handler.Requests[1].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"r1"},{"id":"r2"}]""", """{"page":1,"per_page":500,"count":2,"total_count":2,"total_pages":1}"""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Dns.UpsertAsync(input));
    }

    [Fact]
    public async Task Tunnel_configuration_adds_catch_all_and_uses_camelCase()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"tunnel_id":"t1","version":2}"""));
        var origin = JsonSerializer.SerializeToElement(new { noTLSVerify = true });
        await cf.Tunnels.PutConfigurationAsync("t1", [new TunnelIngressRule { Hostname = "app.example.com", Service = "https://localhost:8443", OriginRequest = origin }]);
        var body = JsonDocument.Parse(handler.Requests[0].Body!).RootElement.GetProperty("config").GetProperty("ingress");
        Assert.Equal(2, body.GetArrayLength());
        Assert.True(body[0].GetProperty("originRequest").GetProperty("noTLSVerify").GetBoolean());
        Assert.Equal("http_status:404", body[1].GetProperty("service").GetString());
        Assert.Contains("/accounts/acc1/cfd_tunnel/t1/configurations", handler.Requests[0].Url);
    }

    [Fact]
    public async Task Ruleset_upsert_by_ref_keeps_foreign_rules()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""
            {"id":"rs","phase":"http_request_firewall_custom","rules":[
              {"id":"1","ref":"foreign","action":"block","expression":"ip.src eq 1.1.1.1","version":"3","last_updated":"2026-01-01T00:00:00Z"},
              {"id":"2","ref":"ours","action":"log","expression":"true"}]}
            """));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"rs","rules":[]}"""));
        await cf.Rulesets.UpsertRuleByRefAsync(RulesetPhases.FirewallCustom,
            new RulesetRule { Ref = "ours", Action = "managed_challenge", Expression = "http.request.uri.path eq \"/login\"" });

        var rules = JsonDocument.Parse(handler.Requests[1].Body!).RootElement.GetProperty("rules");
        Assert.Equal(2, rules.GetArrayLength());
        Assert.Equal("foreign", rules[0].GetProperty("ref").GetString());
        Assert.False(rules[0].TryGetProperty("version", out _));
        Assert.Equal("managed_challenge", rules[1].GetProperty("action").GetString());
        Assert.Equal(HttpMethod.Put, handler.Requests[1].Method);
    }

    [Fact]
    public async Task Missing_phase_entrypoint_returns_null()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Json("""{"success":false,"errors":[{"code":10003,"message":"could not find entrypoint ruleset"}]}""", HttpStatusCode.NotFound));
        Assert.Null(await cf.Rulesets.GetPhaseEntrypointAsync(RulesetPhases.RateLimit));
    }

    [Fact]
    public async Task R2_create_uses_camelCase_body_and_unwraps_bucket_list()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"name":"backups"}"""));
        await cf.R2.CreateBucketAsync("backups", locationHint: "weur");
        Assert.Equal("""{"name":"backups","locationHint":"weur"}""", handler.Requests[0].Body);

        handler.Responses.Enqueue(FakeHandler.Ok("""{"buckets":[{"name":"a"},{"name":"b"}]}"""));
        Assert.Equal(2, (await cf.R2.ListBucketsAsync()).Count);
        Assert.Equal("https://acc1.r2.cloudflarestorage.com", cf.R2.S3Endpoint());
    }

    [Fact]
    public void Analytics_parsing()
    {
        var traffic = AnalyticsClient.ParseTraffic(JsonDocument.Parse("""
            {"data":{"viewer":{"zones":[{"httpRequests1dGroups":[{"sum":{"requests":100,"threats":5,"cachedRequests":40,"bytes":1000}},{"sum":{"requests":50,"threats":0,"cachedRequests":10,"bytes":500}}]}]}}}
            """).RootElement);
        Assert.Equal(150, traffic.Requests);
        Assert.Equal(5, traffic.Threats);
        Assert.Equal(1500, traffic.Bytes);

        var events = AnalyticsClient.ParseEvents(JsonDocument.Parse("""
            {"data":{"viewer":{"zones":[{"firewallEventsAdaptive":[{"action":"block","clientCountryName":"DE","clientIP":"198.51.100.23","clientRequestHTTPHost":"example.com","clientRequestPath":"/wp-login.php","datetime":"2026-11-09T10:00:00Z","ruleId":"r","source":"firewallCustom"}]}]}}}
            """).RootElement);
        Assert.Single(events);
        Assert.Equal("198.51.100.x", events[0].MaskedIp);
        Assert.Equal("2001:db8:1::", SecurityEvent.MaskIp("2001:db8:1:2::5"));
    }

    [Fact]
    public void Access_service_tokens_due_for_rotation()
    {
        var now = new DateTimeOffset(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
        var due = AccessClient.DueForRotation([
            new AccessServiceToken { Id = "soon", ExpiresAt = now.AddDays(10) },
            new AccessServiceToken { Id = "later", ExpiresAt = now.AddDays(200) },
            new AccessServiceToken { Id = "forever" },
        ], now);
        Assert.Equal(["soon"], due.Select(t => t.Id));
    }
}
