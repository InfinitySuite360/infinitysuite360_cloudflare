using System.Net;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Page Shield and API Shield clients (0.4.0). Fake handler only: no network, no real token.</summary>
public class ShieldTests
{
    private const string Info = """{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}""";

    [Fact]
    public async Task Page_shield_scripts_use_filter_and_flag_malicious_by_reported_fields()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"s1","url":"https://evil.example/x.js","host":"evil.example","url_reported_malicious":true,"first_seen_at":"2026-11-01T10:00:00Z","js_integrity_score":3,"page_urls":["https://a.example/"]},{"id":"s2","url":"https://cdn.example/y.js","host":"cdn.example","url_contains_cdn_cgi_path":false}]""", Info));
        var list = await cf.PageShield.ListScriptsAsync(new PageShieldQuery { Status = "active,infrequent", ExcludeCdnCgi = true, PrioritizeMalicious = true });
        Assert.Equal(2, list.Count);
        Assert.True(list[0].IsMalicious);
        Assert.False(list[1].IsMalicious);
        Assert.Equal(3, list[0].JsIntegrityScore);
        var url = h.Requests[0].Url;
        Assert.Contains("/zones/zone1/page_shield/scripts?", url);
        Assert.Contains("exclude_cdn_cgi=true", url);
        Assert.Contains("prioritize_malicious=true", url);
        Assert.Contains("status=active", url);
        Assert.DoesNotContain("hosts=", url);
        Assert.Equal("Bearer secret-token-123", h.Requests[0].Auth);
    }

    [Fact]
    public async Task Page_shield_list_stops_at_MaxItems()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"1"},{"id":"2"},{"id":"3"}]""", """{"page":1,"per_page":100,"count":3,"total_count":9,"total_pages":3}"""));
        var list = await cf.PageShield.ListConnectionsAsync(new PageShieldQuery { MaxItems = 2 });
        Assert.Equal(2, list.Count);
        Assert.Single(h.Requests);
    }

    [Fact]
    public async Task Page_shield_cookies_and_settings_are_typed()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"c1","name":"sid","host":"a.example","type":"first_party","secure_attribute":true,"http_only_attribute":false,"same_site_attribute":"lax","max_age_attribute":3600}]""", Info));
        var c = Assert.Single(await cf.PageShield.ListCookiesAsync());
        Assert.Equal("lax", c.SameSiteAttribute);
        Assert.False(c.HttpOnlyAttribute);
        h.Responses.Enqueue(FakeHandler.Ok("""{"enabled":true,"updated_at":"2026-11-01T00:00:00Z","use_cloudflare_reporting_endpoint":true,"use_connection_url_path":false}"""));
        var s = await cf.PageShield.GetSettingsAsync();
        Assert.True(s.Enabled);
        Assert.True(s.UseCloudflareReportingEndpoint);
    }

    [Fact]
    public async Task Page_shield_writes_are_blocked_without_AllowWrites_and_preview_sends_nothing()
    {
        var (cf, h, _) = FakeHandler.Create();
        var input = new PageShieldPolicyInput { Action = "log", Description = "Report only", Expression = "(http.host eq \"a.example\")", Value = "script-src 'self'" };
        var preview = cf.PageShield.PreviewCreatePolicy(input);
        Assert.Equal("POST", preview.Method);
        Assert.Equal("zones/zone1/page_shield/policies", preview.Path.TrimStart('/'));
        Assert.Contains("\"action\": \"log\"", preview.BodyJson);
        Assert.DoesNotContain("secret-token", preview.BodyJson + preview.Summary + preview.Path);
        Assert.Empty(h.Requests);
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.PageShield.CreatePolicyAsync(input));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.PageShield.SetSettingsAsync(enabled: true));
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Page_shield_policy_create_sends_body_and_rejects_bad_action_locally()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"p1","action":"log","description":"d","enabled":true,"expression":"e","value":"v"}"""));
        var p = await cf.PageShield.CreatePolicyAsync(new PageShieldPolicyInput { Action = "log", Description = "d", Expression = "e", Value = "v" });
        Assert.Equal("p1", p.Id);
        Assert.Equal(HttpMethod.Post, h.Requests[0].Method);
        Assert.Contains("\"value\":\"v\"", h.Requests[0].Body);
        Assert.Throws<ArgumentException>(() => cf.PageShield.PreviewCreatePolicy(new PageShieldPolicyInput { Action = "block" }));
        Assert.Single(h.Requests);
    }

    [Fact]
    public async Task Api_shield_operations_discovery_and_schema_listing()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Ok("""[{"operation_id":"o1","method":"GET","host":"api.example.com","endpoint":"/v1/users/{var1}","last_updated":"2026-11-01T00:00:00Z","features":{"thresholds":{"request_count":5}}}]""", Info));
        var ops = await cf.ApiShield.ListOperationsAsync(new ApiOperationQuery { Host = "api.example.com", Feature = "thresholds" });
        Assert.Equal("/v1/users/{var1}", ops[0].Endpoint);
        Assert.NotNull(ops[0].Features);
        Assert.Contains("host=api.example.com", h.Requests[0].Url);
        Assert.Contains("feature=thresholds", h.Requests[0].Url);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"d1","method":"POST","host":"api.example.com","endpoint":"/v1/orders","state":"review","origin":["ML"]}]""", Info));
        var disc = await cf.ApiShield.ListDiscoveredOperationsAsync(new ApiOperationQuery { State = "review" });
        Assert.Equal("review", disc[0].State);
        Assert.Contains("/api_gateway/discovery/operations?", h.Requests[1].Url);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"schema_id":"sc1","name":"MT5GW api","kind":"openapi_v3","validation_enabled":true,"created_at":"2026-11-01T00:00:00Z"}]""", Info));
        var schemas = await cf.ApiShield.ListSchemasAsync();
        Assert.True(schemas[0].ValidationEnabled);
        Assert.Null(schemas[0].Source);
        Assert.Contains("omit_source=true", h.Requests[2].Url);
    }

    [Fact]
    public async Task Api_shield_actions_are_validated_and_writes_need_AllowWrites()
    {
        var (cf, h, _) = FakeHandler.Create();
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewSetDefaultAction("drop"));
        var preview = cf.ApiShield.PreviewSetOperationAction("o1", "log");
        Assert.Equal("PUT", preview.Method);
        Assert.Contains("schema_validation/settings/operations/o1", preview.Path);
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.ApiShield.SetDefaultActionAsync("log"));
        Assert.Empty(h.Requests);

        var (cf2, h2, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h2.Responses.Enqueue(FakeHandler.Ok("""{"validation_default_mitigation_action":"log"}"""));
        var s = await cf2.ApiShield.SetDefaultActionAsync("log");
        Assert.Equal("log", s.ValidationDefaultMitigationAction);
        Assert.Equal(HttpMethod.Patch, h2.Requests[0].Method);
    }

    [Fact]
    public async Task Api_shield_token_validation_and_mtls_reads()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"c1","title":"JWT","token_type":"JWT","token_sources":["http.request.headers[\"authorization\"][0]"]}]""", Info));
        Assert.Equal("JWT", (await cf.ApiShield.ListTokenValidationConfigsAsync())[0].TokenType);
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"r1","title":"rule","action":"log","enabled":true,"expression":"is_jwt_valid(\"c1\")"}]""", Info));
        Assert.Equal("log", (await cf.ApiShield.ListTokenValidationRulesAsync())[0].Action);
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"cc1","status":"active","common_name":"gw","fingerprint_sha256":"ab","expires_on":"2027-01-01T00:00:00Z"}]""", Info));
        Assert.Equal("active", (await cf.ApiShield.ListClientCertificatesAsync())[0].Status);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    [Fact]
    public async Task Plan_or_permission_errors_surface_without_the_token()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Json("""{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}""", HttpStatusCode.Forbidden));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.PageShield.ListPoliciesAsync());
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.DoesNotContain("secret-token-123", ex.Message);
    }

    [Fact]
    public async Task Rate_limit_is_retried_for_reads()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(FakeHandler.Json("""{"success":false,"errors":[{"code":971,"message":"rate"}]}""", (HttpStatusCode)429));
        h.Responses.Enqueue(FakeHandler.Ok("""{"enabled":false,"use_cloudflare_reporting_endpoint":true,"use_connection_url_path":false}"""));
        Assert.False((await cf.PageShield.GetSettingsAsync()).Enabled);
        Assert.Equal(2, h.Requests.Count);
    }
}
