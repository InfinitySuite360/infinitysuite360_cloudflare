#pragma warning disable CS0618 // the obsolete methods are tested on purpose: since 0.7.1 they take the guarded paths
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Findings of the independent security review of 0.7.0, fixed in 0.7.1. Fake handler only: no network, no real token.</summary>
public class SecurityHardeningTests
{
    private static HttpResponseMessage Ok(string result, string? info = null) => FakeHandler.Ok(result, info);

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    /// <summary>Answers by method and URL fragment (first match); every other request is answered with 404 and a marker.</summary>
    private static void Route(FakeHandler h, params (string Method, string Fragment, string Result)[] routes) =>
        h.Responder = (req, _) =>
        {
            var url = req.RequestUri!.ToString();
            foreach (var (method, fragment, result) in routes)
                if (req.Method.Method == method && url.Contains(fragment, StringComparison.Ordinal)) return Ok(result);
            return Error(HttpStatusCode.NotFound, 7003, "UNEXPECTED-REQUEST " + req.Method + " " + url);
        };

    /// <summary>A local refusal of a risky option: not the write guard, and nothing written (reads may have happened when <paramref name="noRequests"/> is false).</summary>
    private static async Task Refused(FakeHandler h, Func<Task> action, bool noRequests = true)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        if (noRequests) Assert.Empty(h.Requests);
        else Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    // =================================================================================================================== H-2 / N-2

    private const string PoolWithExtras = """
        {"id":"p1","name":"eu","enabled":true,"minimum_origins":1,"monitor":"m1","origins":[
          {"name":"o1","address":"203.0.113.10","enabled":true,"weight":1,"header":{"Host":["app.example.com"]},"virtual_network_id":"vnet-1"},
          {"name":"o2","address":"203.0.113.11","enabled":true,"weight":0.5,"header":{"Host":["api.example.com"],"X-Origin":["b"]},"virtual_network_id":"vnet-2","port":8443}]}
        """;

    [Fact]
    public async Task Changing_one_origin_keeps_headers_and_virtual_networks_of_every_origin()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, ("GET", "load_balancers/pools/p1", PoolWithExtras), ("PATCH", "load_balancers/pools/p1", PoolWithExtras));
        var (_, changed) = await cf.LoadBalancing.SetOriginEnabledAsync("p1", "o1", false, allowLastHealthyPool: true);
        Assert.True(changed);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!["origins"]!.AsArray();
        Assert.Equal(2, body.Count);
        Assert.False(body[0]!["enabled"]!.GetValue<bool>());
        Assert.Equal("app.example.com", body[0]!["header"]!["Host"]![0]!.GetValue<string>());
        Assert.Equal("vnet-1", body[0]!["virtual_network_id"]!.GetValue<string>());
        Assert.Equal("vnet-2", body[1]!["virtual_network_id"]!.GetValue<string>());
        Assert.Equal("b", body[1]!["header"]!["X-Origin"]![0]!.GetValue<string>());
        Assert.Equal(8443, body[1]!["port"]!.GetValue<int>());
        Assert.Equal(0.5, body[1]!["weight"]!.GetValue<double>());

        // Upsert of o2 without HostHeader: header and virtual network stay, the address changes.
        await cf.LoadBalancing.UpsertOriginAsync("p1", new LbOriginInput("o2", "203.0.113.12", Weight: 0.5), allowLastHealthyPool: true);
        var upserted = JsonNode.Parse(h.Requests[^1].Body!)!["origins"]!.AsArray()[1]!;
        Assert.Equal("203.0.113.12", upserted["address"]!.GetValue<string>());
        Assert.Equal("vnet-2", upserted["virtual_network_id"]!.GetValue<string>());
        Assert.Equal("api.example.com", upserted["header"]!["Host"]![0]!.GetValue<string>());
        Assert.Equal("b", upserted["header"]!["X-Origin"]![0]!.GetValue<string>());
    }

    [Fact]
    public async Task A_pool_without_monitor_or_health_report_is_not_counted_as_healthy_fallback()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            ("GET", "load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            ("GET", "load_balancers/pools/p1", """{"id":"p1","name":"eu","enabled":true,"monitor":"m1","origins":[{"name":"o1","address":"203.0.113.10","enabled":true}]}"""),
            ("GET", "load_balancers/pools", """[{"id":"p1","name":"eu","enabled":true,"monitor":"m1"},{"id":"p2","name":"us","enabled":true}]"""),
            ("GET", "zones/zone1/load_balancers", """[{"id":"lb1","name":"lb.example.com","enabled":true,"default_pools":["p1","p2"],"fallback_pool":"p2"}]"""));
        await Refused(h, () => cf.LoadBalancing.SetPoolEnabledAsync("p1", false), noRequests: false);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);
    }

    [Fact]
    public async Task An_origin_with_weight_zero_counts_as_unusable_for_the_last_healthy_check()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            ("GET", "load_balancers/pools/p1/references", """[{"resource_type":"load_balancer","resource_id":"lb1","resource_name":"lb.example.com"}]"""),
            ("GET", "load_balancers/pools/p1", """{"id":"p1","name":"eu","enabled":true,"origins":[{"name":"o1","address":"203.0.113.10","enabled":true,"weight":1}]}"""),
            ("GET", "load_balancers/pools", """[{"id":"p1","name":"eu","enabled":true}]"""),
            ("GET", "zones/zone1/load_balancers", """[{"id":"lb1","name":"lb.example.com","enabled":true,"default_pools":["p1"],"fallback_pool":"p1"}]"""));
        await Refused(h, () => cf.LoadBalancing.UpsertOriginAsync("p1", new LbOriginInput("o1", "203.0.113.10", Weight: 0)), noRequests: false);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);
    }

    // =================================================================================================================== M-1

    [Fact]
    public async Task Obsolete_and_generic_methods_take_the_guarded_paths()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Refused(h, () => cf.Zones.PurgeEverythingAsync());
        await Refused(h, () => cf.Zones.PurgeHostsAsync(["https://example.com/"]));
        await Refused(h, () => cf.Zones.PurgePrefixesAsync(["https://example.com/assets/"]));
        await Refused(h, () => cf.Zones.SetSettingAsync(ZoneSettingIds.AlwaysUseHttps, "off"));
        await Refused(h, () => cf.Zones.SetSettingAsync(ZoneSettingIds.MinTlsVersion, "1.3"));
        await Refused(h, () => cf.R2.DeleteBucketAsync("assets"));
        await Refused(h, () => cf.R2.PutLifecycleAsync("assets", new JsonObject { ["rules"] = new JsonArray(new JsonObject { ["id"] = "x", ["enabled"] = true, ["deleteObjectsTransition"] = new JsonObject() }) }));
        await Refused(h, () => cf.R2.PutCorsAsync("assets", new { rules = new[] { new { allowed = new { origins = new[] { "*" }, methods = new[] { "GET" } } } } }));
        await Refused(h, () => cf.R2.PutCorsAsync("assets", new { rules = new[] { new { allowed = new { origins = new[] { "https://*" }, methods = new[] { "GET" } } } } }));
        await Refused(h, () => cf.Workers.UploadModuleAsync("w", "export default {};"));
        await Refused(h, () => cf.Workers.DeleteScriptAsync("w"));
        await Refused(h, () => cf.Monitoring.DeleteLogpushJobAsync(1));

        // Allowed changes still go through.
        await cf.R2.PutCorsAsync("assets", new { rules = new[] { new { allowed = new { origins = new[] { "https://app.example.com" }, methods = new[] { "GET" } } } } });
        await cf.Zones.PurgeHostsAsync(["example.com"]);
        Assert.Equal(2, h.Requests.Count);
    }

    [Fact]
    public async Task Generic_zone_settings_refuse_weakening_after_reading_the_current_value()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, ("GET", "zones/zone1/settings", """[{"id":"ssl","value":"strict"},{"id":"min_tls_version","value":"1.2"}]"""), ("PATCH", "zones/zone1/settings", """{"id":"ssl","value":"strict"}"""));
        await Refused(h, () => cf.Zones.SetSettingAsync(ZoneSettingIds.Ssl, "off"), noRequests: false);
        await Refused(h, () => cf.Zones.SetSettingAsync(ZoneSettingIds.MinTlsVersion, "1.0"), noRequests: false);
        await Refused(h, () => cf.Zones.SetSettingsAsync(new Dictionary<string, object> { [ZoneSettingIds.Ssl] = "flexible", [ZoneSettingIds.Brotli] = "on" }), noRequests: false);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Patch);

        await cf.Zones.SetSettingAsync(ZoneSettingIds.Ssl, "strict");
        await cf.Zones.SetSettingAsync(ZoneSettingIds.Brotli, "on");
        Assert.Equal(2, h.Requests.Count(r => r.Method == HttpMethod.Patch));

        // With AllowWrites = false nothing is read either.
        var (ro, h2, _) = FakeHandler.Create();
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => ro.Zones.SetSettingAsync(ZoneSettingIds.Ssl, "off"));
        Assert.Empty(h2.Requests);
    }

    private const string ProxiedRecord = """{"id":"r1","type":"A","name":"app.example.com","content":"203.0.113.10","proxied":true,"proxiable":true,"ttl":1}""";

    [Fact]
    public async Task Dns_update_patch_and_upsert_never_unproxy_and_keep_proxied_when_not_set()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, ("GET", "dns_records/r1", ProxiedRecord), ("GET", "dns_records?", $"[{ProxiedRecord}]"), ("PUT", "dns_records/r1", ProxiedRecord), ("PATCH", "dns_records/r1", ProxiedRecord));
        var unproxy = new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.10", Proxied = false };
        await Refused(h, () => cf.Dns.UpdateAsync("r1", unproxy), noRequests: false);
        await Refused(h, () => cf.Dns.PatchAsync("r1", new { proxied = false }), noRequests: false);
        await Refused(h, () => cf.Dns.UpsertAsync(unproxy), noRequests: false);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        // M-6: proxied not set → the current value (true) is sent with the PUT.
        await cf.Dns.UpdateAsync("r1", new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.20" });
        Assert.Contains("\"proxied\":true", h.Requests[^1].Body);
        var (_, changed) = await cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.30" });
        Assert.True(changed);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        Assert.Contains("\"proxied\":true", h.Requests[^1].Body);

        // A patch without proxied needs no read.
        var before = h.Requests.Count;
        await cf.Dns.PatchAsync("r1", new { comment = "x" });
        Assert.Equal(before + 1, h.Requests.Count);
    }

    [Fact]
    public async Task Generic_rulesets_client_refuses_loosenings_compared_with_the_current_phase()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string current = """
            {"id":"rs1","phase":"http_request_firewall_custom","rules":[
            {"id":"a","ref":"admin","action":"block","expression":"(http.request.uri.path contains \"/admin\")","enabled":true},
            {"id":"b","ref":"office","action":"skip","expression":"(ip.src eq 198.51.100.1)","enabled":true,"action_parameters":{"ruleset":"current"}}]}
            """;
        Route(h, ("GET", "rulesets/phases/http_request_firewall_custom/entrypoint", current), ("GET", "rulesets/rs1", current), ("PUT", "entrypoint", current), ("PATCH", "rules/", current), ("POST", "rules", current));
        var skip = new RulesetRule { Ref = "new-skip", Action = "skip", Expression = "(http.host eq \"a.example.com\")" };
        var blockAll = new RulesetRule { Ref = "all", Action = "block", Expression = "(not false)" };
        await Refused(h, () => cf.Rulesets.UpsertRuleByRefAsync(RulesetPhases.FirewallCustom, skip), noRequests: false);
        await Refused(h, () => cf.Rulesets.UpsertRuleByRefAsync(RulesetPhases.FirewallCustom, blockAll), noRequests: false);
        await Refused(h, () => cf.Rulesets.RemoveRuleByRefAsync(RulesetPhases.FirewallCustom, "admin"), noRequests: false);
        await Refused(h, () => cf.Rulesets.PutPhaseEntrypointAsync(RulesetPhases.FirewallCustom, []), noRequests: false);
        await Refused(h, () => cf.Rulesets.AddRuleAsync("rs1", skip), noRequests: false);
        await Refused(h, () => cf.Rulesets.UpdateRuleAsync("rs1", "a", new RulesetRule { Ref = "admin", Action = "log", Expression = "(http.request.uri.path contains \"/admin\")" }), noRequests: false);
        await Refused(h, () => cf.Rulesets.DeleteRuleAsync("rs1", "a"), noRequests: false);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        // Adding a harmless rule re-sends the existing skip rule unchanged: allowed.
        await cf.Rulesets.UpsertRuleByRefAsync(RulesetPhases.FirewallCustom, new RulesetRule { Ref = "bots", Action = "managed_challenge", Expression = "(cf.client.bot)" });
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        Assert.Contains("\"office\"", h.Requests[^1].Body);
    }

    // =================================================================================================================== M-2 .. M-7

    [Fact]
    public async Task Cache_extra_parameters_cannot_override_the_guarded_members()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        foreach (var key in new[] { "cache", "edge_ttl", "browser_ttl" })
        {
            var extra = JsonSerializer.SerializeToElement(new Dictionary<string, object> { [key] = key == "cache" ? true : new { mode = "override_origin", @default = 31_536_000 } });
            await Refused(h, () => cf.Cache.UpsertRuleAsync(new CacheRuleInput { Ref = "all", Expression = "true", EdgeTtl = new("respect_origin"), ExtraParameters = extra }));
        }
    }

    [Theory]
    [InlineData("tcp://203.0.113.10:22", null)]
    [InlineData("tcp://203.0.113.10:3389", null)]
    [InlineData(null, 3306)]
    [InlineData(null, 6379)]
    public async Task Spectrum_checks_origin_ports_too(string? direct, int? originPort)
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var app = new SpectrumAppInput
        {
            Hostname = "tcp.example.com", Protocol = "tcp/8443", OriginDirect = direct is null ? null : [direct],
            OriginDnsName = direct is null ? "origin.example.com" : null, OriginPort = originPort,
        };
        await Refused(h, () => cf.Spectrum.EnsureAppAsync(app));
        await Refused(h, () => cf.Spectrum.UpdateAppAsync("a1", app));
    }

    [Theory]
    [InlineData("*", true)]
    [InlineData("https://*", true)]
    [InlineData("http://*", true)]
    [InlineData("https://*.com", true)]
    [InlineData("https://a*b.example.com", false)]
    [InlineData("https://*.*.example.com", false)]
    [InlineData("https://app.*.example.com", false)]
    public async Task R2_cors_wildcards_that_cover_every_site_need_allowAnyOrigin(string origin, bool anyOrigin)
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Refused(h, () => cf.R2.SetCorsAsync("assets", [new R2CorsRule([origin], ["GET"])]));
        if (anyOrigin) await cf.R2.SetCorsAsync("assets", [new R2CorsRule([origin], ["GET"])], allowAnyOrigin: true);
        else await Assert.ThrowsAsync<ArgumentException>(() => cf.R2.SetCorsAsync("assets", [new R2CorsRule([origin], ["GET"])], allowAnyOrigin: true));
        await cf.R2.SetCorsAsync("assets", [new R2CorsRule(["https://*.example.com"], ["GET"])]);
    }

    [Theory]
    [InlineData("PRAGMA user_version", D1SqlKind.ReadOnly)]
    [InlineData("PRAGMA main.table_info(users)", D1SqlKind.ReadOnly)]
    [InlineData("PRAGMA user_version(5)", D1SqlKind.Write)]
    [InlineData("PRAGMA user_version = 5", D1SqlKind.Write)]
    [InlineData("PRAGMA page_size(1024)", D1SqlKind.Write)]
    [InlineData("PRAGMA schema_version(1)", D1SqlKind.Destructive)]
    [InlineData("PRAGMA writable_schema = 1", D1SqlKind.Destructive)]
    [InlineData("PRAGMA journal_mode", D1SqlKind.Write)]
    [InlineData("DELETE FROM t WHERE 1", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE 1 = 1", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE ?", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE 'a' = 'a'", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE id = id", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE id = ? OR 1 = 1", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE abs(1) > 0", D1SqlKind.Destructive)]
    [InlineData("UPDATE t SET a = (SELECT b FROM u WHERE c = 1)", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE 1 OR id IN (SELECT id FROM u WHERE x = 1)", D1SqlKind.Destructive)]
    [InlineData("DELETE FROM t WHERE id = ? AND tenant = ?", D1SqlKind.Write)]
    [InlineData("DELETE FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)", D1SqlKind.Write)]
    [InlineData("CREATE TRIGGER tr AFTER INSERT ON a BEGIN DELETE FROM b; END", D1SqlKind.Destructive)]
    [InlineData("CREATE TRIGGER tr AFTER INSERT ON a BEGIN UPDATE b SET x = 1 WHERE id = new.id; END", D1SqlKind.Destructive)]
    [InlineData("CREATE TRIGGER tr AFTER INSERT ON a BEGIN INSERT INTO log VALUES (1); END", D1SqlKind.Write)]
    public void D1_classifies_pragma_forms_tautologies_and_triggers_conservatively(string sql, D1SqlKind expected) =>
        Assert.Equal(expected, D1Sql.Classify(sql));

    [Fact]
    public async Task Updating_the_own_api_token_needs_allowSelf()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, ("GET", "user/tokens/verify", """{"id":"t1","status":"active"}"""), ("PUT", "user/tokens/", """{"id":"t1","name":"ci","status":"active"}"""));
        var input = new ApiTokenInput
        {
            Name = "ci", ExpiresOn = DateTimeOffset.UtcNow.AddDays(30),
            Policies = [new ApiTokenPolicyInput { PermissionGroupIds = ["g1"], Resources = new JsonObject { [ApiTokenResources.Zone("zone1")] = "*" } }],
        };
        await Refused(h, () => cf.ApiTokens.UpdateAsync("t1", input), noRequests: false);
        Assert.Single(h.Requests);
        await cf.ApiTokens.UpdateAsync("t1", input, allowSelf: true);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        await cf.ApiTokens.UpdateAsync("t2-other", input);
    }

    // =================================================================================================================== M-8

    [Fact]
    public async Task Lock_out_and_loosening_methods_are_refused_without_their_switch_and_send_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Func<Task>[] refused =
        [
            () => cf.ApiShield.RevokeClientCertificateAsync("cc1"),
            () => cf.ApiShield.SetOverrideActionAsync("none"),
            () => cf.ApiShield.DeleteTokenValidationConfigAsync("c1"),
            () => cf.ApiShield.DeleteTokenValidationRuleAsync("r1"),
            () => cf.Workers.AttachDomainAsync("app.example.com", "w"),
            () => cf.Waf.RemoveCustomRuleAsync("admin"),
            () => cf.Tls.SetSwitchAsync(ZoneSettingIds.AlwaysUseHttps, false),
            () => cf.Tls.SetSwitchAsync(ZoneSettingIds.Tls13, false),
            () => cf.Tls.SetSwitchAsync(ZoneSettingIds.OpportunisticEncryption, false),
            () => cf.CustomHostnames.CreateAsync(new CustomHostnameInput { Hostname = "shop.customer.example", MinTlsVersion = "1.0" }),
            () => cf.CustomHostnames.EnsureAsync(new CustomHostnameInput { Hostname = "shop.customer.example", MinTlsVersion = "1.1" }),
            () => cf.CustomHostnames.UpdateAsync("ch1", new CustomHostnameChange { MinTlsVersion = "1.0" }),
            () => cf.R2.EnsureCustomDomainAsync("assets", "cdn.example.com", "zone1", allowPublicAccess: true, minTls: "1.0"),
            () => cf.Logpush.SetJobEnabledAsync(1, false),
            () => cf.Logpush.DeleteJobAsync(1),
        ];
        foreach (var action in refused) await Refused(h, action);
        Assert.Throws<ArgumentException>(() => cf.CustomHostnames.PreviewCreate(new CustomHostnameInput { Hostname = "shop.customer.example", MinTlsVersion = "1.0" }));

        // The previews name the risk.
        Assert.Contains("WARNING", cf.Workers.PreviewAttachDomain("app.example.com", "w").Summary);
        Assert.Contains("WARNING", cf.ApiShield.PreviewRevokeClientCertificate("cc1").Summary);
        Assert.Contains("off", cf.ApiShield.PreviewSetOverrideAction("none").Summary);
        Assert.Contains("Loosening", cf.Tls.PreviewSetSwitch(ZoneSettingIds.AlwaysUseHttps, false).Summary);
        Assert.Contains("WARNING", cf.Logpush.PreviewSetJobEnabled(1, false).Summary);
        Assert.Contains("WARNING", cf.Logpush.PreviewDeleteJob(1).Summary);
        Assert.Empty(h.Requests);

        // With the switch they are sent.
        await cf.Tls.SetSwitchAsync(ZoneSettingIds.AlwaysUseHttps, false, allowWeaken: true);
        await cf.Tls.SetSwitchAsync(ZoneSettingIds.AlwaysUseHttps, true);
        await cf.Workers.AttachDomainAsync("app.example.com", "w", allowDeploy: true);
        await cf.ApiShield.SetOverrideActionAsync("none", allowLoosen: true);
        await cf.ApiShield.SetOverrideActionAsync(null);
        await cf.Logpush.SetJobEnabledAsync(1, true);
        Assert.Equal(6, h.Requests.Count);
    }

    [Fact]
    public async Task Replacing_jwt_keys_that_drop_a_current_key_needs_allowKeyRemoval()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, ("GET", "token_validation/config/c1", """{"id":"c1","title":"jwt","credentials":{"keys":[{"kid":"old","kty":"EC","alg":"ES256","crv":"P-256"}]}}"""),
            ("PUT", "token_validation/config/c1/credentials", """{"keys":[]}"""));
        var onlyNew = JwtKeySet.Parse("""{"keys":[{"kty":"EC","alg":"ES256","kid":"new","crv":"P-256","x":"AAAA","y":"BBBB"}]}""");
        var both = JwtKeySet.Parse("""{"keys":[{"kty":"EC","alg":"ES256","kid":"old","crv":"P-256","x":"CCCC","y":"DDDD"},{"kty":"EC","alg":"ES256","kid":"new","crv":"P-256","x":"AAAA","y":"BBBB"}]}""");
        await Refused(h, () => cf.ApiShield.ReplaceTokenValidationKeysAsync("c1", onlyNew), noRequests: false);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Put);
        await cf.ApiShield.ReplaceTokenValidationKeysAsync("c1", both);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        await cf.ApiShield.ReplaceTokenValidationKeysAsync("c1", onlyNew, allowKeyRemoval: true);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
    }

    // =================================================================================================================== N-1 .. N-10

    [Fact]
    public async Task Rolling_a_token_is_never_retried()
    {
        Assert.False(CloudflareWritePolicy.IsIdempotent(HttpMethod.Put, "user/tokens/t1/value"));
        Assert.False(CloudflareWritePolicy.IsIdempotent(HttpMethod.Put, "accounts/acc1/tokens/t1/value"));
        Assert.True(CloudflareWritePolicy.IsIdempotent(HttpMethod.Put, "user/tokens/t1"));
        var (cf, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.MaxRetries = 3; });
        h.Responder = (req, _) => req.Method == HttpMethod.Get
            ? Ok("""{"id":"other","status":"active"}""")
            : FakeHandler.Json("""{"success":false,"errors":[]}""", HttpStatusCode.ServiceUnavailable);
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.ApiTokens.RollAsync("t1"));
        Assert.Single(h.Requests, r => r.Method == HttpMethod.Put);
    }

    [Fact]
    public async Task Upsert_guards_check_the_actual_plan_before_writing()
    {
        // The allow-list allows creating records only: the existing record would be replaced with PUT, which is refused before anything is written.
        var (cf, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (m, p) => m == HttpMethod.Post && p == "zones/zone1/dns_records"; });
        Route(h, ("GET", "dns_records?", $"[{ProxiedRecord}]"));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.99", Proxied = true }));
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        // An allow-list that allows none of the plans sends nothing at all.
        var (cf2, h2, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, p) => p.StartsWith("accounts/", StringComparison.Ordinal); });
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf2.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.99" }));
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf2.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "r", Expression = "(http.host eq \"a\")", Action = "log" }));
        Assert.Empty(h2.Requests);

        // Rulesets: the filter allows the paths below rulesets but not the entry point PUT the plan needs.
        var (cf3, h3, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (m, p) => p.StartsWith("zones/zone1/rulesets", StringComparison.Ordinal) && m != HttpMethod.Put; });
        h3.Responder = (_, _) => Error(HttpStatusCode.NotFound, 10000, "no entrypoint");
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf3.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "r", Expression = "(http.host eq \"a\")", Action = "log" }));
        Assert.All(h3.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("(true)", true)]
    [InlineData("not false", true)]
    [InlineData("!false", true)]
    [InlineData("1 == 1", true)]
    [InlineData("1 eq 1", true)]
    [InlineData("\"a\" eq \"a\"", true)]
    [InlineData("http.host ne \"\"", true)]
    [InlineData("len(http.host) ge 0", true)]
    [InlineData("starts_with(http.request.uri.path, \"/\")", true)]
    [InlineData("http.request.uri.path matches \".*\"", true)]
    [InlineData("ip.src in {0.0.0.0/0 ::/0}", true)]
    [InlineData("(http.host eq \"a.example.com\") or true", true)]
    [InlineData("(http.host eq \"a.example.com\") or (1 == 1)", true)]
    [InlineData("(http.host eq \"a.example.com\")", false)]
    [InlineData("http.host eq \"true\"", false)]
    [InlineData("(http.host eq \"a\") and true", false)]
    [InlineData("1 == 2", false)]
    public void Expressions_that_match_every_request_are_recognised(string expression, bool matchesAll) =>
        Assert.Equal(matchesAll, RulesetRisk.MatchesAll(expression));

    [Fact]
    public async Task Blocking_a_tautology_needs_allowBroadMatch()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Refused(h, () => cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "r", Expression = "not false", Action = "block" }));
        await Refused(h, () => cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "r", Expression = "http.host ne \"\"", Action = "block" }));
    }

    [Fact]
    public void Secrets_are_hidden_from_the_debugger_and_buffers_are_cleared()
    {
        foreach (var type in new[] { typeof(ApiTokenSecret), typeof(WorkerSecretText), typeof(OriginPullKeyPair), typeof(JwtKeySet) })
        {
            var display = type.GetCustomAttribute<DebuggerDisplayAttribute>();
            Assert.NotNull(display);
            Assert.Contains("redacted", display!.Value);
            Assert.True(typeof(IDisposable).IsAssignableFrom(type), type.Name);
            foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic).Where(f => f.FieldType == typeof(char[])))
                Assert.Equal(DebuggerBrowsableState.Never, field.GetCustomAttribute<DebuggerBrowsableAttribute>()?.State);
        }
        var secret = new ApiTokenSecret("SYNTHETIC-SECRET-1");
        var buffer = (char[])typeof(ApiTokenSecret).GetField("_value", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(secret)!;
        Assert.Equal("SYNTHETIC-SECRET-1", secret.TakeValue());
        Assert.All(buffer, c => Assert.Equal('\0', c));
        Assert.False(secret.HasValue);

        var worker = WorkerSecretText.From("SYNTHETIC-SECRET-2");
        var wbuf = (char[])typeof(WorkerSecretText).GetField("_value", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(worker)!;
        worker.Dispose();
        Assert.All(wbuf, c => Assert.Equal('\0', c));
        Assert.Throws<ObjectDisposedException>(() => worker.Reveal());
    }

    [Theory]
    [InlineData("splunk://splunk.example.com:8088/services/collector/raw/TOKEN123?channel=abc", "splunk://splunk.example.com:8088/[redacted]?channel=abc")]
    [InlineData("datadog://intake.example.com/v1/input/APIKEY?service=x", "datadog://intake.example.com/[redacted]?service=x")]
    [InlineData("https://collector.example.com/x?BARETOKEN123&region=eu", "https://collector.example.com/[redacted]?[redacted]&region=eu")]
    [InlineData("r2://logs/http/{DATE}?account-id=acc1&TOKENWITHOUTVALUE", "r2://logs/http/{DATE}?account-id=acc1&[redacted]")]
    [InlineData("s3://bucket/path?region=eu-west-1", "s3://bucket/path?region=eu-west-1")]
    public void Logpush_redaction_covers_bare_parameters_and_collector_paths(string destination, string expected)
    {
        Assert.Equal(expected, LogpushClient.RedactDestination(destination));
        Assert.DoesNotContain("TOKEN", LogpushClient.RedactDestination(destination));
    }

    [Fact]
    public async Task Older_monitoring_logpush_methods_redact_the_destination()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responder = (_, _) => Ok("""[{"id":1,"dataset":"http_requests","enabled":true,"destination_conf":"https://collector.example.com/TOKEN?header_Authorization=SECRET","ownership_challenge":"CHALLENGE"}]""");
        var jobs = await cf.Monitoring.ListLogpushJobsAsync();
        Assert.Equal("https://collector.example.com/[redacted]?header_Authorization=[redacted]", jobs[0].DestinationConf);
        Assert.DoesNotContain("CHALLENGE", JsonSerializer.Serialize(jobs[0].AdditionalData));
    }

    [Fact]
    public async Task Kv_key_listing_stops_on_a_repeated_cursor_or_an_empty_page()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responder = (_, _) => Ok("""[{"name":"k"}]""", """{"cursor":"same"}""");
        var keys = await cf.Kv.ListKeysAsync("ns1", maxItems: 100_000).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(2, h.Requests.Count);
        Assert.Equal(2, keys.Count);

        var (cf2, h2, _) = FakeHandler.Create();
        var n = 0;
        h2.Responder = (_, _) => Ok("[]", $$"""{"cursor":"c{{n++}}"}""");
        Assert.Empty(await cf2.Kv.ListKeysAsync("ns1", maxItems: 100_000).WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Single(h2.Requests);
    }

    [Theory]
    [InlineData("http://api.cloudflare.com/client/v4/")]
    [InlineData("http://localhost.evil.example/")]
    [InlineData("ftp://api.cloudflare.com/")]
    [InlineData("api.cloudflare.com/client/v4/")]
    [InlineData("https://user:pw@api.cloudflare.com/client/v4/")]
    public void Create_refuses_a_base_address_without_https(string baseAddress) =>
        Assert.Throws<CloudflareConfigurationException>(() => CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", BaseAddress = baseAddress }));

    [Fact]
    public void Create_checks_the_retry_and_size_limits()
    {
        Assert.Throws<CloudflareConfigurationException>(() => CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", MaxRetries = 11 }));
        Assert.Throws<CloudflareConfigurationException>(() => CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", MaxRetries = -1 }));
        Assert.Throws<CloudflareConfigurationException>(() => CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", MaxResponseBytes = 0 }));
        Assert.Throws<CloudflareConfigurationException>(() => CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", RetryBaseDelay = TimeSpan.FromSeconds(-1) }));
        Assert.NotNull(CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", BaseAddress = "http://localhost:8080/client/v4/", MaxRetries = 10 }));
        Assert.NotNull(CloudflareClient.Create(new CloudflareOptions { ApiToken = "x", BaseAddress = "http://127.0.0.1:8080/" }));
    }

    [Fact]
    public async Task An_oversized_answer_fails_instead_of_filling_the_memory()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.MaxResponseBytes = 1024);
        h.Responder = (_, _) => Ok("\"" + new string('x', 4096) + "\"");
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Zones.GetAsync());
        Assert.Contains("MaxResponseBytes", ex.Message);
        h.Responder = (_, _) => Ok("""{"id":"zone1","name":"example.com"}""");
        Assert.Equal("example.com", (await cf.Zones.GetAsync()).Name);
    }

    [Fact]
    public void Preview_of_attaching_a_domain_uses_the_given_account()
    {
        var (cf, h, _) = FakeHandler.Create();
        Assert.Equal("accounts/acc2/workers/domains", cf.Workers.PreviewAttachDomain("app.example.com", "w", accountId: "acc2").Path);
        Assert.Equal("accounts/acc1/workers/domains", cf.Workers.PreviewAttachDomain("app.example.com", "w").Path);
        Assert.Empty(h.Requests);
    }

    // =================================================================================================================== guard tests

    [Fact]
    public async Task Remaining_shield_and_priority1_writes_are_refused_without_AllowWrites()
    {
        var (cf, h, _) = FakeHandler.Create();
        var token = new ApiTokenInput
        {
            Name = "ci", ExpiresOn = DateTimeOffset.UtcNow.AddDays(30),
            Policies = [new ApiTokenPolicyInput { PermissionGroupIds = ["g1"], Resources = new JsonObject { [ApiTokenResources.Zone("zone1")] = "*" } }],
        };
        Func<Task>[] writes =
        [
            () => cf.ApiShield.SetDiscoveryStatesAsync(new Dictionary<string, string> { ["d1"] = "review" }),
            () => cf.ApiShield.UpdateTokenValidationConfigAsync("c1", title: "t"),
            () => cf.ApiShield.DeleteTokenValidationConfigAsync("c1", allowRemoval: true),
            () => cf.ApiShield.UpdateTokenValidationRuleAsync("r1", new TokenValidationRuleChange { Title = "t" }),
            () => cf.ApiShield.CreateUserLabelsAsync([("team-a", null)]),
            () => cf.ApiShield.UpdateUserLabelAsync("team-a", null),
            () => cf.ApiShield.DeleteUserLabelAsync("team-a"),
            () => cf.ApiShield.RemoveLabelsFromOperationsAsync(["o1"], userLabels: ["team-a"]),
            () => cf.ApiShield.ReactivateClientCertificateAsync("cc1"),
            () => cf.ApiShield.SetDefaultActionAsync("log"),
            () => cf.ApiShield.SetOperationActionAsync("o1", "log"),
            () => cf.PageShield.CreatePolicyAsync(new PageShieldPolicyInput { Description = "d", Expression = "e", Value = "v" }),
            () => cf.PageShield.UpdatePolicyAsync("p1", new PageShieldPolicyInput { Description = "d", Expression = "e", Value = "v" }),
            () => cf.Bots.CreateLeakedCredentialDetectionAsync("lookup_json_string(http.request.body.raw, \"user\")"),
            () => cf.Bots.UpdateLeakedCredentialDetectionAsync("d1", "lookup_json_string(http.request.body.raw, \"user\")"),
            () => cf.CustomHostnames.UpdateAsync("ch1", new CustomHostnameChange { MinTlsVersion = "1.2" }),
            () => cf.OriginPulls.DeleteHostnameCertificateAsync("cert1", allowDisable: true),
            () => cf.ApiTokens.UpdateAsync("t1", token, allowSelf: true),
            () => cf.ApiTokens.UpdateAsync("t1", token),
        ];
        foreach (var write in writes) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(write);
        Assert.Empty(h.Requests);
    }

    /// <summary>
    /// Every public method of every curated client with sample arguments (allow switches on, AllowWrites off): no write reaches the wire, and a method that
    /// hits the write guard has sent nothing at all before (no preparing read).
    /// </summary>
    [Fact]
    public async Task Every_public_write_method_sends_nothing_without_AllowWrites()
    {
        var violations = new List<string>();
        var guarded = 0;
        foreach (var m in ClientSurface.Methods())
        {
            var (client, h, _) = FakeHandler.Create();
            var ex = await ClientSurface.InvokeAsync(m.Client.GetValue(client)!, m.Method, ClientSurface.Arguments(m.Method));
            if (ex is TimeoutException) violations.Add($"{ClientSurface.Name(m)}: timed out");
            foreach (var r in h.Requests.Where(r => r.Method != HttpMethod.Get && !r.Url.EndsWith("/graphql", StringComparison.Ordinal)))
                violations.Add($"{ClientSurface.Name(m)}: sent {r.Method} {r.Url}");
            if (ex is CloudflareWriteNotAllowedException)
            {
                guarded++;
                if (h.Requests.Count > 0) violations.Add($"{ClientSurface.Name(m)}: read {h.Requests.Count}x before the guard refused ({string.Join(", ", h.Requests.Select(r => r.Url))})");
            }
        }
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
        Assert.True(guarded >= 150, $"only {guarded} methods reached the write guard; the sample arguments need care");
    }
}
