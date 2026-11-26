using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>IP lists, IP access rules, edge certificates, tunnel connectors, notification history and Access additions (0.3.0). Fake HTTP handler only.</summary>
public class EdgeStatusTests
{
    private static JsonElement Body(FakeHandler handler, int index) => JsonDocument.Parse(handler.Requests[index].Body!).RootElement;

    // ---- IP lists ----

    [Fact]
    public async Task List_create_sends_name_kind_and_description_to_the_account()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"l1","name":"waechter","kind":"ip","num_items":0}"""));
        var list = await cf.Lists.CreateAsync("waechter", description: "blocked by the watchdog");
        Assert.Equal("l1", list.Id);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.EndsWith("/accounts/acc1/rules/lists", handler.Requests[0].Url);
        Assert.Equal("ip", Body(handler, 0).GetProperty("kind").GetString());
        Assert.Equal("blocked by the watchdog", Body(handler, 0).GetProperty("description").GetString());
    }

    [Fact]
    public async Task List_ensure_creates_only_when_missing()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"l1","name":"waechter","kind":"ip","num_items":3}]"""));
        Assert.Equal("l1", (await cf.Lists.EnsureAsync("waechter")).Id);
        Assert.Single(handler.Requests);

        handler.Requests.Clear();
        handler.Responses.Enqueue(FakeHandler.Ok("[]"));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"l2","name":"waechter","kind":"ip"}"""));
        Assert.Equal("l2", (await cf.Lists.EnsureAsync("waechter")).Id);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
    }

    [Fact]
    public async Task List_items_follow_the_cursor()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"i1","ip":"203.0.113.1","comment":"a"}]""", """{"cursors":{"after":"c2"}}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"i2","ip":"203.0.113.0/24"}]""", """{"cursors":{}}"""));
        var items = await cf.Lists.ListItemsAsync("l1");
        Assert.Equal(["i1", "i2"], items.Select(i => i.Id));
        Assert.Equal("203.0.113.0/24", items[1].Ip);
        Assert.Contains("/rules/lists/l1/items?per_page=500", handler.Requests[0].Url);
        Assert.DoesNotContain("cursor=", handler.Requests[0].Url);
        Assert.Contains("cursor=c2", handler.Requests[1].Url);
    }

    [Fact]
    public async Task List_add_ips_posts_an_array_and_returns_the_operation()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op1"}"""));
        var op = await cf.Lists.AddIpsAsync("l1", ["203.0.113.7", "2001:db8::/64"], "ssh scan");
        Assert.Equal("op1", op.OperationId);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        var body = Body(handler, 0);
        Assert.Equal(2, body.GetArrayLength());
        Assert.Equal("203.0.113.7", body[0].GetProperty("ip").GetString());
        Assert.Equal("ssh scan", body[1].GetProperty("comment").GetString());
    }

    [Fact]
    public async Task List_replace_uses_put_and_remove_sends_ids_in_a_delete_body()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op1"}"""));
        await cf.Lists.ReplaceIpItemsAsync("l1", [new IpListItemInput { Ip = "198.51.100.1" }]);
        Assert.Equal(HttpMethod.Put, handler.Requests[0].Method);
        Assert.False(Body(handler, 0)[0].TryGetProperty("comment", out _));

        handler.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op2"}"""));
        var op = await cf.Lists.RemoveItemsAsync("l1", ["i1", "i2"]);
        Assert.Equal("op2", op.OperationId);
        Assert.Equal(HttpMethod.Delete, handler.Requests[1].Method);
        Assert.Equal("i2", Body(handler, 1).GetProperty("items")[1].GetProperty("id").GetString());

        await Assert.ThrowsAsync<ArgumentException>(() => cf.Lists.RemoveItemsAsync("l1", []));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Lists.AddIpsAsync("l1", []));
    }

    [Fact]
    public async Task List_wait_polls_until_completed_and_reports_failures()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"op1","status":"pending"}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"op1","status":"running"}"""));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"op1","status":"completed","completed":"2026-11-13T10:00:00Z"}"""));
        var op = await cf.Lists.WaitForOperationAsync("op1", pollInterval: TimeSpan.Zero);
        Assert.True(op.Succeeded);
        Assert.Equal(3, handler.Requests.Count);
        Assert.EndsWith("/rules/lists/bulk_operations/op1", handler.Requests[0].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"op2","status":"failed","error":"invalid ip"}"""));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Lists.WaitForOperationAsync("op2", pollInterval: TimeSpan.Zero));
        Assert.Contains("invalid ip", ex.Message);

        handler.Responder = (_, _) => FakeHandler.Ok("""{"id":"op3","status":"running"}""");
        await Assert.ThrowsAsync<TimeoutException>(() => cf.Lists.WaitForOperationAsync("op3", TimeSpan.Zero, TimeSpan.Zero));
    }

    [Fact]
    public async Task List_writes_are_blocked_without_AllowWrites_and_outside_the_filter()
    {
        var (cf, handler, _) = FakeHandler.Create();
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.Lists.AddIpsAsync("l1", ["203.0.113.7"]));
        Assert.Empty(handler.Requests);

        var (filtered, handler2, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, path) => path.Contains("/rules/lists/l1/", StringComparison.Ordinal); });
        handler2.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op"}"""));
        await filtered.Lists.AddIpsAsync("l1", ["203.0.113.7"]);
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => filtered.Lists.AddIpsAsync("other", ["203.0.113.7"]));
        Assert.Single(handler2.Requests);
    }

    [Fact]
    public async Task List_writes_retry_on_429_and_gateway_errors_only_when_idempotent()
    {
        var (cf, handler, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.MaxRetries = 2; });
        handler.Responses.Enqueue(FakeHandler.Json("""{"success":false}""", HttpStatusCode.TooManyRequests));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op1"}"""));
        Assert.Equal("op1", (await cf.Lists.AddIpsAsync("l1", ["203.0.113.7"])).OperationId);
        Assert.Equal(2, handler.Requests.Count);

        // POST is not repeated after 503 (could duplicate), PUT is.
        handler.Requests.Clear();
        handler.Responses.Enqueue(FakeHandler.Json("""{"success":false}""", HttpStatusCode.ServiceUnavailable));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Lists.AddIpsAsync("l1", ["203.0.113.7"]));
        Assert.Single(handler.Requests);

        handler.Requests.Clear();
        handler.Responses.Enqueue(FakeHandler.Json("""{"success":false}""", HttpStatusCode.BadGateway));
        handler.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"op2"}"""));
        await cf.Lists.ReplaceIpItemsAsync("l1", [new IpListItemInput { Ip = "203.0.113.7" }]);
        Assert.Equal(2, handler.Requests.Count);
    }

    // ---- IP access rules ----

    [Fact]
    public async Task IpAccess_create_sends_mode_configuration_and_notes_to_the_zone()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"r1","mode":"block","configuration":{"target":"ip","value":"203.0.113.9"},"notes":"scanner"}"""));
        var rule = await cf.IpAccess.CreateAsync(IpAccessModes.Block, IpAccessTargets.Ip, "203.0.113.9", "scanner");
        Assert.Equal("203.0.113.9", rule.Configuration.Value);
        Assert.EndsWith("/zones/zone1/firewall/access_rules/rules", handler.Requests[0].Url);
        var body = Body(handler, 0);
        Assert.Equal("block", body.GetProperty("mode").GetString());
        Assert.Equal("ip", body.GetProperty("configuration").GetProperty("target").GetString());
        await Assert.ThrowsAsync<ArgumentException>(() => cf.IpAccess.CreateAsync("block", "ip", " "));
    }

    [Fact]
    public async Task IpAccess_list_filters_by_configuration_and_pages()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"r1","mode":"whitelist","configuration":{"target":"ip_range","value":"10.0.0.0/8"}}]""", """{"page":1,"per_page":50,"total_pages":1}"""));
        var rules = await cf.IpAccess.ListAsync(IpAccessModes.Allow, IpAccessTargets.IpRange);
        Assert.Equal("ip_range", rules[0].Configuration.Target);
        Assert.Contains("mode=whitelist", handler.Requests[0].Url);
        Assert.Contains("configuration.target=ip_range", handler.Requests[0].Url);
    }

    [Fact]
    public async Task IpAccess_update_delete_and_account_scope()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"r1","mode":"challenge"}"""));
        await cf.IpAccess.UpdateAsync("r1", mode: IpAccessModes.Challenge);
        Assert.Equal(HttpMethod.Patch, handler.Requests[0].Method);
        Assert.False(Body(handler, 0).TryGetProperty("notes", out _));

        await cf.IpAccess.DeleteAsync("r1");
        Assert.Equal(HttpMethod.Delete, handler.Requests[1].Method);
        Assert.EndsWith("/zones/zone1/firewall/access_rules/rules/r1", handler.Requests[1].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"r2","mode":"block","configuration":{"target":"country","value":"XX"}}"""));
        await cf.IpAccess.CreateAccountRuleAsync("block", "country", "XX");
        Assert.EndsWith("/accounts/acc1/firewall/access_rules/rules", handler.Requests[2].Url);
    }

    // ---- Zone settings ----

    [Fact]
    public async Task New_zone_setting_ids_address_the_right_settings()
    {
        Assert.Equal("challenge_ttl", ZoneSettingIds.ChallengeTtl);
        Assert.Equal("0rtt", ZoneSettingIds.ZeroRtt);
        Assert.Equal("ech", ZoneSettingIds.Ech);
        Assert.Equal("ssl_recommender", ZoneSettingIds.SslRecommender);

        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"0rtt","value":"off","editable":true}"""));
        await cf.Zones.SetSettingAsync(ZoneSettingIds.ZeroRtt, "off");
        Assert.EndsWith("/zones/zone1/settings/0rtt", handler.Requests[0].Url);
        Assert.Equal("off", Body(handler, 0).GetProperty("value").GetString());

        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"challenge_ttl","value":1800,"editable":true}"""));
        await cf.Zones.SetSettingAsync(ZoneSettingIds.ChallengeTtl, 1800);
        Assert.Equal(1800, Body(handler, 1).GetProperty("value").GetInt32());
    }

    // ---- Edge certificates ----

    [Fact]
    public async Task Universal_ssl_status_verification_and_packs_are_read()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"enabled":true}"""));
        Assert.True((await cf.Certificates.GetUniversalSslSettingsAsync()).Enabled);
        Assert.EndsWith("/zones/zone1/ssl/universal/settings", handler.Requests[0].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""[{"cert_pack_uuid":"p1","certificate_status":"pending_validation","verification_type":"cname","validation_method":"txt","verification_status":false}]"""));
        var verification = await cf.Certificates.GetSslVerificationAsync();
        Assert.Equal("pending_validation", verification[0].CertificateStatus);

        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"p1","type":"universal","hosts":["example.com","*.example.com"],"status":"active","certificate_authority":"lets_encrypt"}]""", """{"page":1,"per_page":50,"total_pages":1}"""));
        var packs = await cf.Certificates.ListCertificatePacksAsync();
        Assert.Equal("lets_encrypt", packs[0].CertificateAuthority);
        Assert.Contains("status=all", handler.Requests[2].Url);
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("www.example.com", true)]
    [InlineData("WWW.Example.com.", true)]
    [InlineData("a.b.example.com", false)]       // two levels deep: Universal SSL does not cover it
    [InlineData("example.org", false)]
    [InlineData("notexample.com", false)]
    [InlineData("*.example.com", true)]          // the wildcard name itself is the certificate name
    [InlineData("*.a.example.com", false)]
    [InlineData("", false)]
    public void Universal_ssl_covers_the_zone_and_one_level_only(string host, bool covered) =>
        Assert.Equal(covered, CertificateHostMatcher.Covers(["example.com", "*.example.com"], host));

    [Fact]
    public async Task Uncovered_hostnames_ignore_packs_that_are_not_active()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""
            [{"id":"p1","type":"universal","hosts":["example.com","*.example.com"],"status":"active"},
             {"id":"p2","type":"advanced","hosts":["*.api.example.com"],"status":"pending_validation"}]
            """, """{"page":1,"per_page":50,"total_pages":1}"""));
        var gaps = await cf.Certificates.FindUncoveredHostnamesAsync(["app.example.com", "x.api.example.com"]);
        Assert.Equal(["x.api.example.com"], gaps);
    }

    // ---- Tunnel ----

    [Fact]
    public async Task Tunnel_connections_and_connectors_are_read()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""
            [{"id":"c1","version":"2026.10.0","arch":"linux_amd64","origin_ip":"198.51.100.4","run_at":"2026-11-13T08:00:00Z","features":["serialized_headers"],
              "conns":[{"colo_name":"FRA","uuid":"u1","is_pending_reconnect":false},{"colo_name":"AMS","uuid":"u2","is_pending_reconnect":true}]}]
            """));
        var connectors = await cf.Tunnels.ListConnectionsAsync("t1");
        Assert.EndsWith("/accounts/acc1/cfd_tunnel/t1/connections", handler.Requests[0].Url);
        Assert.Equal(2, connectors[0].Conns.Count);
        Assert.Equal(1, connectors[0].ActiveConnections);
        Assert.Equal("FRA", connectors[0].Conns[0].ColoName);

        handler.Responses.Enqueue(FakeHandler.Ok("[]"));
        Assert.Empty(await cf.Tunnels.ListConnectorsAsync("t1"));
        Assert.EndsWith("/cfd_tunnel/t1/connectors", handler.Requests[1].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"c1","conns":[]}"""));
        Assert.Equal("c1", (await cf.Tunnels.GetConnectorAsync("t1", "c1")).Id);
        Assert.EndsWith("/cfd_tunnel/t1/connectors/c1", handler.Requests[2].Url);
    }

    // ---- Notification history ----

    [Fact]
    public async Task Alert_history_is_requested_with_window_and_page()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"h1","name":"Tunnel down","alert_type":"tunnel_health_event","mechanism":"ops@example.com","mechanism_type":"email","policy_id":"p1","sent":"2026-11-12T22:00:00Z"}]"""));
        var since = new DateTimeOffset(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);
        var entries = await cf.Monitoring.ListAlertHistoryAsync(since, perPage: 500, page: 0);
        Assert.Equal("tunnel_health_event", entries[0].AlertType);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 22, 0, 0, TimeSpan.Zero), entries[0].Sent);
        var url = handler.Requests[0].Url;
        Assert.Contains("/accounts/acc1/alerting/v3/history?", url);
        Assert.Contains("per_page=100", url);
        Assert.Contains("page=1", url);
        Assert.Contains("since=2026-11-12T00%3A00%3A00", url);
        Assert.DoesNotContain("before=", url);
    }

    // ---- Access ----

    [Fact]
    public async Task Access_identity_providers_are_listed_and_created()
    {
        var (cf, handler, _) = FakeHandler.Create(o => o.AllowWrites = true);
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"id":"idp1","name":"One-time PIN","type":"onetimepin","config":{}}]""", """{"page":1,"per_page":50,"total_pages":1}"""));
        var providers = await cf.Access.ListIdentityProvidersAsync();
        Assert.Equal("onetimepin", providers[0].Type);
        Assert.Contains("/accounts/acc1/access/identity_providers", handler.Requests[0].Url);

        handler.Responses.Enqueue(FakeHandler.Ok("""{"id":"idp2","name":"GitHub","type":"github"}"""));
        await cf.Access.CreateIdentityProviderAsync("GitHub", "github", new { client_id = "x", client_secret = "y" });
        var body = Body(handler, 1);
        Assert.Equal("github", body.GetProperty("type").GetString());
        Assert.Equal("x", body.GetProperty("config").GetProperty("client_id").GetString());

        await cf.Access.DeleteIdentityProviderAsync("idp2");
        Assert.Equal(HttpMethod.Delete, handler.Requests[2].Method);
    }

    [Fact]
    public async Task Access_request_logs_are_read_newest_first_with_filters()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""[{"action":"login","allowed":false,"app_domain":"mt5.example.com","created_at":"2026-11-13T09:00:00Z","ip_address":"203.0.113.9","ray_id":"r1","user_email":"x@example.com"}]"""));
        var logs = await cf.Access.ListRequestLogsAsync(limit: 5000, userEmail: "x@example.com");
        Assert.False(logs[0].Allowed);
        Assert.Equal("mt5.example.com", logs[0].AppDomain);
        var url = handler.Requests[0].Url;
        Assert.Contains("/accounts/acc1/access/logs/access_requests?", url);
        Assert.Contains("limit=1000", url);
        Assert.Contains("direction=desc", url);
        Assert.Contains("user_email=x%40example.com", url);
    }

    // ---- Cloudflare IP ranges ----

    [Fact]
    public async Task Cloudflare_ip_ranges_are_read_and_matched()
    {
        var (cf, handler, _) = FakeHandler.Create();
        handler.Responses.Enqueue(FakeHandler.Ok("""{"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22"],"ipv6_cidrs":["2400:cb00::/32"],"etag":"abc"}"""));
        var ips = await cf.Ips.GetAsync();
        Assert.EndsWith("/client/v4/ips", handler.Requests[0].Url.Split('?')[0]);
        Assert.Equal(3, ips.AllCidrs.Count);
        Assert.True(ips.Contains(IPAddress.Parse("173.245.63.255")));
        Assert.False(ips.Contains(IPAddress.Parse("173.245.64.0")));
        Assert.True(ips.Contains(IPAddress.Parse("::ffff:103.21.245.1")));
        Assert.True(ips.Contains(IPAddress.Parse("2400:cb00:1234::1")));
        Assert.False(ips.Contains(IPAddress.Parse("2400:cb01::1")));
        Assert.False(ips.Contains(IPAddress.Parse("198.51.100.1")));
    }
}
