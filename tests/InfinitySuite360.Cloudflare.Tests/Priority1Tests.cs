using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Priority-1 clients of 0.6.0. Fake handler only: no network, no real token, keys are generated per test run.</summary>
public class Priority1Tests
{
    private const string Info = """{"page":1,"per_page":50,"count":1,"total_count":1,"total_pages":1}""";
    private const string Empty = """{"page":1,"per_page":50,"count":0,"total_count":0,"total_pages":0}""";
    private const string Token = "secret-token-123";

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    private static readonly RateLimitRuleInput LoginLimit = new()
    {
        Ref = "login", Expression = "(http.request.uri.path eq \"/api/login\")", Action = WafActions.Block, RequestsPerPeriod = 10, Period = 60, MitigationTimeout = 60,
        Characteristics = ["ip.src"],
    };

    private const string RateLimitEntrypoint = """
        {"id":"rs1","name":"default","kind":"zone","phase":"http_ratelimit","rules":[
          {"id":"r1","ref":"login","action":"block","expression":"(http.request.uri.path eq \"/api/login\")","enabled":true,
           "ratelimit":{"characteristics":["cf.colo.id","ip.src"],"period":60,"requests_per_period":10,"mitigation_timeout":60,"requests_to_origin":false}}]}
        """;

    private static (string CertPem, string KeyPem, string OtherKeyPem) KeyPair()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=origin-pull-test", key, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(), other.ExportPkcs8PrivateKeyPem());
    }

    // Longest run of letters and digits of the key's base64 body: survives JSON escaping, so DoesNotContain cannot pass by accident.
    private static string KeyBody(string keyPem)
    {
        var needle = keyPem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal))
            .SelectMany(l => System.Text.RegularExpressions.Regex.Matches(l, "[A-Za-z0-9]+").Select(m => m.Value))
            .OrderByDescending(v => v.Length).First();
        Assert.True(needle.Length >= 12);
        return needle;
    }

    [Fact]
    public async Task Every_new_write_is_refused_without_AllowWrites_and_nothing_is_sent()
    {
        var (cf, h, _) = FakeHandler.Create();
        var (certPem, keyPem, _) = KeyPair();
        var pair = OriginPullKeyPair.FromPem(certPem, keyPem);
        Func<Task>[] writes =
        [
            () => cf.RateLimiting.UpsertRuleAsync(LoginLimit),
            () => cf.RateLimiting.RemoveRuleAsync("login"),
            () => cf.RateLimiting.DeleteLegacyRateLimitAsync("l1"),
            () => cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "admin", Expression = "http.request.uri.path eq \"/admin\"", Action = WafActions.ManagedChallenge }),
            () => cf.Waf.RemoveCustomRuleAsync("admin"),
            () => cf.Waf.DeployManagedRulesetAsync(ManagedRulesetIds.FreeManaged, "free-managed"),
            () => cf.Waf.RemoveManagedDeploymentAsync("free-managed", allowLoosen: true),
            () => cf.Bots.UpdateSettingsAsync(new BotManagementChange { EnableJs = true }),
            () => cf.Bots.ReportFeedbackAsync("false_positive", "ip.src eq 192.0.2.1", "own monitor"),
            () => cf.Bots.SetLeakedCredentialChecksAsync(true),
            () => cf.Bots.EnsureLeakedCredentialDetectionAsync("lookup_json_string(http.request.body.raw, \"user\")"),
            () => cf.Bots.DeleteLeakedCredentialDetectionAsync("d1"),
            () => cf.CustomHostnames.CreateAsync(new CustomHostnameInput { Hostname = "app.customer.example" }),
            () => cf.CustomHostnames.EnsureAsync(new CustomHostnameInput { Hostname = "app.customer.example" }),
            () => cf.CustomHostnames.DeleteAsync("ch1"),
            () => cf.CustomHostnames.SetFallbackOriginAsync("fallback.example.com"),
            () => cf.CustomHostnames.RemoveFallbackOriginAsync(allowRemoval: true),
            () => cf.OriginPulls.SetZoneEnabledAsync(true),
            () => cf.OriginPulls.UploadZoneCertificateAsync(pair),
            () => cf.OriginPulls.UploadHostnameCertificateAsync(pair),
            () => cf.OriginPulls.SetHostnamesAsync([new("api.example.com", "c1")]),
            () => cf.OriginPulls.DeleteZoneCertificateAsync("c1", allowDisable: true),
            () => cf.Tls.SetSslModeAsync("strict"),
            () => cf.Tls.SetMinTlsVersionAsync("1.2"),
            () => cf.Tls.SetHstsAsync(new HstsSettings { Enabled = true, MaxAge = 300 }),
            () => cf.Tls.SetSwitchAsync(ZoneSettingIds.Http3, true),
            () => cf.Logpush.CreateJobAsync(new LogpushJobInput { Dataset = "http_requests", DestinationConf = "r2://logs/http?account-id=a&access-key-id=k&secret-access-key=s" }),
            () => cf.Logpush.EnsureJobAsync(new LogpushJobInput { Name = "edge", Dataset = "http_requests", DestinationConf = "r2://logs/http" }),
            () => cf.Logpush.SetJobEnabledAsync(1, false),
            () => cf.Logpush.DeleteJobAsync(1),
            () => cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = true }),
            () => cf.Dns.DeleteIfExistsAsync("rec1"),
            () => cf.ApiTokens.CreateAsync(ApiTokenTests.MinimalToken()),
            () => cf.ApiTokens.RollAsync("t1"),
            () => cf.ApiTokens.RevokeAsync("t1"),
            () => cf.ApiTokens.SetStatusAsync("t1", "disabled"),
        ];
        foreach (var write in writes) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(write);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public void Previews_build_the_request_send_nothing_and_never_contain_the_token()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        CloudflareChangePreview[] previews =
        [
            cf.RateLimiting.PreviewDeleteLegacyRateLimit("l1"),
            cf.Bots.PreviewUpdateSettings(new BotManagementChange { SbfmDefinitelyAutomated = "managed_challenge" }, allowChallengeAutomation: true),
            cf.Bots.PreviewSetLeakedCredentialChecks(false),
            cf.Bots.PreviewCreateLeakedCredentialDetection("lookup_json_string(http.request.body.raw, \"user\")", "lookup_json_string(http.request.body.raw, \"pass\")"),
            cf.CustomHostnames.PreviewCreate(new CustomHostnameInput { Hostname = "App.Customer.Example", MinTlsVersion = "1.2" }),
            cf.CustomHostnames.PreviewRemoveFallbackOrigin(),
            cf.OriginPulls.PreviewSetZoneEnabled(false),
            cf.OriginPulls.PreviewSetHostnames([new("api.example.com", "c1", Enabled: null)]),
            cf.Tls.PreviewSetHsts(new HstsSettings { Enabled = true, MaxAge = 31536000, IncludeSubdomains = true, Preload = true }),
            cf.Tls.PreviewSetSwitch(ZoneSettingIds.ZeroRtt, true),
            cf.Logpush.PreviewSetJobEnabled(7, false),
            cf.Dns.PreviewCreate(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = true }),
        ];
        Assert.Contains("\"hostname\": \"app.customer.example\"", previews[4].BodyJson);
        Assert.Contains("\"min_tls_version\": \"1.2\"", previews[4].BodyJson);
        Assert.Contains("WARNING", previews[1].Summary);
        Assert.Contains("WARNING", previews[5].Summary);
        Assert.Contains("WARNING", previews[6].Summary);
        Assert.Contains("WARNING", previews[7].Summary);
        Assert.Contains("WARNING", previews[8].Summary);
        Assert.Contains("replayed", previews[9].Summary);
        Assert.Contains("lost", previews[10].Summary);
        Assert.Equal("zones/zone1/origin_tls_client_auth/hostnames", previews[7].Path);
        foreach (var p in previews) Assert.DoesNotContain(Token, p.Path + p.Summary + p.BodyJson + p);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Rate_limit_upsert_creates_patches_or_skips_and_touches_only_its_rule()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);

        // no entry point yet → PUT entry point with the one rule (cf.colo.id added)
        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 10003, "not found"));
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        var (_, created) = await cf.RateLimiting.UpsertRuleAsync(LoginLimit);
        Assert.True(created);
        Assert.Equal(HttpMethod.Put, h.Requests[1].Method);
        Assert.EndsWith("/zones/zone1/rulesets/phases/http_ratelimit/entrypoint", h.Requests[1].Url);
        var rl = JsonDocument.Parse(h.Requests[1].Body!).RootElement.GetProperty("rules")[0].GetProperty("ratelimit");
        Assert.Equal("cf.colo.id", rl.GetProperty("characteristics")[0].GetString());

        // same rule (Cloudflare adds defaults) → no write
        h.Requests.Clear();
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        var (_, changed) = await cf.RateLimiting.UpsertRuleAsync(LoginLimit);
        Assert.False(changed);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        // changed threshold → PATCH of rule r1 only
        h.Requests.Clear();
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        var stricter = new RateLimitRuleInput { Ref = "login", Expression = LoginLimit.Expression, Action = WafActions.Block, RequestsPerPeriod = 5 };
        await cf.RateLimiting.UpsertRuleAsync(stricter);
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
        Assert.EndsWith("/zones/zone1/rulesets/rs1/rules/r1", h.Requests[^1].Url);

        // another ref → POST appended
        h.Responses.Enqueue(FakeHandler.Ok(RateLimitEntrypoint));
        var plan = await cf.RateLimiting.PreviewUpsertRuleAsync(new RateLimitRuleInput { Ref = "api", Expression = "starts_with(http.request.uri.path, \"/api/\")", Action = WafActions.ManagedChallenge, RequestsPerPeriod = 100 });
        Assert.Equal("POST", plan!.Method);
        Assert.Equal("zones/zone1/rulesets/rs1/rules", plan.Path);
    }

    [Fact]
    public async Task Rate_limit_and_waf_inputs_are_checked_locally()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.RateLimiting.UpsertRuleAsync(new RateLimitRuleInput { Ref = "x", Expression = "true", Action = "block", RequestsPerPeriod = 1 }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.RateLimiting.UpsertRuleAsync(new RateLimitRuleInput { Ref = "x", Expression = "e", Action = "block", RequestsPerPeriod = 1, Period = 7 }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.RateLimiting.UpsertRuleAsync(new RateLimitRuleInput { Ref = "x", Expression = "e", Action = "skip", RequestsPerPeriod = 1 }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "s", Expression = "ip.src eq 192.0.2.1", Action = WafActions.Skip }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "b", Expression = "(true)", Action = WafActions.Block }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Waf.DeployManagedRulesetAsync(ManagedRulesetIds.OwaspCore, "owasp",
            new ManagedRulesetOverrides { Rules = [new ManagedRuleOverride("6179ae15870a4bb7b2d480d4843b323c", Enabled: false)] }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Waf.DeployManagedRulesetAsync(ManagedRulesetIds.OwaspCore, "owasp", new ManagedRulesetOverrides { SensitivityLevel = "eoff" }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Waf.RemoveManagedDeploymentAsync("owasp"));
        Assert.Empty(h.Requests);

        // skip with opt-in: default action parameters "current ruleset"
        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 10003, "not found"));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"c1","kind":"zone","phase":"http_request_firewall_custom","rules":[]}"""));
        await cf.Waf.UpsertCustomRuleAsync(new WafCustomRuleInput { Ref = "monitor", Expression = "ip.src eq 192.0.2.1", Action = WafActions.Skip }, allowSkip: true);
        Assert.Contains("\"ruleset\":\"current\"", h.Requests[^1].Body);
    }

    [Fact]
    public async Task Managed_deployments_are_typed_and_loosening_needs_an_opt_in()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""
            {"id":"m1","kind":"zone","phase":"http_request_firewall_managed","rules":[
              {"id":"x1","ref":"owasp","action":"execute","expression":"true","enabled":true,
               "action_parameters":{"id":"4814384a9e5d4991b9815dcfc25d2f1f","overrides":{"sensitivity_level":"medium"}}}]}
            """));
        var deployed = Assert.Single(await cf.Waf.ListManagedDeploymentsAsync());
        Assert.Equal(ManagedRulesetIds.OwaspCore, deployed.RulesetId);
        Assert.Equal("medium", deployed.Overrides!.Value.GetProperty("sensitivity_level").GetString());

        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"m1","kind":"zone","phase":"http_request_firewall_managed","rules":[{"id":"x1","ref":"owasp","action":"execute","expression":"true","enabled":true,"action_parameters":{"id":"4814384a9e5d4991b9815dcfc25d2f1f"}}]}"""));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"m1","rules":[]}"""));
        var (_, changed) = await cf.Waf.DeployManagedRulesetAsync(ManagedRulesetIds.OwaspCore, "owasp", new ManagedRulesetOverrides { Action = WafActions.Log }, allowLoosen: true);
        Assert.True(changed);
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
        Assert.Contains("\"overrides\":{\"action\":\"log\"}", h.Requests[^1].Body);

        // remove with opt-in: read, then DELETE of the one rule
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"m1","rules":[{"id":"x1","ref":"owasp","action":"execute","expression":"true","enabled":true}]}"""));
        Assert.True(await cf.Waf.RemoveManagedDeploymentAsync("owasp", allowLoosen: true));
        Assert.Equal(HttpMethod.Delete, h.Requests[^1].Method);
        Assert.EndsWith("/rulesets/m1/rules/x1", h.Requests[^1].Url);
    }

    [Fact]
    public async Task Bot_settings_guard_automation_and_send_only_set_fields()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var ex = Assert.Throws<ArgumentException>(() => cf.Bots.PreviewUpdateSettings(new BotManagementChange { FightMode = true }));
        Assert.Contains("allowChallengeAutomation", ex.Message);
        Assert.Throws<ArgumentException>(() => cf.Bots.PreviewUpdateSettings(new BotManagementChange { SbfmDefinitelyAutomated = "block" }));
        Assert.Throws<ArgumentException>(() => cf.Bots.PreviewUpdateSettings(new BotManagementChange { SbfmVerifiedBots = "block" }));
        Assert.Throws<ArgumentException>(() => cf.Bots.PreviewUpdateSettings(new BotManagementChange()));
        Assert.Empty(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok("""{"fight_mode":false,"enable_js":true,"ai_bots_protection":"block","using_latest_model":true}"""));
        var s = await cf.Bots.UpdateSettingsAsync(new BotManagementChange { EnableJs = true, AiBotsProtection = "block" });
        Assert.True(s.EnableJs);
        var body = JsonDocument.Parse(h.Requests[0].Body!).RootElement;
        Assert.Equal(2, body.EnumerateObject().Count());
        Assert.Equal(HttpMethod.Put, h.Requests[0].Method);

        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 1004, "Super Bot Fight Mode is not available on your plan"));
        await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.Bots.UpdateSettingsAsync(new BotManagementChange { SbfmLikelyAutomated = "allow" }));

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"d1","username":"lookup_json_string(http.request.body.raw, \"user\")"}]"""));
        var (detection, created) = await cf.Bots.EnsureLeakedCredentialDetectionAsync("lookup_json_string(http.request.body.raw, \"user\")");
        Assert.False(created);
        Assert.Equal("d1", detection.Id);
        Assert.Equal(HttpMethod.Get, h.Requests[^1].Method);
    }

    [Fact]
    public async Task Custom_hostnames_ensure_survives_a_conflict_strips_keys_and_guard_removals()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Assert.Throws<ArgumentException>(() => cf.CustomHostnames.PreviewCreate(new CustomHostnameInput { Hostname = "app.customer.example", ValidationMethod = "email" }));
        Assert.Throws<ArgumentException>(() => cf.CustomHostnames.PreviewCreate(new CustomHostnameInput { Hostname = "https://app.customer.example/x" }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.CustomHostnames.RemoveFallbackOriginAsync());
        Assert.Empty(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok("[]", Empty));
        h.Responses.Enqueue(Error(HttpStatusCode.Conflict, 1406, "Duplicate custom hostname found."));
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"ch1","hostname":"app.customer.example","status":"pending","ssl":{"status":"pending_validation","method":"http","custom_key":"KEY-MATERIAL-SYNTH","validation_records":[{"http_url":"http://app.customer.example/.well-known/pki-validation/x.txt","http_body":"ca3-..."}]}}]""", Info));
        var (hostname, created) = await cf.CustomHostnames.EnsureAsync(new CustomHostnameInput { Hostname = "app.customer.example" });
        Assert.False(created);
        Assert.Equal("ch1", hostname.Id);
        Assert.Equal("pending_validation", hostname.Ssl!.Status);
        Assert.NotNull(hostname.Ssl.ValidationRecords![0].HttpUrl);
        Assert.DoesNotContain("KEY-MATERIAL-SYNTH", JsonSerializer.Serialize(hostname));
        Assert.Equal(1, h.Requests.Count(r => r.Method == HttpMethod.Post));

        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 1436, "custom hostname not found"));
        Assert.False(await cf.CustomHostnames.DeleteAsync("gone"));
        h.Responses.Enqueue(FakeHandler.Ok("""{"origin":"fallback.example.com","status":"active"}"""));
        Assert.Equal("active", (await cf.CustomHostnames.SetFallbackOriginAsync("fallback.example.com")).Status);
    }

    [Fact]
    public async Task Origin_pull_key_never_leaves_the_request_body_and_disabling_needs_an_opt_in()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var (certPem, keyPem, otherKey) = KeyPair();
        var keyLine = KeyBody(keyPem);
        var pair = OriginPullKeyPair.FromPem(certPem, keyPem);
        Assert.Contains("origin-pull-test", pair.ToString());
        Assert.DoesNotContain(keyLine, pair.ToString());
        Assert.DoesNotContain(keyLine, JsonSerializer.Serialize(pair));

        var preview = cf.OriginPulls.PreviewUploadZoneCertificate(pair);
        Assert.DoesNotContain(keyLine, preview.BodyJson + preview.Summary + preview);
        Assert.Contains("[redacted]", preview.BodyJson);

        // wrong key, key in the certificate field, encrypted key: refused without echoing the input
        var mismatch = Assert.Throws<ArgumentException>(() => OriginPullKeyPair.FromPem(certPem, otherKey));
        Assert.DoesNotContain(KeyBody(otherKey), mismatch.Message);
        var mixed = Assert.Throws<ArgumentException>(() => OriginPullKeyPair.FromPem(certPem + "\n" + keyPem, keyPem));
        Assert.DoesNotContain(keyLine, mixed.Message);
        Assert.Throws<ArgumentException>(() => OriginPullKeyPair.FromPem(certPem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----"));

        // upload: only the wire carries the key; Cloudflare's echo of private_key is stripped from the model
        h.Responses.Enqueue(FakeHandler.Ok($$"""{"id":"c1","status":"pending_deployment","certificate":"PEM","private_key":"{{keyLine}}"}"""));
        var uploaded = await cf.OriginPulls.UploadZoneCertificateAsync(pair);
        Assert.Contains(keyLine, JsonDocument.Parse(h.Requests[0].Body!).RootElement.GetProperty("private_key").GetString());
        Assert.DoesNotContain(keyLine, JsonSerializer.Serialize(uploaded));
        Assert.Equal("c1", uploaded.Id);

        // an error answer does not echo the key either
        h.Responses.Enqueue(Error(HttpStatusCode.BadRequest, 1402, "certificate rejected"));
        var err = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.OriginPulls.UploadHostnameCertificateAsync(pair));
        Assert.DoesNotContain(keyLine, err.Message + err);
        Assert.DoesNotContain(Token, err.Message);

        var count = h.Requests.Count;
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.OriginPulls.SetZoneEnabledAsync(false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.OriginPulls.DeleteZoneCertificateAsync("c1"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.OriginPulls.DeleteHostnameCertificateAsync("c1"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.OriginPulls.SetHostnamesAsync([new("api.example.com", "c1", Enabled: false)]));
        Assert.Equal(count, h.Requests.Count);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"hostname":"api.example.com","cert_id":"c1","enabled":true,"status":"pending_deployment","private_key":"X"}]"""));
        var assoc = Assert.Single(await cf.OriginPulls.SetHostnamesAsync([new("api.example.com", "c1")]));
        Assert.True(assoc.Enabled);
        Assert.False(assoc.AdditionalData?.ContainsKey("private_key") ?? false);
    }

    [Fact]
    public async Task Tls_settings_refuse_weakening_and_lock_outs_before_writing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"min_tls_version","value":"1.2","editable":true}"""));
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Tls.SetMinTlsVersionAsync("1.0"));
        Assert.Contains("allowWeaken", refused.Message);
        Assert.Single(h.Requests);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Tls.SetMinTlsVersionAsync("1.3"));
        Assert.Throws<ArgumentException>(() => cf.Tls.SetHstsAsync(new HstsSettings { Enabled = true, MaxAge = 31536000 }).GetAwaiter().GetResult());
        Assert.Throws<ArgumentException>(() => cf.Tls.PreviewSetSwitch(ZoneSettingIds.Ssl, true));

        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"ssl","value":"strict","editable":true}"""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Tls.SetSslModeAsync("flexible"));
        Assert.Equal(2, h.Requests.Count);

        // rate limit on the PATCH is retried
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"ssl","value":"full","editable":true}"""));
        h.Responses.Enqueue(Error((HttpStatusCode)429, 971, "rate limited"));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"ssl","value":"strict","editable":true}"""));
        Assert.Equal("strict", (await cf.Tls.SetSslModeAsync("strict")).ValueText);
        Assert.Equal(5, h.Requests.Count);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"ssl","value":"strict"},{"id":"min_tls_version","value":"1.2"},{"id":"security_header","value":{"strict_transport_security":{"enabled":true,"max_age":300,"include_subdomains":false,"preload":false,"nosniff":true}}}]"""));
        var overview = await cf.Tls.GetOverviewAsync();
        Assert.Equal("strict", overview.SslMode);
        Assert.Equal(300, overview.Hsts!.MaxAge);
        Assert.True(overview.Hsts.Nosniff);
    }

    [Fact]
    public async Task Logpush_destinations_are_redacted_everywhere_but_on_the_wire()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string secret = "SECRET-ACCESS-KEY-SYNTH";
        var destination = $"r2://logs/http/{{DATE}}?account-id=acc1&access-key-id=AKID-SYNTH&secret-access-key={secret}";
        Assert.Equal("r2://logs/http/{DATE}?account-id=acc1&access-key-id=[redacted]&secret-access-key=[redacted]", LogpushClient.RedactDestination(destination));
        Assert.Equal("https://collector.example.com/[redacted]?header_Authorization=[redacted]", LogpushClient.RedactDestination("https://collector.example.com/receiver/v1/http/TOKEN?header_Authorization=Splunk%20X"));
        Assert.Equal("s3://[redacted]@bucket/path?region=eu-west-1", LogpushClient.RedactDestination("s3://user:pw@bucket/path?region=eu-west-1"));

        var input = new LogpushJobInput { Name = "edge-http", Dataset = "http_requests", DestinationConf = destination, OwnershipChallenge = "CHALLENGE-SYNTH" };
        var preview = cf.Logpush.PreviewCreateJob(input);
        Assert.DoesNotContain(secret, preview.BodyJson + preview.Summary + preview);
        Assert.DoesNotContain("CHALLENGE-SYNTH", preview.BodyJson);
        Assert.DoesNotContain(secret, input.ToString());

        h.Responses.Enqueue(FakeHandler.Ok($$"""{"id":7,"name":"edge-http","dataset":"http_requests","enabled":true,"destination_conf":"{{destination}}"}"""));
        var job = await cf.Logpush.CreateJobAsync(input);
        Assert.Contains(secret, h.Requests[0].Body);
        Assert.DoesNotContain(secret, job.DestinationConf);
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(job));
        Assert.Single(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok($$"""[{"id":7,"name":"edge-http","dataset":"http_requests","enabled":true,"destination_conf":"{{destination}}"}]"""));
        var (same, created) = await cf.Logpush.EnsureJobAsync(input);
        Assert.False(created);
        Assert.Equal(7, same.Id);
        Assert.EndsWith("/zones/zone1/logpush/jobs", h.Requests[^1].Url);

        h.Responses.Enqueue(FakeHandler.Ok("[]"));
        await cf.Logpush.ListJobsAsync(LogpushScope.Account);
        Assert.EndsWith("/accounts/acc1/logpush/jobs", h.Requests[^1].Url);
        Assert.Throws<ArgumentException>(() => cf.Logpush.PreviewCreateJob(new LogpushJobInput { Dataset = "http_requests", DestinationConf = "not a url" }));
    }

    [Fact]
    public async Task Dns_safe_upsert_keeps_the_origin_hidden_and_writes_only_on_change()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string existing = """[{"id":"rec1","type":"A","name":"app.example.com","content":"203.0.113.5","proxied":true,"ttl":1}]""";
        h.Responses.Enqueue(FakeHandler.Ok(existing, Info));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = false }));
        Assert.Single(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok(existing, Info));
        var (_, changed) = await cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.5", Proxied = true });
        Assert.False(changed);
        Assert.Equal(2, h.Requests.Count);

        h.Responses.Enqueue(FakeHandler.Ok(existing, Info));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"rec1","type":"A","name":"app.example.com","content":"203.0.113.9","proxied":true,"ttl":1}"""));
        var (record, changed2) = await cf.Dns.SafeUpsertAsync(new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.9", Proxied = true });
        Assert.True(changed2);
        Assert.Equal("203.0.113.9", record.Content);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);

        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 81044, "Record does not exist."));
        Assert.False(await cf.Dns.DeleteIfExistsAsync("gone"));
    }

    [Fact]
    public void The_old_client_certificate_method_is_obsolete()
    {
        var method = typeof(CertificatesClient).GetMethod(nameof(CertificatesClient.CreateClientCertificateAsync))!;
        var attribute = Assert.Single(method.GetCustomAttributes(typeof(ObsoleteAttribute), false));
        Assert.Contains("ApiShield.CreateClientCertificateAsync", ((ObsoleteAttribute)attribute).Message);
    }
}
