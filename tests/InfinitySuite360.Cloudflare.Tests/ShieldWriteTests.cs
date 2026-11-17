using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Shield write calls (0.5.0). Fake handler only: no network, no real token, no real keys.</summary>
public class ShieldWriteTests
{
    private const string Info = """{"page":1,"per_page":50,"count":1,"total_count":1,"total_pages":1}""";
    private const string Token = "secret-token-123";

    // Synthetic public RSA JWK (not a real key) and a symmetric one whose value must never show up anywhere.
    private const string RsaJwks = """{"keys":[{"kty":"RSA","alg":"RS256","kid":"k1","n":"MODULUS-SYNTHETIC-AAAA","e":"AQAB"}]}""";
    private const string SymmetricSecret = "SYMMETRIC-SECRET-VALUE-XYZ";
    private static readonly string OctJwks = $$"""[{"kty":"oct","alg":"HS256","kid":"h1","k":"{{SymmetricSecret}}"}]""";

    private static readonly string Schema = """{"openapi":"3.0.3","info":{"title":"t","version":"1"},"servers":[{"url":"https://api.example.com"}],"paths":{}}""";

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    [Fact]
    public async Task Every_write_is_refused_without_AllowWrites_and_nothing_is_sent()
    {
        var (cf, h, _) = FakeHandler.Create();
        var keys = JwtKeySet.Parse(RsaJwks);
        Func<Task>[] writes =
        [
            () => cf.ApiShield.AddOperationsAsync([new("GET", "api.example.com", "/v1/x")]),
            () => cf.ApiShield.EnsureOperationsAsync([new("GET", "api.example.com", "/v1/x")]),
            () => cf.ApiShield.DeleteOperationAsync("o1"),
            () => cf.ApiShield.DeleteOperationsAsync(["o1", "o2"]),
            () => cf.ApiShield.SetDiscoveryStateAsync("d1", "ignored"),
            () => cf.ApiShield.SetSessionIdentifierAsync([new("header", "authorization")]),
            () => cf.ApiShield.UploadSchemaAsync(new ApiShieldSchemaInput { Name = "s", Source = Schema }),
            () => cf.ApiShield.EnsureSchemaAsync(new ApiShieldSchemaInput { Name = "s", Source = Schema }),
            () => cf.ApiShield.SetSchemaValidationEnabledAsync("sc1", true),
            () => cf.ApiShield.DeleteSchemaAsync("sc1"),
            () => cf.ApiShield.SetOverrideActionAsync(null),
            () => cf.ApiShield.SetOperationActionsAsync(new Dictionary<string, string?> { ["o1"] = "log" }),
            () => cf.ApiShield.ResetOperationActionAsync("o1"),
            () => cf.ApiShield.CreateTokenValidationConfigAsync(new TokenValidationConfigInput { Title = "t", Description = "", TokenSources = ["http.request.headers[\"authorization\"][0]"], Keys = keys }),
            () => cf.ApiShield.ReplaceTokenValidationKeysAsync("c1", keys),
            () => cf.ApiShield.CreateTokenValidationRuleAsync(new TokenValidationRuleInput { Title = "r", Expression = "is_jwt_valid(\"c1\")" }),
            () => cf.ApiShield.DeleteTokenValidationRuleAsync("r1"),
            () => cf.ApiShield.EnsureUserLabelAsync("team-a"),
            () => cf.ApiShield.AddLabelsToOperationsAsync(["o1"], userLabels: ["team-a"]),
            () => cf.ApiShield.CreateClientCertificateAsync("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----"),
            () => cf.ApiShield.RevokeClientCertificateAsync("cc1"),
            () => cf.ApiShield.ReplaceHostnameAssociationsAsync(["api.example.com"]),
            () => cf.PageShield.EnsurePolicyAsync(new PageShieldPolicyInput { Description = "d", Expression = "e", Value = "v" }),
            () => cf.PageShield.DeletePolicyAsync("p1"),
        ];
        foreach (var write in writes) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(write);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Write_filter_is_honoured_by_the_new_methods()
    {
        var (cf, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, path) => path.EndsWith("/page_shield", StringComparison.Ordinal); });
        await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(() => cf.ApiShield.DeleteSchemaAsync("sc1"));
        Assert.Empty(h.Requests);
        h.Responses.Enqueue(FakeHandler.Ok("""{"enabled":true,"use_cloudflare_reporting_endpoint":true,"use_connection_url_path":false}"""));
        Assert.True((await cf.PageShield.SetSettingsAsync(enabled: true)).Enabled);
        Assert.Single(h.Requests);
    }

    [Fact]
    public async Task Previews_build_the_request_and_send_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var p1 = cf.ApiShield.PreviewAddOperations([new("get", "API.example.com", "/v1/users/{var1}")]);
        Assert.Equal("POST", p1.Method);
        Assert.Equal("zones/zone1/api_gateway/operations", p1.Path);
        Assert.Contains("\"method\": \"GET\"", p1.BodyJson);
        Assert.Contains("\"host\": \"api.example.com\"", p1.BodyJson);

        var p2 = cf.ApiShield.PreviewDeleteOperations(["o1", "o1", "o2"]);
        Assert.Equal("DELETE", p2.Method);
        Assert.Contains("2 API operation", p2.Summary);

        var p3 = cf.ApiShield.PreviewSetOperationAction("o1", null);
        Assert.Contains("\"mitigation_action\": null", p3.BodyJson);

        var p4 = cf.ApiShield.PreviewSetDiscoveryStates(new Dictionary<string, string> { ["d1"] = "review", ["d2"] = "ignored" });
        Assert.Equal("PATCH", p4.Method);
        Assert.Contains("\"d2\"", p4.BodyJson);

        var p5 = cf.ApiShield.PreviewSetSessionIdentifier([new("header", "authorization"), new("cookie", "sid")]);
        Assert.Contains("auth_id_characteristics", p5.BodyJson);

        var p6 = cf.ApiShield.PreviewCreateClientCertificate("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----", 30);
        Assert.Contains("\"validity_days\": 30", p6.BodyJson);

        var p7 = cf.PageShield.PreviewSetSettings(enabled: false);
        Assert.Contains("OFF", p7.Summary);

        foreach (var p in new[] { p1, p2, p3, p4, p5, p6, p7 })
            Assert.DoesNotContain(Token, p.Path + p.Summary + p.BodyJson + p);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public void Block_is_never_a_default_and_needs_an_explicit_option()
    {
        var (cf, _, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var ex = Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewSetDefaultAction("block"));
        Assert.Contains("allowBlock", ex.Message);
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewSetOperationAction("o1", "block"));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewSetOperationActions(new Dictionary<string, string?> { ["o1"] = "block" }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateTokenValidationRule(new TokenValidationRuleInput { Title = "r", Action = "block", Expression = "x" }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUpdateTokenValidationRule("r1", new TokenValidationRuleChange { Action = "block" }));
        Assert.Throws<ArgumentException>(() => cf.PageShield.PreviewCreatePolicy(new PageShieldPolicyInput { Action = "allow", Description = "d", Expression = "e", Value = "v" }));

        Assert.Equal("log", new TokenValidationRuleInput().Action);
        Assert.Equal("log", new PageShieldPolicyInput().Action);
        Assert.False(new ApiShieldSchemaInput().ValidationEnabled);

        var blocked = cf.ApiShield.PreviewSetDefaultAction("block", allowBlock: true);
        Assert.Contains("WARNING", blocked.Summary);
        var enforce = cf.PageShield.PreviewCreatePolicy(new PageShieldPolicyInput { Action = "allow", Description = "d", Expression = "e", Value = "v" }, allowEnforce: true);
        Assert.Contains("WARNING", enforce.Summary);
        // token rules know no "none"
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateTokenValidationRule(new TokenValidationRuleInput { Title = "r", Action = "none", Expression = "x" }));
    }

    [Fact]
    public async Task Ensure_operations_adds_only_missing_ones_in_one_call()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""[{"operation_id":"o1","method":"GET","host":"api.example.com","endpoint":"/v1/users/{var1}"}]""", Info));
        h.Responses.Enqueue(FakeHandler.Ok("""[{"operation_id":"o2","method":"POST","host":"api.example.com","endpoint":"/v1/orders"}]"""));
        var result = await cf.ApiShield.EnsureOperationsAsync([new("GET", "api.example.com", "/v1/users/{var1}"), new("POST", "api.example.com", "/v1/orders"), new("post", "API.example.com", "/v1/orders")]);
        Assert.Equal("o1", Assert.Single(result.Existing).OperationId);
        Assert.Equal("o2", Assert.Single(result.Added).OperationId);
        Assert.Equal(2, h.Requests.Count);
        Assert.Equal(HttpMethod.Post, h.Requests[1].Method);
        Assert.DoesNotContain("users", h.Requests[1].Body);

        // everything present: nothing written
        h.Responses.Enqueue(FakeHandler.Ok("""[{"operation_id":"o1","method":"GET","host":"api.example.com","endpoint":"/v1/users/{var1}"}]""", Info));
        Assert.Null(await cf.ApiShield.PreviewEnsureOperationsAsync([new("GET", "api.example.com", "/v1/users/{var1}")]));
        Assert.Equal(HttpMethod.Get, h.Requests[^1].Method);
    }

    [Fact]
    public async Task Bulk_delete_sends_body_and_single_delete_is_idempotent()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await cf.ApiShield.DeleteOperationsAsync(["o1", "o2"]);
        Assert.Equal(HttpMethod.Delete, h.Requests[0].Method);
        Assert.Contains("\"operation_id\":\"o2\"", h.Requests[0].Body);

        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 10404, "operation not found"));
        Assert.False(await cf.ApiShield.DeleteOperationAsync("gone"));
        Assert.True(await cf.ApiShield.DeleteOperationAsync("o3"));
        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 10404, "not found"));
        Assert.False(await cf.PageShield.DeletePolicyAsync("p-gone"));
    }

    [Fact]
    public async Task Schema_upload_checks_locally_and_keeps_the_text_out_of_the_preview()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var input = new ApiShieldSchemaInput { Name = "MT5GW api v1", Source = Schema };
        var preview = cf.ApiShield.PreviewUploadSchema(input, new ApiShieldSchemaUploadOptions { AllowedHosts = ["api.example.com"] });
        Assert.DoesNotContain("\"paths\"", preview.BodyJson);
        Assert.Contains("sha256", preview.BodyJson);
        Assert.Contains("not enabled", preview.Summary);

        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUploadSchema(input, new ApiShieldSchemaUploadOptions { AllowedHosts = ["other.example.com"] }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUploadSchema(input, new ApiShieldSchemaUploadOptions { MaxBytes = 10 }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUploadSchema(new ApiShieldSchemaInput { Name = "x", Source = """{"swagger":"2.0"}""" }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUploadSchema(new ApiShieldSchemaInput { Name = "x", Source = "openapi: 3.0.0\n" }, new ApiShieldSchemaUploadOptions { AllowedHosts = ["a"] }));
        Assert.Empty(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok("""{"schema_id":"sc1","name":"MT5GW api v1","kind":"openapi_v3","validation_enabled":false}"""));
        var s = await cf.ApiShield.UploadSchemaAsync(input);
        Assert.Equal("sc1", s.SchemaId);
        var sent = JsonDocument.Parse(h.Requests[0].Body!).RootElement;
        Assert.False(sent.GetProperty("validation_enabled").GetBoolean());
        Assert.Equal(Schema, sent.GetProperty("source").GetString());
        Assert.EndsWith("/zones/zone1/schema_validation/schemas", h.Requests[0].Url);
    }

    [Fact]
    public async Task Ensure_schema_reuses_an_existing_name_and_survives_a_conflict()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""[{"schema_id":"sc1","name":"api","kind":"openapi_v3","validation_enabled":false}]""", Info));
        var (schema, created) = await cf.ApiShield.EnsureSchemaAsync(new ApiShieldSchemaInput { Name = "api", Source = Schema });
        Assert.False(created);
        Assert.Equal("sc1", schema.SchemaId);
        Assert.Single(h.Requests);

        // missing → POST → 409 (created concurrently) → read back
        h.Responses.Enqueue(FakeHandler.Ok("[]", """{"page":1,"per_page":50,"count":0,"total_count":0,"total_pages":0}"""));
        h.Responses.Enqueue(Error(HttpStatusCode.Conflict, 20409, "schema with this name already exists"));
        h.Responses.Enqueue(FakeHandler.Ok("""[{"schema_id":"sc9","name":"new","kind":"openapi_v3"}]""", Info));
        var (raced, created2) = await cf.ApiShield.EnsureSchemaAsync(new ApiShieldSchemaInput { Name = "new", Source = Schema });
        Assert.False(created2);
        Assert.Equal("sc9", raced.SchemaId);
        Assert.Equal(4, h.Requests.Count);
        Assert.Equal(1, h.Requests.Count(r => r.Method == HttpMethod.Post)); // POST not repeated
    }

    [Fact]
    public async Task Not_entitled_is_its_own_exception_and_differs_from_a_permission_error()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 10403, "zone is not entitled to use token validation"));
        var keys = JwtKeySet.Parse(OctJwks);
        var ex = await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.ApiShield.CreateTokenValidationConfigAsync(new TokenValidationConfigInput
        {
            Title = "jwt", Description = "", TokenSources = ["http.request.headers[\"authorization\"][0]"], Keys = keys,
        }));
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.IsAssignableFrom<CloudflareApiException>(ex);
        Assert.DoesNotContain(Token, ex.Message);
        Assert.DoesNotContain(SymmetricSecret, ex.Message + ex);
        Assert.Single(h.Requests); // POST not retried

        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 10000, "Authentication error"));
        var auth = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.PageShield.CreatePolicyAsync(new PageShieldPolicyInput { Description = "d", Expression = "e", Value = "v" }));
        Assert.IsNotType<CloudflareNotEntitledException>(auth);

        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 1001, "Content security rules are not available on your plan"));
        await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.PageShield.ListPoliciesAsync());
    }

    [Fact]
    public async Task Rate_limit_is_retried_for_writes_but_server_errors_only_for_idempotent_ones()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error((HttpStatusCode)429, 971, "rate limited"));
        h.Responses.Enqueue(FakeHandler.Ok("""{"operation_id":"o1","mitigation_action":"log"}"""));
        Assert.Equal("log", (await cf.ApiShield.SetOperationActionAsync("o1", "log")).MitigationAction);
        Assert.Equal(2, h.Requests.Count);

        h.Requests.Clear();
        h.Responses.Enqueue(Error(HttpStatusCode.ServiceUnavailable, 0, "unavailable"));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.ApiShield.AddOperationsAsync([new("GET", "api.example.com", "/x")]));
        Assert.Single(h.Requests); // POST is not repeated after 503
    }

    [Fact]
    public async Task Jwt_keys_never_leave_the_request_body()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var keys = JwtKeySet.Parse(OctJwks);
        Assert.True(keys.ContainsSymmetricKey);
        Assert.DoesNotContain(SymmetricSecret, keys.ToString());
        Assert.DoesNotContain(SymmetricSecret, JsonSerializer.Serialize(keys));

        var input = new TokenValidationConfigInput { Title = "jwt", Description = "d", TokenSources = ["http.request.cookies[\"jwt\"][0]"], Keys = keys };
        var preview = cf.ApiShield.PreviewCreateTokenValidationConfig(input);
        Assert.DoesNotContain(SymmetricSecret, preview.BodyJson + preview.Summary + preview);
        Assert.Contains("[redacted]", preview.BodyJson);
        Assert.Contains("symmetric", preview.Summary);
        Assert.Empty(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok($$$"""{"id":"c1","title":"jwt","token_type":"JWT","token_sources":["http.request.cookies[\"jwt\"][0]"],"credentials":{"keys":[{"kid":"h1","kty":"oct","alg":"HS256","k":"{{{SymmetricSecret}}}"}]}}"""));
        var config = await cf.ApiShield.CreateTokenValidationConfigAsync(input);
        Assert.Contains(SymmetricSecret, h.Requests[0].Body); // only the wire carries it
        Assert.Equal("h1", config.Credentials!.Keys![0].Kid);
        Assert.DoesNotContain(SymmetricSecret, JsonSerializer.Serialize(config));

        h.Responses.Enqueue(FakeHandler.Ok($$"""{"keys":[{"kid":"h1","kty":"oct","alg":"HS256","k":"{{SymmetricSecret}}"}]}"""));
        var replaced = await cf.ApiShield.ReplaceTokenValidationKeysAsync("c1", keys);
        Assert.DoesNotContain(SymmetricSecret, replaced.GetRawText());
        Assert.Equal(HttpMethod.Put, h.Requests[1].Method);

        // private key members and bad sources are refused, and the message does not repeat the input
        var priv = Assert.Throws<ArgumentException>(() => JwtKeySet.Parse("""{"keys":[{"kty":"RSA","alg":"RS256","n":"N","e":"AQAB","d":"PRIVATE-EXPONENT-SYNTH"}]}"""));
        Assert.DoesNotContain("PRIVATE-EXPONENT-SYNTH", priv.Message);
        var bad = Assert.Throws<ArgumentException>(() => JwtKeySet.Parse("not json " + SymmetricSecret));
        Assert.DoesNotContain(SymmetricSecret, bad.Message + bad);
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateTokenValidationConfig(new TokenValidationConfigInput { Title = "x", Description = "", TokenSources = ["http.request.headers[\"Authorization\"][0]"], Keys = keys }));
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateTokenValidationConfig(new TokenValidationConfigInput { Title = "x", Description = "", TokenSources = ["query.token"], Keys = keys }));
    }

    [Fact]
    public async Task Token_rules_and_labels_send_the_documented_bodies()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"r1","title":"r","action":"log","enabled":true}"""));
        await cf.ApiShield.CreateTokenValidationRuleAsync(new TokenValidationRuleInput { Title = "r", Expression = "is_jwt_valid(\"c1\")", IncludeHosts = ["api.example.com"] });
        var rule = JsonDocument.Parse(h.Requests[0].Body!).RootElement;
        Assert.Equal("log", rule.GetProperty("action").GetString());
        Assert.Equal("api.example.com", rule.GetProperty("selector").GetProperty("include")[0].GetProperty("host")[0].GetString());

        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"r1","title":"r","action":"log","enabled":false}"""));
        await cf.ApiShield.UpdateTokenValidationRuleAsync("r1", new TokenValidationRuleChange { Enabled = false, PositionIndex = 1 });
        Assert.Equal(HttpMethod.Patch, h.Requests[1].Method);
        Assert.Contains("\"position\":{\"index\":1}", h.Requests[1].Body);
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewUpdateTokenValidationRule("r1", new TokenValidationRuleChange { PositionIndex = 1, PositionAfter = "r2" }));

        // EnsureUserLabel: exists → no write
        h.Responses.Enqueue(FakeHandler.Ok("""[{"name":"team-a","source":"user"}]""", Info));
        var (label, created) = await cf.ApiShield.EnsureUserLabelAsync("team-a");
        Assert.False(created);
        Assert.Equal("team-a", label.Name);
        Assert.Equal(3, h.Requests.Count);

        await cf.ApiShield.AddLabelsToOperationsAsync(["o1", "o2"], userLabels: ["team-a"]);
        var labels = JsonDocument.Parse(h.Requests[3].Body!).RootElement;
        Assert.Equal(2, labels.GetProperty("selector").GetProperty("include").GetProperty("operation_ids").GetArrayLength());
        Assert.False(labels.TryGetProperty("managed", out _));
        await cf.ApiShield.RemoveLabelsFromOperationsAsync(["o1"], managedLabels: ["cf-risk-sensitive"]);
        Assert.Equal(HttpMethod.Delete, h.Requests[4].Method);
        Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateUserLabels([("cf-own", null)]));
    }

    [Fact]
    public async Task Mtls_refuses_private_keys_and_guards_hostname_removal()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var key = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----";
        var ex = Assert.Throws<ArgumentException>(() => cf.ApiShield.PreviewCreateClientCertificate(key));
        Assert.DoesNotContain("SYNTHETIC", ex.Message);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.ApiShield.CreateClientCertificateAsync("-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n" + key));
        Assert.Throws<ArgumentOutOfRangeException>(() => cf.ApiShield.PreviewCreateClientCertificate("-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----", 0));
        Assert.Empty(h.Requests);

        // removal refused: read only, nothing written
        h.Responses.Enqueue(FakeHandler.Ok("""{"hostnames":["api.example.com","admin.example.com"]}"""));
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.ApiShield.ReplaceHostnameAssociationsAsync(["api.example.com"]));
        Assert.Contains("admin.example.com", refused.Message);
        Assert.Single(h.Requests);
        Assert.Equal(HttpMethod.Get, h.Requests[0].Method);

        // preview lists added and removed hostnames
        h.Responses.Enqueue(FakeHandler.Ok("""{"hostnames":["api.example.com","admin.example.com"]}"""));
        var preview = await cf.ApiShield.PreviewReplaceHostnameAssociationsAsync(["api.example.com", "new.example.com"]);
        Assert.Contains("add new.example.com", preview.Summary);
        Assert.Contains("remove admin.example.com", preview.Summary);
        Assert.Contains("WARNING", preview.Summary);

        // only additions → PUT
        h.Responses.Enqueue(FakeHandler.Ok("""{"hostnames":["api.example.com"]}"""));
        h.Responses.Enqueue(FakeHandler.Ok("""{"hostnames":["api.example.com","new.example.com"]}"""));
        var result = await cf.ApiShield.ReplaceHostnameAssociationsAsync(["new.example.com", "api.example.com"]);
        Assert.Equal(2, result.Hostnames.Count);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);

        // explicit removal skips the read
        var before = h.Requests.Count;
        h.Responses.Enqueue(FakeHandler.Ok("""{"hostnames":[]}"""));
        await cf.ApiShield.ReplaceHostnameAssociationsAsync([], allowRemovals: true);
        Assert.Equal(before + 1, h.Requests.Count);

        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"cc1","status":"pending_revocation"}"""));
        Assert.Equal("pending_revocation", (await cf.ApiShield.RevokeClientCertificateAsync("cc1")).Status);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"cc1","status":"pending_reactivation"}"""));
        Assert.Equal("pending_reactivation", (await cf.ApiShield.ReactivateClientCertificateAsync("cc1")).Status);
        Assert.Contains("\"reactivate\":true", h.Requests[^1].Body);
    }

    [Fact]
    public async Task Page_shield_ensure_policy_writes_only_on_change()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var input = new PageShieldPolicyInput { Description = "csp report", Expression = "(http.host eq \"a.example\")", Value = "script-src 'self'" };
        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"p1","action":"log","description":"csp report","enabled":true,"expression":"(http.host eq \"a.example\")","value":"script-src 'self'"}]""", Info));
        var (same, changed) = await cf.PageShield.EnsurePolicyAsync(input);
        Assert.False(changed);
        Assert.Equal("p1", same.Id);
        Assert.Single(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"p1","action":"log","description":"csp report","enabled":true,"expression":"(http.host eq \"a.example\")","value":"script-src 'none'"}]""", Info));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"p1","action":"log","description":"csp report","enabled":true,"expression":"e","value":"script-src 'self'"}"""));
        var (_, changed2) = await cf.PageShield.EnsurePolicyAsync(input);
        Assert.True(changed2);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        Assert.EndsWith("/page_shield/policies/p1", h.Requests[^1].Url);

        Assert.Throws<ArgumentException>(() => cf.PageShield.PreviewSetSettings());
        Assert.Throws<ArgumentException>(() => cf.PageShield.PreviewCreatePolicy(new PageShieldPolicyInput { Description = "", Expression = "e", Value = "v" }));
    }
}
