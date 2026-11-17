#pragma warning disable CS0618 // the obsolete Access/Tunnels methods are tested on purpose (M7)
using System.ComponentModel;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>
/// 0.8.1: findings of the independent security review of the Zero Trust clients (H1–H3, M1–M8, L1–L8) and the tests the review missed.
/// Fake handler only: no network, no real token, synthetic markers.
/// </summary>
public class ZeroTrustHardeningTests
{
    private const string SecretMarker = "SYNTHETIC-ZT-SECRET-7730";

    private static HttpResponseMessage Ok(string result, string? info = null) => FakeHandler.Ok(result, info);

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

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

    private const string OnePage = """{"page":1,"per_page":50,"count":1,"total_count":1,"total_pages":1}""";

    private static async Task<Exception> Refused(FakeHandler h, Func<Task> action)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.Empty(h.Requests);
        return ex;
    }

    private static async Task<Exception> RefusedAfterRead(FakeHandler h, Func<Task> action)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        return ex;
    }

    private static List<JsonElement> Rules(params JsonElement[] r) => [.. r];

    private static JsonElement Rule(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static GatewayRuleInput DnsRule(string action, string traffic = "any(dns.domains[*] == \"bad.example\")", bool enabled = true, int? precedence = null) =>
        new() { Name = "r", Action = action, Filters = ["dns"], Traffic = traffic, Enabled = enabled, Precedence = precedence };

    private static readonly string[] ZeroTrustClients = ["Access", "Gateway", "Tunnels", "Devices"];

    // ---------------------------------------------------------------- H1: ".." as id

    [Theory]
    [InlineData("Access")]
    [InlineData("Gateway")]
    [InlineData("Tunnels")]
    [InlineData("Devices")]
    public async Task H1_no_method_of_the_client_builds_a_path_with_a_dot_segment(string clientName)
    {
        var violations = new List<string>();
        var called = 0;
        foreach (var m in ClientSurface.Methods().Where(m => m.Client.Name == clientName))
        {
            if (!m.Method.GetParameters().Any(p => p.ParameterType == typeof(string) || p.ParameterType.GetInterfaces().Contains(typeof(IEnumerable<string>)))) continue;
            foreach (var forced in new[] { "..", "%2e%2e", "." })
            {
                var (_, h, options) = FakeHandler.Create(o => o.AllowWrites = true);
                var spy = new RecordingConnection(new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask));
                var ex = await ClientSurface.InvokeAsync(m.Client.GetValue(new CloudflareClient(spy))!, m.Method, ClientSurface.Arguments(m.Method, forced));
                called++;
                if (ex is TimeoutException) violations.Add($"{ClientSurface.Name(m)} with {forced}: timed out");
                foreach (var (method, path) in spy.Calls)
                    if (CloudflarePath.Normalize(path).Split('/').Any(s => s is "." or ".." || Uri.UnescapeDataString(s) is "." or ".."))
                        violations.Add($"{ClientSurface.Name(m)} with {forced}: {method} {path}");
                foreach (var r in h.Requests)
                    if (r.Url.Contains("/../", StringComparison.Ordinal) || r.Url.EndsWith("/..", StringComparison.Ordinal) || r.Url.Contains("%2e", StringComparison.OrdinalIgnoreCase))
                        violations.Add($"{ClientSurface.Name(m)} with {forced}: sent {r.Method} {r.Url}");
            }
        }
        Assert.True(called >= 30, $"only {called} calls for {clientName}");
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    [Fact]
    public async Task H1_dot_dot_ids_in_the_reviewed_scenarios_send_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var policy = new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.Email("a@example.com")) };
        Func<Task>[] calls =
        [
            () => cf.Access.ChangeApplicationPolicyAsync("..", "p1", policy, allowLoosen: true, allowBlock: true),
            () => cf.Access.ChangeApplicationPolicyAsync("a1", "..", policy, allowLoosen: true, allowBlock: true),
            () => cf.Access.RemoveApplicationPolicyAsync("..", "p1", allowRemoveLast: true, allowLoosen: true),
            () => cf.Access.RemoveApplicationPolicyAsync("a1", "..", allowRemoveLast: true, allowLoosen: true),
            () => cf.Access.ChangePolicyAsync("..", policy, allowLoosen: true, allowBlock: true),
            () => cf.Access.RemoveGroupAsync("..", allowInUse: true),
            () => cf.Tunnels.RemoveAsync("..", allowDeleteActive: true),
            () => cf.Tunnels.RemoveAsync("%2e%2e", allowDeleteActive: true),
            () => cf.Tunnels.SetIngressAsync("..", [], allowDisconnect: true),
            () => cf.Tunnels.GetRunTokenAsync("..", allowReadSecret: true),
            () => cf.Gateway.ChangeRuleAsync("..", DnsRule("block"), true, true, true),
            () => cf.Gateway.RemoveListAsync("..", allowInUse: true),
            () => cf.Devices.UpdateProfileAsync("..", new DeviceProfileSettings(), null, true, true),
            () => cf.Devices.SetSplitTunnelExcludeAsync([], "..", true, true, true, allowBroadRoute: true),
            () => cf.Devices.RemovePostureRuleAsync("..", allowInUse: true),
        ];
        foreach (var call in calls) await Assert.ThrowsAsync<ArgumentException>(call);
        Assert.Empty(h.Requests);
    }

    // ---------------------------------------------------------------- guards the review found missing

    /// <summary>Every Zero Trust method that hits <c>WriteFilter</c> has sent nothing before – also the ones that read before they write.</summary>
    [Fact]
    public async Task WriteFilter_is_checked_before_every_preparing_read_of_the_Zero_Trust_clients()
    {
        var violations = new List<string>();
        var guarded = 0;
        foreach (var m in ClientSurface.Methods().Where(m => ZeroTrustClients.Contains(m.Client.Name)))
        {
            var (client, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, _) => false; });
            var ex = await ClientSurface.InvokeAsync(m.Client.GetValue(client)!, m.Method, ClientSurface.Arguments(m.Method));
            if (ex is TimeoutException) violations.Add($"{ClientSurface.Name(m)}: timed out");
            foreach (var r in h.Requests.Where(r => r.Method != HttpMethod.Get))
                violations.Add($"{ClientSurface.Name(m)}: sent {r.Method} {r.Url}");
            if (ex is CloudflareWriteNotAllowedException)
            {
                guarded++;
                if (h.Requests.Count > 0) violations.Add($"{ClientSurface.Name(m)}: read {h.Requests.Count}x before WriteFilter refused ({string.Join(", ", h.Requests.Select(r => r.Url))})");
            }
        }
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
        Assert.True(guarded >= 60, $"only {guarded} Zero Trust methods reached the write filter");
    }

    [Fact]
    public async Task Async_previews_read_but_never_write()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h,
            R("GET", "/access/apps/a1/policies/p1", """{"id":"p1","name":"staff","decision":"allow","include":[{"email":{"email":"a@example.com"}}]}"""),
            R("GET", "/access/organizations", """{"name":"Team","auth_domain":"team.cloudflareaccess.com"}"""),
            R("GET", "/gateway/rules/r1", """{"id":"r1","name":"bad","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"bad.example\")"}"""),
            R("GET", "/gateway/configuration", """{"settings":{"tls_decrypt":{"enabled":true}}}"""),
            R("GET", "/cfd_tunnel/t1/configurations", """{"tunnel_id":"t1","version":1,"config":{"ingress":[{"hostname":"gw.example.com","service":"http://localhost:8080"},{"service":"http_status:404"}]}}"""),
            R("GET", "/devices/policy/exclude", """[{"address":"192.168.0.0/16"}]"""),
            R("GET", "/devices/policy", """{"name":"Default","default":true,"switch_locked":true}"""));
        var previews = new[]
        {
            await cf.Access.PreviewChangeApplicationPolicyAsync("a1", "p1", new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.Everyone()) }),
            await cf.Access.PreviewUpdateOrganizationAsync(new AccessOrganizationChange { SessionDuration = "720h", AllowAuthenticateViaWarp = true }),
            await cf.Gateway.PreviewChangeRuleAsync("r1", DnsRule("allow")),
            await cf.Gateway.PreviewUpdateConfigurationAsync(new GatewaySettingsChange { TlsDecrypt = false }),
            await cf.Tunnels.PreviewSetIngressAsync("t1", [new TunnelIngressRule { Hostname = "*.example.com", Service = "http://localhost:9000" }, new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080" }]),
            await cf.Devices.PreviewUpdateDefaultProfileAsync(new DeviceProfileSettings { SwitchLocked = false }),
            await cf.Devices.PreviewSetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress("10.0.0.0/8")]),
        };
        Assert.NotEmpty(h.Requests);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        Assert.All(previews, p => Assert.Contains("WARNING", p.Summary));
        Assert.Contains("gw.example.com", previews[4].Summary);
    }

    // ---------------------------------------------------------------- H2: Access loosening

    [Fact]
    public async Task H2c_policies_that_admit_nearly_everyone_need_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        AccessPolicyInput[] wide =
        [
            new() { Name = "a", Include = Rules(AccessRules.Everyone()), Require = Rules(AccessRules.Everyone()) },
            new() { Name = "b", Include = Rules(AccessRules.IpRange("0.0.0.0/0")) },
            new() { Name = "c", Include = Rules(AccessRules.IpRange("::/0")) },
            new() { Name = "d", Decision = "non_identity", Include = Rules(AccessRules.AnyValidServiceToken()) },
            new() { Name = "e", Include = Rules(AccessRules.EmailDomain("gmail.com")) },
            new() { Name = "f", Include = Rules(AccessRules.Everyone()), Require = Rules(AccessRules.IpRange("0.0.0.0/0")) },
        ];
        foreach (var p in wide) Assert.Contains("allowLoosen", (await Refused(h, () => cf.Access.AddApplicationPolicyAsync("a1", p))).Message);
        await Refused(h, () => cf.Access.EnsurePolicyAsync(wide[1]));

        // A company domain or a narrowing require is fine.
        h.Responses.Enqueue(Ok("""{"id":"p9","name":"staff","decision":"allow"}"""));
        await cf.Access.AddApplicationPolicyAsync("a1", new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.EmailDomain("example.com")) });
        h.Responses.Enqueue(Ok("""{"id":"p9","name":"staff","decision":"allow"}"""));
        await cf.Access.AddApplicationPolicyAsync("a1", new AccessPolicyInput { Name = "mfa", Include = Rules(AccessRules.Everyone()), Require = Rules(AccessRules.EmailDomain("example.com")) });
        Assert.Equal(2, h.Requests.Count(r => r.Method == HttpMethod.Post));
    }

    [Fact]
    public async Task H2a_H2b_H2d_changes_that_widen_a_policy_need_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string allow = """{"id":"p1","name":"staff","decision":"allow","precedence":5,"session_duration":"24h","include":[{"email":{"email":"a@example.com"}}],"exclude":[],"require":[]}""";
        const string deny = """{"id":"p2","name":"geo","decision":"deny","precedence":1,"include":[{"geo":{"country_code":"RU"}}],"exclude":[],"require":[]}""";
        Route(h, R("GET", "/access/apps/a1/policies/p1", allow), R("PUT", "/access/apps/a1/policies/p1", allow),
            R("GET", "/access/apps/a1/policies/p2", deny), R("PUT", "/access/apps/a1/policies/p2", deny));

        var a = Rules(AccessRules.Email("a@example.com"));
        // a) more include rules on an admitting policy, also broad ones
        Assert.Contains("include rules would be added", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1",
            new AccessPolicyInput { Name = "staff", Include = [.. a, AccessRules.Email("b@example.com")] }))).Message);
        h.Requests.Clear();
        Assert.Contains("everyone", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1",
            new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.IpRange("0.0.0.0/0")) }))).Message);
        // d) earlier precedence and longer sessions
        h.Requests.Clear();
        Assert.Contains("precedence 5 → 1", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1",
            new AccessPolicyInput { Name = "staff", Include = a, Precedence = 1 }))).Message);
        h.Requests.Clear();
        Assert.Contains("longer sessions", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1",
            new AccessPolicyInput { Name = "staff", Include = a, SessionDuration = "720h" }))).Message);
        h.Requests.Clear();
        var (_, shorter) = await cf.Access.ChangeApplicationPolicyAsync("a1", "p1", new AccessPolicyInput { Name = "staff", Include = a, SessionDuration = "1h" });
        Assert.True(shorter);

        // b) a deny that gets exclude or require rules matches fewer requests; a later precedence is loosening, too
        var ru = Rules(AccessRules.Country("RU"));
        h.Requests.Clear();
        Assert.Contains("exclude rules added", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p2",
            new AccessPolicyInput { Name = "geo", Decision = "deny", Include = ru, Exclude = Rules(AccessRules.Email("x@example.com")) }))).Message);
        h.Requests.Clear();
        Assert.Contains("require rules added", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p2",
            new AccessPolicyInput { Name = "geo", Decision = "deny", Include = ru, Require = Rules(AccessRules.Mfa()) }))).Message);
        h.Requests.Clear();
        Assert.Contains("evaluated later", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p2",
            new AccessPolicyInput { Name = "geo", Decision = "deny", Include = ru, Precedence = 9 }))).Message);
    }

    [Fact]
    public async Task H2e_the_PUT_keeps_members_the_input_does_not_model()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string current = """
            {"id":"p1","uid":"u1","name":"staff","decision":"allow","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","app_count":2,"reusable":true,
             "include":[{"email":{"email":"a@example.com"}}],"exclude":[],"require":[{"auth_method":{"auth_method":"mfa"}}],
             "approval_required":true,"approval_groups":[{"approvals_needed":1,"email_addresses":["boss@example.com"]}],"isolation_required":true,
             "purpose_justification_required":true,"purpose_justification_prompt":"Why?","mfa_config":{"allowed_authenticators":["totp"],"session_duration":"1h"},
             "connection_rules":{"ssh":{"usernames":["root"]}}}
            """;
        Route(h, R("GET", "/access/policies/p1", current), R("PUT", "/access/policies/p1", current));
        var (_, changed) = await cf.Access.ChangePolicyAsync("p1", new AccessPolicyInput { Name = "staff (renamed)", Include = Rules(AccessRules.Email("a@example.com")), Require = Rules(AccessRules.Mfa()) });
        Assert.True(changed);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!.AsObject();
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
        Assert.Equal("staff (renamed)", body["name"]!.GetValue<string>());
        Assert.True(body["approval_required"]!.GetValue<bool>());
        Assert.True(body["isolation_required"]!.GetValue<bool>());
        Assert.True(body["purpose_justification_required"]!.GetValue<bool>());
        Assert.Equal("totp", body["mfa_config"]!["allowed_authenticators"]![0]!.GetValue<string>());
        Assert.Equal("root", body["connection_rules"]!["ssh"]!["usernames"]![0]!.GetValue<string>());
        Assert.Single(body["approval_groups"]!.AsArray());
        foreach (var readOnly in new[] { "id", "uid", "created_at", "updated_at", "app_count", "reusable" }) Assert.False(body.ContainsKey(readOnly), readOnly);
    }

    // ---------------------------------------------------------------- M4, M5, M8, L2: Access

    [Fact]
    public async Task M4_EnsureApplication_validates_inline_policies_and_reads_referenced_ones()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var inline = new AccessApplicationInput
        {
            Name = "mt5", Domain = "mt5.example.com",
            Policies = [new JsonObject { ["name"] = "all", ["decision"] = "allow", ["include"] = new JsonArray(new JsonObject { ["everyone"] = new JsonObject() }) }],
        };
        Assert.Contains("allowLoosen", (await Refused(h, () => cf.Access.EnsureApplicationAsync(inline))).Message);
        Assert.Contains("admits everyone", cf.Access.PreviewEnsureApplication(inline).Summary);
        await Refused(h, () => cf.Access.EnsureApplicationAsync(new AccessApplicationInput { Name = "mt5", Domain = "mt5.example.com", Policies = [new JsonObject { ["a"] = 1 }] }));
        await Refused(h, () => cf.Access.EnsureApplicationAsync(new AccessApplicationInput
        {
            Name = "mt5", Domain = "mt5.example.com",
            Policies = [new JsonObject { ["decision"] = "maybe", ["include"] = new JsonArray(new JsonObject { ["email"] = new JsonObject { ["email"] = "a@example.com" } }) }],
        }));

        Route(h, R("GET", "/access/apps", "[]", OnePage), R("GET", "/access/policies/p1", """{"id":"p1","name":"open","decision":"bypass","include":[{"everyone":{}}]}"""),
            R("POST", "/access/apps", """{"id":"a1","name":"mt5","domain":"mt5.example.com","type":"self_hosted"}"""));
        var byId = new AccessApplicationInput { Name = "mt5", Domain = "mt5.example.com", Policies = ["p1"] };
        Assert.Contains("\"open\"", (await RefusedAfterRead(h, () => cf.Access.EnsureApplicationAsync(byId))).Message);
        h.Requests.Clear();
        Assert.Contains("\"open\"", (await RefusedAfterRead(h, () => cf.Access.EnsureApplicationAsync(new AccessApplicationInput
        {
            Name = "mt5", Domain = "mt5.example.com", Policies = [new JsonObject { ["id"] = "p1", ["precedence"] = 1 }],
        }))).Message);
        h.Requests.Clear();
        var (_, created) = await cf.Access.EnsureApplicationAsync(byId, allowLoosen: true);
        Assert.True(created);
        Assert.Equal(HttpMethod.Post, h.Requests[^1].Method);

        // A referenced policy that cannot be read: fail-closed, no POST.
        h.Requests.Clear();
        Route(h, R("GET", "/access/apps", "[]", OnePage), ("GET", "/access/policies/p1", _ => Error(HttpStatusCode.InternalServerError, 10001, "internal")));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.EnsureApplicationAsync(byId, allowLoosen: true));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task M5_changing_a_group_in_use_needs_allowInUse_and_loosening_needs_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string group = """{"id":"g1","name":"admins","is_default":true,"include":[{"email":{"email":"a@example.com"}}],"exclude":[],"require":[{"auth_method":{"auth_method":"mfa"}}]}""";
        Route(h, R("GET", "/access/groups/g1", group), R("PUT", "/access/groups/g1", group),
            R("GET", "/access/policies", """[{"id":"p1","name":"ops","decision":"allow","include":[{"group":{"id":"g1"}}]}]""", OnePage),
            R("GET", "/access/apps", "[]", OnePage), R("GET", "/access/groups", "[]", OnePage));
        var a = Rules(AccessRules.Email("a@example.com"));

        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Access.ChangeGroupAsync("g1", new AccessGroupInput { Name = "admins", Include = a }))).Message);
        h.Requests.Clear();
        var tighter = new AccessGroupInput { Name = "admins", Include = a, Require = Rules(AccessRules.Mfa(), AccessRules.Country("DE")) };
        var ex = await RefusedAfterRead(h, () => cf.Access.ChangeGroupAsync("g1", tighter));
        Assert.Contains("allowInUse", ex.Message);
        Assert.Contains("\"ops\"", ex.Message);

        h.Requests.Clear();
        var (_, renamed) = await cf.Access.ChangeGroupAsync("g1", new AccessGroupInput { Name = "admins-2", Include = a, Require = Rules(AccessRules.Mfa()) });
        Assert.True(renamed);
        Assert.DoesNotContain(h.Requests, r => r.Url.Contains("/access/policies", StringComparison.Ordinal));

        h.Requests.Clear();
        await cf.Access.ChangeGroupAsync("g1", tighter, allowInUse: true);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!.AsObject();
        Assert.True(body["is_default"]!.GetValue<bool>());
        Assert.False(body.ContainsKey("id"));
    }

    [Fact]
    public async Task M8_an_identity_provider_that_is_the_only_one_of_an_application_is_not_removed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/identity_providers", """[{"id":"i1","name":"GitHub","type":"github"},{"id":"i2","name":"PIN","type":"onetimepin"}]""", OnePage),
            R("GET", "/access/apps", """[{"id":"a1","name":"MT5","type":"self_hosted","allowed_idps":["i1"]},{"id":"a2","name":"Web","type":"self_hosted","allowed_idps":["i1","i2"]}]""", OnePage),
            R("DELETE", "/access/identity_providers/i1", "{}"), R("DELETE", "/access/identity_providers/i2", "{}"));
        var ex = await RefusedAfterRead(h, () => cf.Access.RemoveIdentityProviderAsync("i1"));
        Assert.Contains("\"MT5\"", ex.Message);
        Assert.DoesNotContain("\"Web\"", ex.Message);
        Assert.Contains("allowRemoveLast", ex.Message);
        h.Requests.Clear();
        Assert.True(await cf.Access.RemoveIdentityProviderAsync("i2"));
        h.Requests.Clear();
        Assert.True(await cf.Access.RemoveIdentityProviderAsync("i1", allowRemoveLast: true));
    }

    [Fact]
    public async Task L2_longer_sessions_warp_login_and_ui_read_only_off_need_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/organizations", """{"name":"Team","session_duration":"24h","warp_auth_session_duration":"12h","is_ui_read_only":true,"allow_authenticate_via_warp":false}"""),
            R("PATCH", "/access/organizations", """{"name":"Team"}"""));
        Assert.Contains("longer Access sessions", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { SessionDuration = "720h" }))).Message);
        h.Requests.Clear();
        Assert.Contains("WARP authentication", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { WarpAuthSessionDuration = "24h" }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { AllowAuthenticateViaWarp = true }))).Message);
        h.Requests.Clear();
        Assert.Contains("read-only", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { IsUiReadOnly = false }))).Message);
        h.Requests.Clear();
        var (_, changed) = await cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { SessionDuration = "8h" });
        Assert.True(changed);
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
    }

    [Fact]
    public async Task Access_certificate_hostnames_and_deletion_need_allowRemovals()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/certificates/c1", """{"id":"c1","name":"ca","associated_hostnames":["a.example.com","b.example.com"]}"""));
        Assert.Contains("allowRemovals", (await RefusedAfterRead(h, () => cf.Access.SetCertificateHostnamesAsync("c1", ["a.example.com"]))).Message);
        h.Requests.Clear();
        Assert.Contains("allowRemovals", (await RefusedAfterRead(h, () => cf.Access.RemoveCertificateAsync("c1"))).Message);
    }

    // ---------------------------------------------------------------- L3: one rule for secret names

    [Fact]
    public async Task L3_strip_and_redact_use_the_same_secret_names()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""
            {"id":"a1","name":"SaaS","type":"saas","saas_app":{"client_id":"cid","client_secret":"MARK","oidc_credentials":"MARK",
             "custom_password_field":"MARK","hidden":{"signing_private_key":"MARK","api_key":"MARK"}}}
            """.Replace("MARK", SecretMarker, StringComparison.Ordinal)));
        var app = await cf.Access.GetApplicationAsync("a1");
        var json = JsonSerializer.Serialize(app, CloudflareJson.Options);
        Assert.DoesNotContain(SecretMarker, json);
        Assert.Contains("cid", json);

        var preview = cf.Access.PreviewEnsureIdentityProvider("oidc", "oidc", new { client_id = "x", app_credential = SecretMarker, db_password = SecretMarker, client_secret = SecretMarker });
        Assert.DoesNotContain(SecretMarker, preview.BodyJson);
        Assert.Contains("\"x\"", preview.BodyJson);
    }

    // ---------------------------------------------------------------- H3, M6: Gateway

    [Fact]
    public async Task H3_permissive_rules_that_match_everything_or_come_first_need_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/gateway/rules", """[{"id":"b1","name":"malware","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.security_category[*] in {80})","precedence":10}]"""),
            R("POST", "/gateway/rules", """{"id":"n1","name":"r","action":"allow","enabled":true,"filters":["dns"]}"""));
        Assert.Contains("all dns traffic", (await RefusedAfterRead(h, () => cf.Gateway.EnsureRuleAsync(DnsRule("allow", traffic: "")))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.EnsureRuleAsync(DnsRule("off", traffic: "any(dns.domains[*] matches \".*\")")));
        h.Requests.Clear();
        Assert.Contains("\"malware\"", (await RefusedAfterRead(h, () => cf.Gateway.EnsureRuleAsync(DnsRule("allow", precedence: 1)))).Message);
        h.Requests.Clear();
        var (_, created) = await cf.Gateway.EnsureRuleAsync(DnsRule("allow", precedence: 20));
        Assert.True(created);
        h.Requests.Clear();
        await cf.Gateway.EnsureRuleAsync(DnsRule("allow", traffic: ""), allowLoosen: true);
        Assert.Equal(HttpMethod.Post, h.Requests[^1].Method);
        Assert.Contains("WARNING", cf.Gateway.PreviewEnsureRule(DnsRule("noscan")).Summary);
    }

    [Fact]
    public async Task H3_enabling_a_permissive_rule_needs_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string off = """{"id":"r1","name":"skip-inspection","action":"off","enabled":false,"filters":["http"],"traffic":"http.request.host == \"bank.example\""}""";
        Route(h, R("GET", "/gateway/rules/r1", off), R("PATCH", "/gateway/rules/r1", off));
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Gateway.SetRuleEnabledAsync("r1", true))).Message);
        h.Requests.Clear();
        var (_, changed) = await cf.Gateway.SetRuleEnabledAsync("r1", true, allowLoosen: true);
        Assert.True(changed);
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
    }

    [Fact]
    public async Task H3_rule_changes_compare_precedence_filters_and_settings_and_keep_unmodelled_members()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string block = """
            {"id":"r1","name":"bad","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"bad.example\")","identity":"","device_posture":"",
             "precedence":10,"version":4,"created_at":"2026-01-01T00:00:00Z","read_only":false,"rule_settings":{"block_page_enabled":true,"block_reason":"policy"},
             "schedule":{"time_zone":"Europe/Berlin","mon":"08:00-18:00"},"expiration":{"expires_at":"2027-01-01T00:00:00Z"}}
            """;
        Route(h, R("GET", "/gateway/rules/r1", block), R("PUT", "/gateway/rules/r1", block));
        var bad = "any(dns.domains[*] == \"bad.example\")";
        Assert.Contains("evaluated later", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r1", new GatewayRuleInput { Name = "bad", Action = "block", Filters = ["dns"], Traffic = bad, Precedence = 90 }))).Message);
        h.Requests.Clear();
        Assert.Contains("filter", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r1", new GatewayRuleInput { Name = "bad", Action = "block", Filters = ["http"], Traffic = bad }))).Message);
        h.Requests.Clear();
        Assert.Contains("rule settings", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r1", new GatewayRuleInput
        {
            Name = "bad", Action = "block", Filters = ["dns"], Traffic = bad, RuleSettings = new JsonObject { ["block_page_enabled"] = false },
        }))).Message);

        h.Requests.Clear();
        var (_, changed) = await cf.Gateway.ChangeRuleAsync("r1", new GatewayRuleInput { Name = "bad", Action = "block", Filters = ["dns"], Traffic = bad, Description = "documented" });
        Assert.True(changed);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!.AsObject();
        Assert.Equal("documented", body["description"]!.GetValue<string>());
        Assert.Equal("Europe/Berlin", body["schedule"]!["time_zone"]!.GetValue<string>());
        Assert.Equal("2027-01-01T00:00:00Z", body["expiration"]!["expires_at"]!.GetValue<string>());
        Assert.True(body["rule_settings"]!["block_page_enabled"]!.GetValue<bool>());
        Assert.Equal(10, body["precedence"]!.GetValue<int>());
        foreach (var readOnly in new[] { "id", "version", "created_at", "read_only" }) Assert.False(body.ContainsKey(readOnly), readOnly);
    }

    [Fact]
    public async Task H3_a_permissive_rule_moved_before_a_protective_rule_needs_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string allow = """{"id":"r2","name":"partner","action":"allow","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"partner.example\")","precedence":50}""";
        Route(h, R("GET", "/gateway/rules/r2", allow), R("PUT", "/gateway/rules/r2", allow),
            R("GET", "/gateway/rules", $$"""[{"id":"b1","name":"malware","action":"block","enabled":true,"filters":["dns"],"traffic":"x","precedence":10},{{allow}}]"""));
        var input = new GatewayRuleInput { Name = "partner", Action = "allow", Filters = ["dns"], Traffic = "any(dns.domains[*] == \"partner.example\")", Precedence = 5 };
        Assert.Contains("\"malware\"", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r2", input))).Message);
        h.Requests.Clear();
        await cf.Gateway.ChangeRuleAsync("r2", input, allowLoosen: true);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
    }

    [Fact]
    public async Task Gateway_logging_reductions_need_allowLoosen_and_allowPii()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/gateway/logging", """{"redact_pii":true,"settings_by_rule_type":{"http":{"log_all":true,"log_blocks":true}}}"""), R("PUT", "/gateway/logging", "{}"));
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Gateway.SetLoggingAsync(byRuleType: new Dictionary<string, (bool, bool)> { ["http"] = (true, false) }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowPii", (await RefusedAfterRead(h, () => cf.Gateway.SetLoggingAsync(redactPii: false, allowLoosen: true))).Message);
    }

    // ---------------------------------------------------------------- M1, L6, L7, L8: Tunnels

    private const string GwConfig = """
        {"tunnel_id":"t1","version":3,"config":{"ingress":[
          {"hostname":"gw.example.com","service":"http://localhost:8080","originRequest":{"connectTimeout":30,"noTLSVerify":false}},
          {"hostname":"api.example.com","path":"/v1","service":"http://localhost:7000"},
          {"hostname":"api.example.com","service":"http://localhost:7001"},
          {"service":"http_status:404"}],"originRequest":{"connectTimeout":10}}}
        """;

    [Fact]
    public async Task M1_originRequest_changes_shadowing_and_reordering_need_allowDisconnect()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/cfd_tunnel/t1/configurations", GwConfig), R("PUT", "/cfd_tunnel/t1/configurations", GwConfig));
        var gw = new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080", OriginRequest = JsonSerializer.SerializeToElement(new { connectTimeout = 30, noTLSVerify = false }) };
        var apiV1 = new TunnelIngressRule { Hostname = "api.example.com", Path = "/v1", Service = "http://localhost:7000" };
        var api = new TunnelIngressRule { Hostname = "api.example.com", Service = "http://localhost:7001" };

        var insecure = new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080", OriginRequest = JsonSerializer.SerializeToElement(new { noTLSVerify = true }) };
        Assert.Contains("gw.example.com", (await RefusedAfterRead(h, () => cf.Tunnels.SetIngressAsync("t1", [insecure, apiV1, api]))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Tunnels.UpsertIngressRuleAsync("t1", insecure));
        h.Requests.Clear();
        var wildcard = new TunnelIngressRule { Hostname = "*.example.com", Service = "http://localhost:9000" };
        Assert.Contains("gw.example.com", (await RefusedAfterRead(h, () => cf.Tunnels.SetIngressAsync("t1", [wildcard, gw, apiV1, api]))).Message);
        h.Requests.Clear();
        Assert.Contains("api.example.com /v1", (await RefusedAfterRead(h, () => cf.Tunnels.SetIngressAsync("t1", [gw, api, apiV1]))).Message);

        // Unchanged order and settings: nothing written; an upsert without originRequest keeps the current one.
        h.Requests.Clear();
        var (_, same) = await cf.Tunnels.SetIngressAsync("t1", [gw, apiV1, api]);
        Assert.False(same);
        var (_, kept) = await cf.Tunnels.UpsertIngressRuleAsync("t1", new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080" });
        Assert.False(kept);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        // A new hostname behind the others is fine and keeps every originRequest.
        h.Requests.Clear();
        var (_, added) = await cf.Tunnels.UpsertIngressRuleAsync("t1", new TunnelIngressRule { Hostname = "new.example.com", Service = "http://localhost:9100" });
        Assert.True(added);
        var sent = JsonNode.Parse(h.Requests[^1].Body!)!["config"]!;
        Assert.Equal(30, sent["ingress"]![0]!["originRequest"]!["connectTimeout"]!.GetValue<int>());
        Assert.Equal(10, sent["originRequest"]!["connectTimeout"]!.GetValue<int>());
    }

    [Fact]
    public async Task M1_a_path_rule_without_hostname_is_treated_like_a_catch_all()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Assert.Contains("allowCatchAllService", (await Refused(h, () => cf.Tunnels.SetIngressAsync("t1", [new TunnelIngressRule { Path = "/admin", Service = "http://localhost:9" }]))).Message);
        Route(h, R("GET", "/cfd_tunnel/t1/configurations", GwConfig), R("PUT", "/cfd_tunnel/t1/configurations", GwConfig));
        // With allowCatchAllService it is still a shadowing change for every hostname with that path: allowDisconnect.
        await RefusedAfterRead(h, () => cf.Tunnels.SetIngressAsync("t1",
            [new TunnelIngressRule { Path = "/v1", Service = "http://localhost:9" }, new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080", OriginRequest = JsonSerializer.SerializeToElement(new { connectTimeout = 30, noTLSVerify = false }) },
             new TunnelIngressRule { Hostname = "api.example.com", Path = "/v1", Service = "http://localhost:7000" }, new TunnelIngressRule { Hostname = "api.example.com", Service = "http://localhost:7001" }],
            allowCatchAllService: true));
    }

    [Fact]
    public async Task M1_L6_a_concurrent_configuration_change_is_a_conflict()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var reads = 0;
        Route(h, ("GET", "/cfd_tunnel/t1/configurations", _ => Ok(reads++ == 0 ? GwConfig : GwConfig.Replace("\"version\":3", "\"version\":4", StringComparison.Ordinal))));
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Tunnels.UpsertIngressRuleAsync("t1", new TunnelIngressRule { Hostname = "new.example.com", Service = "http://localhost:9100" }));
        Assert.Equal(2, h.Requests.Count);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    [Fact]
    public async Task L7_a_tunnel_that_still_serves_hostnames_is_not_deleted_even_when_down()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/cfd_tunnel/t1/connections", "[]"), R("GET", "/cfd_tunnel/t1/configurations", GwConfig), R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"down"}"""),
            R("GET", "/teamnet/routes", "[]", OnePage), R("DELETE", "/cfd_tunnel/t1", "{}"));
        var ex = await RefusedAfterRead(h, () => cf.Tunnels.RemoveAsync("t1"));
        Assert.Contains("gw.example.com", ex.Message);
        Assert.Contains("allowDeleteActive", ex.Message);
        h.Requests.Clear();
        Assert.True(await cf.Tunnels.RemoveAsync("t1", allowDeleteActive: true));

        // A virtual network with routes needs allowDisconnect.
        h.Requests.Clear();
        Route(h, R("GET", "/teamnet/virtual_networks", """[{"id":"vn1","name":"office","is_default_network":false}]""", OnePage),
            R("GET", "/teamnet/routes", """[{"id":"rt1","network":"10.0.0.0/16","tunnel_id":"t1"}]""", OnePage));
        Assert.Contains("allowDisconnect", (await RefusedAfterRead(h, () => cf.Tunnels.RemoveVirtualNetworkAsync("vn1"))).Message);
    }

    private static void PublishRoutes(FakeHandler h, string zoneAccount, string dnsRecords, Func<string?, HttpResponseMessage>? dnsPost = null) =>
        Route(h,
            R("GET", "/zones/zone1/dns_records", dnsRecords, """{"page":1,"per_page":500,"count":0,"total_count":0,"total_pages":1}"""),
            ("POST", "/zones/zone1/dns_records", dnsPost ?? (_ => Ok("""{"id":"d1","type":"CNAME","name":"new.example.com","content":"t1.cfargotunnel.com","proxied":true}"""))),
            R("PUT", "/zones/zone1/dns_records/", """{"id":"d1"}"""),
            R("GET", "/zones/zone1", """{"id":"zone1","name":"example.com","account":{"id":"ACCOUNT"}}""".Replace("ACCOUNT", zoneAccount, StringComparison.Ordinal)),
            R("GET", "/cfd_tunnel/t1/configurations", GwConfig), R("PUT", "/cfd_tunnel/t1/configurations", GwConfig));

    [Fact]
    public async Task L8_publish_checks_the_zone_account_and_existing_records_first()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        PublishRoutes(h, "other-account", "[]");
        Assert.Contains("other-account", (await RefusedAfterRead(h, () => cf.Tunnels.PublishAsync("t1", "new.example.com", "http://localhost:9100", cf.Dns))).Message);

        h.Requests.Clear();
        PublishRoutes(h, "acc1", """[{"id":"d0","type":"CNAME","name":"new.example.com","content":"elsewhere.example.net","proxied":true}]""");
        Assert.Contains("allowDisconnect", (await RefusedAfterRead(h, () => cf.Tunnels.PublishAsync("t1", "new.example.com", "http://localhost:9100", cf.Dns))).Message);

        h.Requests.Clear();
        PublishRoutes(h, "acc1", "[]");
        await cf.Tunnels.PublishAsync("t1", "new.example.com", "http://localhost:9100", cf.Dns);
        Assert.Contains(h.Requests, r => r.Method == HttpMethod.Put && r.Url.Contains("/configurations", StringComparison.Ordinal));
        Assert.Equal(HttpMethod.Post, h.Requests[^1].Method);
    }

    [Fact]
    public async Task L8_a_failed_DNS_write_rolls_the_ingress_back()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        PublishRoutes(h, "acc1", "[]", _ => Error(HttpStatusCode.BadRequest, 81053, "An A, AAAA, or CNAME record with that host already exists."));
        await Assert.ThrowsAnyAsync<CloudflareApiException>(() => cf.Tunnels.PublishAsync("t1", "new.example.com", "http://localhost:9100", cf.Dns));
        var puts = h.Requests.Where(r => r.Method == HttpMethod.Put && r.Url.Contains("/configurations", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, puts.Count);
        Assert.Contains("new.example.com", puts[0].Body);
        Assert.DoesNotContain("new.example.com", puts[1].Body);
        Assert.Equal(4, JsonNode.Parse(puts[1].Body!)!["config"]!["ingress"]!.AsArray().Count);
    }

    // ---------------------------------------------------------------- M2, M3: devices

    [Theory]
    [InlineData("identity.email matches \".*\"")]
    [InlineData("identity.email ~ \"^.*$\"")]
    [InlineData("identity.email ne \"\"")]
    [InlineData("os.name in {\"windows\" \"mac\" \"linux\" \"android\" \"ios\"}")]
    [InlineData("identity.email == \"a@example.com\" or true")]
    [InlineData("(any)")]
    public async Task M2_broad_device_profile_matches_need_allowBroadProfile(string match)
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Assert.Contains("allowBroadProfile", (await Refused(h, () => cf.Devices.EnsureProfileAsync(new DeviceProfileInput { Name = "p", Match = match, Precedence = 5 }))).Message);
    }

    [Fact]
    public async Task M2_loose_settings_at_creation_and_match_changes_need_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var loose = new DeviceProfileInput { Name = "dev", Match = "identity.email == \"a@example.com\"", Precedence = 5, Settings = new DeviceProfileSettings { SwitchLocked = false, AllowedToLeave = true } };
        Assert.Contains("allowLoosen", (await Refused(h, () => cf.Devices.EnsureProfileAsync(loose))).Message);
        Assert.Contains("WARNING", cf.Devices.PreviewEnsureProfile(loose).Summary);

        Route(h, R("GET", "/devices/policy/dp1", """{"policy_id":"dp1","name":"staff","match":"identity.email == \"a@example.com\"","switch_locked":true}"""),
            R("PATCH", "/devices/policy/dp1", """{"policy_id":"dp1"}"""));
        Assert.Contains("match changes", (await RefusedAfterRead(h, () => cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings(), match: "identity.email == \"b@example.com\""))).Message);
        h.Requests.Clear();
        await cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings(), match: "identity.email == \"b@example.com\"", allowLoosen: true);
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
    }

    [Fact]
    public async Task M3_split_tunnel_default_routes_need_allowBroadRoute_and_include_mode_is_refused()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        foreach (var wide in new[] { "0.0.0.0/0", "::/0", "0.0.0.0/1" })
            Assert.Contains("allowBroadRoute", (await Refused(h, () => cf.Devices.SetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress(wide)], "dp1", allowLoosen: true, allowDisconnect: true))).Message);

        Route(h, R("GET", "/devices/policy/dp1/exclude", "[]"), R("PUT", "/devices/policy/dp1/exclude", "[]"),
            R("GET", "/devices/policy/dp1", """{"policy_id":"dp1","name":"staff","include":[{"address":"10.0.0.0/8"}],"exclude":[]}"""));
        Assert.Contains("Include mode", (await RefusedAfterRead(h, () => cf.Devices.SetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress("192.168.0.0/16")], "dp1", allowLoosen: true, allowDisconnect: true))).Message);

        h.Requests.Clear();
        Route(h, R("GET", "/devices/policy/dp1/exclude", "[]"), R("PUT", "/devices/policy/dp1/exclude", "[]"),
            R("GET", "/devices/policy/dp1", """{"policy_id":"dp1","name":"staff","include":[],"exclude":[]}"""));
        var (_, changed) = await cf.Devices.SetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress("0.0.0.0/0")], "dp1", allowLoosen: true, allowDisconnect: true, allowBroadRoute: true);
        Assert.True(changed);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);
    }

    // ---------------------------------------------------------------- M7: obsolete methods

    [Fact]
    public void M7_every_obsolete_Access_and_Tunnels_method_is_hidden_and_documented()
    {
        var access = typeof(AccessClient).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Where(m => m.GetCustomAttribute<ObsoleteAttribute>() is not null).ToList();
        var tunnels = typeof(TunnelsClient).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Where(m => m.GetCustomAttribute<ObsoleteAttribute>() is not null).ToList();
        Assert.Equal(17, access.Count);
        Assert.Equal(6, tunnels.Count);
        foreach (var m in access.Concat(tunnels))
        {
            Assert.Equal(EditorBrowsableState.Never, m.GetCustomAttribute<EditorBrowsableAttribute>()?.State);
            Assert.Contains("0.8.1", m.GetCustomAttribute<ObsoleteAttribute>()!.Message);
        }
    }

    [Fact]
    public async Task M7_obsolete_methods_never_write_unguarded_and_never_hand_out_secrets()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var policy = new AccessPolicyInput { Name = "all", Include = Rules(AccessRules.Everyone()) };
        Func<Task>[] refused =
        [
            () => cf.Access.CreateServiceTokenAsync("svc"),
            () => cf.Access.RotateServiceTokenAsync("t1"),
            () => cf.Access.UpdateApplicationAsync("a1", new AccessApplicationInput { Name = "x", Domain = "x.example.com", Policies = ["p1"] }),
            () => cf.Access.UpdateIdentityProviderAsync("i1", "x", "github"),
            () => cf.Access.DeleteApplicationAsync("a1"),
            () => cf.Access.CreateApplicationAsync(new AccessApplicationInput { Name = "x", Domain = "x.example.com" }),
            () => cf.Access.CreateApplicationPolicyAsync("a1", policy),
            () => cf.Access.CreatePolicyAsync(policy),
            () => cf.Access.CreateGroupAsync("g", []),
            () => cf.Access.CreateIdentityProviderAsync("x", "not-a-type"),
            () => cf.Tunnels.GetTokenAsync("t1"),
            () => cf.Tunnels.CleanupConnectionsAsync("t1"),
            () => cf.Tunnels.PutConfigurationAsync("t1", [new TunnelIngressRule { Service = "http://localhost:80" }]),
        ];
        foreach (var call in refused) await Refused(h, call);

        // The ones with checks read first and refuse on risk.
        Route(h, R("GET", "/access/apps/a1/policies", """[{"id":"p1","name":"only","decision":"allow","include":[]}]"""),
            R("GET", "/cfd_tunnel/t1/connections", """[{"id":"c1","conns":[{"colo_name":"FRA","is_pending_reconnect":false}]}]"""), R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"healthy"}"""));
        await RefusedAfterRead(h, () => cf.Access.DeleteApplicationPolicyAsync("a1", "p1"));
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Tunnels.DeleteAsync("t1"));

        // CreateAsync no longer returns or keeps the run token.
        h.Requests.Clear();
        Route(h, R("GET", "/cfd_tunnel?", "[]", OnePage), R("POST", "/cfd_tunnel", $$$"""{"id":"t9","name":"gw","token":"{{{SecretMarker}}}","credentials_file":{"TunnelSecret":"{{{SecretMarker}}}"}}"""));
        var tunnel = await cf.Tunnels.CreateAsync("gw");
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(tunnel, CloudflareJson.Options));
    }
}
