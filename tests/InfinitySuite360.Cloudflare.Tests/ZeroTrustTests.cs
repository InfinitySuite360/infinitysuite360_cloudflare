using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>
/// Zero Trust clients of 0.8.0 (Access, Gateway, Tunnels, devices, DLP, risk scoring). Fake handler only: no network, no real token. Secret values are
/// synthetic markers; the tests assert that they reach the wire only where the call needs them and nowhere else.
/// </summary>
public class ZeroTrustTests
{
    private const string Token = "secret-token-123";
    private const string SecretMarker = "SYNTHETIC-ZT-SECRET-4411";
    private const string TunnelTokenMarker = "eyJTYNTHETIC-TUNNEL-TOKEN-9902";
    private const string Pem = "-----BEGIN CERTIFICATE-----\nMIIBsyntheticCA\n-----END CERTIFICATE-----";

    private static HttpResponseMessage Ok(string result, string? info = null) => FakeHandler.Ok(result, info);

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    /// <summary>Answers by method and URL fragment (first match wins); any other request is answered with 404 and a marker.</summary>
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

    private static async Task Refused(FakeHandler h, Func<Task> action)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.Empty(h.Requests);
    }

    /// <summary>Refused after the preparing read: only GET requests went out.</summary>
    private static async Task<Exception> RefusedAfterRead(FakeHandler h, Func<Task> action)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(action);
        Assert.True(ex is InvalidOperationException or ArgumentException, ex.ToString());
        Assert.IsNotType<CloudflareWriteNotAllowedException>(ex);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        return ex;
    }

    private static List<JsonElement> Rules(params JsonElement[] r) => [.. r];

    private static AccessPolicyInput EmailPolicy(string name = "staff") => new() { Name = name, Decision = "allow", Include = Rules(AccessRules.Email("a@example.com")) };

    private static GatewayRuleInput DnsRule(string action, string traffic = "any(dns.domains[*] == \"bad.example\")", bool enabled = true) =>
        new() { Name = "r", Action = action, Filters = ["dns"], Traffic = traffic, Enabled = enabled };

    // ---------------------------------------------------------------- guards

    [Fact]
    public async Task Every_new_write_and_post_read_is_refused_without_AllowWrites_and_nothing_is_sent()
    {
        var (cf, h, _) = FakeHandler.Create();
        var app = new AccessApplicationInput { Name = "mt5", Domain = "mt5.example.com", Policies = ["p1"] };
        var group = new AccessGroupInput { Name = "g", Include = Rules(AccessRules.Email("a@example.com")) };
        var profile = new DeviceProfileInput { Name = "dev", Match = "identity.email == \"a@example.com\"", Precedence = 10 };
        var posture = new DevicePostureRuleInput { Name = "fw", Type = "firewall" };
        var ingress = new[] { new TunnelIngressRule { Hostname = "app.example.com", Service = "http://localhost:8080" } };
        Func<Task>[] writes =
        [
            () => cf.Access.EnsureApplicationAsync(app),
            () => cf.Access.RemoveApplicationAsync("a1", allowUnprotect: true),
            () => cf.Access.RevokeApplicationTokensAsync("a1", allowDisconnect: true),
            () => cf.Access.AddApplicationPolicyAsync("a1", EmailPolicy()),
            () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1", EmailPolicy(), allowLoosen: true, allowBlock: true),
            () => cf.Access.RemoveApplicationPolicyAsync("a1", "p1", allowRemoveLast: true, allowLoosen: true),
            () => cf.Access.EnsurePolicyAsync(EmailPolicy()),
            () => cf.Access.ChangePolicyAsync("p1", EmailPolicy(), allowLoosen: true, allowBlock: true),
            () => cf.Access.RemovePolicyAsync("p1", allowRemoveLast: true, allowLoosen: true),
            () => cf.Access.StartPolicyTestAsync(["p1"]),
            () => cf.Access.EnsureGroupAsync(group),
            () => cf.Access.ChangeGroupAsync("g1", group, allowLoosen: true),
            () => cf.Access.RemoveGroupAsync("g1", allowInUse: true),
            () => cf.Access.IssueServiceTokenAsync("svc"),
            () => cf.Access.RotateServiceTokenSecretAsync("t1", allowDisconnect: true),
            () => cf.Access.RefreshServiceTokenAsync("t1"),
            () => cf.Access.RemoveServiceTokenAsync("t1", allowDisconnect: true),
            () => cf.Access.EnsureIdentityProviderAsync("otp", "onetimepin"),
            () => cf.Access.RemoveIdentityProviderAsync("i1", allowRemoveLast: true),
            () => cf.Access.EnsureCertificateAsync("ca", Pem, ["app.example.com"]),
            () => cf.Access.SetCertificateHostnamesAsync("c1", ["app.example.com"], allowRemovals: true),
            () => cf.Access.RemoveCertificateAsync("c1", allowRemovals: true),
            () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { Name = "x" }, true, true, true),
            () => cf.Access.RevokeUserSessionsAsync("a@example.com", allowDisconnect: true),
            () => cf.Gateway.EnsureRuleAsync(DnsRule("block")),
            () => cf.Gateway.ChangeRuleAsync("r1", DnsRule("allow"), true, true, true),
            () => cf.Gateway.SetRuleEnabledAsync("r1", false, true, true),
            () => cf.Gateway.RemoveRuleAsync("r1", allowLoosen: true),
            () => cf.Gateway.EnsureListAsync("bad", "DOMAIN", ["bad.example"]),
            () => cf.Gateway.AddListItemsAsync("l1", ["bad.example"]),
            () => cf.Gateway.RemoveListItemsAsync("l1", ["bad.example"], allowInUse: true),
            () => cf.Gateway.RemoveListAsync("l1", allowInUse: true),
            () => cf.Gateway.EnsureLocationAsync("office", ["203.0.113.0/24"]),
            () => cf.Gateway.RemoveLocationAsync("loc1", allowDelete: true),
            () => cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { ActivityLog = true }, true, true, true),
            () => cf.Gateway.SetLoggingAsync(redactPii: true, allowPii: true, allowLoosen: true),
            () => cf.Gateway.EnsureProxyEndpointAsync("pac", ["203.0.113.0/24"]),
            () => cf.Gateway.RemoveProxyEndpointAsync("pe1", allowDelete: true),
            () => cf.Gateway.CreateCertificateAsync(),
            () => cf.Gateway.ActivateCertificateAsync("gc1"),
            () => cf.Gateway.DeactivateCertificateAsync("gc1", allowDisable: true),
            () => cf.Gateway.RemoveCertificateAsync("gc1", allowDisable: true),
            () => cf.Tunnels.EnsureAsync("t"),
            () => cf.Tunnels.RotateRunTokenAsync("t1", allowDisconnect: true),
            () => cf.Tunnels.RemoveAsync("t1", allowDeleteActive: true),
            () => cf.Tunnels.DisconnectAsync("t1", allowDisconnect: true),
            () => cf.Tunnels.SetIngressAsync("t1", ingress, allowDisconnect: true, allowCatchAllService: true),
            () => cf.Tunnels.UpsertIngressRuleAsync("t1", ingress[0], allowDisconnect: true),
            () => cf.Tunnels.RemoveIngressRuleAsync("t1", "app.example.com", allowDisconnect: true),
            () => cf.Tunnels.PublishAsync("t1", "app.example.com", "http://localhost:8080", cf.Dns, allowDisconnect: true),
            () => cf.Tunnels.EnsureRouteAsync("10.0.0.0/16", "t1"),
            () => cf.Tunnels.MoveRouteAsync("rt1", "t2", allowDisconnect: true),
            () => cf.Tunnels.RemoveRouteAsync("rt1", allowDisconnect: true),
            () => cf.Tunnels.EnsureVirtualNetworkAsync("vn"),
            () => cf.Tunnels.SetDefaultVirtualNetworkAsync("vn1", allowDefaultChange: true),
            () => cf.Tunnels.RemoveVirtualNetworkAsync("vn1", allowDisconnect: true),
            () => cf.Devices.UpdateDefaultProfileAsync(new DeviceProfileSettings { SwitchLocked = true }, true, true),
            () => cf.Devices.EnsureProfileAsync(profile),
            () => cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings { SwitchLocked = true }, null, true, true),
            () => cf.Devices.RemoveProfileAsync("dp1", allowDelete: true),
            () => cf.Devices.SetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress("192.168.0.0/16")], null, true, true, true),
            () => cf.Devices.EnsurePostureRuleAsync(posture),
            () => cf.Devices.UpdatePostureRuleAsync("pr1", posture, allowInUse: true),
            () => cf.Devices.RemovePostureRuleAsync("pr1", allowInUse: true),
            () => cf.Devices.RevokeRegistrationsAsync(["reg1"], allowDisconnect: true),
            () => cf.Devices.UnrevokeRegistrationsAsync(["reg1"], allowLoosen: true),
        ];
        foreach (var write in writes) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(write);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task WriteFilter_is_checked_before_the_preparing_read()
    {
        var (cf, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, path) => path.Contains("/dns_records", StringComparison.Ordinal); });
        Func<Task>[] guarded =
        [
            () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1", EmailPolicy()),
            () => cf.Access.RemoveApplicationPolicyAsync("a1", "p1"),
            () => cf.Access.RemovePolicyAsync("p1"),
            () => cf.Access.StartPolicyTestAsync(["p1"]),
            () => cf.Gateway.ChangeRuleAsync("r1", DnsRule("allow")),
            () => cf.Gateway.RemoveListAsync("l1"),
            () => cf.Tunnels.SetIngressAsync("t1", []),
            () => cf.Tunnels.RemoveAsync("t1"),
            () => cf.Devices.RemovePostureRuleAsync("pr1"),
        ];
        foreach (var call in guarded) await Assert.ThrowsAsync<CloudflareWriteNotAllowedException>(call);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Unconditional_allow_switches_refuse_locally_without_a_request()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Func<Task>[] refused =
        [
            () => cf.Access.EnsureApplicationAsync(new AccessApplicationInput { Name = "mt5", Domain = "mt5.example.com" }),
            () => cf.Access.RemoveApplicationAsync("a1"),
            () => cf.Access.RevokeApplicationTokensAsync("a1"),
            () => cf.Access.AddApplicationPolicyAsync("a1", new AccessPolicyInput { Name = "all", Include = Rules(AccessRules.Everyone()) }),
            () => cf.Access.AddApplicationPolicyAsync("a1", new AccessPolicyInput { Name = "skip", Decision = "bypass", Include = Rules(AccessRules.Email("a@example.com")) }),
            () => cf.Access.AddApplicationPolicyAsync("a1", new AccessPolicyInput { Name = "none", Decision = "deny", Include = Rules(AccessRules.Everyone()) }),
            () => cf.Access.EnsurePolicyAsync(new AccessPolicyInput { Name = "all", Decision = "non_identity", Include = Rules(AccessRules.Everyone()) }),
            () => cf.Access.EnsureGroupAsync(new AccessGroupInput { Name = "all", Include = Rules(AccessRules.Everyone()) }),
            () => cf.Access.IssueServiceTokenAsync("svc", "forever"),
            () => cf.Access.RotateServiceTokenSecretAsync("t1"),
            () => cf.Access.EnsureCertificateAsync("ca", Pem + "\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"),
            () => cf.Access.RevokeUserSessionsAsync("a@example.com"),
            () => cf.Gateway.EnsureRuleAsync(DnsRule("block", traffic: "")),
            () => cf.Gateway.RemoveLocationAsync("loc1"),
            () => cf.Gateway.RemoveProxyEndpointAsync("pe1"),
            () => cf.Gateway.EnsureListAsync("ips", "IP", ["not-an-ip"]),
            () => cf.Tunnels.RotateRunTokenAsync("t1"),
            () => cf.Tunnels.DisconnectAsync("t1"),
            () => cf.Tunnels.RemoveIngressRuleAsync("t1", "app.example.com"),
            () => cf.Tunnels.SetIngressAsync("t1", [new TunnelIngressRule { Service = "http://localhost:80" }]),
            () => cf.Tunnels.EnsureRouteAsync("0.0.0.0/0", "t1"),
            () => cf.Tunnels.MoveRouteAsync("rt1", "t2"),
            () => cf.Tunnels.RemoveRouteAsync("rt1"),
            () => cf.Tunnels.SetDefaultVirtualNetworkAsync("vn1"),
            () => cf.Devices.UpdateDefaultProfileAsync(new DeviceProfileSettings { SwitchLocked = true }),
            () => cf.Devices.EnsureProfileAsync(new DeviceProfileInput { Name = "all", Match = "", Precedence = 1 }),
            () => cf.Devices.RemoveProfileAsync("dp1"),
            () => cf.Devices.SetSplitTunnelExcludeAsync([SplitTunnelEntry.ForAddress("10.0.0.0/8")]),
            () => cf.Devices.RevokeRegistrationsAsync(["reg1"]),
            () => cf.Devices.UnrevokeRegistrationsAsync(["reg1"]),
        ];
        foreach (var call in refused) await Refused(h, call);
    }

    [Fact]
    public async Task Previews_send_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var previews = new CloudflareChangePreview[]
        {
            cf.Access.PreviewEnsureApplication(new AccessApplicationInput { Name = "mt5", Domain = "mt5.example.com", Policies = ["p1"] }),
            cf.Access.PreviewRemoveApplication("a1"),
            cf.Access.PreviewAddApplicationPolicy("a1", EmailPolicy()),
            cf.Access.PreviewEnsurePolicy(EmailPolicy()),
            cf.Access.PreviewStartPolicyTest(["p1"]),
            cf.Access.PreviewIssueServiceToken("svc"),
            cf.Access.PreviewRotateServiceTokenSecret("t1", TimeSpan.FromHours(24)),
            cf.Access.PreviewEnsureIdentityProvider("gh", "github", new { client_id = "id", client_secret = SecretMarker }),
            cf.Access.PreviewEnsureCertificate("ca", Pem, ["app.example.com"]),
            cf.Access.PreviewRevokeUserSessions("a@example.com"),
            cf.Gateway.PreviewEnsureRule(DnsRule("block")),
            cf.Gateway.PreviewEnsureList("bad", "DOMAIN", ["bad.example"]),
            cf.Gateway.PreviewCreateCertificate(),
            cf.Tunnels.PreviewEnsure("t"),
            cf.Tunnels.PreviewRotateRunToken("t1"),
            cf.Tunnels.PreviewRemove("t1"),
            cf.Tunnels.PreviewEnsureRoute("10.0.0.0/16", "t1"),
            cf.Devices.PreviewEnsureProfile(new DeviceProfileInput { Name = "dev", Match = "identity.email == \"a@example.com\"", Precedence = 5 }),
            cf.Devices.PreviewRevokeRegistrations(["reg-1", "reg-2"]),
        };
        Assert.Empty(h.Requests);
        foreach (var p in previews)
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Summary));
            Assert.DoesNotContain(SecretMarker, (p.BodyJson ?? "") + p.Summary);
            Assert.DoesNotContain(Token, (p.BodyJson ?? "") + p.Summary + p.Path);
        }
        Assert.Contains("[redacted]", previews[7].BodyJson);
        Assert.DoesNotContain("MIIBsyntheticCA", previews[8].BodyJson);
        Assert.DoesNotContain("a@example.com", previews[9].BodyJson + previews[9].Summary);
        Assert.DoesNotContain("reg-1", (previews[18].BodyJson ?? "") + previews[18].Summary);
        Assert.Contains("2 device registrations", previews[18].Summary);
    }

    // ---------------------------------------------------------------- Access: lock-out and loosening

    [Fact]
    public async Task The_last_policy_of_an_application_is_not_removed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/apps/a1/policies", """[{"id":"p1","name":"staff","decision":"allow","include":[{"email":{"email":"a@example.com"}}]}]"""));
        var ex = await RefusedAfterRead(h, () => cf.Access.RemoveApplicationPolicyAsync("a1", "p1"));
        Assert.Contains("allowRemoveLast", ex.Message);

        h.Requests.Clear();
        Route(h, R("GET", "/access/apps/a1/policies", """[{"id":"p1","name":"staff","decision":"allow","include":[]},{"id":"p2","name":"block-ru","decision":"deny","include":[]}]"""));
        ex = await RefusedAfterRead(h, () => cf.Access.RemoveApplicationPolicyAsync("a1", "p1"));
        Assert.Contains("admits anyone", ex.Message);

        h.Requests.Clear();
        ex = await RefusedAfterRead(h, () => cf.Access.RemoveApplicationPolicyAsync("a1", "p2"));
        Assert.Contains("allowLoosen", ex.Message);

        h.Requests.Clear();
        Route(h, R("GET", "/access/apps/a1/policies", """[{"id":"p1","name":"staff","decision":"allow","include":[]},{"id":"p3","name":"admins","decision":"allow","include":[]}]"""),
            R("DELETE", "/access/apps/a1/policies/p1", "{}"));
        Assert.True(await cf.Access.RemoveApplicationPolicyAsync("a1", "p1"));
        Assert.Equal(HttpMethod.Delete, h.Requests[^1].Method);
        Assert.False(await cf.Access.RemoveApplicationPolicyAsync("a1", "missing"));
    }

    [Fact]
    public async Task Policy_changes_that_loosen_need_allowLoosen_and_unchanged_policies_are_not_written()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string current = """{"id":"p1","name":"staff","decision":"allow","include":[{"email":{"email":"a@example.com"}}],"exclude":[],"require":[{"auth_method":{"auth_method":"mfa"}}]}""";
        Route(h, R("GET", "/access/apps/a1/policies/p1", current), R("PUT", "/access/apps/a1/policies/p1", current));

        var everyone = new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.Everyone()) };
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1", everyone))).Message);
        h.Requests.Clear();
        var noMfa = new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.Email("a@example.com")) };
        Assert.Contains("require", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1", noMfa))).Message);
        h.Requests.Clear();
        var bypass = new AccessPolicyInput { Name = "staff", Decision = "bypass", Include = Rules(AccessRules.Email("a@example.com")), Require = Rules(AccessRules.Mfa()) };
        Assert.Contains("allow → bypass", (await RefusedAfterRead(h, () => cf.Access.ChangeApplicationPolicyAsync("a1", "p1", bypass))).Message);

        h.Requests.Clear();
        var same = new AccessPolicyInput { Name = "staff", Include = Rules(AccessRules.Email("a@example.com")), Require = Rules(AccessRules.Mfa()) };
        var (_, changed) = await cf.Access.ChangeApplicationPolicyAsync("a1", "p1", same);
        Assert.False(changed);
        Assert.Single(h.Requests);

        var (_, written) = await cf.Access.ChangeApplicationPolicyAsync("a1", "p1", noMfa, allowLoosen: true);
        Assert.True(written);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!;
        Assert.Empty(body["require"]!.AsArray());
    }

    [Fact]
    public async Task Removing_a_reusable_policy_checks_the_applications_and_fails_closed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/policies/p1", """{"id":"p1","name":"staff","decision":"allow","include":[]}"""),
            R("GET", "/access/apps", """[{"id":"a1","name":"MT5","domain":"mt5.example.com","type":"self_hosted","policies":[{"id":"p1","decision":"allow"}]}]"""));
        Assert.Contains("MT5", (await RefusedAfterRead(h, () => cf.Access.RemovePolicyAsync("p1"))).Message);

        h.Requests.Clear();
        Route(h, R("GET", "/access/policies/p1", """{"id":"p1","name":"staff","decision":"allow","include":[]}"""),
            ("GET", "/access/apps", _ => Error(HttpStatusCode.InternalServerError, 10001, "internal")));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.RemovePolicyAsync("p1"));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task Organization_default_action_and_team_domain_need_switches()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/organizations", """{"name":"Team","auth_domain":"team.cloudflareaccess.com","deny_unmatched_requests":false,"mfa_required_for_all_apps":true}"""),
            R("PATCH", "/access/organizations", """{"name":"Team"}"""));
        Assert.Contains("allowBlock", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { DenyUnmatchedRequests = true }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { MfaRequiredForAllApps = false }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowDisconnect", (await RefusedAfterRead(h, () => cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { AuthDomain = "other.cloudflareaccess.com" }))).Message);

        h.Requests.Clear();
        var (_, changed) = await cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { Name = "Team", MfaRequiredForAllApps = true });
        Assert.False(changed);
        await cf.Access.UpdateOrganizationAsync(new AccessOrganizationChange { DenyUnmatchedRequests = true }, allowBlock: true);
        var body = JsonNode.Parse(h.Requests[^1].Body!)!.AsObject();
        Assert.Equal(HttpMethod.Patch, h.Requests[^1].Method);
        Assert.Equal(["deny_unmatched_requests"], body.Select(p => p.Key).ToArray());
    }

    [Fact]
    public async Task Groups_in_use_and_the_last_identity_provider_are_protected()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/policies", """[{"id":"p1","name":"staff","decision":"allow","include":[{"group":{"id":"g1"}}]}]"""),
            R("GET", "/access/apps", "[]"), R("GET", "/access/groups", """[{"id":"g1","name":"admins","include":[]}]"""));
        Assert.Contains("staff", (await RefusedAfterRead(h, () => cf.Access.RemoveGroupAsync("g1"))).Message);

        h.Requests.Clear();
        Route(h, R("GET", "/access/identity_providers", """[{"id":"i1","name":"PIN","type":"onetimepin","config":{}}]"""));
        Assert.Contains("allowRemoveLast", (await RefusedAfterRead(h, () => cf.Access.RemoveIdentityProviderAsync("i1"))).Message);
    }

    [Fact]
    public async Task Policy_tests_are_a_guarded_POST_that_is_not_retried()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok("""{"id":"pt1","status":"success"}"""));
        h.Responses.Enqueue(Ok("""{"id":"pt1","status":"complete","total_users":10,"users_approved":7,"users_blocked":3}"""));
        var test = await cf.Access.StartPolicyTestAsync(["p1", "p2"]);
        Assert.Equal("pt1", test.Id);
        Assert.Equal(HttpMethod.Post, h.Requests[0].Method);
        Assert.Equal(2, JsonNode.Parse(h.Requests[0].Body!)!["policies"]!.AsArray().Count);
        var state = await cf.Access.GetPolicyTestAsync("pt1");
        Assert.Equal(7, state.UsersApproved);

        h.Requests.Clear();
        h.Responses.Enqueue(Error(HttpStatusCode.ServiceUnavailable, 10000, "unavailable"));
        h.Responses.Enqueue(Ok("""{"id":"pt2"}"""));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.StartPolicyTestAsync(["p1"]));
        Assert.Single(h.Requests);
    }

    // ---------------------------------------------------------------- Access: secrets

    [Fact]
    public async Task Service_token_secret_exists_only_in_the_one_time_secret()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Ok($$"""{"id":"t1","name":"svc","client_id":"cid.access","client_secret":"{{SecretMarker}}","duration":"8760h"}"""));
        var issued = await cf.Access.IssueServiceTokenAsync("svc");
        Assert.Equal("cid.access", issued.ClientId);
        Assert.DoesNotContain(SecretMarker, issued.ToString());
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(issued.Token, CloudflareJson.Options));
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(new { issued.Token, issued.ClientSecret }, CloudflareJson.Options));
        Assert.DoesNotContain(SecretMarker, issued.ClientSecret.ToString());
        Assert.Equal(SecretMarker, issued.ClientSecret.TakeValue());
        Assert.False(issued.ClientSecret.HasValue);
        Assert.Throws<ObjectDisposedException>(() => issued.ClientSecret.Reveal());

        h.Requests.Clear();
        h.Responses.Enqueue(Ok($$"""{"id":"t1","name":"svc","client_id":"cid.access","client_secret":"{{SecretMarker}}"}"""));
        var rotated = await cf.Access.RotateServiceTokenSecretAsync("t1", TimeSpan.FromHours(12));
        Assert.Contains("previous_client_secret_expires_at", h.Requests[0].Body);
        Assert.Equal(SecretMarker, rotated.ClientSecret.Reveal());

        h.Requests.Clear();
        h.Responses.Enqueue(Error(HttpStatusCode.BadGateway, 10000, "bad gateway"));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.IssueServiceTokenAsync("svc"));
        Assert.Single(h.Requests);

        h.Requests.Clear();
        h.Responses.Enqueue(Ok("""{"id":"t1","name":"svc","client_id":"cid"}"""));
        var missing = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.IssueServiceTokenAsync("svc"));
        Assert.Contains("no client secret", missing.Message);
    }

    [Fact]
    public async Task Used_service_tokens_are_not_deleted_without_allowDisconnect()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/service_tokens/t1", """{"id":"t1","name":"mt5-bridge","client_id":"c","last_seen_at":"2026-11-16T10:00:00Z"}"""));
        Assert.Contains("allowDisconnect", (await RefusedAfterRead(h, () => cf.Access.RemoveServiceTokenAsync("t1"))).Message);
        h.Requests.Clear();
        Route(h, R("GET", "/access/service_tokens/t1", """{"id":"t1","name":"new","client_id":"c"}"""),
            R("GET", "/access/policies", """[{"id":"p1","name":"bridge","decision":"non_identity","include":[{"service_token":{"token_id":"t1"}}]}]"""));
        Assert.Contains("bridge", (await RefusedAfterRead(h, () => cf.Access.RemoveServiceTokenAsync("t1"))).Message);
    }

    [Fact]
    public async Task Identity_provider_secrets_reach_only_the_request_body()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/identity_providers", "[]"),
            R("POST", "/access/identity_providers", $$$"""{"id":"i1","name":"GitHub","type":"github","config":{"client_id":"id","client_secret":"{{{SecretMarker}}}"},"scim_config":{"secret":"{{{SecretMarker}}}"}}"""));
        var (provider, created) = await cf.Access.EnsureIdentityProviderAsync("GitHub", "github", new { client_id = "id", client_secret = SecretMarker });
        Assert.True(created);
        Assert.Contains(SecretMarker, h.Requests[^1].Body);
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(provider, CloudflareJson.Options));
        Assert.Equal("id", provider.Config!.Value.GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task Errors_never_contain_the_api_token_or_secrets()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 10000, "Authentication error"));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Access.IssueServiceTokenAsync("svc"));
        Assert.DoesNotContain(Token, ex.ToString());
        Assert.Equal("Bearer " + Token, h.Requests[0].Auth);
    }

    // ---------------------------------------------------------------- Gateway

    [Fact]
    public async Task Gateway_rules_block_to_allow_needs_allowLoosen_and_allow_to_block_needs_allowBlock()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string block = """{"id":"r1","name":"bad","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"bad.example\")","identity":"","device_posture":"","precedence":10}""";
        Route(h, R("GET", "/gateway/rules/r1", block), R("PUT", "/gateway/rules/r1", block), R("PATCH", "/gateway/rules/r1", block), R("DELETE", "/gateway/rules/r1", "{}"));
        Assert.Contains("block → allow", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r1", DnsRule("allow")))).Message);
        h.Requests.Clear();
        Assert.Contains("selector", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r1", DnsRule("block", "any(dns.domains[*] == \"x.example\")")))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.SetRuleEnabledAsync("r1", false));
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.RemoveRuleAsync("r1"));

        h.Requests.Clear();
        var (_, changed) = await cf.Gateway.ChangeRuleAsync("r1", new GatewayRuleInput { Name = "bad", Action = "block", Filters = ["dns"], Traffic = "any(dns.domains[*] == \"bad.example\")", Precedence = 10 });
        Assert.False(changed);
        Assert.Single(h.Requests);
        Assert.True(await cf.Gateway.RemoveRuleAsync("r1", allowLoosen: true));

        const string allow = """{"id":"r2","name":"ok","action":"allow","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"bad.example\")"}""";
        h.Requests.Clear();
        Route(h, R("GET", "/gateway/rules/r2", allow), R("PUT", "/gateway/rules/r2", allow));
        Assert.Contains("allowBlock", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r2", DnsRule("block")))).Message);
        h.Requests.Clear();
        var (_, written) = await cf.Gateway.ChangeRuleAsync("r2", DnsRule("block"), allowBlock: true);
        Assert.True(written);
        Assert.Equal(HttpMethod.Put, h.Requests[^1].Method);

        const string managed = """{"id":"r3","name":"parent","action":"allow","enabled":true,"filters":["dns"],"read_only":true}""";
        h.Requests.Clear();
        Route(h, R("GET", "/gateway/rules/r3", managed));
        Assert.Contains("read-only", (await RefusedAfterRead(h, () => cf.Gateway.ChangeRuleAsync("r3", DnsRule("allow"), allowLoosen: true, allowBlock: true))).Message);
    }

    [Fact]
    public async Task Gateway_lists_in_use_are_protected_and_entries_are_checked()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/gateway/rules", """[{"id":"r1","name":"bad","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] in $l1)"}]"""),
            R("GET", "/gateway/lists/l1", """{"id":"l1","name":"bad","type":"DOMAIN","count":1}"""), R("PATCH", "/gateway/lists/l1", """{"id":"l1","name":"bad","type":"DOMAIN"}"""));
        Assert.Contains("\"bad\" (block)", (await RefusedAfterRead(h, () => cf.Gateway.RemoveListAsync("l1"))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.RemoveListItemsAsync("l1", ["bad.example"]));
        h.Requests.Clear();
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Gateway.AddListItemsAsync("l1", ["https://bad.example/"]));
        h.Requests.Clear();
        await cf.Gateway.AddListItemsAsync("l1", ["bad.example", "*.worse.example"]);
        Assert.Equal(2, JsonNode.Parse(h.Requests[^1].Body!)!["append"]!.AsArray().Count);
    }

    [Fact]
    public async Task Gateway_configuration_patches_only_changed_sections_and_guards_inspection()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string config = """{"settings":{"tls_decrypt":{"enabled":true},"activity_log":{"enabled":true},"antivirus":{"enabled_download_phase":true,"enabled_upload_phase":false,"fail_closed":false}}}""";
        Route(h, R("GET", "/gateway/configuration", config), R("PATCH", "/gateway/configuration", config));
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { TlsDecrypt = false }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowBlock", (await RefusedAfterRead(h, () => cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { AntivirusFailClosed = true }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowTlsDecrypt", (await RefusedAfterRead(h, () => cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { CertificateId = "gc2" }))).Message);

        h.Requests.Clear();
        var (_, unchanged) = await cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { TlsDecrypt = true, ActivityLog = true });
        Assert.False(unchanged);
        await cf.Gateway.UpdateConfigurationAsync(new GatewaySettingsChange { AntivirusUploadScan = true });
        var settings = JsonNode.Parse(h.Requests[^1].Body!)!["settings"]!.AsObject();
        Assert.Equal(["antivirus"], settings.Select(p => p.Key).ToArray());
        Assert.True(settings["antivirus"]!["enabled_download_phase"]!.GetValue<bool>());
        Assert.True(settings["antivirus"]!["enabled_upload_phase"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Gateway_logging_keeps_pii_redaction_unless_allowed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/gateway/logging", """{"redact_pii":true,"settings_by_rule_type":{"dns":{"log_all":true,"log_blocks":true}}}"""), R("PUT", "/gateway/logging", "{}"));
        Assert.Contains("allowPii", (await RefusedAfterRead(h, () => cf.Gateway.SetLoggingAsync(redactPii: false))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.SetLoggingAsync(byRuleType: new Dictionary<string, (bool, bool)> { ["dns"] = (false, true) }));
    }

    [Fact]
    public async Task Not_entitled_conflict_and_rate_limit_are_handled()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 2017, "This feature is not available on your plan"));
        await Assert.ThrowsAsync<CloudflareNotEntitledException>(() => cf.Gateway.ListRulesAsync());

        h.Requests.Clear();
        var listed = 0;
        Route(h, ("GET", "/gateway/rules", _ => Ok(listed++ == 0 ? "[]" : """[{"id":"r9","name":"r","action":"block","enabled":true,"filters":["dns"]}]""")),
            ("POST", "/gateway/rules", _ => Error(HttpStatusCode.Conflict, 1000, "rule already exists")));
        var (rule, created) = await cf.Gateway.EnsureRuleAsync(DnsRule("block"));
        Assert.False(created);
        Assert.Equal("r9", rule.Id);

        h.Requests.Clear();
        h.Responder = null;
        var limited = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("""{"success":false,"errors":[{"code":971,"message":"rate limited"}]}""") };
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero);
        h.Responses.Enqueue(limited);
        h.Responses.Enqueue(Ok("""{"gateway_tag":"tag1","provider_name":"Cloudflare"}"""));
        Assert.Equal("tag1", (await cf.Gateway.GetAccountAsync()).GatewayTag);
        Assert.Equal(2, h.Requests.Count);
    }

    [Fact]
    public async Task Gateway_certificates_in_use_are_not_deactivated()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/gateway/certificates/gc1", """{"id":"gc1","in_use":true,"binding_status":"available","type":"gateway_managed"}"""));
        await RefusedAfterRead(h, () => cf.Gateway.DeactivateCertificateAsync("gc1"));
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Gateway.RemoveCertificateAsync("gc1"));
    }

    // ---------------------------------------------------------------- Tunnels

    [Fact]
    public async Task Tunnel_run_token_is_only_in_the_one_time_secret()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/cfd_tunnel?", "[]"),
            R("POST", "/cfd_tunnel", $$$"""{"id":"t1","name":"gw","status":"inactive","token":"{{{TunnelTokenMarker}}}","credentials_file":{"TunnelSecret":"{{{SecretMarker}}}"}}"""),
            R("GET", "/cfd_tunnel/t1/token", $"\"{TunnelTokenMarker}\""),
            R("PATCH", "/cfd_tunnel/t1", """{"id":"t1"}"""));
        var (ensured, created) = await cf.Tunnels.EnsureAsync("gw");
        Assert.True(created);
        Assert.DoesNotContain(TunnelTokenMarker, JsonSerializer.Serialize(ensured.Tunnel, CloudflareJson.Options));
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(ensured.Tunnel, CloudflareJson.Options));
        Assert.DoesNotContain(TunnelTokenMarker, ensured.ToString());
        Assert.Equal(TunnelTokenMarker, ensured.RunToken!.TakeValue());

        var token = await cf.Tunnels.GetRunTokenAsync("t1");
        Assert.DoesNotContain(TunnelTokenMarker, token.ToString());
        Assert.Equal(TunnelTokenMarker, token.Reveal());

        h.Requests.Clear();
        var rotated = await cf.Tunnels.RotateRunTokenAsync("t1", allowDisconnect: true);
        var secret = JsonNode.Parse(h.Requests[0].Body!)!["tunnel_secret"]!.GetValue<string>();
        Assert.Equal(32, Convert.FromBase64String(secret).Length);
        Assert.DoesNotContain(secret, cf.Tunnels.PreviewRotateRunToken("t1").BodyJson);
        Assert.Equal(TunnelTokenMarker, rotated.Reveal());
    }

    [Fact]
    public async Task Ingress_changes_that_cut_hostnames_off_need_allowDisconnect_and_keep_origin_settings()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        const string config = """
            {"tunnel_id":"t1","version":3,"config":{"ingress":[{"hostname":"gw.example.com","service":"http://localhost:8080"},{"service":"http_status:404"}],
             "originRequest":{"connectTimeout":10},"warp-routing":{"enabled":true}}}
            """;
        Route(h, R("GET", "/cfd_tunnel/t1/configurations", config), R("PUT", "/cfd_tunnel/t1/configurations", config));

        var other = new TunnelIngressRule { Hostname = "new.example.com", Service = "http://localhost:9000" };
        var ex = await RefusedAfterRead(h, () => cf.Tunnels.SetIngressAsync("t1", [other]));
        Assert.Contains("gw.example.com", ex.Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Tunnels.UpsertIngressRuleAsync("t1", new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:9999" }));

        h.Requests.Clear();
        var (_, unchanged) = await cf.Tunnels.SetIngressAsync("t1", [new TunnelIngressRule { Hostname = "gw.example.com", Service = "http://localhost:8080" }]);
        Assert.False(unchanged);
        Assert.Single(h.Requests);

        var (_, changed) = await cf.Tunnels.UpsertIngressRuleAsync("t1", other);
        Assert.True(changed);
        var sent = JsonNode.Parse(h.Requests[^1].Body!)!["config"]!;
        var ingress = sent["ingress"]!.AsArray();
        Assert.Equal(3, ingress.Count);
        Assert.Equal("gw.example.com", ingress[0]!["hostname"]!.GetValue<string>());
        Assert.Equal("new.example.com", ingress[1]!["hostname"]!.GetValue<string>());
        Assert.Equal("http_status:404", ingress[2]!["service"]!.GetValue<string>());
        Assert.Equal(10, sent["originRequest"]!["connectTimeout"]!.GetValue<int>());
        Assert.True(sent["warp-routing"]!["enabled"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Active_tunnels_and_tunnels_with_routes_are_not_deleted_and_unreadable_state_fails_closed()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/cfd_tunnel/t1/connections", """[{"id":"c1","conns":[{"colo_name":"FRA","is_pending_reconnect":false}]}]"""),
            R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"healthy"}"""));
        Assert.Contains("allowDeleteActive", (await RefusedAfterRead(h, () => cf.Tunnels.RemoveAsync("t1"))).Message);

        h.Requests.Clear();
        Route(h, R("GET", "/cfd_tunnel/t1/connections", "[]"), R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"inactive"}"""),
            R("GET", "/teamnet/routes", """[{"id":"rt1","network":"10.0.0.0/16","tunnel_id":"t1"}]"""));
        Assert.Contains("route", (await RefusedAfterRead(h, () => cf.Tunnels.RemoveAsync("t1"))).Message);

        h.Requests.Clear();
        Route(h, ("GET", "/cfd_tunnel/t1/connections", _ => Error(HttpStatusCode.InternalServerError, 1000, "internal")),
            R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"inactive"}"""));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.Tunnels.RemoveAsync("t1"));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);

        h.Requests.Clear();
        Route(h, R("GET", "/cfd_tunnel/t1/connections", "[]"), R("GET", "/cfd_tunnel/t1", """{"id":"t1","name":"gw","status":"inactive"}"""),
            R("GET", "/teamnet/routes", "[]"), R("DELETE", "/cfd_tunnel/t1", "{}"));
        Assert.True(await cf.Tunnels.RemoveAsync("t1"));
    }

    [Fact]
    public async Task Routes_of_other_tunnels_conflict_and_the_default_virtual_network_stays()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/teamnet/routes", """[{"id":"rt1","network":"10.0.0.0/16","tunnel_id":"t2","tunnel_name":"old"}]"""));
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Tunnels.EnsureRouteAsync("10.0.0.0/16", "t1"));
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));

        h.Requests.Clear();
        Route(h, R("GET", "/teamnet/virtual_networks", """[{"id":"vn1","name":"default","is_default_network":true}]"""));
        await RefusedAfterRead(h, () => cf.Tunnels.RemoveVirtualNetworkAsync("vn1", allowDisconnect: true));
    }

    // ---------------------------------------------------------------- devices

    [Fact]
    public async Task Device_profiles_need_allowBroadProfile_and_allowLoosen()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/devices/policy/dp1", """{"policy_id":"dp1","name":"staff","match":"identity.email == \"a@example.com\"","switch_locked":true}"""),
            R("PATCH", "/devices/policy/dp1", """{"policy_id":"dp1"}"""),
            R("GET", "/devices/policy/exclude", """[{"address":"192.168.0.0/16"}]"""), R("PUT", "/devices/policy/exclude", "[]"));
        Assert.Contains("allowLoosen", (await RefusedAfterRead(h, () => cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings { SwitchLocked = false }))).Message);
        h.Requests.Clear();
        Assert.Contains("allowBroadProfile", (await RefusedAfterRead(h, () => cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings(), match: "any"))).Message);
        h.Requests.Clear();
        await cf.Devices.UpdateProfileAsync("dp1", new DeviceProfileSettings { SwitchLocked = true, SupportUrl = "https://help.example.com" });
        Assert.Equal(["support_url"], JsonNode.Parse(h.Requests[^1].Body!)!.AsObject().Select(p => p.Key).ToArray());

        h.Requests.Clear();
        var more = new[] { SplitTunnelEntry.ForAddress("192.168.0.0/16"), SplitTunnelEntry.ForHost("intranet.example.com") };
        Assert.Contains("bypass Gateway", (await RefusedAfterRead(h, () => cf.Devices.SetSplitTunnelExcludeAsync(more, allowBroadProfile: true))).Message);
        h.Requests.Clear();
        Assert.Contains("allowDisconnect", (await RefusedAfterRead(h, () => cf.Devices.SetSplitTunnelExcludeAsync([], allowBroadProfile: true))).Message);
    }

    [Fact]
    public async Task Posture_rules_in_use_are_not_changed_or_deleted()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Route(h, R("GET", "/access/policies", """[{"id":"p1","name":"managed","decision":"allow","include":[],"require":[{"device_posture":{"integration_uid":"pr1"}}]}]"""),
            R("GET", "/access/groups", "[]"), R("GET", "/access/apps", "[]"), R("GET", "/gateway/rules", "[]"));
        Assert.Contains("managed", (await RefusedAfterRead(h, () => cf.Devices.RemovePostureRuleAsync("pr1"))).Message);
        h.Requests.Clear();
        await RefusedAfterRead(h, () => cf.Devices.UpdatePostureRuleAsync("pr1", new DevicePostureRuleInput { Name = "fw", Type = "firewall" }));
    }

    [Fact]
    public async Task Device_revocation_sends_ids_as_query_and_devices_are_read()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await cf.Devices.RevokeRegistrationsAsync(["reg1", "reg2"], allowDisconnect: true);
        Assert.Contains("/devices/registrations/revoke?id=reg1&id=reg2", h.Requests[0].Url);

        h.Requests.Clear();
        h.Responses.Enqueue(Ok("""[{"id":"d1","name":"laptop","os_version":"14.1","serial_number":"SN-1","last_seen_user":{"email":"a@example.com"}}]"""));
        var devices = await cf.Devices.ListDevicesAsync(maxItems: 10);
        Assert.Equal("laptop", devices[0].Name);
        Assert.Contains("/devices/physical-devices", h.Requests[0].Url);
    }

    // ---------------------------------------------------------------- DLP and risk

    [Fact]
    public async Task Dlp_models_carry_no_patterns_word_lists_or_cells()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responses.Enqueue(Ok("""[{"id":"pr1","name":"Credentials","type":"custom","entries":[{"id":"e1","name":"key","type":"custom","enabled":true,"pattern":{"regex":"PATTERN-MARKER"}},{"id":"e2","name":"words","type":"word_list","enabled":true,"word_list":["WORD-MARKER"]}]}]"""));
        var profiles = await cf.Dlp.ListProfilesAsync();
        var json = JsonSerializer.Serialize(profiles, CloudflareJson.Options);
        Assert.Equal(2, profiles[0].Entries.Count);
        Assert.DoesNotContain("PATTERN-MARKER", json);
        Assert.DoesNotContain("WORD-MARKER", json);

        h.Responses.Enqueue(Ok("""{"users":[{"user_id":"u1","name":"A","email":"a@example.com","max_risk_level":"high","event_count":3,"last_event":"2026-11-16T10:00:00Z"}]}"""));
        Assert.Equal("high", (await cf.RiskScoring.GetSummaryAsync())[0].MaxRiskLevel);
        h.Responses.Enqueue(Ok("""{"behaviors":{"imp_travel":{"name":"Impossible travel","enabled":true,"risk_level":"high"}}}"""));
        Assert.True((await cf.RiskScoring.ListBehaviorsAsync())["imp_travel"].Enabled);
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    // ---------------------------------------------------------------- obsolete

    [Theory]
    [InlineData(typeof(AccessClient), "CreateApplicationAsync")]
    [InlineData(typeof(AccessClient), "DeleteApplicationAsync")]
    [InlineData(typeof(AccessClient), "DeleteApplicationPolicyAsync")]
    [InlineData(typeof(AccessClient), "DeletePolicyAsync")]
    [InlineData(typeof(AccessClient), "CreateServiceTokenAsync")]
    [InlineData(typeof(AccessClient), "RotateServiceTokenAsync")]
    [InlineData(typeof(AccessClient), "DeleteIdentityProviderAsync")]
    [InlineData(typeof(TunnelsClient), "CreateAsync")]
    [InlineData(typeof(TunnelsClient), "DeleteAsync")]
    [InlineData(typeof(TunnelsClient), "GetTokenAsync")]
    [InlineData(typeof(TunnelsClient), "PutConfigurationAsync")]
    [InlineData(typeof(TunnelsClient), "PublishHostnameAsync")]
    [InlineData(typeof(TunnelsClient), "CleanupConnectionsAsync")]
    public void Old_unguarded_methods_are_obsolete(Type type, string method)
    {
        var m = type.GetMethod(method)!;
        Assert.NotNull(m.GetCustomAttributes(typeof(ObsoleteAttribute), false).SingleOrDefault());
    }
}
