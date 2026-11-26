using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>
/// Token management (0.6.0). The token value is synthetic; the tests check that it appears only in <see cref="ApiTokenSecret"/> and on the wire,
/// never in models, previews, ToString, JSON or exception messages (same rule as <see cref="JwtKeySet"/>).
/// </summary>
public class ApiTokenTests
{
    private const string ClientToken = "secret-token-123";
    private const string NewValue = "NEWTOKENVALUESYNTHETIC0123456789abcdefABCDEF";
    private const string RolledValue = "ROLLEDVALUESYNTHETIC9876543210zyxwvuZYXWVU";
    private const string Info = """{"page":1,"per_page":50,"count":1,"total_count":1,"total_pages":1}""";

    internal static ApiTokenInput MinimalToken() => new()
    {
        Name = "dns-edit-zone1",
        ExpiresOn = DateTimeOffset.UtcNow.AddDays(30),
        AllowedIps = ["203.0.113.0/24"],
        Policies = [new ApiTokenPolicyInput { PermissionGroupIds = ["4755a26eedb94da69e1066d98aa820be"], Resources = new JsonObject { [ApiTokenResources.Zone("zone1")] = "*" } }],
    };

    private static string Created(string value) => $$$"""
        {"id":"t1","name":"dns-edit-zone1","status":"active","issued_on":"2026-11-17T08:00:00Z","expires_on":"2026-12-17T08:00:00Z",
         "policies":[{"id":"p1","effect":"allow","permission_groups":[{"id":"4755a26eedb94da69e1066d98aa820be","name":"DNS Write"}],"resources":{"com.cloudflare.api.account.zone.zone1":"*"}}],
         "token_suffix":"cdef","value":"{{{value}}}"}
        """;

    private static HttpResponseMessage Error(HttpStatusCode status, int code, string message) =>
        FakeHandler.Json($$"""{"success":false,"errors":[{"code":{{code}},"message":"{{message}}"}],"messages":[],"result":null}""", status);

    [Fact]
    public async Task Created_token_value_exists_only_in_the_secret_object()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var preview = cf.ApiTokens.PreviewCreate(MinimalToken());
        Assert.Equal("POST", preview.Method);
        Assert.Equal("user/tokens", preview.Path);
        Assert.Contains("shown once", preview.Summary);
        Assert.Contains("\"in\": [", preview.BodyJson);
        Assert.Empty(h.Requests);

        h.Responses.Enqueue(FakeHandler.Ok(Created(NewValue)));
        var issued = await cf.ApiTokens.CreateAsync(MinimalToken());
        Assert.Equal("t1", issued.Token.Id);
        Assert.Equal("DNS Write", issued.Token.Policies[0].PermissionGroups[0].Name);

        // nowhere but in the secret
        Assert.DoesNotContain(NewValue, issued.ToString());
        Assert.DoesNotContain(NewValue, issued.Secret.ToString());
        Assert.DoesNotContain(NewValue, JsonSerializer.Serialize(issued));
        Assert.DoesNotContain(NewValue, JsonSerializer.Serialize(issued.Token));
        Assert.False(issued.Token.AdditionalData?.ContainsKey("value") ?? false);
        Assert.Contains("[redacted]", JsonSerializer.Serialize(issued));

        // one-time hand-over
        Assert.Equal(NewValue, issued.Secret.Reveal());
        Assert.Equal(NewValue, issued.Secret.TakeValue());
        Assert.False(issued.Secret.HasValue);
        Assert.Throws<ObjectDisposedException>(() => issued.Secret.Reveal());

        // the client's own token is only in the Authorization header, never in the body
        Assert.Equal("Bearer " + ClientToken, h.Requests[0].Auth);
        Assert.DoesNotContain(ClientToken, h.Requests[0].Body);
    }

    [Fact]
    public async Task Least_privilege_is_checked_locally()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        var broad = new ApiTokenInput
        {
            Name = "too-broad", ExpiresOn = DateTimeOffset.UtcNow.AddDays(1),
            Policies = [new ApiTokenPolicyInput { PermissionGroupIds = ["g1"], Resources = ApiTokenResources.AllZonesOf("acc1") }],
        };
        var ex = Assert.Throws<ArgumentException>(() => cf.ApiTokens.PreviewCreate(broad));
        Assert.Contains("allowBroadResources", ex.Message);
        Assert.Contains("WARNING", cf.ApiTokens.PreviewCreate(broad, allowBroadResources: true).Summary);

        var forever = new ApiTokenInput { Name = "forever", Policies = MinimalToken().Policies };
        Assert.Contains("allowNoExpiry", Assert.Throws<ArgumentException>(() => cf.ApiTokens.PreviewCreate(forever)).Message);
        Assert.Contains("never expires", cf.ApiTokens.PreviewCreate(forever, allowNoExpiry: true).Summary);

        Assert.Throws<ArgumentException>(() => cf.ApiTokens.PreviewCreate(new ApiTokenInput { Name = "x", ExpiresOn = DateTimeOffset.UtcNow.AddDays(-1), Policies = MinimalToken().Policies }));
        Assert.Throws<ArgumentException>(() => cf.ApiTokens.PreviewCreate(new ApiTokenInput { Name = "x", ExpiresOn = DateTimeOffset.UtcNow.AddDays(1), AllowedIps = ["not-an-ip"], Policies = MinimalToken().Policies }));
        Assert.Throws<ArgumentException>(() => cf.ApiTokens.PreviewCreate(new ApiTokenInput { Name = "x", ExpiresOn = DateTimeOffset.UtcNow.AddDays(1), Policies = [] }));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.ApiTokens.CreateAsync(broad));
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Rolling_or_revoking_the_own_token_is_refused_and_nothing_is_written()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => cf.ApiTokens.RollAsync("self1"));
        Assert.Contains("allowSelf", refused.Message);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.ApiTokens.RevokeAsync("self1"));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.ApiTokens.SetStatusAsync("self1", "disabled"));
        Assert.All(h.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        Assert.All(h.Requests, r => Assert.EndsWith("/user/tokens/verify", r.Url));

        // another token: roll returns only the secret
        h.Requests.Clear();
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        h.Responses.Enqueue(FakeHandler.Ok($"\"{RolledValue}\""));
        using var rolled = await cf.ApiTokens.RollAsync("t2");
        Assert.Equal(HttpMethod.Put, h.Requests[1].Method);
        Assert.EndsWith("/user/tokens/t2/value", h.Requests[1].Url);
        Assert.DoesNotContain(RolledValue, rolled.ToString() + JsonSerializer.Serialize(rolled));
        Assert.Equal(RolledValue, rolled.Reveal());
        Assert.DoesNotContain(RolledValue, cf.ApiTokens.PreviewRoll("t2").ToString());

        // revoke: 404 → false
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        h.Responses.Enqueue(Error(HttpStatusCode.NotFound, 1003, "Invalid token"));
        Assert.False(await cf.ApiTokens.RevokeAsync("gone"));
    }

    [Fact]
    public async Task Disabling_keeps_the_policies_and_account_tokens_use_the_account_path()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        h.Responses.Enqueue(FakeHandler.Ok(Created("SHOULD-NOT-BE-READ-BACK")));
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"t1","name":"dns-edit-zone1","status":"disabled","policies":[]}"""));
        var disabled = await cf.ApiTokens.SetStatusAsync("t1", "disabled", owner: ApiTokenOwner.Account);
        Assert.Equal("disabled", disabled.Status);
        Assert.EndsWith("/accounts/acc1/tokens/verify", h.Requests[0].Url);
        Assert.EndsWith("/accounts/acc1/tokens/t1", h.Requests[2].Url);
        var body = JsonDocument.Parse(h.Requests[2].Body!).RootElement;
        Assert.Equal("disabled", body.GetProperty("status").GetString());
        Assert.Equal("4755a26eedb94da69e1066d98aa820be", body.GetProperty("policies")[0].GetProperty("permission_groups")[0].GetProperty("id").GetString());
        Assert.DoesNotContain("SHOULD-NOT-BE-READ-BACK", h.Requests[2].Body);

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"t1","name":"a","status":"active","value":"LEAK-SYNTH"}]""", Info));
        var list = await cf.ApiTokens.ListAsync(ApiTokenOwner.Account);
        Assert.DoesNotContain("LEAK-SYNTH", JsonSerializer.Serialize(list));

        h.Responses.Enqueue(FakeHandler.Ok("""[{"id":"g1","name":"DNS Write","scopes":["com.cloudflare.api.account.zone"]},{"id":"g2","name":"Zone Read","scopes":["com.cloudflare.api.account.zone"]}]"""));
        var groups = await cf.ApiTokens.ListPermissionGroupsAsync(nameContains: "dns");
        Assert.Equal("g1", Assert.Single(groups).Id);
        Assert.EndsWith("/user/tokens/permission_groups", h.Requests[^1].Url);
    }

    [Fact]
    public async Task Create_is_not_repeated_after_a_server_error_and_errors_carry_no_secret()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responses.Enqueue(Error(HttpStatusCode.ServiceUnavailable, 0, "unavailable"));
        var ex = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.ApiTokens.CreateAsync(MinimalToken()));
        Assert.Single(h.Requests);
        Assert.DoesNotContain(ClientToken, ex.Message + ex);

        // a rate limit is answered before processing: retried
        h.Requests.Clear();
        h.Responses.Enqueue(Error((HttpStatusCode)429, 971, "rate limited"));
        h.Responses.Enqueue(FakeHandler.Ok(Created(NewValue)));
        var issued = await cf.ApiTokens.CreateAsync(MinimalToken());
        Assert.Equal(2, h.Requests.Count);
        issued.Secret.Dispose();
        Assert.False(issued.Secret.HasValue);

        // an answer without value is an error that does not invent one
        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"t9","name":"x","status":"active"}"""));
        var missing = await Assert.ThrowsAsync<CloudflareApiException>(() => cf.ApiTokens.CreateAsync(MinimalToken()));
        Assert.Contains("no token value", missing.Message);

        h.Responses.Enqueue(Error(HttpStatusCode.Forbidden, 9109, "Unauthorized to access requested resource"));
        await Assert.ThrowsAsync<CloudflareApiException>(() => cf.ApiTokens.ListAsync());

        h.Responses.Enqueue(FakeHandler.Ok("""{"id":"self1","status":"active"}"""));
        Assert.Equal("self1", (await cf.ApiTokens.VerifyAsync()).Id);
    }
}
