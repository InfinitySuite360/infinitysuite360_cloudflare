using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using InfinitySuite360.Cloudflare.AccessJwt;

namespace InfinitySuite360.Cloudflare.Tests;

internal sealed class JwtClock : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan span) => _now += span;
    public long Unix(TimeSpan offset = default) => (_now + offset).ToUnixTimeSeconds();
}

/// <summary>A team: one or more signing keys, the key document Cloudflare would serve, and tokens signed with them.</summary>
internal sealed class FakeTeam : IDisposable
{
    public const string Domain = "myteam.cloudflareaccess.com";
    public const string Aud = "aud-tag-1234567890";

    public Dictionary<string, RSA> Keys { get; } = new() { ["key-1"] = RSA.Create(2048) };
    public int Fetches;
    public Exception? FetchFails;
    public string? Document;      // overrides the generated key document

    public void Dispose() { foreach (var k in Keys.Values) k.Dispose(); }

    public string KeyDocument()
    {
        var keys = Keys.Select(k =>
        {
            var p = k.Value.ExportParameters(false);
            return new { kid = k.Key, kty = "RSA", alg = "RS256", use = "sig", e = B64(p.Exponent!), n = B64(p.Modulus!) };
        });
        return JsonSerializer.Serialize(new { keys });
    }

    public Task<string> FetchAsync(string url, CancellationToken ct)
    {
        Fetches++;
        Assert.Equal($"https://{Domain}/cdn-cgi/access/certs", url);
        if (FetchFails is not null) throw FetchFails;
        return Task.FromResult(Document ?? KeyDocument());
    }

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string Token(JwtClock clock, Action<Dictionary<string, object?>>? payload = null, Action<Dictionary<string, object?>>? header = null, string kid = "key-1", RSA? signWith = null)
    {
        var h = new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = kid, ["typ"] = "JWT" };
        var p = new Dictionary<string, object?>
        {
            ["iss"] = "https://" + Domain, ["aud"] = new[] { Aud }, ["sub"] = "user-1", ["email"] = "ann@example.com",
            ["iat"] = clock.Unix(), ["exp"] = clock.Unix(TimeSpan.FromHours(1)), ["identity_nonce"] = "nonce-1", ["type"] = "app", ["country"] = "AT",
        };
        header?.Invoke(h);
        payload?.Invoke(p);
        var signingInput = B64(JsonSerializer.SerializeToUtf8Bytes(h)) + "." + B64(JsonSerializer.SerializeToUtf8Bytes(p));
        var key = signWith ?? Keys.GetValueOrDefault(kid) ?? Keys.Values.First();
        return signingInput + "." + B64(key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
}

public class AccessJwtValidatorTests : IDisposable
{
    private readonly FakeTeam _team = new();
    private readonly JwtClock _clock = new();

    public void Dispose() => _team.Dispose();

    private CloudflareAccessJwtValidator Validator(Action<CloudflareAccessJwtOptions>? configure = null)
    {
        var options = new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud] };
        configure?.Invoke(options);
        return new CloudflareAccessJwtValidator(options, _team.FetchAsync, _clock);
    }

    private string Token(Action<Dictionary<string, object?>>? payload = null, Action<Dictionary<string, object?>>? header = null, string kid = "key-1") => _team.Token(_clock, payload, header, kid);

    [Fact]
    public async Task A_valid_token_gives_the_identity()
    {
        var result = await Validator().ValidateAsync(Token(p => p["groups"] = new[] { "admins", "dev" }));
        Assert.True(result.Ok);
        var id = result.Identity!;
        Assert.Equal(("user-1", "ann@example.com", "nonce-1", "app", "AT"), (id.Subject, id.Email, id.IdentityNonce, id.Type, id.Country));
        Assert.Equal(["admins", "dev"], id.Groups);
        Assert.Equal([FakeTeam.Aud], id.Audiences);
        Assert.Equal(_clock.GetUtcNow().AddHours(1), id.ExpiresAt);
    }

    [Fact]
    public async Task A_service_token_has_a_common_name_and_no_email()
    {
        var result = await Validator().ValidateAsync(Token(p => { p.Remove("sub"); p.Remove("email"); p["common_name"] = "abc.access"; p["type"] = "service-token"; }));
        Assert.True(result.Ok);
        Assert.Equal(("abc.access", null, "abc.access"), (result.Identity!.Subject, result.Identity.Email, result.Identity.CommonName));
        Assert.False((await Validator().ValidateAsync(Token(p => { p.Remove("sub"); p.Remove("email"); }))).Ok);    // names nobody
    }

    [Fact]
    public async Task The_audience_may_be_a_string_or_a_list_and_one_of_several_configured_is_enough()
    {
        Assert.True((await Validator().ValidateAsync(Token(p => p["aud"] = FakeTeam.Aud))).Ok);
        Assert.True((await Validator().ValidateAsync(Token(p => p["aud"] = new[] { "other", FakeTeam.Aud }))).Ok);
        Assert.True((await Validator(o => o.Audiences = ["x", FakeTeam.Aud]).ValidateAsync(Token())).Ok);
        Assert.Equal(CloudflareAccessFailure.WrongAudience, (await Validator().ValidateAsync(Token(p => p["aud"] = new[] { "other" }))).Failure);
        Assert.Equal(CloudflareAccessFailure.WrongAudience, (await Validator().ValidateAsync(Token(p => p.Remove("aud")))).Failure);
        Assert.Equal(CloudflareAccessFailure.WrongAudience, (await Validator().ValidateAsync(Token(p => p["aud"] = 42))).Failure);
    }

    [Fact]
    public async Task Missing_oversized_and_malformed_tokens()
    {
        var v = Validator();
        Assert.Equal(CloudflareAccessFailure.MissingToken, (await v.ValidateAsync(null)).Failure);
        Assert.Equal(CloudflareAccessFailure.MissingToken, (await v.ValidateAsync("  ")).Failure);
        Assert.Equal(CloudflareAccessFailure.TokenTooLong, (await v.ValidateAsync(new string('a', 9000))).Failure);
        foreach (var bad in new[] { "abc", "a.b", "a.b.c.d", "a..c", ".b.c", "!!.@@.##", "e30.e30.", Convert.ToBase64String("{}"u8.ToArray()) + ".x.y" })
            Assert.Equal(CloudflareAccessFailure.Malformed, (await v.ValidateAsync(bad)).Failure);
        Assert.Equal(CloudflareAccessFailure.Malformed, (await v.ValidateAsync(FakeTeam.B64("[]"u8.ToArray()) + "." + FakeTeam.B64("{}"u8.ToArray()) + ".AAAA")).Failure);   // header is not an object
        Assert.Equal(0, _team.Fetches);          // nothing was fetched for rubbish
    }

    [Fact]
    public async Task Only_RS256_is_accepted()
    {
        var v = Validator();
        Assert.Equal(CloudflareAccessFailure.UnsupportedAlgorithm, (await v.ValidateAsync(Token(header: h => h["alg"] = "none"))).Failure);
        Assert.Equal(CloudflareAccessFailure.UnsupportedAlgorithm, (await v.ValidateAsync(Token(header: h => h["alg"] = "RS512"))).Failure);
        Assert.Equal(CloudflareAccessFailure.UnsupportedAlgorithm, (await v.ValidateAsync(Token(header: h => h.Remove("alg")))).Failure);
        Assert.Equal(CloudflareAccessFailure.UnsupportedAlgorithm, (await v.ValidateAsync(Token(header: h => h["alg"] = "rs256"))).Failure);     // exact match
    }

    [Fact]
    public async Task The_classic_HS256_trick_with_the_public_key_as_secret_fails()
    {
        // The attacker knows the public key (it is published) and signs an HS256 token with it as the HMAC secret.
        var publicKey = Encoding.ASCII.GetBytes(_team.KeyDocument());
        var h = FakeTeam.B64("""{"alg":"HS256","kid":"key-1","typ":"JWT"}"""u8.ToArray());
        var p = FakeTeam.B64(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["iss"] = "https://" + FakeTeam.Domain, ["aud"] = new[] { FakeTeam.Aud }, ["sub"] = "attacker", ["exp"] = _clock.Unix(TimeSpan.FromHours(1)) }));
        var token = $"{h}.{p}." + FakeTeam.B64(HMACSHA256.HashData(publicKey, Encoding.ASCII.GetBytes(h + "." + p)));
        Assert.Equal(CloudflareAccessFailure.UnsupportedAlgorithm, (await Validator().ValidateAsync(token)).Failure);
    }

    [Fact]
    public async Task Key_id_is_required_and_must_be_known()
    {
        var v = Validator();
        Assert.Equal(CloudflareAccessFailure.MissingKeyId, (await v.ValidateAsync(Token(header: h => h.Remove("kid")))).Failure);
        Assert.Equal(CloudflareAccessFailure.UnknownKey, (await v.ValidateAsync(Token(header: h => h["kid"] = "key-9"))).Failure);
    }

    [Fact]
    public async Task A_tampered_or_foreign_signed_token_fails()
    {
        var v = Validator();
        var good = Token();
        var parts = good.Split('.');
        var tamperedPayload = FakeTeam.B64(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["iss"] = "https://" + FakeTeam.Domain, ["aud"] = new[] { FakeTeam.Aud }, ["sub"] = "admin", ["exp"] = _clock.Unix(TimeSpan.FromDays(300)) }));
        Assert.Equal(CloudflareAccessFailure.BadSignature, (await v.ValidateAsync($"{parts[0]}.{tamperedPayload}.{parts[2]}")).Failure);
        using var other = RSA.Create(2048);
        Assert.Equal(CloudflareAccessFailure.BadSignature, (await v.ValidateAsync(_team.Token(_clock, signWith: other))).Failure);     // right kid, someone else's key
        Assert.Equal(CloudflareAccessFailure.BadSignature, (await v.ValidateAsync(parts[0] + "." + parts[1] + "." + FakeTeam.B64(new byte[256]))).Failure);
    }

    [Fact]
    public async Task Issuer_must_be_the_team()
    {
        Assert.Equal(CloudflareAccessFailure.WrongIssuer, (await Validator().ValidateAsync(Token(p => p["iss"] = "https://otherteam.cloudflareaccess.com"))).Failure);
        Assert.Equal(CloudflareAccessFailure.WrongIssuer, (await Validator().ValidateAsync(Token(p => p["iss"] = FakeTeam.Domain))).Failure);     // no scheme
        Assert.Equal(CloudflareAccessFailure.WrongIssuer, (await Validator().ValidateAsync(Token(p => p.Remove("iss")))).Failure);
    }

    [Fact]
    public async Task Validity_with_clock_skew()
    {
        var v = Validator();
        Assert.Equal(CloudflareAccessFailure.MissingExpiry, (await v.ValidateAsync(Token(p => p.Remove("exp")))).Failure);
        Assert.Equal(CloudflareAccessFailure.MissingExpiry, (await v.ValidateAsync(Token(p => p["exp"] = "tomorrow"))).Failure);
        Assert.True((await v.ValidateAsync(Token(p => p["exp"] = _clock.Unix(TimeSpan.FromSeconds(-30))))).Ok);                  // expired 30 s ago: inside the 60 s skew
        Assert.Equal(CloudflareAccessFailure.Expired, (await v.ValidateAsync(Token(p => p["exp"] = _clock.Unix(TimeSpan.FromSeconds(-90))))).Failure);
        Assert.True((await v.ValidateAsync(Token(p => p["nbf"] = _clock.Unix(TimeSpan.FromSeconds(30))))).Ok);
        Assert.Equal(CloudflareAccessFailure.NotYetValid, (await v.ValidateAsync(Token(p => p["nbf"] = _clock.Unix(TimeSpan.FromMinutes(5))))).Failure);
        _clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(CloudflareAccessFailure.Expired, (await v.ValidateAsync(Token(p => p["exp"] = _clock.Unix(TimeSpan.FromHours(-1))))).Failure);
        var strict = Validator(o => o.ClockSkew = TimeSpan.Zero);
        Assert.Equal(CloudflareAccessFailure.Expired, (await strict.ValidateAsync(Token(p => p["exp"] = _clock.Unix(TimeSpan.FromSeconds(-1))))).Failure);
    }

    [Theory]
    [InlineData("evil.com")]
    [InlineData("https://myteam.cloudflareaccess.com")]
    [InlineData("myteam.cloudflareaccess.com/certs")]
    [InlineData("myteam.cloudflareaccess.com:8443")]
    [InlineData("cloudflareaccess.com.evil.com")]
    [InlineData("evil.com#.cloudflareaccess.com")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("localhost")]
    [InlineData("")]
    [InlineData("my team.cloudflareaccess.com")]
    [InlineData("-bad.cloudflareaccess.com")]
    public async Task A_team_domain_that_could_point_the_server_elsewhere_is_never_used(string domain)
    {
        var v = Validator();
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => v.ValidateAsync(Token(), domain, [FakeTeam.Aud]));
        Assert.Equal(0, _team.Fetches);
        Assert.NotNull(new CloudflareAccessJwtOptions { TeamDomain = domain, Audiences = [FakeTeam.Aud] }.Validate());
    }

    [Fact]
    public async Task Case_is_ignored_and_a_custom_domain_needs_a_switch()
    {
        Assert.True((await Validator().ValidateAsync(Token(), "MyTeam.CloudflareAccess.com", [FakeTeam.Aud])).Ok);
        Assert.False(CloudflareAccessJwtOptions.ValidTeamDomain("access.example.com", false));
        Assert.True(CloudflareAccessJwtOptions.ValidTeamDomain("access.example.com", true));
        Assert.False(CloudflareAccessJwtOptions.ValidTeamDomain("192.168.0.1", true));
        Assert.False(CloudflareAccessJwtOptions.ValidTeamDomain("1.2.3.4", true));
    }

    [Fact]
    public async Task Audiences_and_configuration_are_checked()
    {
        var v = Validator();
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => v.ValidateAsync(Token(), FakeTeam.Domain, []));
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => v.ValidateAsync(Token(), FakeTeam.Domain, [" "]));
        var unconfigured = new CloudflareAccessJwtValidator(new CloudflareAccessJwtOptions(), _team.FetchAsync, _clock);
        Assert.Equal(CloudflareAccessFailure.NotConfigured, (await unconfigured.ValidateAsync(Token())).Failure);
        Assert.Null(new CloudflareAccessJwtOptions().Validate());                                                       // off is fine
        Assert.NotNull(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain }.Validate());                    // domain without audience
        Assert.NotNull(new CloudflareAccessJwtOptions { Audiences = [FakeTeam.Aud] }.Validate());
        Assert.NotNull(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud], MinKeyBits = 1024 }.Validate());
        Assert.NotNull(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud], ClockSkew = TimeSpan.FromHours(1) }.Validate());
        Assert.Null(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud] }.Validate());
    }

    // ---- the key cache ----

    [Fact]
    public async Task Keys_are_fetched_once_and_cached()
    {
        var v = Validator();
        for (var i = 0; i < 5; i++) Assert.True((await v.ValidateAsync(Token())).Ok);
        Assert.Equal(1, _team.Fetches);
        _clock.Advance(TimeSpan.FromMinutes(61));
        Assert.True((await v.ValidateAsync(Token())).Ok);
        Assert.Equal(2, _team.Fetches);                      // the cache expired after an hour
    }

    [Fact]
    public async Task A_rotated_key_is_found_but_forged_key_ids_cannot_cause_a_flood_of_fetches()
    {
        var v = Validator();
        Assert.True((await v.ValidateAsync(Token())).Ok);
        for (var i = 0; i < 20; i++) Assert.Equal(CloudflareAccessFailure.UnknownKey, (await v.ValidateAsync(Token(header: h => h["kid"] = "forged-" + i))).Failure);
        Assert.Equal(1, _team.Fetches);                      // within 30 s: no new fetch at all

        _team.Keys["key-2"] = RSA.Create(2048);                // Cloudflare rotates
        _clock.Advance(TimeSpan.FromSeconds(31));
        Assert.True((await v.ValidateAsync(Token(kid: "key-2"))).Ok);
        Assert.Equal(2, _team.Fetches);

        for (var i = 0; i < 20; i++) await v.ValidateAsync(Token(header: h => h["kid"] = "forged-b" + i));
        Assert.Equal(2, _team.Fetches);
        _clock.Advance(TimeSpan.FromSeconds(31));
        await v.ValidateAsync(Token(header: h => h["kid"] = "forged-c"));
        Assert.Equal(3, _team.Fetches);                      // at most one fetch per 30 s
    }

    [Fact]
    public async Task Without_keys_the_check_fails_closed()
    {
        _team.FetchFails = new HttpRequestException("Cloudflare is down");
        var result = await Validator().ValidateAsync(Token());
        Assert.Equal(CloudflareAccessFailure.KeysUnavailable, result.Failure);
        Assert.False(result.Ok);
    }

    [Fact]
    public async Task Known_keys_survive_a_short_outage_but_not_a_long_one()
    {
        var v = Validator();
        Assert.True((await v.ValidateAsync(Token())).Ok);
        _team.FetchFails = new HttpRequestException("Cloudflare is down");
        _clock.Advance(TimeSpan.FromHours(2));                  // the cache time (1 h) is over, the outage begins
        Assert.True((await v.ValidateAsync(Token())).Ok);        // stale keys still work (up to 12 h)
        _clock.Advance(TimeSpan.FromHours(11));
        Assert.Equal(CloudflareAccessFailure.KeysUnavailable, (await v.ValidateAsync(Token())).Failure);   // 13 h old: too old
    }

    [Fact]
    public async Task Fail_closed_setting_does_not_use_stale_keys()
    {
        var v = Validator(o => o.MaxStaleKeyAge = TimeSpan.Zero);
        Assert.True((await v.ValidateAsync(Token())).Ok);
        _team.FetchFails = new HttpRequestException("down");
        _clock.Advance(TimeSpan.FromHours(2));
        Assert.False((await v.ValidateAsync(Token())).Ok);
    }

    [Fact]
    public async Task A_broken_key_document_is_a_failure_not_an_exception()
    {
        _team.Document = "this is not json";
        Assert.Equal(CloudflareAccessFailure.KeysUnavailable, (await Validator().ValidateAsync(Token())).Failure);
        _team.Document = """{"keys":"nope"}""";
        _clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(CloudflareAccessFailure.UnknownKey, (await Validator().ValidateAsync(Token())).Failure);
    }

    [Fact]
    public async Task Caller_cancellation_is_not_swallowed()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var v = new CloudflareAccessJwtValidator(new CloudflareAccessJwtOptions { TeamDomain = FakeTeam.Domain, Audiences = [FakeTeam.Aud] }, (_, ct) => Task.Delay(Timeout.Infinite, ct).ContinueWith(_ => "", ct), _clock);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => v.ValidateAsync(Token(), cts.Token));
    }

    [Fact]
    public async Task Probe_counts_the_usable_keys()
    {
        _team.Keys["key-2"] = RSA.Create(2048);
        Assert.Equal(2, await Validator().ProbeAsync());
        Assert.Equal(2, await Validator().ProbeAsync("MYTEAM.cloudflareaccess.com"));
        await Assert.ThrowsAsync<CloudflareConfigurationException>(() => Validator().ProbeAsync("evil.com"));
    }

    // ---- reading the key document ----

    [Fact]
    public void Only_strong_signing_RSA_keys_are_taken_from_a_key_document()
    {
        using var strong = RSA.Create(2048);
        using var weak = RSA.Create(1024);
        string Jwk(string kid, RSA rsa, string kty = "RSA", string? use = "sig")
        {
            var p = rsa.ExportParameters(false);
            return JsonSerializer.Serialize(new Dictionary<string, object?> { ["kid"] = kid, ["kty"] = kty, ["use"] = use, ["n"] = FakeTeam.B64(p.Modulus!), ["e"] = FakeTeam.B64(p.Exponent!) });
        }
        var doc = $$"""{"keys":[{{Jwk("ok", strong)}},{{Jwk("weak", weak)}},{{Jwk("ec", strong, "EC")}},{{Jwk("enc", strong, use: "enc")}},{"kid":"broken","kty":"RSA","n":"!!","e":"AQAB"},{"kty":"RSA"}]}""";
        Assert.Equal(["ok"], CloudflareAccessJwtValidator.ParseKeys(doc).Keys);
        Assert.Equal(["ok", "weak"], CloudflareAccessJwtValidator.ParseKeys(doc, 1024).Keys.Order());
        Assert.Empty(CloudflareAccessJwtValidator.ParseKeys("""{"keys":[]}"""));
        Assert.Empty(CloudflareAccessJwtValidator.ParseKeys("[]"));
    }

    [Fact]
    public void Base64Url_is_strict()
    {
        Assert.Equal([0xfb, 0xff], CloudflareAccessJwtValidator.Base64Url("-_8"));
        Assert.Throws<FormatException>(() => CloudflareAccessJwtValidator.Base64Url("ab+/"));
        Assert.Throws<FormatException>(() => CloudflareAccessJwtValidator.Base64Url("ab=="));
        Assert.Throws<FormatException>(() => CloudflareAccessJwtValidator.Base64Url("a b"));
    }

    // ---- the default way of fetching ----

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(respond(request));
    }

    [Fact]
    public async Task Key_documents_are_read_over_https_with_a_size_limit()
    {
        using var ok = new HttpClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"keys":[]}""") }));
        Assert.Equal("""{"keys":[]}""", await CloudflareAccessJwtValidator.ReadLimitedAsync(ok, "https://x.cloudflareaccess.com/cdn-cgi/access/certs", CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => CloudflareAccessJwtValidator.ReadLimitedAsync(ok, "http://x.cloudflareaccess.com/cdn-cgi/access/certs", CancellationToken.None));

        using var big = new HttpClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('x', CloudflareAccessJwtValidator.MaxKeyDocumentBytes + 5)) }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => CloudflareAccessJwtValidator.ReadLimitedAsync(big, "https://x.cloudflareaccess.com/c", CancellationToken.None));

        using var denied = new HttpClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        await Assert.ThrowsAsync<HttpRequestException>(() => CloudflareAccessJwtValidator.ReadLimitedAsync(denied, "https://x.cloudflareaccess.com/c", CancellationToken.None));
    }
}
