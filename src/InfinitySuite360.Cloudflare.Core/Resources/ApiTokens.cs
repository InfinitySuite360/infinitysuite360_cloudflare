using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Who owns an API token: the user (<c>user/tokens</c>) or an account (<c>accounts/{id}/tokens</c>, account-owned tokens).</summary>
public enum ApiTokenOwner
{
    User,
    Account,
}

/// <summary>
/// The secret value of a newly created or rolled API token. Cloudflare shows it <b>once</b>; this object is the only place it exists in the package.
/// <see cref="ToString"/> and JSON serialization write <c>[redacted]</c>; read it with <see cref="Reveal"/> or, preferably, <see cref="TakeValue"/>,
/// which hands it over and clears this object. Store it in a secret store at once, never in logs, audit entries or exceptions.
/// </summary>
[JsonConverter(typeof(ApiTokenSecretConverter))]
public sealed class ApiTokenSecret : IDisposable
{
    private string? _value;

    internal ApiTokenSecret(string value) => _value = value;

    /// <summary>False after <see cref="TakeValue"/> or <see cref="Dispose"/>.</summary>
    public bool HasValue => _value is not null;

    /// <summary>The token value. Throws once the value was taken or disposed.</summary>
    public string Reveal() => _value ?? throw new ObjectDisposedException(nameof(ApiTokenSecret), "The token value was already taken or disposed.");

    /// <summary>Returns the value and clears it here (one-time hand-over).</summary>
    public string TakeValue()
    {
        var v = Reveal();
        _value = null;
        return v;
    }

    public void Dispose() => _value = null;

    public override string ToString() => $"ApiTokenSecret({(HasValue ? P1.Redacted : "taken")})";
}

internal sealed class ApiTokenSecretConverter : JsonConverter<ApiTokenSecret>
{
    public override ApiTokenSecret Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("API token secrets are not deserialized.");

    public override void Write(Utf8JsonWriter writer, ApiTokenSecret value, JsonSerializerOptions options) => writer.WriteStringValue(P1.Redacted);
}

/// <summary>A permission group of a token policy, for example "Zone Read" or "DNS Write".</summary>
public sealed class ApiTokenPermissionGroup : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    /// <summary>For example "com.cloudflare.api.account" or "com.cloudflare.api.account.zone".</summary>
    public List<string>? Scopes { get; init; }
}

/// <summary>A policy of a token.</summary>
public sealed class ApiTokenPolicy : CloudflareModel
{
    public string? Id { get; init; }
    /// <summary>"allow" or "deny".</summary>
    public string Effect { get; init; } = "";
    public List<ApiTokenPermissionGroup> PermissionGroups { get; init; } = [];
    /// <summary>Resources, for example <c>{"com.cloudflare.api.account.zone.&lt;zone id&gt;":"*"}</c>.</summary>
    public JsonElement? Resources { get; init; }
}

/// <summary>An API token as Cloudflare lists it. It never carries the token value (that is only in <see cref="IssuedApiToken.Secret"/>).</summary>
public sealed class ApiToken : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"active", "disabled" or "expired".</summary>
    public string Status { get; init; } = "";
    public DateTimeOffset? IssuedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
    public DateTimeOffset? LastUsedOn { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public List<ApiTokenPolicy> Policies { get; init; } = [];
    public JsonElement? Condition { get; init; }
    /// <summary>Prefix and last four characters of the value, for identification only (Cloudflare provides them for newer tokens).</summary>
    public string? TokenPrefix { get; init; }
    public string? TokenSuffix { get; init; }
}

/// <summary>Result of creating a token: its details and the secret value (shown by Cloudflare only once).</summary>
public sealed class IssuedApiToken
{
    internal IssuedApiToken(ApiToken token, ApiTokenSecret secret)
    {
        Token = token;
        Secret = secret;
    }

    public ApiToken Token { get; }
    /// <summary>The value; <see cref="ApiTokenSecret.TakeValue"/> hands it over once.</summary>
    public ApiTokenSecret Secret { get; }

    public override string ToString() => $"IssuedApiToken({Token.Id}, \"{Token.Name}\", secret {P1.Redacted})";
}

/// <summary>Resource keys of token policies.</summary>
public static class ApiTokenResources
{
    public static string Zone(string zoneId) => "com.cloudflare.api.account.zone." + P1.Required(zoneId, nameof(zoneId), 64);
    public static string Account(string accountId) => "com.cloudflare.api.account." + P1.Required(accountId, nameof(accountId), 64);
    public static string User(string userId) => "com.cloudflare.api.user." + P1.Required(userId, nameof(userId), 64);
    /// <summary>Every zone of the account (broad; needs <c>allowBroadResources</c>).</summary>
    public static JsonObject AllZonesOf(string accountId) => new() { [Account(accountId)] = new JsonObject { ["com.cloudflare.api.account.zone.*"] = "*" } };
}

/// <summary>One policy of a new token: effect, permission group ids and resources (prefer single zones or accounts).</summary>
public sealed class ApiTokenPolicyInput
{
    /// <summary>"allow" (default) or "deny".</summary>
    public string Effect { get; init; } = "allow";
    public required IReadOnlyList<string> PermissionGroupIds { get; init; }
    /// <summary>Resource key → "*" (or a nested object for "all zones of an account"), see <see cref="ApiTokenResources"/>.</summary>
    public required JsonObject Resources { get; init; }
}

/// <summary>A new or replaced token. Least privilege is checked locally: wildcard resources and tokens without expiry need an explicit opt-in.</summary>
public sealed class ApiTokenInput
{
    public required string Name { get; init; }
    public required IReadOnlyList<ApiTokenPolicyInput> Policies { get; init; }
    /// <summary>Expiry; required unless <c>allowNoExpiry: true</c>.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    /// <summary>Client IP ranges that may use the token (CIDR).</summary>
    public IReadOnlyList<string>? AllowedIps { get; init; }
    public IReadOnlyList<string>? DeniedIps { get; init; }
    /// <summary>Only for <see cref="ApiTokensClient.UpdateAsync"/>: "active" or "disabled" (null keeps it).</summary>
    public string? Status { get; init; }
}

/// <summary>
/// API token management: list, read, verify, create, update, roll, disable and revoke user and account-owned tokens, and list permission groups.
/// Sources: developers.cloudflare.com/fundamentals/api/get-started/create-token/ ("The token secret is only shown once") and …/how-to/roll-token/ (rolling invalidates the
/// old value at once), API schema operations <c>user-api-tokens-*</c> and <c>account-api-tokens-*</c> (cloudflare/api-schemas@650bd71), retrieved 17.11.2026.
/// </summary>
/// <remarks>
/// <para>Secret handling: the token value of <see cref="CreateAsync"/> and <see cref="RollAsync"/> is moved into an <see cref="ApiTokenSecret"/> before any model is
/// built, so it is neither in <see cref="ApiToken"/>, its <c>AdditionalData</c>, a preview, a <c>ToString</c> nor an exception message.</para>
/// <para>Least privilege: policies with wildcard resources (<c>….*</c>) need <c>allowBroadResources</c>; a token without expiry needs <c>allowNoExpiry</c>.</para>
/// <para>Lock-out: rolling, disabling or revoking the token this client itself uses would cut the client off; <see cref="RollAsync"/>, <see cref="SetStatusAsync"/>
/// and <see cref="RevokeAsync"/> verify the own token first and refuse unless <c>allowSelf: true</c>.</para>
/// <para>Token permission for managing tokens: "User: API Tokens: Edit" (user tokens) or "Account: Account API Tokens: Edit"; the managing token should do
/// nothing else and live shortly.</para>
/// </remarks>
public sealed class ApiTokensClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Secret = ["value"];

    public Task<IReadOnlyList<ApiToken>> ListAsync(ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default) =>
        P1.ListStrippedAsync<ApiToken>(Api, Base(owner, accountId), 50, ct, Secret);

    public Task<ApiToken> GetAsync(string tokenId, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default) =>
        P1.SendStrippedAsync<ApiToken>(Api, HttpMethod.Get, Base(owner, accountId, tokenId), null, ct, Secret);

    /// <summary>Verifies the token this client uses (id, status, expiry).</summary>
    public Task<TokenVerification> VerifyAsync(ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TokenVerification>(Base(owner, accountId, "verify"), ct);

    /// <summary>Permission groups, optionally filtered by name (contains, case-insensitive) or scope.</summary>
    public async Task<IReadOnlyList<ApiTokenPermissionGroup>> ListPermissionGroupsAsync(string? nameContains = null, string? scope = null,
        ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default)
    {
        var groups = await Api.GetAsync<List<ApiTokenPermissionGroup>>(Base(owner, accountId, "permission_groups"), ct).ConfigureAwait(false) ?? [];
        return groups.Where(g => (nameContains is null || (g.Name ?? "").Contains(nameContains, StringComparison.OrdinalIgnoreCase))
                                 && (scope is null || g.Scopes?.Contains(scope) == true)).ToList();
    }

    /// <summary>Plan of a new token (sends nothing; contains no secret).</summary>
    /// <param name="allowBroadResources">Wildcard resources (all zones, all accounts) instead of named ones.</param>
    /// <param name="allowNoExpiry">A token that never expires.</param>
    public CloudflareChangePreview PreviewCreate(ApiTokenInput token, bool allowBroadResources = false, bool allowNoExpiry = false, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null)
    {
        var (body, summary) = TokenBody(token, allowBroadResources, allowNoExpiry, includeStatus: false);
        return new("POST", Base(owner, accountId), body, $"Create API token \"{token.Name}\": {summary} The value is shown once in the result.");
    }

    /// <summary>Creates a token (POST, never retried after a server error: a retry could create a second token). The value is only in the result's <see cref="IssuedApiToken.Secret"/>.</summary>
    /// <inheritdoc cref="PreviewCreate" path="/param"/>
    public async Task<IssuedApiToken> CreateAsync(ApiTokenInput token, bool allowBroadResources = false, bool allowNoExpiry = false, ApiTokenOwner owner = ApiTokenOwner.User,
        string? accountId = null, CancellationToken ct = default)
    {
        var (body, _) = TokenBody(token, allowBroadResources, allowNoExpiry, includeStatus: false);
        var response = await Api.SendAsync<JsonElement>(HttpMethod.Post, Base(owner, accountId), body, ct).ConfigureAwait(false);
        var result = response.Result;
        if (result.ValueKind != JsonValueKind.Object || !result.TryGetProperty("value", out var v) || v.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(v.GetString()))
            throw new CloudflareApiException(HttpStatusCode.OK, "POST", CloudflarePath.Normalize(Base(owner, accountId)),
                [new CloudflareError { Message = "The answer carries no token value; the token may exist without a known value. List the tokens and revoke it." }]);
        var secret = new ApiTokenSecret(v.GetString()!);
        return new IssuedApiToken(P1.As<ApiToken>(P1.Strip(result, Secret)), secret);
    }

    public CloudflareChangePreview PreviewUpdate(string tokenId, ApiTokenInput token, bool allowBroadResources = false, bool allowNoExpiry = false, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null)
    {
        var (body, summary) = TokenBody(token, allowBroadResources, allowNoExpiry, includeStatus: true);
        return new("PUT", Base(owner, accountId, tokenId), body, $"Replace API token {tokenId} (\"{token.Name}\"): {summary}");
    }

    /// <summary>Replaces name, policies, condition, expiry and status of a token (PUT, the value stays the same).</summary>
    public Task<ApiToken> UpdateAsync(string tokenId, ApiTokenInput token, bool allowBroadResources = false, bool allowNoExpiry = false, ApiTokenOwner owner = ApiTokenOwner.User,
        string? accountId = null, CancellationToken ct = default) =>
        P1.SendStrippedAsync<ApiToken>(Api, HttpMethod.Put, Base(owner, accountId, tokenId), TokenBody(token, allowBroadResources, allowNoExpiry, includeStatus: true).Body, ct, Secret);

    /// <summary>Plan of a status change (reads the token to keep its policies).</summary>
    public async Task<CloudflareChangePreview> PreviewSetStatusAsync(string tokenId, string status, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetAsync(tokenId, owner, accountId, ct).ConfigureAwait(false);
        return new("PUT", Base(owner, accountId, tokenId), StatusBody(current, CheckStatus(status)), $"Set API token {tokenId} (\"{current.Name}\") to {status}.");
    }

    /// <summary>
    /// Disables or re-activates a token. Cloudflare's update replaces the whole token, so this reads it and sends name, policies, condition and expiry back
    /// with the new status. Disabling the token this client uses needs <paramref name="allowSelf"/>.
    /// </summary>
    public async Task<ApiToken> SetStatusAsync(string tokenId, string status, bool allowSelf = false, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default)
    {
        CheckStatus(status);
        var path = Base(owner, accountId, tokenId);
        EnsureWritable(HttpMethod.Put, path);
        if (status == "disabled") await RefuseSelfAsync(tokenId, allowSelf, "disabling", owner, accountId, ct).ConfigureAwait(false);
        var current = await GetAsync(tokenId, owner, accountId, ct).ConfigureAwait(false);
        return await P1.SendStrippedAsync<ApiToken>(Api, HttpMethod.Put, path, StatusBody(current, status), ct, Secret).ConfigureAwait(false);
    }

    public CloudflareChangePreview PreviewRoll(string tokenId, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null) =>
        new("PUT", Base(owner, accountId, tokenId, "value"), new JsonObject(),
            $"Roll API token {tokenId}: the old value stops working at once; the new value is shown once in the result.");

    /// <summary>
    /// Rolls the token: Cloudflare issues a new value and invalidates the old one at once (same permissions). The new value is only in the returned secret.
    /// Rolling the token this client uses needs <paramref name="allowSelf"/> (the client fails with the old value afterwards).
    /// </summary>
    public async Task<ApiTokenSecret> RollAsync(string tokenId, bool allowSelf = false, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default)
    {
        var path = Base(owner, accountId, tokenId, "value");
        EnsureWritable(HttpMethod.Put, path);
        await RefuseSelfAsync(tokenId, allowSelf, "rolling", owner, accountId, ct).ConfigureAwait(false);
        var response = await Api.SendAsync<JsonElement>(HttpMethod.Put, path, new JsonObject(), ct).ConfigureAwait(false);
        if (response.Result.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(response.Result.GetString()))
            throw new CloudflareApiException(HttpStatusCode.OK, "PUT", CloudflarePath.Normalize(path),
                [new CloudflareError { Message = "The answer carries no token value; the old value may already be invalid. Roll again." }]);
        return new ApiTokenSecret(response.Result.GetString()!);
    }

    public CloudflareChangePreview PreviewRevoke(string tokenId, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null) =>
        new("DELETE", Base(owner, accountId, tokenId), null, $"Revoke (delete) API token {tokenId}; every caller using it is refused at once.");

    /// <summary>Revokes (deletes) a token. True when deleted, false when it did not exist. Revoking the own token needs <paramref name="allowSelf"/>.</summary>
    public async Task<bool> RevokeAsync(string tokenId, bool allowSelf = false, ApiTokenOwner owner = ApiTokenOwner.User, string? accountId = null, CancellationToken ct = default)
    {
        var path = Base(owner, accountId, tokenId);
        EnsureWritable(HttpMethod.Delete, path);
        await RefuseSelfAsync(tokenId, allowSelf, "revoking", owner, accountId, ct).ConfigureAwait(false);
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private async Task RefuseSelfAsync(string tokenId, bool allowSelf, string what, ApiTokenOwner owner, string? accountId, CancellationToken ct)
    {
        P1.Required(tokenId, nameof(tokenId), 64);
        if (allowSelf) return;
        var self = await VerifyAsync(owner, accountId, ct).ConfigureAwait(false);
        if (string.Equals(self.Id, tokenId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Refused: {what} the token this client is using cuts the client off. Pass allowSelf: true deliberately and switch to the new token at once.");
    }

    private string Base(ApiTokenOwner owner, string? accountId, params string[] rest) =>
        owner == ApiTokenOwner.Account ? AccountPath(accountId, ["tokens", .. rest]) : CloudflarePath.Of(["user", "tokens", .. rest]);

    private static string CheckStatus(string status) =>
        status is "active" or "disabled" ? status : throw new ArgumentException("Status must be active or disabled.", nameof(status));

    private static JsonObject StatusBody(ApiToken current, string status)
    {
        var body = new JsonObject
        {
            ["name"] = current.Name,
            ["status"] = status,
            ["policies"] = new JsonArray(current.Policies.Select(p => (JsonNode?)new JsonObject
            {
                ["effect"] = p.Effect,
                ["permission_groups"] = new JsonArray(p.PermissionGroups.Select(g => (JsonNode?)new JsonObject { ["id"] = g.Id }).ToArray()),
                ["resources"] = P1.Node(p.Resources) ?? new JsonObject(),
            }).ToArray()),
        };
        if (current.ExpiresOn is { } e) body["expires_on"] = e.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        if (current.NotBefore is { } nb) body["not_before"] = nb.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        if (P1.Node(current.Condition) is { } c) body["condition"] = c;
        return body;
    }

    private static (JsonObject Body, string Summary) TokenBody(ApiTokenInput t, bool allowBroadResources, bool allowNoExpiry, bool includeStatus)
    {
        P1.Required(t.Name, nameof(t), 120);
        if (t.Policies is null || t.Policies.Count == 0) throw new ArgumentException("At least one policy is required.", nameof(t));
        if (t.ExpiresOn is null && !allowNoExpiry)
            throw new ArgumentException("Give the token an expiry (ExpiresOn); a token that never expires needs allowNoExpiry: true.", nameof(t));
        if (t.ExpiresOn is { } exp && exp <= DateTimeOffset.UtcNow) throw new ArgumentException("ExpiresOn lies in the past.", nameof(t));
        if (t.NotBefore is { } nbf && t.ExpiresOn is { } exp2 && nbf >= exp2) throw new ArgumentException("NotBefore must be before ExpiresOn.", nameof(t));

        var broad = new List<string>();
        var policies = new JsonArray();
        var groups = 0;
        foreach (var p in t.Policies)
        {
            if (p.Effect is not ("allow" or "deny")) throw new ArgumentException("Effect must be allow or deny.", nameof(t));
            if (p.PermissionGroupIds is null || p.PermissionGroupIds.Count == 0) throw new ArgumentException("A policy needs at least one permission group.", nameof(t));
            if (p.Resources is null || p.Resources.Count == 0) throw new ArgumentException("A policy needs at least one resource.", nameof(t));
            CollectBroad(p.Resources, broad);
            groups += p.PermissionGroupIds.Count;
            policies.Add(new JsonObject
            {
                ["effect"] = p.Effect,
                ["permission_groups"] = new JsonArray(p.PermissionGroupIds.Distinct().Select(id => (JsonNode?)new JsonObject { ["id"] = P1.Required(id, nameof(t), 64) }).ToArray()),
                ["resources"] = p.Resources.DeepClone(),
            });
        }
        if (broad.Count > 0 && !allowBroadResources)
            throw new ArgumentException($"Wildcard resources ({string.Join(", ", broad.Distinct())}) give the token more than it needs. Name single zones/accounts or pass allowBroadResources: true.", nameof(t));

        var body = new JsonObject { ["name"] = t.Name, ["policies"] = policies };
        if (t.ExpiresOn is { } e) body["expires_on"] = e.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        if (t.NotBefore is { } n) body["not_before"] = n.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        if (t.AllowedIps is { Count: > 0 } || t.DeniedIps is { Count: > 0 })
        {
            var ip = new JsonObject();
            if (t.AllowedIps is { Count: > 0 } a) ip["in"] = P1.Arr(a.Select(Cidr));
            if (t.DeniedIps is { Count: > 0 } d) ip["not_in"] = P1.Arr(d.Select(Cidr));
            body["condition"] = new JsonObject { ["request_ip"] = ip };
        }
        if (includeStatus && t.Status is not null) body["status"] = CheckStatus(t.Status);

        var summary = $"{t.Policies.Count} polic{(t.Policies.Count == 1 ? "y" : "ies")} with {groups} permission group(s)"
                      + (t.ExpiresOn is { } x ? $", expires {x.ToUniversalTime():yyyy-MM-dd}" : ", WARNING: never expires")
                      + (t.AllowedIps is { Count: > 0 } ? ", IP-restricted" : "")
                      + (broad.Count > 0 ? ", WARNING: wildcard resources" : "") + ".";
        return (body, summary);
    }

    private static void CollectBroad(JsonObject resources, List<string> broad)
    {
        foreach (var (key, value) in resources)
        {
            if (key.EndsWith(".*", StringComparison.Ordinal) || key == "*") broad.Add(key);
            if (value is JsonObject nested) CollectBroad(nested, broad);
        }
    }

    private static string Cidr(string value)
    {
        var v = (value ?? "").Trim();
        var slash = v.IndexOf('/');
        var address = slash < 0 ? v : v[..slash];
        if (!IPAddress.TryParse(address, out var ip) || (slash >= 0 && (!int.TryParse(v[(slash + 1)..], out var bits) || bits < 0 || bits > (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))))
            throw new ArgumentException($"\"{value}\" is not an IP address or CIDR range.", nameof(value));
        return v;
    }
}
