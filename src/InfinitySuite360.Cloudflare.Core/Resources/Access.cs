using System.ComponentModel;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class AccessApplication : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Domain { get; init; }
    /// <summary>For example "self_hosted", "saas", "ssh", "vnc", "app_launcher".</summary>
    public string Type { get; init; } = "";
    /// <summary>Audience tag (AUD) used to validate the Access JWT at the origin.</summary>
    public string? Aud { get; init; }
    public string? SessionDuration { get; init; }
    public List<string> SelfHostedDomains { get; init; } = [];
    /// <summary>Identity providers allowed for this application (empty: all of them).</summary>
    public List<string> AllowedIdps { get; init; } = [];
    public List<JsonElement> Policies { get; init; } = [];
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

public sealed class AccessApplicationInput
{
    public required string Name { get; init; }
    public required string Domain { get; init; }
    public string Type { get; init; } = "self_hosted";
    public string SessionDuration { get; init; } = "24h";
    public bool? AppLauncherVisible { get; init; }
    public bool? AutoRedirectToIdentity { get; init; }
    public List<string>? AllowedIdps { get; init; }
    /// <summary>IDs of reusable policies (or policy objects).</summary>
    public List<object>? Policies { get; init; }
}

public sealed class AccessPolicy : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"allow", "deny", "non_identity", "bypass".</summary>
    public string Decision { get; init; } = "";
    public List<JsonElement> Include { get; init; } = [];
    public List<JsonElement> Exclude { get; init; } = [];
    public List<JsonElement> Require { get; init; } = [];
    public int? Precedence { get; init; }
    public string? SessionDuration { get; init; }
}

public sealed class AccessPolicyInput
{
    public required string Name { get; init; }
    public string Decision { get; init; } = "allow";
    public required List<JsonElement> Include { get; init; }
    public List<JsonElement>? Exclude { get; init; }
    public List<JsonElement>? Require { get; init; }
    public int? Precedence { get; init; }
    public string? SessionDuration { get; init; }
}

public sealed class AccessGroup : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public List<JsonElement> Include { get; init; } = [];
    public List<JsonElement> Exclude { get; init; } = [];
    public List<JsonElement> Require { get; init; } = [];
}

public sealed class AccessServiceToken : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string ClientId { get; init; } = "";
    /// <summary>Only returned on create/rotate; store it securely right away.</summary>
    [Obsolete("The client secret belongs in a CloudflareOneTimeSecret. Use IssueServiceTokenAsync/RotateServiceTokenSecretAsync (0.8.0), which never put it into a model. Removed in 1.0.")]
    public string? ClientSecret { get; init; }
    public string? Duration { get; init; }
    public bool? Enabled { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? LastSeenAt { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }

    public int? DaysLeft(DateTimeOffset now) => ExpiresAt is { } e ? (int)Math.Floor((e - now).TotalDays) : null;
}

/// <summary>Building blocks for include/exclude/require rules of Access policies and groups.</summary>
public static class AccessRules
{
    private static JsonElement E(object o) => JsonSerializer.SerializeToElement(o);
    public static JsonElement Everyone() => E(new { everyone = new { } });
    public static JsonElement Email(string email) => E(new { email = new { email } });
    public static JsonElement EmailDomain(string domain) => E(new { email_domain = new { domain } });
    public static JsonElement Group(string groupId) => E(new { group = new { id = groupId } });
    public static JsonElement Country(string isoCode) => E(new { geo = new { country_code = isoCode } });
    public static JsonElement IpRange(string cidr) => E(new { ip = new { ip = cidr } });
    public static JsonElement ServiceToken(string tokenId) => E(new { service_token = new { token_id = tokenId } });
    public static JsonElement AnyValidServiceToken() => E(new { any_valid_service_token = new { } });
    public static JsonElement Mfa() => E(new { auth_method = new { auth_method = "mfa" } });
    public static JsonElement DevicePosture(string integrationUid) => E(new { device_posture = new { integration_uid = integrationUid } });
    /// <summary>Requires a valid client certificate (mTLS, see <c>AccessClient.EnsureCertificateAsync</c>).</summary>
    public static JsonElement ValidCertificate() => E(new { certificate = new { } });
}

/// <summary>An identity provider of Zero Trust (Google, GitHub, one-time PIN, SAML, OIDC, …).</summary>
public sealed class AccessIdentityProvider : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>For example "onetimepin", "google", "github", "azureAD", "saml", "oidc".</summary>
    public string Type { get; init; } = "";
    /// <summary>Provider settings without secrets (since 0.8.0 <c>client_secret</c> and other secret members are removed from the answer).</summary>
    public JsonElement? Config { get; init; }
    public JsonElement? ScimConfig { get; init; }
}

/// <summary>An entry of the Access request log (who tried to reach which application, allowed or not).</summary>
public sealed class AccessRequestLog : CloudflareModel
{
    public string? Action { get; init; }
    public bool Allowed { get; init; }
    public string? AppDomain { get; init; }
    public string? AppUid { get; init; }
    public string? Connection { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public string? IpAddress { get; init; }
    public string? RayId { get; init; }
    public string? UserEmail { get; init; }
}

/// <summary>
/// Zero Trust Access: applications, policies, groups, service tokens, identity providers, mTLS certificates, organization, users and request logs.
/// The guarded methods of 0.8.0 (<c>Ensure…</c>, <c>Change…</c>, <c>Remove…</c>, <c>Issue…</c>) are in <c>Access.ZeroTrust.cs</c>; the older unguarded
/// write methods here are <see cref="ObsoleteAttribute">obsolete</see>.
/// </summary>
public sealed partial class AccessClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    // ---- Applications ----
    public Task<IReadOnlyList<AccessApplication>> ListApplicationsAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessApplication>(Api, AccountPath(accountId, "access", "apps"), 50, ct);

    public Task<AccessApplication> GetApplicationAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessApplication>(Api, HttpMethod.Get, AccountPath(accountId, "access", "apps", appId), null, ct);

    // M7 (0.8.1): the obsolete write methods below no longer write unguarded. Each one either goes through its guarded replacement with every allow
    // switch off (so a risky call is refused locally and names the switch), or is always refused where the old signature cannot be made safe (it would
    // put a secret into a model or replace an object without a check). None of them returns a secret.

    /// <summary>Since 0.8.1 the checks of <see cref="EnsureApplicationAsync"/> (policy required, inline policies validated, referenced policies read) and a POST.</summary>
    [Obsolete("Use EnsureApplicationAsync (0.8.0). Since 0.8.1 this applies the same checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task<AccessApplication> CreateApplicationAsync(AccessApplicationInput app, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps");
        EnsureWritable(HttpMethod.Post, path);
        var (body, _) = AppBody(app, allowNoPolicy: false, allowLoosen: false, allowBlock: false);
        await CheckReferencedPoliciesAsync(app, allowLoosen: false, accountId, ct).ConfigureAwait(false);
        return await ZT.SendAsync<AccessApplication>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false);
    }

    /// <summary>Always refused since 0.8.1: a full replacement can drop the policies or the login of an application without any check.</summary>
    [Obsolete("Always refused since 0.8.1. Use EnsureApplicationAsync and the policy methods, or the OpenApi client deliberately. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessApplication> UpdateApplicationAsync(string appId, AccessApplicationInput app, string? accountId = null, CancellationToken ct = default)
    {
        EnsureWritable(HttpMethod.Put, AccountPath(accountId, "access", "apps", appId));
        return Task.FromException<AccessApplication>(AlwaysRefused("UpdateApplicationAsync", "replacing an application can drop its policies and login protection", "EnsureApplicationAsync and the policy methods"));
    }

    /// <summary>Since 0.8.1 <see cref="RemoveApplicationAsync"/> without <c>allowUnprotect</c>: always refused.</summary>
    [Obsolete("Always refused since 0.8.1. Use RemoveApplicationAsync(appId, allowUnprotect: true) (0.8.0). Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteApplicationAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveApplicationAsync(appId, allowUnprotect: false, accountId, ct).ConfigureAwait(false);

    // ---- Application policies ----
    public Task<List<AccessPolicy>> ListApplicationPoliciesAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<AccessPolicy>>(AccountPath(accountId, "access", "apps", appId, "policies"), ct);

    /// <summary>Since 0.8.1 <see cref="AddApplicationPolicyAsync"/> with every allow switch off.</summary>
    [Obsolete("Use AddApplicationPolicyAsync (0.8.0); since 0.8.1 this applies its checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessPolicy> CreateApplicationPolicyAsync(string appId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        AddApplicationPolicyAsync(appId, policy, allowLoosen: false, allowBlock: false, accountId, ct);

    /// <summary>Since 0.8.1 <see cref="ChangeApplicationPolicyAsync"/> with every allow switch off.</summary>
    [Obsolete("Use ChangeApplicationPolicyAsync (0.8.0); since 0.8.1 this applies its checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task<AccessPolicy> UpdateApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        (await ChangeApplicationPolicyAsync(appId, policyId, policy, allowLoosen: false, allowBlock: false, accountId, ct).ConfigureAwait(false)).Policy;

    /// <summary>Since 0.8.1 <see cref="RemoveApplicationPolicyAsync"/> with every allow switch off.</summary>
    [Obsolete("Use RemoveApplicationPolicyAsync(appId, policyId, allowRemoveLast, allowLoosen) (0.8.0); since 0.8.1 this applies its checks with every switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteApplicationPolicyAsync(string appId, string policyId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveApplicationPolicyAsync(appId, policyId, allowRemoveLast: false, allowLoosen: false, accountId, ct).ConfigureAwait(false);

    // ---- Reusable policies ----
    public Task<IReadOnlyList<AccessPolicy>> ListPoliciesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessPolicy>(AccountPath(accountId, "access", "policies"), 50, ct);

    /// <summary>Since 0.8.1 the checks of <see cref="EnsurePolicyAsync"/> with every allow switch off, then a POST.</summary>
    [Obsolete("Use EnsurePolicyAsync (0.8.0); since 0.8.1 this applies its checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessPolicy> CreatePolicyAsync(AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "policies");
        EnsureWritable(HttpMethod.Post, path);
        return Api.PostAsync<AccessPolicy>(path, PolicyBody(policy, allowLoosen: false, allowBlock: false, null), ct);
    }

    /// <summary>Since 0.8.1 <see cref="RemovePolicyAsync"/> with every allow switch off.</summary>
    [Obsolete("Use RemovePolicyAsync(policyId, allowRemoveLast, allowLoosen) (0.8.0); since 0.8.1 this applies its checks with every switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeletePolicyAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        await RemovePolicyAsync(policyId, allowRemoveLast: false, allowLoosen: false, accountId, ct).ConfigureAwait(false);

    // ---- Groups ----
    public Task<IReadOnlyList<AccessGroup>> ListGroupsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessGroup>(AccountPath(accountId, "access", "groups"), 50, ct);

    /// <summary>Creates a group that includes the given email addresses (since 0.8.1 with the checks of <see cref="EnsureGroupAsync"/>).</summary>
    [Obsolete("Use EnsureGroupAsync (0.8.0); since 0.8.1 this applies its checks with every allow switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessGroup> CreateGroupAsync(string name, IEnumerable<string> emails, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups");
        EnsureWritable(HttpMethod.Post, path);
        var body = GroupBody(new AccessGroupInput { Name = name, Include = emails.Select(AccessRules.Email).ToList() }, allowLoosen: false, null);
        return Api.PostAsync<AccessGroup>(path, body, ct);
    }

    /// <summary>
    /// Since 0.8.1 <see cref="ChangeGroupAsync"/> with every switch off: the old signature has no exclude/require rules, so a group that has some is
    /// refused (removing them loosens), and a group in use is refused.
    /// </summary>
    [Obsolete("Use ChangeGroupAsync (0.8.0); since 0.8.1 this applies its checks with every switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task<AccessGroup> UpdateGroupAsync(string groupId, string name, IEnumerable<JsonElement> include, string? accountId = null, CancellationToken ct = default) =>
        (await ChangeGroupAsync(groupId, new AccessGroupInput { Name = name, Include = include.ToList() }, allowLoosen: false, accountId, allowInUse: false, ct).ConfigureAwait(false)).Group;

    /// <summary>Since 0.8.1 <see cref="RemoveGroupAsync"/> without <c>allowInUse</c>.</summary>
    [Obsolete("Use RemoveGroupAsync(groupId, allowInUse) (0.8.0); since 0.8.1 this applies its checks with the switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteGroupAsync(string groupId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveGroupAsync(groupId, allowInUse: false, accountId, ct).ConfigureAwait(false);

    // ---- Service tokens ----
    public Task<IReadOnlyList<AccessServiceToken>> ListServiceTokensAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessServiceToken>(Api, AccountPath(accountId, "access", "service_tokens"), 50, ct);

    /// <summary>Always refused since 0.8.1: the old return type would carry the client secret in a model.</summary>
    [Obsolete("Always refused since 0.8.1. Use IssueServiceTokenAsync (0.8.0): the secret is only in a CloudflareOneTimeSecret. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessServiceToken> CreateServiceTokenAsync(string name, string duration = "8760h", string? accountId = null, CancellationToken ct = default)
    {
        EnsureWritable(HttpMethod.Post, AccountPath(accountId, "access", "service_tokens"));
        return Task.FromException<AccessServiceToken>(AlwaysRefused("CreateServiceTokenAsync", "its result would carry the client secret in a model", "IssueServiceTokenAsync"));
    }

    /// <summary>Always refused since 0.8.1: it invalidated the old secret at once and put the new one into a model.</summary>
    [Obsolete("Always refused since 0.8.1. Use RotateServiceTokenSecretAsync (0.8.0). Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessServiceToken> RotateServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default)
    {
        EnsureWritable(HttpMethod.Post, AccountPath(accountId, "access", "service_tokens", tokenId, "rotate"));
        return Task.FromException<AccessServiceToken>(AlwaysRefused("RotateServiceTokenAsync", "it invalidates the old secret at once and its result would carry the new secret in a model", "RotateServiceTokenSecretAsync"));
    }

    private static InvalidOperationException AlwaysRefused(string method, string why, string replacement) =>
        new($"Refused: {method} is obsolete and always refused since 0.8.1 ({why}). Use {replacement}.");

    /// <summary>Extends the expiry without changing the secret.</summary>
    public Task<AccessServiceToken> RefreshServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessServiceToken>(Api, HttpMethod.Post, AccountPath(accountId, "access", "service_tokens", tokenId, "refresh"), null, ct);

    /// <summary>Since 0.8.1 <see cref="RemoveServiceTokenAsync"/> without <c>allowDisconnect</c>.</summary>
    [Obsolete("Use RemoveServiceTokenAsync(tokenId, allowDisconnect) (0.8.0); since 0.8.1 this applies its checks with the switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveServiceTokenAsync(tokenId, allowDisconnect: false, accountId, ct).ConfigureAwait(false);

    // ---- Identity providers ----
    /// <summary>Identity providers; secret members of <c>config</c> and <c>scim_config</c> are removed (0.8.0).</summary>
    public Task<IReadOnlyList<AccessIdentityProvider>> ListIdentityProvidersAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessIdentityProvider>(Api, AccountPath(accountId, "access", "identity_providers"), 50, ct);

    public Task<AccessIdentityProvider> GetIdentityProviderAsync(string providerId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Get, AccountPath(accountId, "access", "identity_providers", providerId), null, ct);

    /// <summary>Creates an identity provider (since 0.8.1 write guard first, type checked, secrets stripped from the answer).</summary>
    [Obsolete("Use EnsureIdentityProviderAsync (0.8.0); since 0.8.1 this checks the write guard and the type first. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessIdentityProvider> CreateIdentityProviderAsync(string name, string type, object? config = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "identity_providers");
        EnsureWritable(HttpMethod.Post, path);
        return ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Post, path, IdpBody(name, type, config), ct);
    }

    /// <summary>Always refused since 0.8.1: a full replacement of a login method without any check can lock everybody out.</summary>
    [Obsolete("Always refused since 0.8.1. Use the OpenApi client deliberately. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public Task<AccessIdentityProvider> UpdateIdentityProviderAsync(string providerId, string name, string type, object? config = null, string? accountId = null, CancellationToken ct = default)
    {
        EnsureWritable(HttpMethod.Put, AccountPath(accountId, "access", "identity_providers", providerId));
        return Task.FromException<AccessIdentityProvider>(AlwaysRefused("UpdateIdentityProviderAsync", "replacing a login method without a check can lock everybody out", "the OpenApi client deliberately"));
    }

    /// <summary>Since 0.8.1 <see cref="RemoveIdentityProviderAsync"/> without <c>allowRemoveLast</c>.</summary>
    [Obsolete("Use RemoveIdentityProviderAsync(providerId, allowRemoveLast) (0.8.0); since 0.8.1 this applies its checks with the switch off. Removed in 1.0.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public async Task DeleteIdentityProviderAsync(string providerId, string? accountId = null, CancellationToken ct = default) =>
        await RemoveIdentityProviderAsync(providerId, allowRemoveLast: false, accountId, ct).ConfigureAwait(false);

    // ---- Request logs ----
    /// <summary>Latest Access request log entries (newest first by default).</summary>
    public async Task<List<AccessRequestLog>> ListRequestLogsAsync(DateTimeOffset? since = null, DateTimeOffset? until = null, int limit = 100, bool newestFirst = true,
        string? userEmail = null, string? rayId = null, string? appDomain = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "access", "logs", "access_requests"),
            ("limit", Math.Clamp(limit, 1, 1000).ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("direction", newestFirst ? "desc" : "asc"),
            ("since", since?.ToUniversalTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture)),
            ("until", until?.ToUniversalTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture)),
            ("user_email", userEmail), ("ray_id", rayId), ("app_domain", appDomain));
        return await Api.GetAsync<List<AccessRequestLog>>(path, ct).ConfigureAwait(false) ?? [];
    }

    /// <summary>Tokens that expire within the next <paramref name="withinDays"/> days.</summary>
    public static IReadOnlyList<AccessServiceToken> DueForRotation(IEnumerable<AccessServiceToken> tokens, DateTimeOffset now, int withinDays = 30) =>
        tokens.Where(t => t.DaysLeft(now) is { } d && d <= withinDays).OrderBy(t => t.ExpiresAt).ToList();
}
