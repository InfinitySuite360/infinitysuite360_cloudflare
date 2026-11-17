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

    [Obsolete("No checks and no preview: an application without policies denies everyone. Use EnsureApplicationAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessApplication> CreateApplicationAsync(AccessApplicationInput app, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessApplication>(AccountPath(accountId, "access", "apps"), app, ct);

    [Obsolete("No checks and no preview. Use EnsureApplicationAsync or the policy methods (0.8.0). Removed in 1.0.")]
    public Task<AccessApplication> UpdateApplicationAsync(string appId, AccessApplicationInput app, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessApplication>(AccountPath(accountId, "access", "apps", appId), app, ct);

    [Obsolete("Deleting an application removes the login protection of its hostname. Use RemoveApplicationAsync(appId, allowUnprotect) (0.8.0). Removed in 1.0.")]
    public Task DeleteApplicationAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "apps", appId), ct);

    // ---- Application policies ----
    public Task<List<AccessPolicy>> ListApplicationPoliciesAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<AccessPolicy>>(AccountPath(accountId, "access", "apps", appId, "policies"), ct);

    [Obsolete("No loosening check. Use AddApplicationPolicyAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessPolicy> CreateApplicationPolicyAsync(string appId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessPolicy>(AccountPath(accountId, "access", "apps", appId, "policies"), policy, ct);

    [Obsolete("No loosening check. Use ChangeApplicationPolicyAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessPolicy> UpdateApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessPolicy>(AccountPath(accountId, "access", "apps", appId, "policies", policyId), policy, ct);

    [Obsolete("Can remove the last policy of an application. Use RemoveApplicationPolicyAsync(appId, policyId, allowRemoveLast, allowLoosen) (0.8.0). Removed in 1.0.")]
    public Task DeleteApplicationPolicyAsync(string appId, string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "apps", appId, "policies", policyId), ct);

    // ---- Reusable policies ----
    public Task<IReadOnlyList<AccessPolicy>> ListPoliciesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessPolicy>(AccountPath(accountId, "access", "policies"), 50, ct);

    [Obsolete("No loosening check. Use EnsurePolicyAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessPolicy> CreatePolicyAsync(AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessPolicy>(AccountPath(accountId, "access", "policies"), policy, ct);

    [Obsolete("Can remove the last policy of applications. Use RemovePolicyAsync(policyId, allowRemoveLast, allowLoosen) (0.8.0). Removed in 1.0.")]
    public Task DeletePolicyAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "policies", policyId), ct);

    // ---- Groups ----
    public Task<IReadOnlyList<AccessGroup>> ListGroupsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessGroup>(AccountPath(accountId, "access", "groups"), 50, ct);

    /// <summary>Creates a group that includes the given email addresses.</summary>
    [Obsolete("No checks and no preview. Use EnsureGroupAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessGroup> CreateGroupAsync(string name, IEnumerable<string> emails, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessGroup>(AccountPath(accountId, "access", "groups"), new { name, include = emails.Select(AccessRules.Email).ToList() }, ct);

    [Obsolete("Drops exclude/require rules and has no loosening check. Use ChangeGroupAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessGroup> UpdateGroupAsync(string groupId, string name, IEnumerable<JsonElement> include, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessGroup>(AccountPath(accountId, "access", "groups", groupId), new { name, include = include.ToList() }, ct);

    [Obsolete("No check for policies that use the group. Use RemoveGroupAsync(groupId, allowInUse) (0.8.0). Removed in 1.0.")]
    public Task DeleteGroupAsync(string groupId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "groups", groupId), ct);

    // ---- Service tokens ----
    public Task<IReadOnlyList<AccessServiceToken>> ListServiceTokensAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessServiceToken>(Api, AccountPath(accountId, "access", "service_tokens"), 50, ct);

    /// <summary>Creates a service token; <paramref name="duration"/> for example "8760h" (one year) or "forever".</summary>
    [Obsolete("Puts the client secret into a model. Use IssueServiceTokenAsync (0.8.0): the secret is only in a CloudflareOneTimeSecret. Removed in 1.0.")]
    public Task<AccessServiceToken> CreateServiceTokenAsync(string name, string duration = "8760h", string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens"), new { name, duration }, ct);

    [Obsolete("Invalidates the old secret at once and puts the new one into a model. Use RotateServiceTokenSecretAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessServiceToken> RotateServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens", tokenId, "rotate"), null, ct);

    /// <summary>Extends the expiry without changing the secret.</summary>
    public Task<AccessServiceToken> RefreshServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessServiceToken>(Api, HttpMethod.Post, AccountPath(accountId, "access", "service_tokens", tokenId, "refresh"), null, ct);

    [Obsolete("Cuts off every machine that uses the token. Use RemoveServiceTokenAsync(tokenId, allowDisconnect) (0.8.0). Removed in 1.0.")]
    public Task DeleteServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "service_tokens", tokenId), ct);

    // ---- Identity providers ----
    /// <summary>Identity providers; secret members of <c>config</c> and <c>scim_config</c> are removed (0.8.0).</summary>
    public Task<IReadOnlyList<AccessIdentityProvider>> ListIdentityProvidersAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessIdentityProvider>(Api, AccountPath(accountId, "access", "identity_providers"), 50, ct);

    public Task<AccessIdentityProvider> GetIdentityProviderAsync(string providerId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Get, AccountPath(accountId, "access", "identity_providers", providerId), null, ct);

    /// <summary>Creates an identity provider. <paramref name="config"/> depends on the type (for example <c>new { }</c> for "onetimepin").</summary>
    [Obsolete("No preview (the config carries the client secret). Use EnsureIdentityProviderAsync (0.8.0). Removed in 1.0.")]
    public Task<AccessIdentityProvider> CreateIdentityProviderAsync(string name, string type, object? config = null, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Post, AccountPath(accountId, "access", "identity_providers"), new { name, type, config = config ?? new { } }, ct);

    /// <summary>Replaces an identity provider (PUT: send the complete configuration).</summary>
    [Obsolete("No preview. Use EnsureIdentityProviderAsync or the OpenApi client (0.8.0). Removed in 1.0.")]
    public Task<AccessIdentityProvider> UpdateIdentityProviderAsync(string providerId, string name, string type, object? config = null, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Put, AccountPath(accountId, "access", "identity_providers", providerId), new { name, type, config = config ?? new { } }, ct);

    [Obsolete("Can remove the last login method. Use RemoveIdentityProviderAsync(providerId, allowRemoveLast) (0.8.0). Removed in 1.0.")]
    public Task DeleteIdentityProviderAsync(string providerId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "identity_providers", providerId), ct);

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
