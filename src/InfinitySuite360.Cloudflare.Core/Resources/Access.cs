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
    public string? ClientSecret { get; init; }
    public string? Duration { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
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
}

/// <summary>Zero Trust Access: applications, policies, groups and service tokens.</summary>
public sealed class AccessClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    // ---- Applications ----
    public Task<IReadOnlyList<AccessApplication>> ListApplicationsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessApplication>(AccountPath(accountId, "access", "apps"), 50, ct);

    public Task<AccessApplication> GetApplicationAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<AccessApplication>(AccountPath(accountId, "access", "apps", appId), ct);

    public Task<AccessApplication> CreateApplicationAsync(AccessApplicationInput app, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessApplication>(AccountPath(accountId, "access", "apps"), app, ct);

    public Task<AccessApplication> UpdateApplicationAsync(string appId, AccessApplicationInput app, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessApplication>(AccountPath(accountId, "access", "apps", appId), app, ct);

    public Task DeleteApplicationAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "apps", appId), ct);

    // ---- Application policies ----
    public Task<List<AccessPolicy>> ListApplicationPoliciesAsync(string appId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<AccessPolicy>>(AccountPath(accountId, "access", "apps", appId, "policies"), ct);

    public Task<AccessPolicy> CreateApplicationPolicyAsync(string appId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessPolicy>(AccountPath(accountId, "access", "apps", appId, "policies"), policy, ct);

    public Task<AccessPolicy> UpdateApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessPolicy>(AccountPath(accountId, "access", "apps", appId, "policies", policyId), policy, ct);

    public Task DeleteApplicationPolicyAsync(string appId, string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "apps", appId, "policies", policyId), ct);

    // ---- Reusable policies ----
    public Task<IReadOnlyList<AccessPolicy>> ListPoliciesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessPolicy>(AccountPath(accountId, "access", "policies"), 50, ct);

    public Task<AccessPolicy> CreatePolicyAsync(AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessPolicy>(AccountPath(accountId, "access", "policies"), policy, ct);

    public Task DeletePolicyAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "policies", policyId), ct);

    // ---- Groups ----
    public Task<IReadOnlyList<AccessGroup>> ListGroupsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessGroup>(AccountPath(accountId, "access", "groups"), 50, ct);

    /// <summary>Creates a group that includes the given email addresses.</summary>
    public Task<AccessGroup> CreateGroupAsync(string name, IEnumerable<string> emails, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessGroup>(AccountPath(accountId, "access", "groups"), new { name, include = emails.Select(AccessRules.Email).ToList() }, ct);

    public Task<AccessGroup> UpdateGroupAsync(string groupId, string name, IEnumerable<JsonElement> include, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<AccessGroup>(AccountPath(accountId, "access", "groups", groupId), new { name, include = include.ToList() }, ct);

    public Task DeleteGroupAsync(string groupId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "groups", groupId), ct);

    // ---- Service tokens ----
    public Task<IReadOnlyList<AccessServiceToken>> ListServiceTokensAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens"), 50, ct);

    /// <summary>Creates a service token; <paramref name="duration"/> for example "8760h" (one year) or "forever".</summary>
    public Task<AccessServiceToken> CreateServiceTokenAsync(string name, string duration = "8760h", string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens"), new { name, duration }, ct);

    public Task<AccessServiceToken> RotateServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens", tokenId, "rotate"), null, ct);

    /// <summary>Extends the expiry without changing the secret.</summary>
    public Task<AccessServiceToken> RefreshServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<AccessServiceToken>(AccountPath(accountId, "access", "service_tokens", tokenId, "refresh"), null, ct);

    public Task DeleteServiceTokenAsync(string tokenId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "access", "service_tokens", tokenId), ct);

    /// <summary>Tokens that expire within the next <paramref name="withinDays"/> days.</summary>
    public static IReadOnlyList<AccessServiceToken> DueForRotation(IEnumerable<AccessServiceToken> tokens, DateTimeOffset now, int withinDays = 30) =>
        tokens.Where(t => t.DaysLeft(now) is { } d && d <= withinDays).OrderBy(t => t.ExpiresAt).ToList();
}
