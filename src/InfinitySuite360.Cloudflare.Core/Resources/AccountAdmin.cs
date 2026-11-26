using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A domain registered with Cloudflare Registrar.</summary>
public sealed class DomainRegistration : CloudflareModel
{
    public string DomainName { get; init; } = "";
    /// <summary>For example "active", "registration_pending", "transfer_pending", "expired".</summary>
    public string? Status { get; init; }
    public bool? AutoRenew { get; init; }
    /// <summary>Registrar lock (transfer protection).</summary>
    public bool? Locked { get; init; }
    /// <summary>"off" or "redaction" (WHOIS redaction).</summary>
    public string? PrivacyMode { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>
/// Cloudflare Registrar, narrow wrapper (0.9.0, matrix priority 3): list and read registrations and their status; switch auto-renew with preview
/// (switching it off needs <c>allowDisableAutoRenew</c>, because the domain then expires). Registering, transferring in and domain search are
/// deliberately only reachable through <c>OpenApi</c>: they cost money and need the registrant's contact data. Endpoints
/// <c>registrar-domain-registration-*</c> of cloudflare/api-schemas@650bd71. Tariff (developers.cloudflare.com/registrar/about/, retrieved 17.11.2026):
/// at-cost prices of the registry and ICANN, no mark-up.
/// </summary>
public sealed class RegistrarClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>All registrations of the account (cursor paging).</summary>
    public Task<IReadOnlyList<DomainRegistration>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListAllSecretFreeAsync<DomainRegistration>(Api, AccountPath(accountId, "registrar", "registrations"), 50, ct);

    /// <summary>One registration; null when the domain is not registered with this account.</summary>
    public Task<DomainRegistration?> GetAsync(string domainName, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeOrNullAsync<DomainRegistration>(Api, Path(accountId, domainName), ct);

    /// <summary>Progress of a registration (state, error, links) as Cloudflare returns it.</summary>
    public Task<JsonElement> GetRegistrationStatusAsync(string domainName, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.SecretFreeResultAsync(Api, HttpMethod.Get, Path(accountId, domainName) + "/registration-status", null, ct);

    /// <summary>What <see cref="SetAutoRenewAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewSetAutoRenew(string domainName, bool autoRenew, string? accountId = null) =>
        Preview(HttpMethod.Patch, Path(accountId, domainName), new { auto_renew = autoRenew },
            autoRenew ? $"Switch auto-renew on for {domainName}." : $"Switch auto-renew off for {domainName}. WARNING: the domain expires at the end of its term unless renewed by hand.");

    /// <summary>Switches auto-renew. Off needs <paramref name="allowDisableAutoRenew"/> (the domain would expire). Write guard first.</summary>
    public Task<JsonElement> SetAutoRenewAsync(string domainName, bool autoRenew, string? accountId = null, bool allowDisableAutoRenew = false, CancellationToken ct = default) =>
        GuardedWriteAsync<JsonElement>(HttpMethod.Patch, Path(accountId, domainName), new { auto_renew = autoRenew }, ct,
            autoRenew || allowDisableAutoRenew, $"switching auto-renew off lets {domainName} expire", nameof(allowDisableAutoRenew));

    private string Path(string? accountId, string domainName) =>
        AccountPath(accountId, "registrar", "registrations", ResourceKit.Hostname(domainName, nameof(domainName)));
}

/// <summary>A member of an account (no personal data beyond name, e-mail and two-factor flag that Cloudflare returns).</summary>
public sealed class AccountMember : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Email { get; init; }
    /// <summary>"accepted" or "pending".</summary>
    public string? Status { get; init; }
    public List<AccountRole> Roles { get; init; } = [];
    public AccountMemberUser? User { get; init; }
}

/// <summary>The user behind a membership.</summary>
public sealed class AccountMemberUser : CloudflareModel
{
    public string? Id { get; init; }
    public string? Email { get; init; }
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public bool? TwoFactorAuthenticationEnabled { get; init; }
}

/// <summary>A role of an account.</summary>
public sealed class AccountRole : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Description { get; init; }
}

/// <summary>
/// Account members and roles, narrow wrapper (0.9.0, matrix priority 3): list and read members and roles; remove a member with preview and
/// <c>allowRemoval</c>; removing the last member with a role whose name contains "Super Administrator" is refused (lock-out). Inviting members and changing
/// roles are deliberately only reachable through <c>OpenApi</c>: an invitation sends an e-mail to a person, and role changes are the account's access control,
/// which belongs in the dashboard with its own confirmation. Endpoints <c>account-members-*</c>, <c>account-roles-*</c> of cloudflare/api-schemas@650bd71;
/// developers.cloudflare.com/fundamentals/manage-members/manage/ (retrieved 17.11.2026).
/// </summary>
public sealed class MembersClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<AccountMember>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListAllSecretFreeAsync<AccountMember>(Api, AccountPath(accountId, "members"), 50, ct);

    public Task<AccountMember?> GetAsync(string memberId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeOrNullAsync<AccountMember>(Api, AccountPath(accountId, "members", ResourceKit.Required(memberId, nameof(memberId))), ct);

    public Task<IReadOnlyList<AccountRole>> ListRolesAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListAllSecretFreeAsync<AccountRole>(Api, AccountPath(accountId, "roles"), 50, ct);

    /// <summary>What <see cref="RemoveAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewRemove(string memberId, string? accountId = null) =>
        Preview(HttpMethod.Delete, AccountPath(accountId, "members", ResourceKit.Required(memberId, nameof(memberId))), null,
            $"Remove member {memberId} from the account. The person loses access at once.");

    /// <summary>
    /// Removes a member (write guard first, then <paramref name="allowRemoval"/>; then the member list is read and the last super administrator is never
    /// removed). False when the member did not exist.
    /// </summary>
    public async Task<bool> RemoveAsync(string memberId, string? accountId = null, bool allowRemoval = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "members", ResourceKit.Required(memberId, nameof(memberId)));
        EnsureWritable(HttpMethod.Delete, path);
        ResourceKit.Allow(allowRemoval, "removing a member ends the person's access", nameof(allowRemoval));
        var members = await ListAsync(accountId, ct).ConfigureAwait(false);
        static bool Super(AccountMember m) => m.Roles.Any(r => (r.Name ?? "").Contains("Super Administrator", StringComparison.OrdinalIgnoreCase));
        var target = members.FirstOrDefault(m => m.Id == memberId);
        if (target is null) return false;
        if (Super(target) && members.Count(Super) <= 1)
            throw ResourceKit.Conflict("DELETE", path, "Refused: this is the last super administrator of the account (lock-out).");
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }
}

/// <summary>An entry of the account audit log (v2).</summary>
public sealed class AuditLogV2Entry : CloudflareModel
{
    public string Id { get; init; } = "";
    public JsonElement? Action { get; init; }
    public JsonElement? Actor { get; init; }
    public JsonElement? Resource { get; init; }
    public JsonElement? Zone { get; init; }
}

/// <summary>
/// Audit logs, read-only (0.9.0, matrix priority 3): the account audit log v2 (<c>accounts/{id}/logs/audit</c>, cursor paging, period required); the older
/// v1 log stays in <see cref="MonitoringClient"/>. Request and response bodies that an entry carries pass through the secret rule (secret-looking members
/// removed). Endpoint <c>audit-logs-v2-get-account-audit-logs</c> of cloudflare/api-schemas@650bd71. Retention
/// (developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/, retrieved 17.11.2026): 18 months; longer only via Logpush (Enterprise).
/// </summary>
public sealed class AuditLogsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Entries between <paramref name="since"/> and <paramref name="before"/> (v2; at most <paramref name="maxItems"/>).</summary>
    public async Task<IReadOnlyList<AuditLogV2Entry>> ListAsync(DateTimeOffset since, DateTimeOffset before, string? accountId = null, string? actorEmail = null,
        int maxItems = 1000, CancellationToken ct = default)
    {
        if (before <= since) throw new ArgumentException("before must be after since.", nameof(before));
        if (maxItems < 1) throw new ArgumentOutOfRangeException(nameof(maxItems));
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "logs", "audit"),
            ("since", since.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture)),
            ("before", before.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture)),
            ("actor_email", actorEmail));
        var list = new List<AuditLogV2Entry>();
        await foreach (var e in Api.ListAllAsync<JsonElement>(path, 100, ct).ConfigureAwait(false))
        {
            list.Add(ResourceKit.As<AuditLogV2Entry>(ResourceKit.StripSecrets(e)));
            if (list.Count >= maxItems) break;
        }
        return list;
    }
}

/// <summary>
/// Cloudflare Radar, read-only (0.9.0, matrix priority 3): domain ranking, autonomous systems and the raw form for any other Radar dataset. Radar is not
/// account-bound; the token needs "Account → Radar → Read" (developers.cloudflare.com/radar/get-started/first-request/, retrieved 17.11.2026). The 279 Radar
/// operations of cloudflare/api-schemas@650bd71 are reachable through <c>OpenApi</c>; this wrapper types the ones a security dashboard uses.
/// </summary>
public sealed class RadarClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Ranking details of a domain (rank, bucket, categories) as Cloudflare returns them.</summary>
    public Task<JsonElement> GetDomainRankingAsync(string domain, CancellationToken ct = default) =>
        ResourceKit.ResultAsync(Api, HttpMethod.Get, CloudflarePath.Of("radar", "ranking", "domain", ResourceKit.Hostname(domain, nameof(domain))), null, ct);

    /// <summary>An autonomous system by number.</summary>
    public Task<JsonElement> GetAsnAsync(int asn, CancellationToken ct = default)
    {
        if (asn is < 1) throw new ArgumentOutOfRangeException(nameof(asn));
        return ResourceKit.ResultAsync(Api, HttpMethod.Get, CloudflarePath.Of("radar", "entities", "asns", asn.ToString(System.Globalization.CultureInfo.InvariantCulture)), null, ct);
    }

    /// <summary>
    /// Any other Radar dataset below <c>radar/</c> (for example <c>http/summary/device_type</c>) with query parameters; GET only. The path is checked like
    /// every other path (no dot segments).
    /// </summary>
    public Task<JsonElement> GetAsync(string dataset, IEnumerable<KeyValuePair<string, string?>>? query = null, CancellationToken ct = default)
    {
        var segments = ResourceKit.Required(dataset, nameof(dataset)).Trim('/').Split('/');
        return ResourceKit.ResultAsync(Api, HttpMethod.Get, CloudflarePath.WithQuery(CloudflarePath.Of(["radar", .. segments]), query), null, ct);
    }
}
