using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>What an IP access rule matches: <see cref="Target"/> is "ip", "ip6", "ip_range", "asn" or "country".</summary>
public sealed class IpAccessConfiguration
{
    public string Target { get; init; } = "";
    public string Value { get; init; } = "";
}

public sealed class IpAccessRule : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"block", "challenge", "whitelist", "js_challenge" or "managed_challenge".</summary>
    public string Mode { get; init; } = "";
    public IpAccessConfiguration Configuration { get; init; } = new();
    public string? Notes { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

public static class IpAccessModes
{
    public const string Block = "block";
    public const string Challenge = "challenge";
    public const string ManagedChallenge = "managed_challenge";
    public const string JsChallenge = "js_challenge";
    /// <summary>Allow (Cloudflare calls it "whitelist" in the API).</summary>
    public const string Allow = "whitelist";
}

public static class IpAccessTargets
{
    public const string Ip = "ip";
    public const string Ip6 = "ip6";
    public const string IpRange = "ip_range";
    public const string Asn = "asn";
    public const string Country = "country";
}

/// <summary>
/// IP access rules (block, challenge or allow an IP, range, ASN or country). Zone rules apply to one zone, account rules to all zones of the account.
/// They do not count against the rule limits of the WAF.
/// </summary>
public sealed class IpAccessClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    // ---- Zone ----

    public Task<IReadOnlyList<IpAccessRule>> ListAsync(string? mode = null, string? target = null, string? value = null, string? notes = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<IpAccessRule>(Query(ZonePath(zoneId, "firewall", "access_rules", "rules"), mode, target, value, notes), 50, ct);

    public Task<IpAccessRule> GetAsync(string ruleId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<IpAccessRule>(ZonePath(zoneId, "firewall", "access_rules", "rules", ruleId), ct);

    /// <summary>Creates a rule. <paramref name="target"/> see <see cref="IpAccessTargets"/>, <paramref name="mode"/> see <see cref="IpAccessModes"/>.</summary>
    public Task<IpAccessRule> CreateAsync(string mode, string target, string value, string? notes = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<IpAccessRule>(ZonePath(zoneId, "firewall", "access_rules", "rules"), Body(mode, target, value, notes), ct);

    /// <summary>Changes mode and/or notes; the matched address cannot be changed (delete and create instead).</summary>
    public Task<IpAccessRule> UpdateAsync(string ruleId, string? mode = null, string? notes = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<IpAccessRule>(ZonePath(zoneId, "firewall", "access_rules", "rules", ruleId), new { mode, notes }, ct);

    public Task DeleteAsync(string ruleId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "firewall", "access_rules", "rules", ruleId), ct);

    // ---- Account ----

    public Task<IReadOnlyList<IpAccessRule>> ListAccountRulesAsync(string? mode = null, string? target = null, string? value = null, string? notes = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<IpAccessRule>(Query(AccountPath(accountId, "firewall", "access_rules", "rules"), mode, target, value, notes), 50, ct);

    public Task<IpAccessRule> CreateAccountRuleAsync(string mode, string target, string value, string? notes = null, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<IpAccessRule>(AccountPath(accountId, "firewall", "access_rules", "rules"), Body(mode, target, value, notes), ct);

    public Task<IpAccessRule> UpdateAccountRuleAsync(string ruleId, string? mode = null, string? notes = null, string? accountId = null, CancellationToken ct = default) =>
        Api.PatchAsync<IpAccessRule>(AccountPath(accountId, "firewall", "access_rules", "rules", ruleId), new { mode, notes }, ct);

    public Task DeleteAccountRuleAsync(string ruleId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "firewall", "access_rules", "rules", ruleId), ct);

    private static string Query(string path, string? mode, string? target, string? value, string? notes) =>
        CloudflarePath.WithQuery(path, ("mode", mode), ("configuration.target", target), ("configuration.value", value), ("notes", notes));

    private static object Body(string mode, string target, string value, string? notes)
    {
        if (string.IsNullOrWhiteSpace(mode)) throw new ArgumentException("A mode is required.", nameof(mode));
        if (string.IsNullOrWhiteSpace(target)) throw new ArgumentException("A target is required.", nameof(target));
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("A value is required.", nameof(value));
        return new { mode, configuration = new { target, value }, notes };
    }
}
