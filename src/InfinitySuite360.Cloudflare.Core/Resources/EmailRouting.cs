using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class EmailRoutingSettings : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public bool Enabled { get; init; }
    /// <summary>"ready", "unconfigured", "misconfigured", …</summary>
    public string Status { get; init; } = "";
}

public sealed class EmailRoutingRule : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Tag { get; init; } = "";
    public string Name { get; init; } = "";
    public bool Enabled { get; init; }
    public int Priority { get; init; }
    public List<EmailRoutingMatcher> Matchers { get; init; } = [];
    public List<EmailRoutingAction> Actions { get; init; } = [];
}

public sealed class EmailRoutingMatcher
{
    /// <summary>"literal" or "all".</summary>
    public string Type { get; init; } = "literal";
    public string? Field { get; init; } = "to";
    public string? Value { get; init; }
}

public sealed class EmailRoutingAction
{
    /// <summary>"forward", "worker" or "drop".</summary>
    public string Type { get; init; } = "forward";
    public List<string>? Value { get; init; }
}

public sealed class EmailDestinationAddress : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Tag { get; init; } = "";
    public string Email { get; init; } = "";
    /// <summary>Time of verification; null = not verified yet.</summary>
    public DateTimeOffset? Verified { get; init; }
    public bool IsVerified => Verified is not null;
}

/// <summary>Email Routing.</summary>
public sealed class EmailRoutingClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<EmailRoutingSettings> GetSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<EmailRoutingSettings>(ZonePath(zoneId, "email", "routing"), ct);

    /// <summary>Enables Email Routing (creates the required MX/SPF records).</summary>
    public Task<EmailRoutingSettings> EnableAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<EmailRoutingSettings>(ZonePath(zoneId, "email", "routing", "enable"), new { }, ct);

    public Task<EmailRoutingSettings> DisableAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<EmailRoutingSettings>(ZonePath(zoneId, "email", "routing", "disable"), new { }, ct);

    /// <summary>DNS records required for Email Routing.</summary>
    public Task<List<JsonElement>> GetRequiredDnsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<JsonElement>>(ZonePath(zoneId, "email", "routing", "dns"), ct);

    public Task<IReadOnlyList<EmailRoutingRule>> ListRulesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<EmailRoutingRule>(ZonePath(zoneId, "email", "routing", "rules"), 50, ct);

    /// <summary>Creates a forwarding rule <paramref name="from"/> → <paramref name="to"/>. The destination must be verified.</summary>
    public Task<EmailRoutingRule> CreateForwardRuleAsync(string name, string from, string to, bool enabled = true, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<EmailRoutingRule>(ZonePath(zoneId, "email", "routing", "rules"), new
        {
            name,
            enabled,
            matchers = new[] { new EmailRoutingMatcher { Type = "literal", Field = "to", Value = from } },
            actions = new[] { new EmailRoutingAction { Type = "forward", Value = [to] } },
        }, ct);

    public Task<EmailRoutingRule> UpdateRuleAsync(string ruleId, object rule, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<EmailRoutingRule>(ZonePath(zoneId, "email", "routing", "rules", ruleId), rule, ct);

    public Task DeleteRuleAsync(string ruleId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "email", "routing", "rules", ruleId), ct);

    public Task<EmailRoutingRule> GetCatchAllAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<EmailRoutingRule>(ZonePath(zoneId, "email", "routing", "rules", "catch_all"), ct);

    /// <summary>Sets the catch-all rule: <paramref name="forwardTo"/> = null drops mail to unknown addresses.</summary>
    public Task<EmailRoutingRule> SetCatchAllAsync(bool enabled, string? forwardTo, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<EmailRoutingRule>(ZonePath(zoneId, "email", "routing", "rules", "catch_all"), new
        {
            enabled,
            matchers = new[] { new EmailRoutingMatcher { Type = "all", Field = null } },
            actions = new[] { forwardTo is null ? new EmailRoutingAction { Type = "drop" } : new EmailRoutingAction { Type = "forward", Value = [forwardTo] } },
        }, ct);

    // ---- Destination addresses (account) ----
    public Task<IReadOnlyList<EmailDestinationAddress>> ListAddressesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<EmailDestinationAddress>(AccountPath(accountId, "email", "routing", "addresses"), 50, ct);

    /// <summary>Creates a destination address; Cloudflare sends a verification email.</summary>
    public Task<EmailDestinationAddress> CreateAddressAsync(string email, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<EmailDestinationAddress>(AccountPath(accountId, "email", "routing", "addresses"), new { email }, ct);

    public Task DeleteAddressAsync(string addressId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "email", "routing", "addresses", addressId), ct);
}
