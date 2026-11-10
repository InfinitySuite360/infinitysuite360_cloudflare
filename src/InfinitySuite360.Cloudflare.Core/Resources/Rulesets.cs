using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Phases of the Rulesets engine (WAF, rate limiting, transforms, redirects, cache, …).</summary>
public static class RulesetPhases
{
    public const string FirewallCustom = "http_request_firewall_custom";
    public const string FirewallManaged = "http_request_firewall_managed";
    public const string RateLimit = "http_ratelimit";
    public const string DynamicRedirect = "http_request_dynamic_redirect";
    public const string RequestTransform = "http_request_transform";
    public const string RequestLateTransform = "http_request_late_transform";
    public const string ResponseHeadersTransform = "http_response_headers_transform";
    public const string CacheSettings = "http_request_cache_settings";
    public const string ConfigSettings = "http_config_settings";
    public const string Origin = "http_request_origin";
    public const string CustomErrors = "http_custom_errors";
    public const string ResponseCompression = "http_response_compression";
}

public sealed class Ruleset : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public string Kind { get; init; } = "";
    public string Phase { get; init; } = "";
    public string? Version { get; init; }
    public List<RulesetRule> Rules { get; init; } = [];
    public DateTimeOffset? LastUpdated { get; init; }
}

public sealed class RulesetRule : CloudflareModel
{
    public string? Id { get; init; }
    public string? Ref { get; init; }
    /// <summary>For example "block", "managed_challenge", "js_challenge", "skip", "log", "redirect", "rewrite", "set_cache_settings".</summary>
    public string Action { get; init; } = "";
    public string Expression { get; init; } = "";
    public string? Description { get; init; }
    public bool Enabled { get; init; } = true;
    public JsonElement? ActionParameters { get; init; }
    public JsonElement? Ratelimit { get; init; }
    public JsonElement? Logging { get; init; }
}

/// <summary>Rulesets (WAF custom rules, rate limits, redirects, header transforms, …).</summary>
public sealed class RulesetsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<List<Ruleset>> ListAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<Ruleset>>(ZonePath(zoneId, "rulesets"), ct);

    public Task<Ruleset> GetAsync(string rulesetId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<Ruleset>(ZonePath(zoneId, "rulesets", rulesetId), ct);

    /// <summary>Entry point ruleset of a phase; null when the phase has none yet.</summary>
    public Task<Ruleset?> GetPhaseEntrypointAsync(string phase, string? zoneId = null, CancellationToken ct = default) =>
        GetOrNullAsync<Ruleset>(ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint"), ct);

    /// <summary>Replaces all rules of a phase (creates the entry point ruleset if needed).</summary>
    public Task<Ruleset> PutPhaseEntrypointAsync(string phase, IEnumerable<RulesetRule> rules, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<Ruleset>(ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint"), new { rules = rules.ToList() }, ct);

    public Task<Ruleset?> GetAccountPhaseEntrypointAsync(string phase, string? accountId = null, CancellationToken ct = default) =>
        GetOrNullAsync<Ruleset>(AccountPath(accountId, "rulesets", "phases", phase, "entrypoint"), ct);

    public Task<Ruleset> PutAccountPhaseEntrypointAsync(string phase, IEnumerable<RulesetRule> rules, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<Ruleset>(AccountPath(accountId, "rulesets", "phases", phase, "entrypoint"), new { rules = rules.ToList() }, ct);

    /// <summary>Appends a single rule to an existing ruleset.</summary>
    public Task<Ruleset> AddRuleAsync(string rulesetId, RulesetRule rule, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<Ruleset>(ZonePath(zoneId, "rulesets", rulesetId, "rules"), rule, ct);

    public Task<Ruleset> UpdateRuleAsync(string rulesetId, string ruleId, RulesetRule rule, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<Ruleset>(ZonePath(zoneId, "rulesets", rulesetId, "rules", ruleId), rule, ct);

    public async Task<Ruleset> DeleteRuleAsync(string rulesetId, string ruleId, string? zoneId = null, CancellationToken ct = default) =>
        (await Api.SendAsync<Ruleset>(HttpMethod.Delete, ZonePath(zoneId, "rulesets", rulesetId, "rules", ruleId), null, ct).ConfigureAwait(false)).Result!;

    /// <summary>
    /// Creates or replaces the rule identified by <see cref="RulesetRule.Ref"/> without touching other rules of the phase
    /// (idempotent, suitable for desired-state reconciliation).
    /// </summary>
    public async Task<Ruleset> UpsertRuleByRefAsync(string phase, RulesetRule rule, string? zoneId = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rule.Ref)) throw new ArgumentException("The rule needs a ref.", nameof(rule));
        var current = await GetPhaseEntrypointAsync(phase, zoneId, ct).ConfigureAwait(false);
        var rules = current?.Rules.Where(r => r.Ref != rule.Ref).Select(StripReadOnly).ToList() ?? [];
        rules.Add(rule);
        return await PutPhaseEntrypointAsync(phase, rules, zoneId, ct).ConfigureAwait(false);
    }

    /// <summary>Removes the rule with this ref from the phase. Returns false when it did not exist.</summary>
    public async Task<bool> RemoveRuleByRefAsync(string phase, string reference, string? zoneId = null, CancellationToken ct = default)
    {
        var current = await GetPhaseEntrypointAsync(phase, zoneId, ct).ConfigureAwait(false);
        if (current is null || current.Rules.All(r => r.Ref != reference)) return false;
        await PutPhaseEntrypointAsync(phase, current.Rules.Where(r => r.Ref != reference).Select(StripReadOnly), zoneId, ct).ConfigureAwait(false);
        return true;
    }

    // Only send writable fields back (version/last_updated would be rejected).
    private static RulesetRule StripReadOnly(RulesetRule r) => new()
    {
        Id = r.Id, Ref = r.Ref, Action = r.Action, Expression = r.Expression, Description = r.Description, Enabled = r.Enabled,
        ActionParameters = r.ActionParameters, Ratelimit = r.Ratelimit, Logging = r.Logging,
    };
}
