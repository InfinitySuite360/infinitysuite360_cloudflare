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

/// <summary>
/// Rulesets (WAF custom rules, rate limits, redirects, header transforms, …): the generic way to any phase.
/// <para>Since 0.7.1 the write methods apply the checks of the typed clients with their safe defaults, compared with the current state (one read after the
/// guard check): a new or changed rule that skips (<c>skip</c>), blocks every request, or deploys a managed ruleset with loosening overrides is refused, and
/// in the protecting phases (<c>http_request_firewall_custom</c>, <c>http_request_firewall_managed</c>) so is removing or disabling a rule or turning an acting
/// rule into <c>log</c>. Unchanged rules sent back as they are never count. Use <see cref="WafClient"/>, <see cref="RateLimitingClient"/> or
/// <see cref="CacheClient"/> with their <c>allow…</c> switches for such changes, or <c>Api</c>/<c>OpenApi</c>, which only know <c>AllowWrites</c> and
/// <c>WriteFilter</c>.</para>
/// </summary>
public sealed class RulesetsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<List<Ruleset>> ListAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<Ruleset>>(ZonePath(zoneId, "rulesets"), ct);

    public Task<Ruleset> GetAsync(string rulesetId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<Ruleset>(ZonePath(zoneId, "rulesets", rulesetId), ct);

    /// <summary>Entry point ruleset of a phase; null when the phase has none yet.</summary>
    public Task<Ruleset?> GetPhaseEntrypointAsync(string phase, string? zoneId = null, CancellationToken ct = default) =>
        GetOrNullAsync<Ruleset>(ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint"), ct);

    /// <summary>Replaces all rules of a phase (creates the entry point ruleset if needed). Refuses loosenings (see the class remarks).</summary>
    public async Task<Ruleset> PutPhaseEntrypointAsync(string phase, IEnumerable<RulesetRule> rules, string? zoneId = null, CancellationToken ct = default)
    {
        var list = (rules ?? throw new ArgumentNullException(nameof(rules))).ToList();
        var path = ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint");
        EnsureWritable(HttpMethod.Put, path);
        RefuseLoosening(phase, list, await GetOrNullAsync<Ruleset>(path, ct).ConfigureAwait(false));
        return await Api.PutAsync<Ruleset>(path, new { rules = list }, ct).ConfigureAwait(false);
    }

    public Task<Ruleset?> GetAccountPhaseEntrypointAsync(string phase, string? accountId = null, CancellationToken ct = default) =>
        GetOrNullAsync<Ruleset>(AccountPath(accountId, "rulesets", "phases", phase, "entrypoint"), ct);

    /// <summary>Replaces all rules of an account phase. Refuses loosenings (see the class remarks).</summary>
    public async Task<Ruleset> PutAccountPhaseEntrypointAsync(string phase, IEnumerable<RulesetRule> rules, string? accountId = null, CancellationToken ct = default)
    {
        var list = (rules ?? throw new ArgumentNullException(nameof(rules))).ToList();
        var path = AccountPath(accountId, "rulesets", "phases", phase, "entrypoint");
        EnsureWritable(HttpMethod.Put, path);
        RefuseLoosening(phase, list, await GetOrNullAsync<Ruleset>(path, ct).ConfigureAwait(false));
        return await Api.PutAsync<Ruleset>(path, new { rules = list }, ct).ConfigureAwait(false);
    }

    /// <summary>Appends a single rule to an existing ruleset. A skip rule, a block of every request or loosening overrides are refused.</summary>
    public async Task<Ruleset> AddRuleAsync(string rulesetId, RulesetRule rule, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var path = ZonePath(zoneId, "rulesets", rulesetId, "rules");
        EnsureWritable(HttpMethod.Post, path);
        Refuse(RulesetRisk.Risks(rule, null, null));
        return await Api.PostAsync<Ruleset>(path, rule, ct).ConfigureAwait(false);
    }

    /// <summary>Changes one rule (PATCH). Reads the ruleset first (after the guard check) and refuses loosenings (see the class remarks).</summary>
    public async Task<Ruleset> UpdateRuleAsync(string rulesetId, string ruleId, RulesetRule rule, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var path = ZonePath(zoneId, "rulesets", rulesetId, "rules", ruleId);
        EnsureWritable(HttpMethod.Patch, path);
        var ruleset = await GetAsync(rulesetId, zoneId, ct).ConfigureAwait(false);
        var before = ruleset?.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (before is null || !RulesetRisk.Same(before, rule)) Refuse(RulesetRisk.Risks(rule, ruleset?.Phase, before));
        return await Api.PatchAsync<Ruleset>(path, rule, ct).ConfigureAwait(false);
    }

    /// <summary>Deletes one rule. In a protecting phase (WAF custom or managed rules) this is a loosening and refused (use the <see cref="WafClient"/> methods with <c>allowLoosen</c>).</summary>
    public async Task<Ruleset> DeleteRuleAsync(string rulesetId, string ruleId, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "rulesets", rulesetId, "rules", ruleId);
        EnsureWritable(HttpMethod.Delete, path);
        var ruleset = await GetAsync(rulesetId, zoneId, ct).ConfigureAwait(false);
        if (ruleset is not null && RulesetRisk.ProtectingPhases.Contains(ruleset.Phase) && ruleset.Rules.Any(r => r.Id == ruleId && r.Enabled))
            Refuse([$"rule {ruleId} is removed from {ruleset.Phase} (allowLoosen)"]);
        return (await Api.SendAsync<Ruleset>(HttpMethod.Delete, path, null, ct).ConfigureAwait(false)).Result!;
    }

    /// <summary>
    /// Creates or replaces the rule identified by <see cref="RulesetRule.Ref"/> without touching other rules of the phase
    /// (idempotent, suitable for desired-state reconciliation). Refuses loosenings (see the class remarks).
    /// </summary>
    public async Task<Ruleset> UpsertRuleByRefAsync(string phase, RulesetRule rule, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (string.IsNullOrWhiteSpace(rule.Ref)) throw new ArgumentException("The rule needs a ref.", nameof(rule));
        var path = ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint");
        EnsureWritable(HttpMethod.Put, path);
        var current = await GetOrNullAsync<Ruleset>(path, ct).ConfigureAwait(false);
        var rules = current?.Rules.Where(r => r.Ref != rule.Ref).Select(StripReadOnly).ToList() ?? [];
        rules.Add(rule);
        RefuseLoosening(phase, rules, current);
        return await Api.PutAsync<Ruleset>(path, new { rules }, ct).ConfigureAwait(false);
    }

    /// <summary>Removes the rule with this ref from the phase. Returns false when it did not exist. Refused in protecting phases (see the class remarks).</summary>
    public async Task<bool> RemoveRuleByRefAsync(string phase, string reference, string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint");
        EnsureWritable(HttpMethod.Put, path);
        var current = await GetOrNullAsync<Ruleset>(path, ct).ConfigureAwait(false);
        if (current is null || current.Rules.All(r => r.Ref != reference)) return false;
        var rules = current.Rules.Where(r => r.Ref != reference).Select(StripReadOnly).ToList();
        RefuseLoosening(phase, rules, current);
        await Api.PutAsync<Ruleset>(path, new { rules }, ct).ConfigureAwait(false);
        return true;
    }

    private static void RefuseLoosening(string phase, IReadOnlyList<RulesetRule> rules, Ruleset? current)
    {
        var before = current?.Rules ?? [];
        RulesetRule? Match(RulesetRule r) => before.FirstOrDefault(b => (r.Id is not null && b.Id == r.Id) || (r.Ref is not null && b.Ref == r.Ref));
        var risks = new List<string>();
        foreach (var r in rules)
        {
            var old = Match(r);
            if (old is not null && RulesetRisk.Same(old, r)) continue;
            risks.AddRange(RulesetRisk.Risks(r, phase, old));
        }
        if (RulesetRisk.ProtectingPhases.Contains(phase))
            foreach (var b in before.Where(b => b.Enabled && !rules.Any(r => (r.Id is not null && r.Id == b.Id) || (r.Ref is not null && r.Ref == b.Ref))))
                risks.Add($"rule {b.Ref ?? b.Id} is removed from {phase} (allowLoosen)");
        Refuse(risks);
    }

    private static void Refuse(List<string> risks)
    {
        if (risks.Count == 0) return;
        throw new InvalidOperationException($"Refused: {string.Join("; ", risks)}. RulesetsClient applies the safe defaults; use WafClient, RateLimitingClient or CacheClient with the named allow… switch deliberately.");
    }

    // Only send writable fields back (version/last_updated would be rejected).
    private static RulesetRule StripReadOnly(RulesetRule r) => new()
    {
        Id = r.Id, Ref = r.Ref, Action = r.Action, Expression = r.Expression, Description = r.Description, Enabled = r.Enabled,
        ActionParameters = r.ActionParameters, Ratelimit = r.Ratelimit, Logging = r.Logging,
    };
}
