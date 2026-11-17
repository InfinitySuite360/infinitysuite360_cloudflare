using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// Ids of Cloudflare's managed rulesets (developers.cloudflare.com/waf/managed-rules/, retrieved 17.11.2026). Check the ids of your account with
/// <see cref="WafClient.ListManagedRulesetsAsync"/>; which ones you may deploy depends on the plan (Free: the free managed ruleset only).
/// </summary>
public static class ManagedRulesetIds
{
    public const string CloudflareManaged = "efb7b8c949ac4650a09736fc376e9aee";
    public const string OwaspCore = "4814384a9e5d4991b9815dcfc25d2f1f";
    public const string ExposedCredentialsCheck = "c2e184081120413c86c3ab7e14069605";
    public const string FreeManaged = "77454fe2d30c4220b5701f6fdfb893ba";
}

/// <summary>A WAF custom rule (phase <c>http_request_firewall_custom</c>). Plan limits: Free 5 rules, Pro 20, Business 100, Enterprise 1000 (Cloudflare decides).</summary>
public sealed class WafCustomRuleInput
{
    public required string Ref { get; init; }
    public string? Description { get; init; }
    public required string Expression { get; init; }
    /// <summary>block, managed_challenge, js_challenge, challenge, log or skip (no default; skip needs <c>allowSkip</c>).</summary>
    public required string Action { get; init; }
    public bool Enabled { get; init; } = true;
    /// <summary>For skip: what to skip, for example <c>{"ruleset":"current"}</c> (default) or <c>{"phases":["http_ratelimit"]}</c>, <c>{"products":["bic"]}</c>.</summary>
    public JsonElement? ActionParameters { get; init; }
}

/// <summary>Override of one rule of a managed ruleset.</summary>
public sealed record ManagedRuleOverride(string Id, string? Action = null, bool? Enabled = null, int? ScoreThreshold = null);

/// <summary>Override of all rules with a tag (category) of a managed ruleset.</summary>
public sealed record ManagedCategoryOverride(string Category, string? Action = null, bool? Enabled = null);

/// <summary>Overrides of a managed ruleset deployment. Every field is optional; null means "as Cloudflare ships it".</summary>
public sealed class ManagedRulesetOverrides
{
    /// <summary>Action for every rule of the ruleset.</summary>
    public string? Action { get; init; }
    /// <summary>false disables every rule of the ruleset (a loosening).</summary>
    public bool? Enabled { get; init; }
    /// <summary>OWASP: paranoia/sensitivity level ("default", "medium", "low", "eoff").</summary>
    public string? SensitivityLevel { get; init; }
    public IReadOnlyList<ManagedCategoryOverride>? Categories { get; init; }
    public IReadOnlyList<ManagedRuleOverride>? Rules { get; init; }

    internal JsonObject? ToJson(out List<string> loosenings)
    {
        loosenings = [];
        var o = new JsonObject();
        if (Action is not null) { o["action"] = Action; if (Action is WafActions.Log or WafActions.Skip) loosenings.Add($"ruleset action {Action}"); }
        if (Enabled is { } e) { o["enabled"] = e; if (!e) loosenings.Add("ruleset disabled"); }
        if (SensitivityLevel is not null)
        {
            o["sensitivity_level"] = SensitivityLevel is "default" or "medium" or "low" or "eoff" ? SensitivityLevel : throw new ArgumentException("Sensitivity must be default, medium, low or eoff.", nameof(SensitivityLevel));
            if (SensitivityLevel is "low" or "eoff") loosenings.Add($"sensitivity {SensitivityLevel}");
        }
        if (Categories is { Count: > 0 })
        {
            var arr = new JsonArray();
            foreach (var c in Categories)
            {
                var co = new JsonObject { ["category"] = P1.Required(c.Category, nameof(Categories)) };
                if (c.Action is not null) { co["action"] = c.Action; if (c.Action is WafActions.Log or WafActions.Skip) loosenings.Add($"category {c.Category} {c.Action}"); }
                if (c.Enabled is { } ce) { co["enabled"] = ce; if (!ce) loosenings.Add($"category {c.Category} disabled"); }
                arr.Add(co);
            }
            o["categories"] = arr;
        }
        if (Rules is { Count: > 0 })
        {
            var arr = new JsonArray();
            foreach (var r in Rules)
            {
                var ro = new JsonObject { ["id"] = P1.Required(r.Id, nameof(Rules)) };
                if (r.Action is not null) { ro["action"] = r.Action; if (r.Action is WafActions.Log or WafActions.Skip) loosenings.Add($"rule {r.Id} {r.Action}"); }
                if (r.Enabled is { } re) { ro["enabled"] = re; if (!re) loosenings.Add($"rule {r.Id} disabled"); }
                if (r.ScoreThreshold is { } st) ro["score_threshold"] = st;
                arr.Add(ro);
            }
            o["rules"] = arr;
        }
        return o.Count == 0 ? null : o;
    }
}

/// <summary>A deployed managed ruleset (an <c>execute</c> rule in phase <c>http_request_firewall_managed</c>).</summary>
public sealed class ManagedRulesetDeployment
{
    public string? RuleId { get; init; }
    public string? Ref { get; init; }
    public string RulesetId { get; init; } = "";
    public string Expression { get; init; } = "";
    public bool Enabled { get; init; }
    public string? Description { get; init; }
    /// <summary>The overrides as Cloudflare stores them (null without overrides).</summary>
    public JsonElement? Overrides { get; init; }
}

/// <summary>
/// WAF custom rules and managed rules (deployments and overrides) as a typed facade on top of the Rulesets engine (<see cref="RulesetsClient"/> stays the
/// generic way). Loosenings need an explicit opt-in: <c>skip</c> rules (<c>allowSkip</c>), disabling or logging managed rules, removing a deployment and
/// (since 0.7.1) removing a custom rule (<c>allowLoosen</c>), blocking every request (<c>allowBroadMatch</c>). Token permission: "Zone: Zone WAF: Edit" (reading "Zone WAF: Read").
/// Sources: developers.cloudflare.com/waf/custom-rules/, …/waf/managed-rules/deploy-zone-dashboard/ and …/ruleset-engine/managed-rulesets/override-managed-ruleset/ (17.11.2026).
/// </summary>
public sealed class WafClient(ICloudflareApiConnection api) : RulesetPhaseClient(api)
{
    private static readonly HashSet<string> CustomActions = [WafActions.Block, WafActions.ManagedChallenge, WafActions.JsChallenge, WafActions.Challenge, WafActions.Log, WafActions.Skip];

    // ---- custom rules ----

    /// <summary>The custom rules of the zone in evaluation order (empty when the phase has none).</summary>
    public async Task<IReadOnlyList<RulesetRule>> ListCustomRulesAsync(string? zoneId = null, CancellationToken ct = default) =>
        (await EntrypointAsync(RulesetPhases.FirewallCustom, zoneId, ct).ConfigureAwait(false))?.Rules ?? [];

    /// <summary>Plans the upsert of a custom rule (read-only). Null when it already exists as wanted.</summary>
    /// <param name="allowSkip">A skip rule lets matching requests pass later rules or products: a loosening, needs true.</param>
    /// <param name="allowBroadMatch">Blocking an expression that matches every request locks everyone out; needs true.</param>
    public Task<CloudflareChangePreview?> PreviewUpsertCustomRuleAsync(WafCustomRuleInput rule, bool allowSkip = false, bool allowBroadMatch = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = BuildCustom(rule, allowSkip, allowBroadMatch);
        return PlanUpsertAsync(RulesetPhases.FirewallCustom, built, summary, zoneId, ct);
    }

    /// <summary>Creates or changes the custom rule with this ref (only this rule, writes only on change).</summary>
    /// <inheritdoc cref="PreviewUpsertCustomRuleAsync" path="/param"/>
    public Task<(Ruleset? Ruleset, bool Changed)> UpsertCustomRuleAsync(WafCustomRuleInput rule, bool allowSkip = false, bool allowBroadMatch = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = BuildCustom(rule, allowSkip, allowBroadMatch);
        return UpsertAsync(RulesetPhases.FirewallCustom, built, summary, zoneId, ct);
    }

    public Task<CloudflareChangePreview?> PreviewRemoveCustomRuleAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        PlanRemoveAsync(RulesetPhases.FirewallCustom, CheckRef(reference), "", zoneId, ct);

    /// <summary>Removes the custom rule with this ref (a loosening): needs <paramref name="allowLoosen"/> (M-8, 0.7.1). False when it did not exist.</summary>
    public Task<bool> RemoveCustomRuleAsync(string reference, string? zoneId = null, bool allowLoosen = false, CancellationToken ct = default)
    {
        var r = CheckRef(reference);
        if (!allowLoosen)
            throw new InvalidOperationException("Refused: removing a WAF custom rule switches its protection off. Pass allowLoosen: true deliberately.");
        return RemoveAsync(RulesetPhases.FirewallCustom, r, zoneId, ct);
    }

    // ---- managed rules ----

    /// <summary>Managed rulesets the zone can deploy (<c>kind = managed</c>).</summary>
    public async Task<IReadOnlyList<Ruleset>> ListManagedRulesetsAsync(string? zoneId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<List<Ruleset>>(ZonePath(zoneId, "rulesets"), ct).ConfigureAwait(false) ?? []).Where(r => r.Kind == "managed").ToList();

    /// <summary>Managed rulesets deployed in the zone, with their overrides.</summary>
    public async Task<IReadOnlyList<ManagedRulesetDeployment>> ListManagedDeploymentsAsync(string? zoneId = null, CancellationToken ct = default)
    {
        var ruleset = await EntrypointAsync(RulesetPhases.FirewallManaged, zoneId, ct).ConfigureAwait(false);
        return ruleset?.Rules.Where(r => r.Action == "execute").Select(r => new ManagedRulesetDeployment
        {
            RuleId = r.Id, Ref = r.Ref, Expression = r.Expression, Enabled = r.Enabled, Description = r.Description,
            RulesetId = r.ActionParameters is { ValueKind: JsonValueKind.Object } ap && ap.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
            Overrides = r.ActionParameters is { ValueKind: JsonValueKind.Object } ap2 && ap2.TryGetProperty("overrides", out var ov) ? ov.Clone() : null,
        }).ToList() ?? [];
    }

    /// <summary>Plans deploying (or changing the overrides of) a managed ruleset (read-only). Null when already deployed as wanted.</summary>
    /// <param name="allowLoosen">Overrides that disable rules, log instead of acting or lower the sensitivity weaken the protection; need true.</param>
    public Task<CloudflareChangePreview?> PreviewDeployManagedRulesetAsync(string rulesetId, string reference, ManagedRulesetOverrides? overrides = null, string expression = "true",
        bool allowLoosen = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (rule, summary) = BuildDeployment(rulesetId, reference, overrides, expression, allowLoosen);
        return PlanUpsertAsync(RulesetPhases.FirewallManaged, rule, summary, zoneId, ct);
    }

    /// <summary>Deploys a managed ruleset (an execute rule with this ref) or changes its overrides. Writes only on change.</summary>
    /// <inheritdoc cref="PreviewDeployManagedRulesetAsync" path="/param"/>
    public Task<(Ruleset? Ruleset, bool Changed)> DeployManagedRulesetAsync(string rulesetId, string reference, ManagedRulesetOverrides? overrides = null, string expression = "true",
        bool allowLoosen = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (rule, summary) = BuildDeployment(rulesetId, reference, overrides, expression, allowLoosen);
        return UpsertAsync(RulesetPhases.FirewallManaged, rule, summary, zoneId, ct);
    }

    public Task<CloudflareChangePreview?> PreviewRemoveManagedDeploymentAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        PlanRemoveAsync(RulesetPhases.FirewallManaged, CheckRef(reference), "WARNING: the managed rules of this deployment stop protecting the zone.", zoneId, ct);

    /// <summary>Removes a managed ruleset deployment (a loosening): refused unless <paramref name="allowLoosen"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveManagedDeploymentAsync(string reference, bool allowLoosen = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (!allowLoosen)
            throw new InvalidOperationException("Refused: removing a managed ruleset deployment switches its protection off. Pass allowLoosen: true deliberately.");
        return RemoveAsync(RulesetPhases.FirewallManaged, CheckRef(reference), zoneId, ct);
    }

    private static (RulesetRule, string) BuildCustom(WafCustomRuleInput r, bool allowSkip, bool allowBroadMatch)
    {
        var reference = CheckRef(r.Ref);
        P1.Required(r.Expression, nameof(r), 4096);
        if (!CustomActions.Contains(r.Action ?? "")) throw new ArgumentException("Action must be block, managed_challenge, js_challenge, challenge, log or skip.", nameof(r));
        if (r.Action == WafActions.Skip && !allowSkip)
            throw new ArgumentException("A skip rule lets matching requests bypass later rules or security products (a loosening). Pass allowSkip: true deliberately.", nameof(r));
        if (r.Action == WafActions.Block && MatchesAll(r.Expression) && !allowBroadMatch)
            throw new ArgumentException("Blocking an expression that matches every request locks everybody out. Pass allowBroadMatch: true deliberately.", nameof(r));
        var parameters = r.ActionParameters ?? (r.Action == WafActions.Skip ? El(new JsonObject { ["ruleset"] = "current" }) : null);
        var rule = new RulesetRule { Ref = reference, Action = r.Action!, Expression = r.Expression, Description = r.Description, Enabled = r.Enabled, ActionParameters = parameters };
        var summary = $"{r.Action} when {Short(r.Expression)}." + (r.Action == WafActions.Skip ? " WARNING: skip loosens the protection for matching requests." : "")
                      + (r.Action == WafActions.Log ? " (log needs Enterprise.)" : "");
        return (rule, summary);
    }

    private static (RulesetRule, string) BuildDeployment(string rulesetId, string reference, ManagedRulesetOverrides? overrides, string expression, bool allowLoosen)
    {
        P1.Required(rulesetId, nameof(rulesetId), 64);
        P1.Required(expression, nameof(expression), 4096);
        List<string> loosenings = [];
        JsonObject? ov = null;
        if (overrides is not null) ov = overrides.ToJson(out loosenings);
        if (loosenings.Count > 0 && !allowLoosen)
            throw new ArgumentException($"The overrides weaken the managed rules ({string.Join("; ", loosenings)}). Pass allowLoosen: true deliberately.", nameof(overrides));
        var ap = new JsonObject { ["id"] = rulesetId };
        if (ov is not null) ap["overrides"] = ov;
        var rule = new RulesetRule { Ref = CheckRef(reference), Action = "execute", Expression = expression, Enabled = true, ActionParameters = El(ap) };
        var summary = $"execute managed ruleset {rulesetId}" + (ov is null ? "" : " with overrides") + "."
                      + (loosenings.Count > 0 ? $" WARNING: weakens the protection ({string.Join("; ", loosenings)})." : "");
        return (rule, summary);
    }

    private static string Short(string expression) => expression.Length <= 120 ? expression : expression[..117] + "...";
}
