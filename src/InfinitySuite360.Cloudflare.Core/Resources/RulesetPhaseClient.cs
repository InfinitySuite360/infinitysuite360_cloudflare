using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// Base of the typed facades on top of one Rulesets phase (<see cref="RateLimitingClient"/>, <see cref="WafClient"/>). Rules are identified by their
/// <c>ref</c>. Unlike <see cref="RulesetsClient.UpsertRuleByRefAsync"/> (which replaces the whole phase) a change touches only the one rule:
/// an existing rule is changed with PATCH, a new one is appended with POST, and the entry point is created with PUT only when the phase has none yet.
/// Concurrent edits of other rules are therefore not overwritten.
/// </summary>
/// <remarks>
/// The write guard is checked against <c>zones/{zone}/rulesets</c> before the preparing read, so with <c>AllowWrites = false</c> nothing is sent;
/// a <see cref="CloudflareOptions.WriteFilter"/> has to allow the paths below <c>zones/{zone}/rulesets</c>. Since 0.7.1 the filter is asked again with
/// the method and path of the actual plan (PATCH <c>…/rulesets/{id}/rules/{rule}</c>, POST <c>…/rulesets/{id}/rules</c> or PUT
/// <c>…/rulesets/phases/{phase}/entrypoint</c>) before the write (N-3).
/// Source: developers.cloudflare.com/ruleset-engine/rulesets-api/ (add, update and delete a rule), retrieved 17.11.2026.
/// </remarks>
public abstract class RulesetPhaseClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Entry point ruleset of the phase; null when the phase has none yet.</summary>
    protected Task<Ruleset?> EntrypointAsync(string phase, string? zoneId, CancellationToken ct) =>
        GetOrNullAsync<Ruleset>(ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint"), ct);

    /// <summary>Reads the phase and plans the change of the rule with <paramref name="rule"/>'s ref. Null when the rule is already as wanted.</summary>
    protected async Task<CloudflareChangePreview?> PlanUpsertAsync(string phase, RulesetRule rule, string summary, string? zoneId, CancellationToken ct)
    {
        var current = await EntrypointAsync(phase, zoneId, ct).ConfigureAwait(false);
        var existing = current?.Rules.FirstOrDefault(r => r.Ref == rule.Ref);
        var body = RuleBody(rule);
        if (existing is not null)
        {
            if (P1.Covers(RuleBody(existing), body)) return null;
            return new("PATCH", ZonePath(zoneId, "rulesets", current!.Id, "rules", existing.Id ?? throw new InvalidOperationException("Rule without id.")), body,
                $"Change rule \"{rule.Ref}\" in phase {phase}: {summary}");
        }
        if (current is not null)
            return new("POST", ZonePath(zoneId, "rulesets", current.Id, "rules"), body, $"Add rule \"{rule.Ref}\" to phase {phase}: {summary}");
        return new("PUT", ZonePath(zoneId, "rulesets", "phases", phase, "entrypoint"), new JsonObject { ["rules"] = new JsonArray(body) },
            $"Create the {phase} entry point with rule \"{rule.Ref}\": {summary}");
    }

    /// <summary>
    /// Checks the guard, reads, then writes only when something changes. The allow-list is checked with the method and path of the actual
    /// plan before anything is written (N-3, 0.7.1). Returns the ruleset after the change (or the unchanged one).
    /// </summary>
    protected async Task<(Ruleset? Ruleset, bool Changed)> UpsertAsync(string phase, RulesetRule rule, string summary, string? zoneId, CancellationToken ct)
    {
        EnsureWritable(HttpMethod.Patch, ZonePath(zoneId, "rulesets"));
        var plan = await PlanUpsertAsync(phase, rule, summary, zoneId, ct).ConfigureAwait(false);
        if (plan is null) return (await EntrypointAsync(phase, zoneId, ct).ConfigureAwait(false), false);
        EnsureWritable(new HttpMethod(plan.Method), plan.Path);
        var result = await Api.SendAsync<Ruleset>(new HttpMethod(plan.Method), plan.Path, plan.Body, ct).ConfigureAwait(false);
        return (result.Result, true);
    }

    /// <summary>Plans the removal of the rule with this ref (read-only). Null when there is no such rule.</summary>
    protected async Task<CloudflareChangePreview?> PlanRemoveAsync(string phase, string reference, string summary, string? zoneId, CancellationToken ct)
    {
        var current = await EntrypointAsync(phase, zoneId, ct).ConfigureAwait(false);
        var existing = current?.Rules.FirstOrDefault(r => r.Ref == reference);
        if (current is null || existing?.Id is null) return null;
        return new("DELETE", ZonePath(zoneId, "rulesets", current.Id, "rules", existing.Id), null, $"Remove rule \"{reference}\" from phase {phase}. {summary}");
    }

    /// <summary>Removes the rule with this ref. False when it did not exist (also on HTTP 404).</summary>
    protected async Task<bool> RemoveAsync(string phase, string reference, string? zoneId, CancellationToken ct)
    {
        EnsureWritable(HttpMethod.Delete, ZonePath(zoneId, "rulesets"));
        var plan = await PlanRemoveAsync(phase, reference, "", zoneId, ct).ConfigureAwait(false);
        if (plan is null) return false;
        EnsureWritable(HttpMethod.Delete, plan.Path);
        return await DeleteIfExistsAsync(plan.Path, null, ct).ConfigureAwait(false);
    }

    /// <summary>The writable fields of a rule as JSON (id, version and last_updated are not sent).</summary>
    protected static JsonObject RuleBody(RulesetRule r) => RulesetRisk.Body(r);

    protected static string CheckRef(string? reference)
    {
        var r = (reference ?? "").Trim();
        if (r.Length is 0 or > 100 || r.Any(char.IsWhiteSpace)) throw new ArgumentException("Ref must be 1 to 100 characters without spaces.", nameof(reference));
        return r;
    }

    /// <inheritdoc cref="RulesetRisk.MatchesAll"/>
    protected static bool MatchesAll(string expression) => RulesetRisk.MatchesAll(expression);

    protected static JsonElement El(JsonNode node) => JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
}

/// <summary>Shared rule checks of the typed ruleset clients and the generic <see cref="RulesetsClient"/> (0.7.1).</summary>
internal static class RulesetRisk
{
    /// <summary>Phases in which removing or disabling a rule switches protection off.</summary>
    public static readonly HashSet<string> ProtectingPhases = [RulesetPhases.FirewallCustom, RulesetPhases.FirewallManaged];

    // Compared without whitespace and in lower case.
    private static readonly Regex Tautology = new(
        "^(true|notfalse|!false|not\\(false\\)|!\\(false\\)|(\\d+)(==|eq)\\2|\"([^\"]*)\"(==|eq)\"\\4\"|"
        + "(http\\.host|http\\.request\\.uri\\.path|http\\.request\\.uri|http\\.request\\.full_uri|http\\.request\\.method)(ne|!=)\"\"|"
        + "len\\((http\\.host|http\\.request\\.uri\\.path|http\\.request\\.uri)\\)(>=|ge)0|"
        + "starts_with\\(http\\.request\\.uri\\.path,\"/\"\\)|http\\.request\\.uri\\.path(contains|starts_with)\"/\"|"
        + "(http\\.host|http\\.request\\.uri\\.path|http\\.request\\.uri|http\\.request\\.full_uri)(matches|~)\"(\\^|\\.\\*|\\^\\.\\*|\\.\\*\\$|\\^\\.\\*\\$)\"|"
        + "ip\\.src(in|eq)\\{0\\.0\\.0\\.0/0(::/0)?\\}|ip\\.src(in|eq)\\{::/0(0\\.0\\.0\\.0/0)?\\})$",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>
    /// True for expressions that match every request: empty, <c>true</c>, <c>not false</c>, <c>1 == 1</c>, <c>"a" eq "a"</c>, <c>http.host ne ""</c>,
    /// <c>len(http.host) ge 0</c>, <c>starts_with(http.request.uri.path, "/")</c>, <c>http.request.uri.path matches ".*"</c>,
    /// <c>ip.src in {0.0.0.0/0 ::/0}</c>, also in brackets and as one side of a top-level <c>or</c>. Limit (N-4, 0.7.1): the check is syntactic; an expression
    /// that is always true for other reasons (a list that holds every address, a comparison with a field that is always set) is not recognised.
    /// Read the preview before writing.
    /// </summary>
    public static bool MatchesAll(string expression)
    {
        var e = StripParens(expression ?? "");
        if (e.Length == 0) return true;
        var parts = SplitTopLevelOr(e);
        foreach (var part in parts)
        {
            var trimmed = StripParens(part);
            if (parts.Count > 1 && MatchesAll(trimmed)) return true;
            var compact = new string(trimmed.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();
            if (compact.Length == 0 || Tautology.IsMatch(compact)) return true;
        }
        return false;
    }

    private static string StripParens(string e)
    {
        e = e.Trim();
        while (e.Length >= 2 && e[0] == '(' && e[^1] == ')' && Balanced(e[1..^1])) e = e[1..^1].Trim();
        return e;
    }

    private static bool Balanced(string e)
    {
        var depth = 0;
        var inString = false;
        foreach (var c in e)
        {
            if (c == '"') inString = !inString;
            if (inString) continue;
            if (c == '(') depth++;
            else if (c == ')' && --depth < 0) return false;
        }
        return depth == 0;
    }

    // Splits at "or" / "||" outside brackets and string literals.
    private static List<string> SplitTopLevelOr(string e)
    {
        var parts = new List<string>();
        var depth = 0;
        var inString = false;
        var start = 0;
        for (var i = 0; i < e.Length; i++)
        {
            var c = e[i];
            if (c == '"') { inString = !inString; continue; }
            if (inString) continue;
            if (c is '(' or '{') { depth++; continue; }
            if (c is ')' or '}') { depth--; continue; }
            if (depth != 0) continue;
            if (c == '|' && i + 1 < e.Length && e[i + 1] == '|') { parts.Add(e[start..i]); start = i + 2; i++; continue; }
            if (char.IsWhiteSpace(c) && i + 3 < e.Length && (e[i + 1] is 'o' or 'O') && (e[i + 2] is 'r' or 'R') && (char.IsWhiteSpace(e[i + 3]) || e[i + 3] == '('))
            {
                parts.Add(e[start..i]);
                start = i + 3;
                i += 2;
            }
        }
        parts.Add(e[start..]);
        return parts;
    }

    /// <summary>The writable fields of a rule as JSON (id, version and last_updated are not sent).</summary>
    public static JsonObject Body(RulesetRule r)
    {
        var o = new JsonObject
        {
            ["ref"] = r.Ref, ["action"] = r.Action, ["expression"] = r.Expression, ["enabled"] = r.Enabled,
        };
        if (r.Description is not null) o["description"] = r.Description;
        if (P1.Node(r.ActionParameters) is { } ap) o["action_parameters"] = ap;
        if (P1.Node(r.Ratelimit) is { } rl) o["ratelimit"] = rl;
        if (P1.Node(r.Logging) is { } lg) o["logging"] = lg;
        return o;
    }

    /// <summary>True when both rules have the same writable content.</summary>
    public static bool Same(RulesetRule a, RulesetRule b) => JsonNode.DeepEquals(Body(a), Body(b));

    /// <summary>
    /// The loosenings and lock-out risks a rule brings into a phase compared with <paramref name="before"/> (null = new rule): skip rules (allowSkip),
    /// blocking every request (allowBroadMatch), managed-ruleset overrides that disable, log or lower the sensitivity, and in protecting phases disabling a rule
    /// or turning an acting rule into <c>log</c> (allowLoosen).
    /// </summary>
    public static List<string> Risks(RulesetRule rule, string? phase, RulesetRule? before)
    {
        var risks = new List<string>();
        var name = rule.Ref ?? rule.Id ?? "(new rule)";
        if (rule.Enabled && rule.Action == "skip") risks.Add($"rule {name} skips later rules or products (allowSkip)");
        if (rule.Enabled && rule.Action == "block" && MatchesAll(rule.Expression)) risks.Add($"rule {name} blocks every request (allowBroadMatch)");
        if (rule.Action == "execute" && rule.ActionParameters is { ValueKind: JsonValueKind.Object } ap && ap.TryGetProperty("overrides", out var ov))
            foreach (var l in OverrideLoosenings(ov)) risks.Add($"rule {name}: {l} (allowLoosen)");
        if (phase is not null && ProtectingPhases.Contains(phase) && before is not null)
        {
            if (before.Enabled && !rule.Enabled) risks.Add($"rule {name} is disabled (allowLoosen)");
            if (before.Action is not ("log" or "skip") && rule.Action == "log") risks.Add($"rule {name} only logs instead of {before.Action} (allowLoosen)");
        }
        return risks;
    }

    private static IEnumerable<string> OverrideLoosenings(JsonElement ov)
    {
        if (ov.ValueKind != JsonValueKind.Object) yield break;
        if (ov.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.False) yield return "managed ruleset disabled";
        if (ov.TryGetProperty("action", out var a) && a.ValueKind == JsonValueKind.String && a.GetString() is "log" or "skip") yield return $"managed ruleset action {a.GetString()}";
        if (ov.TryGetProperty("sensitivity_level", out var sl) && sl.ValueKind == JsonValueKind.String && sl.GetString() is "low" or "eoff") yield return $"sensitivity {sl.GetString()}";
        foreach (var list in new[] { "categories", "rules" })
            if (ov.TryGetProperty(list, out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var item in arr.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object) continue;
                    var id = item.TryGetProperty(list == "rules" ? "id" : "category", out var i) ? i.ToString() : "?";
                    if (item.TryGetProperty("enabled", out var ie) && ie.ValueKind == JsonValueKind.False) yield return $"{id} disabled";
                    if (item.TryGetProperty("action", out var ia) && ia.ValueKind == JsonValueKind.String && ia.GetString() is "log" or "skip") yield return $"{id} {ia.GetString()}";
                }
    }
}
