using System.Text.Json;
using System.Text.Json.Nodes;
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
/// a <see cref="CloudflareOptions.WriteFilter"/> has to allow the paths below <c>zones/{zone}/rulesets</c>.
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

    /// <summary>Checks the guard, reads, then writes only when something changes. Returns the ruleset after the change (or the unchanged one).</summary>
    protected async Task<(Ruleset? Ruleset, bool Changed)> UpsertAsync(string phase, RulesetRule rule, string summary, string? zoneId, CancellationToken ct)
    {
        EnsureWritable(HttpMethod.Patch, ZonePath(zoneId, "rulesets"));
        var plan = await PlanUpsertAsync(phase, rule, summary, zoneId, ct).ConfigureAwait(false);
        if (plan is null) return (await EntrypointAsync(phase, zoneId, ct).ConfigureAwait(false), false);
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
        return plan is not null && await DeleteIfExistsAsync(plan.Path, null, ct).ConfigureAwait(false);
    }

    /// <summary>The writable fields of a rule as JSON (id, version and last_updated are not sent).</summary>
    protected static JsonObject RuleBody(RulesetRule r)
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

    protected static string CheckRef(string? reference)
    {
        var r = (reference ?? "").Trim();
        if (r.Length is 0 or > 100 || r.Any(char.IsWhiteSpace)) throw new ArgumentException("Ref must be 1 to 100 characters without spaces.", nameof(reference));
        return r;
    }

    /// <summary>True for expressions that match every request ("true", "(true)").</summary>
    protected static bool MatchesAll(string expression)
    {
        var e = expression.Replace(" ", "", StringComparison.Ordinal).Trim('(', ')');
        return e is "true" or "";
    }

    protected static JsonElement El(JsonNode node) => JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
}
