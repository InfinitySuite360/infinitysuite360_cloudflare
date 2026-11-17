using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Actions of rate limiting rules and WAF custom rules.</summary>
public static class WafActions
{
    public const string Block = "block";
    public const string ManagedChallenge = "managed_challenge";
    public const string JsChallenge = "js_challenge";
    public const string Challenge = "challenge";
    /// <summary>Log only. Cloudflare: Enterprise plans; below that the API refuses it.</summary>
    public const string Log = "log";
    /// <summary>Skip later rules or security products (WAF custom rules only). A loosening: needs <c>allowSkip: true</c>.</summary>
    public const string Skip = "skip";
}

/// <summary>
/// A rate limiting rule (phase <c>http_ratelimit</c>). The action has no default: choose it deliberately (<see cref="WafActions"/>).
/// Plan limits (developers.cloudflare.com/waf/rate-limiting-rules/, "Availability", retrieved 17.11.2026): rules Free 1, Pro 2, Business 5,
/// Enterprise 100; counting period Free 10 s, Pro up to 60 s, Business up to 600 s, Enterprise up to 65 535 s; mitigation timeout Free 10 s,
/// Pro up to 1 h, Business/Enterprise up to 1 day; characteristics below Enterprise only <c>ip.src</c> (Business also NAT support).
/// Cloudflare decides; an unavailable value raises a <see cref="CloudflareApiException"/> with Cloudflare's text.
/// </summary>
public sealed class RateLimitRuleInput
{
    public required string Ref { get; init; }
    public string? Description { get; init; }
    /// <summary>Which requests count, for example <c>(http.request.uri.path eq "/api/login")</c>.</summary>
    public required string Expression { get; init; }
    /// <summary>block, managed_challenge, js_challenge, challenge or log (no default).</summary>
    public required string Action { get; init; }
    public bool Enabled { get; init; } = true;
    /// <summary>Counting key; Cloudflare requires <c>cf.colo.id</c>, it is added when missing. Default: per data centre and client IP.</summary>
    public IReadOnlyList<string> Characteristics { get; init; } = ["cf.colo.id", "ip.src"];
    /// <summary>Counting period in seconds (10, 15, 20, 30, 40, 45, 60, 90, 120, 180, 240, 300, 480, 600, 900, 1200, 1800, 2400, 3600, 65535, 86400).</summary>
    public int Period { get; init; } = 60;
    public int RequestsPerPeriod { get; init; }
    /// <summary>How long the action applies after the limit is reached (seconds, same values as <see cref="Period"/>; 0 = throttle, Enterprise).</summary>
    public int MitigationTimeout { get; init; } = 60;
    /// <summary>Optional counting expression (Business and above), for example only failed logins: <c>http.response.code eq 401</c>.</summary>
    public string? CountingExpression { get; init; }
    /// <summary>Count only requests that reach the origin (cache excluded, Business and above).</summary>
    public bool? RequestsToOrigin { get; init; }
}

/// <summary>Counting settings of a rate limiting rule as Cloudflare returns them.</summary>
public sealed class RateLimitSettings : CloudflareModel
{
    public List<string> Characteristics { get; init; } = [];
    public int Period { get; init; }
    public int? RequestsPerPeriod { get; init; }
    public int? MitigationTimeout { get; init; }
    public string? CountingExpression { get; init; }
    public bool? RequestsToOrigin { get; init; }
}

/// <summary>A rate limiting rule of the zone (typed view of a <see cref="RulesetRule"/> in phase <c>http_ratelimit</c>).</summary>
public sealed class RateLimitRule
{
    public string? Id { get; init; }
    public string? Ref { get; init; }
    public string Action { get; init; } = "";
    public string Expression { get; init; } = "";
    public string? Description { get; init; }
    public bool Enabled { get; init; }
    public RateLimitSettings? Settings { get; init; }
}

/// <summary>A rule of the deprecated classic rate limiting (<c>zones/{id}/rate_limits</c>); Cloudflare migrates them to rate limiting rules.</summary>
public sealed class LegacyRateLimit : CloudflareModel
{
    public string Id { get; init; } = "";
    public bool Disabled { get; init; }
    public string? Description { get; init; }
    public int Threshold { get; init; }
    public int Period { get; init; }
    public JsonElement? Match { get; init; }
    public JsonElement? Action { get; init; }
}

/// <summary>
/// Rate limiting rules (Rulesets phase <c>http_ratelimit</c>) with preview, write guard and idempotent upsert by ref, plus read and delete of the
/// deprecated classic rate limits. Token permission: "Zone: Zone WAF: Edit" (reading: "Zone WAF: Read"); classic rules "Zone: Firewall Services".
/// </summary>
public sealed class RateLimitingClient(ICloudflareApiConnection api) : RulesetPhaseClient(api)
{
    private static readonly int[] Periods = [10, 15, 20, 30, 40, 45, 60, 90, 120, 180, 240, 300, 480, 600, 900, 1200, 1800, 2400, 3600, 65535, 86400];
    private static readonly HashSet<string> Actions = [WafActions.Block, WafActions.ManagedChallenge, WafActions.JsChallenge, WafActions.Challenge, WafActions.Log];

    /// <summary>All rate limiting rules of the zone (empty when the phase has none).</summary>
    public async Task<IReadOnlyList<RateLimitRule>> ListRulesAsync(string? zoneId = null, CancellationToken ct = default)
    {
        var ruleset = await EntrypointAsync(RulesetPhases.RateLimit, zoneId, ct).ConfigureAwait(false);
        return ruleset?.Rules.Select(r => new RateLimitRule
        {
            Id = r.Id, Ref = r.Ref, Action = r.Action, Expression = r.Expression, Description = r.Description, Enabled = r.Enabled,
            Settings = r.Ratelimit is { ValueKind: JsonValueKind.Object } rl ? ResourceKit.As<RateLimitSettings>(rl) : null,
        }).ToList() ?? [];
    }

    /// <summary>Reads the phase and plans the upsert (read-only). Null when the rule already exists as wanted.</summary>
    /// <param name="allowBroadMatch">An expression that matches every request (<c>true</c>) with <c>block</c> limits all clients, including your own; needs true.</param>
    public Task<CloudflareChangePreview?> PreviewUpsertRuleAsync(RateLimitRuleInput rule, bool allowBroadMatch = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = Build(rule, allowBroadMatch);
        return PlanUpsertAsync(RulesetPhases.RateLimit, built, summary, zoneId, ct);
    }

    /// <summary>Creates or changes the rule with <see cref="RateLimitRuleInput.Ref"/>; other rules of the phase stay untouched. Writes only on change.</summary>
    /// <inheritdoc cref="PreviewUpsertRuleAsync" path="/param"/>
    public Task<(Ruleset? Ruleset, bool Changed)> UpsertRuleAsync(RateLimitRuleInput rule, bool allowBroadMatch = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (built, summary) = Build(rule, allowBroadMatch);
        return UpsertAsync(RulesetPhases.RateLimit, built, summary, zoneId, ct);
    }

    /// <summary>Plans the removal of the rule (read-only); null when it does not exist.</summary>
    public Task<CloudflareChangePreview?> PreviewRemoveRuleAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        PlanRemoveAsync(RulesetPhases.RateLimit, CheckRef(reference), "The limit no longer applies.", zoneId, ct);

    /// <summary>Removes the rule with this ref. False when it did not exist.</summary>
    public Task<bool> RemoveRuleAsync(string reference, string? zoneId = null, CancellationToken ct = default) =>
        RemoveAsync(RulesetPhases.RateLimit, CheckRef(reference), zoneId, ct);

    // ---- classic rate limits (deprecated) ----

    /// <summary>Classic rate limits (deprecated API, read for the migration to rate limiting rules).</summary>
    public Task<IReadOnlyList<LegacyRateLimit>> ListLegacyRateLimitsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<LegacyRateLimit>(ZonePath(zoneId, "rate_limits"), 100, ct);

    public CloudflareChangePreview PreviewDeleteLegacyRateLimit(string rateLimitId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "rate_limits", rateLimitId), null, $"Delete classic rate limit {rateLimitId}; create the replacing rate limiting rule first.");

    /// <summary>Deletes a classic rate limit. True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteLegacyRateLimitAsync(string rateLimitId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "rate_limits", rateLimitId), null, ct);

    private static (RulesetRule Rule, string Summary) Build(RateLimitRuleInput r, bool allowBroadMatch)
    {
        var reference = CheckRef(r.Ref);
        ResourceKit.Required(r.Expression, nameof(r), 4096);
        if (!Actions.Contains(r.Action ?? "")) throw new ArgumentException("Action must be block, managed_challenge, js_challenge, challenge or log.", nameof(r));
        if (!Periods.Contains(r.Period)) throw new ArgumentException($"Period {r.Period} s is not a supported value.", nameof(r));
        if (r.MitigationTimeout != 0 && !Periods.Contains(r.MitigationTimeout)) throw new ArgumentException($"Mitigation timeout {r.MitigationTimeout} s is not a supported value.", nameof(r));
        if (r.RequestsPerPeriod < 1) throw new ArgumentException("RequestsPerPeriod must be at least 1.", nameof(r));
        if (r.Action == WafActions.Block && MatchesAll(r.Expression) && !allowBroadMatch)
            throw new ArgumentException("The expression matches every request; blocking above the limit also limits your own clients. Narrow the expression or pass allowBroadMatch: true.", nameof(r));

        var characteristics = r.Characteristics.Where(c => !string.IsNullOrWhiteSpace(c)).Distinct().ToList();
        if (!characteristics.Contains("cf.colo.id")) characteristics.Insert(0, "cf.colo.id");
        var rl = new JsonObject
        {
            ["characteristics"] = ResourceKit.Arr(characteristics),
            ["period"] = r.Period,
            ["requests_per_period"] = r.RequestsPerPeriod,
            ["mitigation_timeout"] = r.MitigationTimeout,
        };
        if (!string.IsNullOrWhiteSpace(r.CountingExpression)) rl["counting_expression"] = r.CountingExpression;
        if (r.RequestsToOrigin is { } rto) rl["requests_to_origin"] = rto;

        var rule = new RulesetRule
        {
            Ref = reference, Action = r.Action!, Expression = r.Expression, Description = r.Description, Enabled = r.Enabled, Ratelimit = El(rl),
        };
        var summary = string.Create(CultureInfo.InvariantCulture,
            $"{r.Action} above {r.RequestsPerPeriod} requests per {r.Period} s for {r.MitigationTimeout} s, counted by {string.Join("+", characteristics)}.")
            + (r.Action == WafActions.Log ? " (log needs Enterprise.)" : "")
            + (MatchesAll(r.Expression) ? " WARNING: matches every request." : "");
        return (rule, summary);
    }
}
