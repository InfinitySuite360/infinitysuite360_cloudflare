using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// Bot settings of a zone (<c>zones/{id}/bot_management</c>). Which fields apply depends on the plan: Free has Bot Fight Mode (<see cref="FightMode"/>),
/// Pro/Business Super Bot Fight Mode (<c>sbfm_*</c>), Enterprise with the add-on Bot Management (developers.cloudflare.com/bots/plans/, 17.11.2026).
/// </summary>
public sealed class BotManagementSettings : CloudflareModel
{
    /// <summary>Bot Fight Mode (Free). Challenges automated traffic and cannot be skipped with WAF rules.</summary>
    public bool? FightMode { get; init; }
    public bool? EnableJs { get; init; }
    /// <summary>"block", "disabled" or "only_on_ad_pages".</summary>
    public string? AiBotsProtection { get; init; }
    public string? CrawlerProtection { get; init; }
    public string? ContentBotsProtection { get; init; }
    /// <summary>Super Bot Fight Mode, definitely automated: "allow", "block" or "managed_challenge".</summary>
    public string? SbfmDefinitelyAutomated { get; init; }
    /// <summary>Super Bot Fight Mode, likely automated (Business and above): "allow", "block" or "managed_challenge".</summary>
    public string? SbfmLikelyAutomated { get; init; }
    /// <summary>Super Bot Fight Mode, verified bots (search engines, monitoring): "allow" or "block".</summary>
    public string? SbfmVerifiedBots { get; init; }
    public bool? SbfmStaticResourceProtection { get; init; }
    public bool? OptimizeWordpress { get; init; }
    public bool? SuppressSessionScore { get; init; }
    public bool? AutoUpdateModel { get; init; }
    public bool? UsingLatestModel { get; init; }
    public bool? IsRobotsTxtManaged { get; init; }
    public string? CfRobotsVariant { get; init; }
    /// <summary>Settings that are active but no longer allowed by the plan (after an up- or downgrade).</summary>
    public JsonElement? StaleZoneConfiguration { get; init; }
}

/// <summary>Change of the bot settings: only set fields are sent.</summary>
public sealed class BotManagementChange
{
    public bool? FightMode { get; init; }
    public bool? EnableJs { get; init; }
    public string? AiBotsProtection { get; init; }
    public string? CrawlerProtection { get; init; }
    public string? SbfmDefinitelyAutomated { get; init; }
    public string? SbfmLikelyAutomated { get; init; }
    public string? SbfmVerifiedBots { get; init; }
    public bool? SbfmStaticResourceProtection { get; init; }
    public bool? OptimizeWordpress { get; init; }
    public bool? SuppressSessionScore { get; init; }
    public bool? AutoUpdateModel { get; init; }
    public bool? IsRobotsTxtManaged { get; init; }
}

/// <summary>A false positive/negative report to Cloudflare's bot detection (Bot Management).</summary>
public sealed class BotFeedbackReport : CloudflareModel
{
    /// <summary>"false_positive" or "false_negative".</summary>
    public string Type { get; init; } = "";
    public string? Description { get; init; }
    public string? Expression { get; init; }
    public DateTimeOffset? FirstRequestSeenAt { get; init; }
    public DateTimeOffset? LastRequestSeenAt { get; init; }
    public long? Requests { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
}

/// <summary>State of leaked credential checks of a zone.</summary>
public sealed class LeakedCredentialChecksStatus : CloudflareModel
{
    public bool Enabled { get; init; }
}

/// <summary>A custom detection location of leaked credential checks: where username and password are in the request.</summary>
public sealed class LeakedCredentialDetection : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>Rules language expression, for example <c>lookup_json_string(http.request.body.raw, "user")</c>.</summary>
    public string? Username { get; init; }
    public string? Password { get; init; }
}

/// <summary>
/// Bot protection (Bot Fight Mode, Super Bot Fight Mode, Bot Management, feedback) and leaked credential checks, typed and with previews.
/// Settings that challenge or block automated traffic also hit your own API and mobile clients (Cloudflare: "they may challenge API or mobile app
/// traffic"; Bot Fight Mode cannot be skipped with WAF rules, developers.cloudflare.com/bots/get-started/bot-fight-mode/, 17.11.2026), so they need
/// <c>allowChallengeAutomation: true</c>; blocking verified bots needs <c>allowBlockVerifiedBots: true</c>.
/// Token permissions: "Zone: Bot Management: Edit" (reading "Read"), leaked credentials "Zone: Zone WAF: Edit".
/// Leaked credential checks: password check on all plans, username/password pair from Pro, custom detection locations Enterprise
/// (developers.cloudflare.com/waf/detections/leaked-credentials/, 17.11.2026).
/// </summary>
public sealed class BotsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly HashSet<string> SbfmActions = ["allow", "block", "managed_challenge"];

    public Task<BotManagementSettings> GetSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<BotManagementSettings>(ZonePath(zoneId, "bot_management"), ct);

    /// <summary>Plan of a change of the bot settings (sends nothing). Inputs are checked locally.</summary>
    /// <param name="allowChallengeAutomation">Bot Fight Mode on, or definitely/likely automated set to block or managed_challenge: also your own API clients are challenged or blocked.</param>
    /// <param name="allowBlockVerifiedBots">Blocking verified bots stops search engines and monitoring services.</param>
    public CloudflareChangePreview PreviewUpdateSettings(BotManagementChange change, bool allowChallengeAutomation = false, bool allowBlockVerifiedBots = false, string? zoneId = null)
    {
        var (body, summary) = Body(change, allowChallengeAutomation, allowBlockVerifiedBots);
        return new("PUT", ZonePath(zoneId, "bot_management"), body, summary);
    }

    /// <summary>Changes the bot settings (PUT with the set fields only, idempotent).</summary>
    /// <inheritdoc cref="PreviewUpdateSettings" path="/param"/>
    public Task<BotManagementSettings> UpdateSettingsAsync(BotManagementChange change, bool allowChallengeAutomation = false, bool allowBlockVerifiedBots = false, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<BotManagementSettings>(ZonePath(zoneId, "bot_management"), Body(change, allowChallengeAutomation, allowBlockVerifiedBots).Body, ct);

    // ---- feedback ----

    public async Task<IReadOnlyList<BotFeedbackReport>> ListFeedbackAsync(string? zoneId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<BotFeedbackReport>>(ZonePath(zoneId, "bot_management", "feedback"), ct).ConfigureAwait(false) ?? [];

    public CloudflareChangePreview PreviewReportFeedback(string type, string expression, string description, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "bot_management", "feedback"), FeedbackBody(type, expression, description), $"Report a {type} of bot detection to Cloudflare.");

    /// <summary>Reports a false positive or negative (Bot Management, POST not retried).</summary>
    public async Task ReportFeedbackAsync(string type, string expression, string description, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Post, ZonePath(zoneId, "bot_management", "feedback"), FeedbackBody(type, expression, description), ct).ConfigureAwait(false);

    // ---- leaked credential checks ----

    public Task<LeakedCredentialChecksStatus> GetLeakedCredentialChecksAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<LeakedCredentialChecksStatus>(ZonePath(zoneId, "leaked-credential-checks"), ct);

    public CloudflareChangePreview PreviewSetLeakedCredentialChecks(bool enabled, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "leaked-credential-checks"), new JsonObject { ["enabled"] = enabled },
            enabled ? "Enable leaked credential checks." : "Disable leaked credential checks (rules that use cf.waf.credential_check.* no longer match).");

    /// <summary>Switches leaked credential checks on or off (Cloudflare uses POST for this setting; it is not retried after a server error).</summary>
    public Task<LeakedCredentialChecksStatus> SetLeakedCredentialChecksAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<LeakedCredentialChecksStatus>(ZonePath(zoneId, "leaked-credential-checks"), new JsonObject { ["enabled"] = enabled }, ct);

    public async Task<IReadOnlyList<LeakedCredentialDetection>> ListLeakedCredentialDetectionsAsync(string? zoneId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<LeakedCredentialDetection>>(ZonePath(zoneId, "leaked-credential-checks", "detections"), ct).ConfigureAwait(false) ?? [];

    public CloudflareChangePreview PreviewCreateLeakedCredentialDetection(string usernameExpression, string? passwordExpression = null, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "leaked-credential-checks", "detections"), DetectionBody(usernameExpression, passwordExpression), "Add a custom detection location for leaked credentials.");

    /// <summary>Adds a custom detection location (Enterprise; leaked credential checks must be on). POST, not retried; see <see cref="EnsureLeakedCredentialDetectionAsync"/>.</summary>
    public Task<LeakedCredentialDetection> CreateLeakedCredentialDetectionAsync(string usernameExpression, string? passwordExpression = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<LeakedCredentialDetection>(ZonePath(zoneId, "leaked-credential-checks", "detections"), DetectionBody(usernameExpression, passwordExpression), ct);

    /// <summary>Idempotent: returns the detection with the same expressions or creates it.</summary>
    public async Task<(LeakedCredentialDetection Detection, bool Created)> EnsureLeakedCredentialDetectionAsync(string usernameExpression, string? passwordExpression = null, string? zoneId = null, CancellationToken ct = default)
    {
        var body = DetectionBody(usernameExpression, passwordExpression);
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "leaked-credential-checks", "detections"));
        var existing = (await ListLeakedCredentialDetectionsAsync(zoneId, ct).ConfigureAwait(false))
            .FirstOrDefault(d => d.Username == usernameExpression && (d.Password ?? "") == (passwordExpression ?? ""));
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<LeakedCredentialDetection>(ZonePath(zoneId, "leaked-credential-checks", "detections"), body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewUpdateLeakedCredentialDetection(string detectionId, string usernameExpression, string? passwordExpression = null, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "leaked-credential-checks", "detections", detectionId), DetectionBody(usernameExpression, passwordExpression), $"Replace detection location {detectionId}.");

    public Task<LeakedCredentialDetection> UpdateLeakedCredentialDetectionAsync(string detectionId, string usernameExpression, string? passwordExpression = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<LeakedCredentialDetection>(ZonePath(zoneId, "leaked-credential-checks", "detections", detectionId), DetectionBody(usernameExpression, passwordExpression), ct);

    public CloudflareChangePreview PreviewDeleteLeakedCredentialDetection(string detectionId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "leaked-credential-checks", "detections", detectionId), null, $"Delete detection location {detectionId}.");

    /// <summary>Deletes a detection location. True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteLeakedCredentialDetectionAsync(string detectionId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "leaked-credential-checks", "detections", detectionId), null, ct);

    private static (JsonObject Body, string Summary) Body(BotManagementChange c, bool allowChallengeAutomation, bool allowBlockVerifiedBots)
    {
        var o = new JsonObject();
        var notes = new List<string>();
        void Sbfm(string name, string? value, bool automation)
        {
            if (value is null) return;
            if (!SbfmActions.Contains(value)) throw new ArgumentException($"{name} must be allow, block or managed_challenge.", nameof(c));
            if (automation && value != "allow" && !allowChallengeAutomation)
                throw new ArgumentException($"{name} = {value} also challenges or blocks your own API and mobile clients. Add a WAF skip rule for them and pass allowChallengeAutomation: true.", nameof(c));
            o[name] = value;
            notes.Add($"{name} {value}");
        }

        if (c.FightMode is { } fm)
        {
            if (fm && !allowChallengeAutomation)
                throw new ArgumentException("Bot Fight Mode challenges automated traffic, including your own API and mobile clients, and cannot be skipped with WAF rules. Pass allowChallengeAutomation: true deliberately.", nameof(c));
            o["fight_mode"] = fm;
            notes.Add(fm ? "Bot Fight Mode ON (cannot be skipped by WAF rules)" : "Bot Fight Mode off (loosening)");
        }
        Sbfm("sbfm_definitely_automated", c.SbfmDefinitelyAutomated, automation: true);
        Sbfm("sbfm_likely_automated", c.SbfmLikelyAutomated, automation: true);
        if (c.SbfmVerifiedBots is { } vb)
        {
            if (vb is not ("allow" or "block")) throw new ArgumentException("sbfm_verified_bots must be allow or block.", nameof(c));
            if (vb == "block" && !allowBlockVerifiedBots)
                throw new ArgumentException("Blocking verified bots stops search engines and uptime monitors. Pass allowBlockVerifiedBots: true deliberately.", nameof(c));
            o["sbfm_verified_bots"] = vb;
            notes.Add($"verified bots {vb}");
        }
        if (c.AiBotsProtection is { } ai)
        {
            o["ai_bots_protection"] = ai is "block" or "disabled" or "only_on_ad_pages" ? ai : throw new ArgumentException("ai_bots_protection must be block, disabled or only_on_ad_pages.", nameof(c));
            notes.Add($"AI bots {ai}");
        }
        if (c.CrawlerProtection is { } cp) { o["crawler_protection"] = cp; notes.Add($"crawler protection {cp}"); }
        if (c.EnableJs is { } js) { o["enable_js"] = js; notes.Add($"JS detections {(js ? "on" : "off")}"); }
        if (c.SbfmStaticResourceProtection is { } srp) { o["sbfm_static_resource_protection"] = srp; notes.Add($"static resource protection {(srp ? "on" : "off")}"); }
        if (c.OptimizeWordpress is { } ow) { o["optimize_wordpress"] = ow; notes.Add($"optimize WordPress {(ow ? "on" : "off")}"); }
        if (c.SuppressSessionScore is { } ss) { o["suppress_session_score"] = ss; notes.Add($"suppress session score {(ss ? "on" : "off")}"); }
        if (c.AutoUpdateModel is { } au) { o["auto_update_model"] = au; notes.Add($"auto update model {(au ? "on" : "off")}"); }
        if (c.IsRobotsTxtManaged is { } rt) { o["is_robots_txt_managed"] = rt; notes.Add($"managed robots.txt {(rt ? "on" : "off")}"); }
        if (o.Count == 0) throw new ArgumentException("Nothing to change.", nameof(c));
        var warn = (c.FightMode == true || c.SbfmDefinitelyAutomated is "block" or "managed_challenge" || c.SbfmLikelyAutomated is "block" or "managed_challenge")
            ? " WARNING: automated clients (APIs, apps, Cloudflare Tunnel with definitely automated) can be challenged or blocked." : "";
        return (o, $"Change bot settings: {string.Join(", ", notes)}.{warn}");
    }

    private static JsonObject FeedbackBody(string type, string expression, string description)
    {
        if (type is not ("false_positive" or "false_negative")) throw new ArgumentException("Type must be false_positive or false_negative.", nameof(type));
        return new JsonObject { ["type"] = type, ["expression"] = P1.Required(expression, nameof(expression), 4096), ["description"] = P1.Required(description, nameof(description), 1000) };
    }

    private static JsonObject DetectionBody(string username, string? password)
    {
        var o = new JsonObject { ["username"] = P1.Required(username, nameof(username), 4096) };
        if (!string.IsNullOrWhiteSpace(password)) o["password"] = password;
        return o;
    }
}
