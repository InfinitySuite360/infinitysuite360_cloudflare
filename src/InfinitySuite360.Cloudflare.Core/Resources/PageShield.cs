using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Zone settings of Page Shield (client-side security). Needs permission "Zone: Page Shield: Read" to read, "Edit" to change.</summary>
public sealed class PageShieldSettings : CloudflareModel
{
    public bool Enabled { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
    public bool UseCloudflareReportingEndpoint { get; init; }
    public bool UseConnectionUrlPath { get; init; }
}

/// <summary>A script or connection detected by Page Shield. Scores are only filled where Cloudflare delivers them for the plan.</summary>
public sealed class PageShieldDetected : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Url { get; init; } = "";
    public string Host { get; init; } = "";
    public DateTimeOffset? AddedAt { get; init; }
    public DateTimeOffset? FirstSeenAt { get; init; }
    public DateTimeOffset? LastSeenAt { get; init; }
    public string? FirstPageUrl { get; init; }
    public List<string>? PageUrls { get; init; }
    public bool UrlContainsCdnCgiPath { get; init; }
    public bool UrlReportedMalicious { get; init; }
    public bool DomainReportedMalicious { get; init; }
    public List<string>? MaliciousDomainCategories { get; init; }
    public List<string>? MaliciousUrlCategories { get; init; }
    /// <summary>Scripts only: SHA-256 of the content, when Cloudflare delivers it.</summary>
    public string? Hash { get; init; }
    public DateTimeOffset? FetchedAt { get; init; }
    public int? JsIntegrityScore { get; init; }
    public int? MalwareScore { get; init; }
    public int? MagecartScore { get; init; }
    public int? CryptominingScore { get; init; }

    /// <summary>Cloudflare reports the URL or the domain as malicious, or assigns a malicious category.</summary>
    public bool IsMalicious => UrlReportedMalicious || DomainReportedMalicious
        || MaliciousDomainCategories is { Count: > 0 } || MaliciousUrlCategories is { Count: > 0 };
}

/// <summary>A cookie detected by Page Shield (cookie monitor).</summary>
public sealed class PageShieldCookie : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Host { get; init; } = "";
    /// <summary>"first_party" or "unknown".</summary>
    public string Type { get; init; } = "";
    public string? DomainAttribute { get; init; }
    public string? PathAttribute { get; init; }
    public DateTimeOffset? ExpiresAttribute { get; init; }
    public int? MaxAgeAttribute { get; init; }
    public bool? HttpOnlyAttribute { get; init; }
    public bool? SecureAttribute { get; init; }
    /// <summary>"lax", "strict" or "none".</summary>
    public string? SameSiteAttribute { get; init; }
    public DateTimeOffset? FirstSeenAt { get; init; }
    public DateTimeOffset? LastSeenAt { get; init; }
    public List<string>? PageUrls { get; init; }
}

/// <summary>A content security rule (policy) of Page Shield. <see cref="Action"/>: "allow", "log" or "add_reporting_directives".</summary>
public sealed class PageShieldPolicy : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Action { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; }
    /// <summary>Wirefilter expression that selects the requests the policy applies to.</summary>
    public string Expression { get; init; } = "";
    /// <summary>The CSP value, for example <c>script-src 'self' https://cdn.example.com</c>.</summary>
    public string Value { get; init; } = "";
}

/// <summary>Filter of the Page Shield list calls. <see cref="Status"/> for example "active,infrequent" (scripts and connections).</summary>
public sealed class PageShieldQuery
{
    public string? Hosts { get; init; }
    public string? Urls { get; init; }
    public string? ExcludeUrls { get; init; }
    public string? PageUrl { get; init; }
    public string? Status { get; init; }
    public bool? PrioritizeMalicious { get; init; }
    public bool? ExcludeCdnCgi { get; init; }
    public bool? ExcludeDuplicates { get; init; }
    /// <summary>"first_seen_at" or "last_seen_at".</summary>
    public string? OrderBy { get; init; }
    /// <summary>"asc" or "desc".</summary>
    public string? Direction { get; init; }
    /// <summary>Upper limit of returned items (default 1000) so that a zone with many scripts cannot exhaust memory.</summary>
    public int MaxItems { get; init; } = 1000;

    internal (string, string?)[] ToQuery() =>
    [
        ("hosts", Hosts), ("urls", Urls), ("exclude_urls", ExcludeUrls), ("page_url", PageUrl), ("status", Status),
        ("prioritize_malicious", PageShieldClient.Flag(PrioritizeMalicious)), ("exclude_cdn_cgi", PageShieldClient.Flag(ExcludeCdnCgi)),
        ("exclude_duplicates", PageShieldClient.Flag(ExcludeDuplicates)), ("order_by", OrderBy), ("direction", Direction),
    ];
}

/// <summary>Input for creating or replacing a content security rule.</summary>
/// <remarks>
/// <see cref="Action"/>: <c>"log"</c> (default, report only: <c>Content-Security-Policy-Report-Only</c>), <c>"add_reporting_directives"</c> (adds
/// report directives to the site's own CSP) or <c>"allow"</c>. Warning: <c>"allow"</c> <b>enforces</b> the CSP in <see cref="Value"/>; every script or
/// connection that is not listed is blocked in the visitors' browsers, so a missing source breaks the site. Run the same value with <c>"log"</c> first.
/// Content security rules need Page Shield "Advanced" (Cloudflare tariff page, 17.11.2026); otherwise <see cref="CloudflareNotEntitledException"/>.
/// </remarks>
public sealed class PageShieldPolicyInput
{
    public string Action { get; init; } = "log";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; } = true;
    public string Expression { get; init; } = "";
    public string Value { get; init; } = "";
}

/// <summary>
/// Page Shield (client-side security): settings, detected scripts, connections and cookies, content security rules (policies).
/// Availability per plan is decided by Cloudflare; the client does not guess, an unavailable feature surfaces as <see cref="CloudflareApiException"/>
/// (typically 403 for the plan or the token permission). All write methods respect <c>CloudflareOptions.AllowWrites</c> and <c>WriteFilter</c>;
/// the <c>Preview…</c> methods build the request without sending it.
/// </summary>
public sealed class PageShieldClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    internal static string? Flag(bool? v) => v is null ? null : v.Value ? "true" : "false";

    // ---- settings ----
    public Task<PageShieldSettings> GetSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<PageShieldSettings>(ZonePath(zoneId, "page_shield"), ct);

    /// <summary>Plan of the settings change (no request). Only given values are sent; at least one is required.</summary>
    /// <param name="enabled">Page Shield on or off. Off stops the script/connection/cookie monitor (a loosening: let the application ask for a second approval).</param>
    /// <param name="useCloudflareReportingEndpoint">CSP reports go to Cloudflare's reporting endpoint (needed for the monitor) instead of a path on the zone.</param>
    /// <param name="useConnectionUrlPath">Connections are reported with their full URL path instead of host only (more detail, may contain personal data in paths).</param>
    public CloudflareChangePreview PreviewSetSettings(bool? enabled = null, bool? useCloudflareReportingEndpoint = null, bool? useConnectionUrlPath = null, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "page_shield"), SettingsBody(enabled, useCloudflareReportingEndpoint, useConnectionUrlPath),
            "Change the Page Shield settings of the zone" + (enabled == false ? " (switch Page Shield OFF: scripts are no longer monitored)." : "."));

    /// <inheritdoc cref="PreviewSetSettings"/>
    public Task<PageShieldSettings> SetSettingsAsync(bool? enabled = null, bool? useCloudflareReportingEndpoint = null, bool? useConnectionUrlPath = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<PageShieldSettings>(ZonePath(zoneId, "page_shield"), SettingsBody(enabled, useCloudflareReportingEndpoint, useConnectionUrlPath), ct);

    private static Dictionary<string, object> SettingsBody(bool? enabled, bool? reporting, bool? urlPath)
    {
        var body = new Dictionary<string, object>();
        if (enabled is { } e) body["enabled"] = e;
        if (reporting is { } r) body["use_cloudflare_reporting_endpoint"] = r;
        if (urlPath is { } u) body["use_connection_url_path"] = u;
        if (body.Count == 0) throw new ArgumentException("Nothing to change: give at least one setting.");
        return body;
    }

    // ---- scripts, connections, cookies ----
    public Task<IReadOnlyList<PageShieldDetected>> ListScriptsAsync(PageShieldQuery? query = null, string? zoneId = null, CancellationToken ct = default) =>
        ListLimitedAsync<PageShieldDetected>("scripts", query ?? new(), zoneId, ct);

    public Task<PageShieldDetected> GetScriptAsync(string scriptId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<PageShieldDetected>(ZonePath(zoneId, "page_shield", "scripts", scriptId), ct);

    public Task<IReadOnlyList<PageShieldDetected>> ListConnectionsAsync(PageShieldQuery? query = null, string? zoneId = null, CancellationToken ct = default) =>
        ListLimitedAsync<PageShieldDetected>("connections", query ?? new(), zoneId, ct);

    public Task<PageShieldDetected> GetConnectionAsync(string connectionId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<PageShieldDetected>(ZonePath(zoneId, "page_shield", "connections", connectionId), ct);

    /// <summary>Cookie monitor. Only <see cref="PageShieldQuery.Hosts"/>, <see cref="PageShieldQuery.PageUrl"/>, order and direction apply to cookies.</summary>
    public Task<IReadOnlyList<PageShieldCookie>> ListCookiesAsync(PageShieldQuery? query = null, string? zoneId = null, CancellationToken ct = default) =>
        ListLimitedAsync<PageShieldCookie>("cookies", new PageShieldQuery { Hosts = query?.Hosts, PageUrl = query?.PageUrl, OrderBy = query?.OrderBy, Direction = query?.Direction, MaxItems = query?.MaxItems ?? 1000 }, zoneId, ct);

    public Task<PageShieldCookie> GetCookieAsync(string cookieId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<PageShieldCookie>(ZonePath(zoneId, "page_shield", "cookies", cookieId), ct);

    private async Task<IReadOnlyList<T>> ListLimitedAsync<T>(string kind, PageShieldQuery query, string? zoneId, CancellationToken ct)
    {
        var path = CloudflarePath.WithQuery(ZonePath(zoneId, "page_shield", kind), query.ToQuery());
        var list = new List<T>();
        await foreach (var item in Api.ListAllAsync<T>(path, 100, ct).ConfigureAwait(false))
        {
            list.Add(item);
            if (list.Count >= Math.Max(1, query.MaxItems)) break;
        }
        return list;
    }

    // ---- content security rules (policies) ----
    public Task<IReadOnlyList<PageShieldPolicy>> ListPoliciesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies"), 50, ct);

    public Task<PageShieldPolicy> GetPolicyAsync(string policyId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies", policyId), ct);

    /// <summary>Plan of a new content security rule (no request). Action <c>"allow"</c> enforces the CSP and needs <paramref name="allowEnforce"/>.</summary>
    /// <param name="allowEnforce">Warning: <c>true</c> permits action <c>"allow"</c>, which blocks every script/connection missing from the CSP in visitors' browsers.</param>
    public CloudflareChangePreview PreviewCreatePolicy(PageShieldPolicyInput policy, string? zoneId = null, bool allowEnforce = false) =>
        new("POST", ZonePath(zoneId, "page_shield", "policies"), PolicyBody(policy, allowEnforce),
            $"Create the content security rule \"{policy.Description}\" (action {policy.Action}).{EnforceWarning(policy)}");

    /// <summary>Creates a content security rule (POST, not retried; see <see cref="EnsurePolicyAsync"/> for an idempotent variant).</summary>
    public Task<PageShieldPolicy> CreatePolicyAsync(PageShieldPolicyInput policy, string? zoneId = null, bool allowEnforce = false, CancellationToken ct = default) =>
        Api.PostAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies"), PolicyBody(policy, allowEnforce), ct);

    public CloudflareChangePreview PreviewUpdatePolicy(string policyId, PageShieldPolicyInput policy, string? zoneId = null, bool allowEnforce = false) =>
        new("PUT", ZonePath(zoneId, "page_shield", "policies", policyId), PolicyBody(policy, allowEnforce), $"Replace the content security rule {policyId}.{EnforceWarning(policy)}");

    /// <summary>Replaces a content security rule (PUT, idempotent).</summary>
    public Task<PageShieldPolicy> UpdatePolicyAsync(string policyId, PageShieldPolicyInput policy, string? zoneId = null, bool allowEnforce = false, CancellationToken ct = default) =>
        Api.PutAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies", policyId), PolicyBody(policy, allowEnforce), ct);

    /// <summary>
    /// Idempotent create-or-update by <see cref="PageShieldPolicyInput.Description"/> (the description serves as the name): unchanged → nothing is written
    /// (<c>Changed = false</c>), different → PUT, missing → POST. Checks the write guard before reading.
    /// </summary>
    public async Task<(PageShieldPolicy Policy, bool Changed)> EnsurePolicyAsync(PageShieldPolicyInput policy, string? zoneId = null, bool allowEnforce = false, CancellationToken ct = default)
    {
        var body = PolicyBody(policy, allowEnforce);
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "page_shield", "policies"));
        var existing = (await ListPoliciesAsync(zoneId, ct).ConfigureAwait(false)).Where(p => p.Description == policy.Description).ToList();
        if (existing.Count > 1)
            throw new InvalidOperationException($"{existing.Count} content security rules share the description \"{policy.Description}\"; resolve the duplicates first.");
        if (existing.Count == 0)
            return (await Api.PostAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies"), body, ct).ConfigureAwait(false), true);
        var e = existing[0];
        if (e.Action == policy.Action && e.Enabled == policy.Enabled && e.Expression == policy.Expression && e.Value == policy.Value) return (e, false);
        return (await Api.PutAsync<PageShieldPolicy>(ZonePath(zoneId, "page_shield", "policies", e.Id), body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewDeletePolicy(string policyId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "page_shield", "policies", policyId), null, $"Delete the content security rule {policyId} (a loosening when it enforced a CSP).");

    /// <summary>Deletes a content security rule. True when deleted, false when it did not exist (idempotent).</summary>
    public Task<bool> DeletePolicyAsync(string policyId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "page_shield", "policies", policyId), null, ct);

    private static Dictionary<string, object> PolicyBody(PageShieldPolicyInput p, bool allowEnforce)
    {
        if (p.Action is not ("allow" or "log" or "add_reporting_directives"))
            throw new ArgumentException("Action must be \"allow\", \"log\" or \"add_reporting_directives\".", nameof(p));
        if (p.Action == "allow" && !allowEnforce)
            throw new ArgumentException("Action \"allow\" enforces the CSP and blocks unlisted scripts in visitors' browsers. Test with \"log\" first; pass allowEnforce: true deliberately.", nameof(p));
        if (string.IsNullOrWhiteSpace(p.Description)) throw new ArgumentException("Description is required (it names the rule).", nameof(p));
        if (string.IsNullOrWhiteSpace(p.Expression)) throw new ArgumentException("Expression is required, for example (http.host eq \"app.example.com\").", nameof(p));
        if (string.IsNullOrWhiteSpace(p.Value)) throw new ArgumentException("Value (the CSP) is required.", nameof(p));
        return new() { ["action"] = p.Action, ["description"] = p.Description, ["enabled"] = p.Enabled, ["expression"] = p.Expression, ["value"] = p.Value };
    }

    private static string EnforceWarning(PageShieldPolicyInput p) =>
        p.Action == "allow" ? " WARNING: allow enforces the CSP; unlisted scripts are blocked in visitors' browsers." : "";
}
