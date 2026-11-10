using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class PageShieldResource : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Url { get; init; } = "";
    public string? Host { get; init; }
    public DateTimeOffset? FirstSeenAt { get; init; }
    public DateTimeOffset? LastSeenAt { get; init; }
    public List<string>? MaliciousDomainCategories { get; init; }
    public List<string>? MaliciousUrlCategories { get; init; }
    public int? JsIntegrityScore { get; init; }
    public string? Status { get; init; }

    /// <summary>Classified as malicious by Cloudflare (domain or URL category).</summary>
    public bool IsMalicious => MaliciousDomainCategories is { Count: > 0 } || MaliciousUrlCategories is { Count: > 0 };
}

public sealed class SecurityInsight : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Subject { get; init; }
    public string? IssueClass { get; init; }
    public string? IssueType { get; init; }
    public string? Severity { get; init; }
    public bool Dismissed { get; init; }
    public DateTimeOffset? Timestamp { get; init; }
    public string? ResolveText { get; init; }
    public string? ResolveLink { get; init; }
}

internal sealed class InsightsPage
{
    public List<SecurityInsight> Issues { get; init; } = [];
    public int Count { get; init; }
}

public sealed class ApiShieldOperation : CloudflareModel
{
    public string OperationId { get; init; } = "";
    public string Method { get; init; } = "";
    public string Host { get; init; } = "";
    public string Endpoint { get; init; } = "";
    public DateTimeOffset? LastUpdated { get; init; }
}

/// <summary>
/// Security features: Page Shield, Security Center (insights, security.txt), API Shield, bot management, leaked credential checks
/// and Authenticated Origin Pulls.
/// </summary>
public sealed class SecurityClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private const string PsFilter = "status=active,infrequent&exclude_cdn_cgi=true&prioritize_malicious=true";

    // ---- Page Shield ----
    public Task<JsonElement> GetPageShieldSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "page_shield"), ct);

    public Task<JsonElement> SetPageShieldEnabledAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "page_shield"), new { enabled }, ct);

    public Task<IReadOnlyList<PageShieldResource>> ListPageShieldScriptsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<PageShieldResource>(ZonePath(zoneId, "page_shield", "scripts") + "?" + PsFilter, 100, ct);

    public Task<IReadOnlyList<PageShieldResource>> ListPageShieldConnectionsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<PageShieldResource>(ZonePath(zoneId, "page_shield", "connections") + "?" + PsFilter, 100, ct);

    public Task<List<JsonElement>> ListPageShieldPoliciesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<JsonElement>>(ZonePath(zoneId, "page_shield", "policies"), ct);

    /// <summary>Creates a CSP policy; <paramref name="action"/> "log" (report only) or "allow".</summary>
    public Task<JsonElement> CreatePageShieldPolicyAsync(string description, string expression, string value, string action = "log", bool enabled = true, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<JsonElement>(ZonePath(zoneId, "page_shield", "policies"), new { description, expression, value, action, enabled }, ct);

    public Task DeletePageShieldPolicyAsync(string policyId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "page_shield", "policies", policyId), ct);

    // ---- Security Center ----
    public async Task<IReadOnlyList<SecurityInsight>> ListInsightsAsync(bool includeDismissed = false, string? zoneId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(ZonePath(zoneId, "security-center", "insights"), ("dismissed", includeDismissed ? null : "false"), ("per_page", "50"));
        return (await Api.GetAsync<InsightsPage>(path, ct).ConfigureAwait(false))?.Issues ?? [];
    }

    public Task<JsonElement> GetSecurityTxtAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "security-center", "securitytxt"), ct);

    /// <summary>Sets security.txt (RFC 9116). Body for example <c>new { enabled = true, contact = new[] { "mailto:security@example.com" }, expires = "2027-01-01T00:00:00Z" }</c>.</summary>
    public Task<JsonElement> PutSecurityTxtAsync(object securityTxt, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "security-center", "securitytxt"), securityTxt, ct);

    public Task DeleteSecurityTxtAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "security-center", "securitytxt"), ct);

    // ---- API Shield ----
    public Task<IReadOnlyList<ApiShieldOperation>> ListApiOperationsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ApiShieldOperation>(ZonePath(zoneId, "api_gateway", "operations"), 100, ct);

    public Task<List<ApiShieldOperation>> AddApiOperationsAsync(IEnumerable<(string Method, string Host, string Endpoint)> operations, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<List<ApiShieldOperation>>(ZonePath(zoneId, "api_gateway", "operations"),
            operations.Select(o => new { method = o.Method.ToUpperInvariant(), host = o.Host, endpoint = o.Endpoint }).ToList(), ct);

    public Task DeleteApiOperationAsync(string operationId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "api_gateway", "operations", operationId), ct);

    public Task<JsonElement> GetApiShieldConfigurationAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "api_gateway", "configuration"), ct);

    public Task<JsonElement> PutApiShieldConfigurationAsync(object configuration, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "api_gateway", "configuration"), configuration, ct);

    public Task<IReadOnlyList<JsonElement>> ListSchemasAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<JsonElement>(ZonePath(zoneId, "schema_validation", "schemas"), 50, ct);

    public Task<JsonElement> GetSchemaValidationSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "schema_validation", "settings"), ct);

    /// <summary>Default action of schema validation: "none", "log" or "block".</summary>
    public Task<JsonElement> SetSchemaValidationDefaultActionAsync(string action, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<JsonElement>(ZonePath(zoneId, "schema_validation", "settings"), new { validation_default_mitigation_action = action }, ct);

    // ---- Bots & Credentials ----
    public Task<JsonElement> GetBotManagementAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "bot_management"), ct);

    /// <summary>Sets bot settings, for example <c>new { fight_mode = true, ai_bots_protection = "block" }</c>.</summary>
    public Task<JsonElement> PutBotManagementAsync(object settings, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "bot_management"), settings, ct);

    public Task<JsonElement> GetLeakedCredentialChecksAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "leaked-credential-checks"), ct);

    public Task<JsonElement> SetLeakedCredentialChecksAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<JsonElement>(ZonePath(zoneId, "leaked-credential-checks"), new { enabled }, ct);

    // ---- Authenticated Origin Pulls ----
    public Task<JsonElement> GetAuthenticatedOriginPullsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "origin_tls_client_auth", "settings"), ct);

    public Task<JsonElement> SetAuthenticatedOriginPullsAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "origin_tls_client_auth", "settings"), new { enabled }, ct);
}
