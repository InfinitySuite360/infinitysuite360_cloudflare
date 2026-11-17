using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A DLP detection profile (predefined, custom or integration) without the detection patterns and word lists.</summary>
public sealed class DlpProfile : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"predefined", "custom" or "integration".</summary>
    public string? Type { get; init; }
    public string? Description { get; init; }
    public int? AllowedMatchCount { get; init; }
    public string? ConfidenceThreshold { get; init; }
    public bool? OcrEnabled { get; init; }
    public List<DlpEntry> Entries { get; init; } = [];
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>A detection entry of a profile (name, type, on/off; the pattern and word list are not part of the model).</summary>
public sealed class DlpEntry : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Type { get; init; }
    public bool Enabled { get; init; }
}

/// <summary>Metadata of an Exact Data Match or word-list dataset (never the cells).</summary>
public sealed class DlpDataset : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    /// <summary>"empty", "uploading", "pending", "processing", "failed", "complete".</summary>
    public string? Status { get; init; }
    public int? NumCells { get; init; }
    /// <summary>True for an Exact Data Match dataset (values are stored hashed).</summary>
    public bool? Secret { get; init; }
    public bool? CaseSensitive { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>Payload log settings: masking level and the public key matched payloads are encrypted with (the private key stays with you).</summary>
public sealed class DlpPayloadLogSettings : CloudflareModel
{
    /// <summary>"full", "partial", "clear" or "default".</summary>
    public string? MaskingLevel { get; init; }
    public string? PublicKey { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>
/// Data Loss Prevention, read-only (0.8.0): profiles, datasets, payload log settings. Changing profiles or uploading datasets is reachable through
/// <c>OpenApi</c> (matrix priority 3). Endpoints <c>dlp-profiles-*</c>, <c>dlp-datasets-read-all</c>, <c>dlp-payload-log-get</c> of cloudflare/api-schemas@650bd71;
/// limits from developers.cloudflare.com/cloudflare-one/account-limits/ (25 custom entries, 1 000 000 dataset cells per account; retrieved 17.11.2026).
/// Detection patterns, word lists and dataset cells are removed from the answers before the models are built.
/// </summary>
public sealed class DlpClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Hidden = ["pattern", "word_list", "words", "cells", "secret_value"];

    public async Task<List<DlpProfile>> ListProfilesAsync(string? accountId = null, CancellationToken ct = default)
    {
        var result = await ResourceKit.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "dlp", "profiles"), null, ct).ConfigureAwait(false);
        return result.ValueKind == JsonValueKind.Array ? result.EnumerateArray().Select(e => ResourceKit.As<DlpProfile>(ResourceKit.Strip(e, Hidden))).ToList() : [];
    }

    public async Task<DlpProfile> GetProfileAsync(string profileId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.As<DlpProfile>(ResourceKit.Strip(await ResourceKit.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "dlp", "profiles", ResourceKit.Required(profileId, nameof(profileId))), null, ct).ConfigureAwait(false), Hidden));

    public async Task<List<DlpDataset>> ListDatasetsAsync(string? accountId = null, CancellationToken ct = default)
    {
        var result = await ResourceKit.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "dlp", "datasets"), null, ct).ConfigureAwait(false);
        return result.ValueKind == JsonValueKind.Array ? result.EnumerateArray().Select(e => ResourceKit.As<DlpDataset>(ResourceKit.Strip(e, Hidden))).ToList() : [];
    }

    public Task<DlpPayloadLogSettings> GetPayloadLogSettingsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<DlpPayloadLogSettings>(AccountPath(accountId, "dlp", "payload_log"), ct);
}

/// <summary>Risk score of a user (Zero Trust risk scoring). Personal data: do not log.</summary>
public sealed class RiskScoreUser : CloudflareModel
{
    public string UserId { get; init; } = "";
    public string? Name { get; init; }
    public string? Email { get; init; }
    /// <summary>"info", "low", "medium", "high".</summary>
    public string? MaxRiskLevel { get; init; }
    public int? EventCount { get; init; }
    public DateTimeOffset? LastEvent { get; init; }
}

/// <summary>A risk behavior and whether it counts.</summary>
public sealed class RiskBehavior : CloudflareModel
{
    public string? Name { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; }
    public string? RiskLevel { get; init; }
}

/// <summary>
/// Zero Trust risk scoring, read-only (0.8.0): behaviors and the per-user summary (<c>dlp-risk-score-behaviors-get</c>, <c>dlp-risk-score-summary-get</c>).
/// Resetting a user's score or changing behaviors is reachable through <c>OpenApi</c>.
/// </summary>
public sealed class RiskScoringClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Behaviors by key (for example "imp_travel", "high_dlp").</summary>
    public async Task<Dictionary<string, RiskBehavior>> ListBehaviorsAsync(string? accountId = null, CancellationToken ct = default)
    {
        var result = await ResourceKit.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "zt_risk_scoring", "behaviors"), null, ct).ConfigureAwait(false);
        var map = new Dictionary<string, RiskBehavior>(StringComparer.Ordinal);
        if (ResourceKit.TryGet(result, "behaviors", out var b) && b.ValueKind == JsonValueKind.Object)
            foreach (var p in b.EnumerateObject()) map[p.Name] = ResourceKit.As<RiskBehavior>(p.Value);
        return map;
    }

    public async Task<List<RiskScoreUser>> GetSummaryAsync(string? accountId = null, CancellationToken ct = default)
    {
        var result = await ResourceKit.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "zt_risk_scoring", "summary"), null, ct).ConfigureAwait(false);
        return ResourceKit.TryGet(result, "users", out var u) && u.ValueKind == JsonValueKind.Array ? u.EnumerateArray().Select(ResourceKit.As<RiskScoreUser>).ToList() : [];
    }
}
