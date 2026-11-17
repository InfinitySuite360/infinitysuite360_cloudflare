using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A saved API operation (method, host, endpoint with <c>{var1}</c> placeholders). <see cref="Features"/> only contains what was requested with a feature filter.</summary>
public sealed class ApiGatewayOperation : CloudflareModel
{
    public string OperationId { get; init; } = "";
    public string Method { get; init; } = "";
    public string Host { get; init; } = "";
    public string Endpoint { get; init; } = "";
    public DateTimeOffset? LastUpdated { get; init; }
    public JsonElement? Features { get; init; }
}

/// <summary>An operation found by API Discovery (not yet saved). <see cref="State"/> is "review", "saved" or "ignored".</summary>
public sealed class ApiDiscoveredOperation : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Method { get; init; } = "";
    public string Host { get; init; } = "";
    public string Endpoint { get; init; } = "";
    public string State { get; init; } = "";
    /// <summary>"ML", "SessionIdentifier" or "LabelDiscovery".</summary>
    public List<string>? Origin { get; init; }
    public DateTimeOffset? LastUpdated { get; init; }
    public JsonElement? Features { get; init; }
}

/// <summary>A schema uploaded for schema validation. The schema text (<see cref="Source"/>) is only returned when requested.</summary>
public sealed class ApiShieldSchema : CloudflareModel
{
    public string SchemaId { get; init; } = "";
    public string Name { get; init; } = "";
    public string Kind { get; init; } = "";
    public bool ValidationEnabled { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public string? Source { get; init; }
}

/// <summary>Zone-wide schema validation settings. Actions: "none", "log" or "block" (log needs an Enterprise plan according to Cloudflare).</summary>
public sealed class SchemaValidationSettings : CloudflareModel
{
    public string? ValidationDefaultMitigationAction { get; init; }
    public string? ValidationOverrideMitigationAction { get; init; }
}

/// <summary>Per-operation schema validation setting.</summary>
public sealed class SchemaValidationOperationSetting : CloudflareModel
{
    public string OperationId { get; init; } = "";
    /// <summary>"log", "block", "none" or null (inherits the zone default).</summary>
    public string? MitigationAction { get; init; }
}

/// <summary>
/// Token (JWT) validation configuration: where tokens are found and which keys check them. Key material is not modelled on purpose:
/// <see cref="Credentials"/> only keeps key id, type and algorithm, the key values (<c>n</c>, <c>e</c>, <c>x</c>, <c>y</c>, <c>k</c>) are dropped while reading
/// and therefore never reach <see cref="CloudflareModel.AdditionalData"/>, logs or <c>ToString</c>.
/// </summary>
public sealed class TokenValidationConfig : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string? Description { get; init; }
    public string TokenType { get; init; } = "";
    public List<string>? TokenSources { get; init; }
    public TokenValidationCredentialsInfo? Credentials { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? LastUpdated { get; init; }
}

/// <summary>Keys of a token validation configuration without key material (deliberately no <see cref="CloudflareModel"/>, so unknown fields are discarded).</summary>
public sealed class TokenValidationCredentialsInfo
{
    public List<JwtKeyInfo>? Keys { get; init; }
}

/// <summary>Identification of a JWT key: id, key type, algorithm and curve. Never carries the key itself.</summary>
public sealed class JwtKeyInfo
{
    public string? Kid { get; init; }
    public string? Kty { get; init; }
    public string? Alg { get; init; }
    public string? Crv { get; init; }

    public override string ToString() => $"{Kty}/{Alg}{(Crv is null ? "" : "/" + Crv)} kid={Kid ?? "-"}";
}

/// <summary>Token validation rule. <see cref="Action"/> is "log" or "block".</summary>
public sealed class TokenValidationRule : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string? Description { get; init; }
    public string Action { get; init; } = "";
    public bool Enabled { get; init; }
    public string? Expression { get; init; }
    public JsonElement? Selector { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? LastUpdated { get; init; }
}

/// <summary>An operation label ("managed" by Cloudflare, for example cf-risk-sensitive, or "user").</summary>
public sealed class ApiShieldLabel : CloudflareModel
{
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public string? Source { get; init; }
    public JsonElement? Metadata { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? LastUpdated { get; init; }
}

/// <summary>
/// An mTLS client certificate of the zone (Cloudflare-managed CA). Cloudflare signs a CSR, so it never sees the private key: the key stays with whoever
/// created the CSR and is not part of any model or method of this package. <see cref="Certificate"/> is the signed (public) certificate PEM.
/// </summary>
public sealed class ZoneClientCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"active", "pending_reactivation", "pending_revocation" or "revoked".</summary>
    public string? Status { get; init; }
    /// <summary>Signed certificate (PEM, public).</summary>
    public string? Certificate { get; init; }
    public string? CommonName { get; init; }
    public string? SerialNumber { get; init; }
    public string? FingerprintSha256 { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? IssuedOn { get; init; }
    public int? ValidityDays { get; init; }
}

/// <summary>Filter for operation lists. <see cref="Feature"/> asks for details such as "thresholds", "parameter_schemas", "schema_info", "api_routing", "confidence_intervals".</summary>
public sealed class ApiOperationQuery
{
    public string? Host { get; init; }
    public string? Method { get; init; }
    public string? Endpoint { get; init; }
    public string? Feature { get; init; }
    /// <summary>For discovery: "review", "saved" or "ignored".</summary>
    public string? State { get; init; }
    public int MaxItems { get; init; } = 1000;
}

/// <summary>
/// API Shield: saved operations, API Discovery, schema validation (zone and operation level), JWT token validation, operation labels and mTLS client certificates.
/// Mostly read-only. Cloudflare decides plan availability (most features need the API Shield add-on on Enterprise; limits and mTLS are explained in the Cloudflare docs),
/// a missing plan surfaces as <see cref="CloudflareNotEntitledException"/>, a missing token permission as <see cref="CloudflareApiException"/>.
/// Every write method respects <c>AllowWrites</c>/<c>WriteFilter</c> and has a <c>Preview…</c> sister that builds the change without sending it
/// (writes: <c>ApiShield.Writes.cs</c>, since 0.5.0).
/// </summary>
/// <remarks>
/// <b>Block is never a default.</b> Schema validation and token validation accept <c>"block"</c> only with <c>allowBlock: true</c>: a wrong schema or
/// key set then rejects legitimate clients (lock-out). Start with <c>"log"</c> (Enterprise) or keep <c>"none"</c>, watch the security events, then tighten.
/// </remarks>
public sealed partial class ApiShieldClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{

    // ---- session identifier configuration (also the cheapest availability probe) ----
    /// <summary>Session identifier ("auth id") characteristics of the zone; raw JSON, because Cloudflare returns a list of header/cookie descriptors.</summary>
    public Task<JsonElement> GetSessionIdentifierConfigurationAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(ZonePath(zoneId, "api_gateway", "configuration"), ct);

    // ---- operations ----
    public Task<IReadOnlyList<ApiGatewayOperation>> ListOperationsAsync(ApiOperationQuery? query = null, string? zoneId = null, CancellationToken ct = default) =>
        ListLimitedAsync<ApiGatewayOperation>(ZonePath(zoneId, "api_gateway", "operations"), query, 50, ct);

    public Task<ApiGatewayOperation> GetOperationAsync(string operationId, string? feature = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<ApiGatewayOperation>(CloudflarePath.WithQuery(ZonePath(zoneId, "api_gateway", "operations", operationId), ("feature", feature)), ct);

    public Task<IReadOnlyList<ApiDiscoveredOperation>> ListDiscoveredOperationsAsync(ApiOperationQuery? query = null, string? zoneId = null, CancellationToken ct = default) =>
        ListLimitedAsync<ApiDiscoveredOperation>(ZonePath(zoneId, "api_gateway", "discovery", "operations"), query, 50, ct);

    public Task<IReadOnlyList<ApiShieldLabel>> ListLabelsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ApiShieldLabel>(ZonePath(zoneId, "api_gateway", "labels"), 50, ct);

    // ---- schema validation ----
    public Task<IReadOnlyList<ApiShieldSchema>> ListSchemasAsync(bool includeSource = false, string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ApiShieldSchema>(CloudflarePath.WithQuery(ZonePath(zoneId, "schema_validation", "schemas"), ("omit_source", includeSource ? null : "true")), 50, ct);

    public Task<ApiShieldSchema> GetSchemaAsync(string schemaId, bool includeSource = false, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<ApiShieldSchema>(CloudflarePath.WithQuery(ZonePath(zoneId, "schema_validation", "schemas", schemaId), ("omit_source", includeSource ? null : "true")), ct);

    /// <summary>Hosts that uploaded schemas cover.</summary>
    public Task<IReadOnlyList<string>> ListSchemaHostsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<string>(ZonePath(zoneId, "schema_validation", "schemas", "hosts"), 50, ct);

    public Task<SchemaValidationSettings> GetSchemaValidationSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<SchemaValidationSettings>(ZonePath(zoneId, "schema_validation", "settings"), ct);

    public Task<IReadOnlyList<SchemaValidationOperationSetting>> ListOperationValidationSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<SchemaValidationOperationSetting>(ZonePath(zoneId, "schema_validation", "settings", "operations"), 50, ct);

    /// <summary>Plan of a change of the zone default action. Validates the value locally; <c>"block"</c> needs <paramref name="allowBlock"/>.</summary>
    /// <param name="action"><c>"none"</c> or <c>"log"</c> (Enterprise; below that Cloudflare only offers block). <c>"block"</c> only with <paramref name="allowBlock"/>.</param>
    /// <param name="allowBlock">
    /// Warning: <c>true</c> lets schema validation reject every request that does not match the uploaded schema, including legitimate clients when the
    /// schema is incomplete or out of date. Use only after a <c>"log"</c> phase without false positives, and after an explicit approval.
    /// </param>
    public CloudflareChangePreview PreviewSetDefaultAction(string action, string? zoneId = null, bool allowBlock = false) =>
        new("PATCH", ZonePath(zoneId, "schema_validation", "settings"), new Dictionary<string, object> { ["validation_default_mitigation_action"] = ApiShieldActions.Check(action, allowBlock, nameof(action)) },
            $"Set the default action of schema validation to \"{action}\".{ApiShieldActions.Warning(action)}");

    /// <inheritdoc cref="PreviewSetDefaultAction"/>
    public Task<SchemaValidationSettings> SetDefaultActionAsync(string action, string? zoneId = null, bool allowBlock = false, CancellationToken ct = default) =>
        Api.PatchAsync<SchemaValidationSettings>(ZonePath(zoneId, "schema_validation", "settings"), new Dictionary<string, object> { ["validation_default_mitigation_action"] = ApiShieldActions.Check(action, allowBlock, nameof(action)) }, ct);

    /// <summary>Plan of the per-operation action. <paramref name="action"/> null removes the override (the operation inherits the zone default).</summary>
    /// <param name="allowBlock">See <see cref="PreviewSetDefaultAction"/>: <c>"block"</c> rejects non-matching requests to this operation.</param>
    public CloudflareChangePreview PreviewSetOperationAction(string operationId, string? action, string? zoneId = null, bool allowBlock = false) =>
        new("PUT", ZonePath(zoneId, "schema_validation", "settings", "operations", operationId), OperationActionBody(action, allowBlock),
            $"Set the schema validation action of operation {operationId} to {(action is null ? "the zone default" : $"\"{action}\"")}.{ApiShieldActions.Warning(action)}");

    /// <inheritdoc cref="PreviewSetOperationAction"/>
    public Task<SchemaValidationOperationSetting> SetOperationActionAsync(string operationId, string? action, string? zoneId = null, bool allowBlock = false, CancellationToken ct = default) =>
        Api.PutAsync<SchemaValidationOperationSetting>(ZonePath(zoneId, "schema_validation", "settings", "operations", operationId), OperationActionBody(action, allowBlock), ct);

    private static System.Text.Json.Nodes.JsonObject OperationActionBody(string? action, bool allowBlock) =>
        new() { ["mitigation_action"] = action is null ? null : ApiShieldActions.Check(action, allowBlock, nameof(action)) };

    // ---- token (JWT) validation ----
    public Task<IReadOnlyList<TokenValidationConfig>> ListTokenValidationConfigsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<TokenValidationConfig>(ZonePath(zoneId, "token_validation", "config"), 50, ct);

    public Task<TokenValidationConfig> GetTokenValidationConfigAsync(string configId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<TokenValidationConfig>(ZonePath(zoneId, "token_validation", "config", configId), ct);

    public Task<IReadOnlyList<TokenValidationRule>> ListTokenValidationRulesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<TokenValidationRule>(ZonePath(zoneId, "token_validation", "rules"), 50, ct);

    public Task<TokenValidationRule> GetTokenValidationRuleAsync(string ruleId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<TokenValidationRule>(ZonePath(zoneId, "token_validation", "rules", ruleId), ct);

    // ---- mTLS (Cloudflare-managed client certificates) ----
    public Task<IReadOnlyList<ZoneClientCertificate>> ListClientCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ZoneClientCertificate>(ZonePath(zoneId, "client_certificates"), 50, ct);

    private async Task<IReadOnlyList<T>> ListLimitedAsync<T>(string path, ApiOperationQuery? q, int perPage, CancellationToken ct)
    {
        q ??= new();
        var url = CloudflarePath.WithQuery(path, ("host", q.Host), ("method", q.Method), ("endpoint", q.Endpoint), ("feature", q.Feature), ("state", q.State));
        var list = new List<T>();
        await foreach (var item in Api.ListAllAsync<T>(url, perPage, ct).ConfigureAwait(false))
        {
            list.Add(item);
            if (list.Count >= Math.Max(1, q.MaxItems)) break;
        }
        return list;
    }
}
