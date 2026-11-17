using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Mitigation actions of schema validation and token validation. <see cref="Block"/> is never a default (see <see cref="ApiShieldClient"/>).</summary>
public static class ApiShieldActions
{
    /// <summary>No action (validation result is ignored).</summary>
    public const string None = "none";
    /// <summary>Log only (Cloudflare: Enterprise plans; below that the API refuses it).</summary>
    public const string Log = "log";
    /// <summary>Reject the request. Lock-out risk: only with <c>allowBlock: true</c>.</summary>
    public const string Block = "block";

    internal static string Check(string action, bool allowBlock, string parameter, bool allowNone = true)
    {
        var valid = action is Log or Block || (allowNone && action is None);
        if (!valid)
            throw new ArgumentException(allowNone ? "Action must be \"none\", \"log\" or \"block\"." : "Action must be \"log\" or \"block\".", parameter);
        if (action == Block && !allowBlock)
            throw new ArgumentException("Action \"block\" rejects legitimate clients when the schema or key set is incomplete (lock-out). " +
                                        "Start with \"log\"; pass allowBlock: true only deliberately, after a log phase and an approval.", parameter);
        return action;
    }

    internal static string Warning(string? action) =>
        action == Block ? " WARNING: block rejects every request that fails validation; legitimate clients can be locked out." : "";
}

/// <summary>An operation to save: HTTP method, host and endpoint path (Cloudflare uses <c>{var1}</c> style placeholders, for example <c>/v1/users/{var1}</c>).</summary>
public sealed record ApiOperationInput(string Method, string Host, string Endpoint)
{
    private static readonly HashSet<string> Methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "TRACE"];

    internal JsonObject ToJson()
    {
        var method = (Method ?? "").Trim().ToUpperInvariant();
        if (!Methods.Contains(method)) throw new ArgumentException($"Unknown HTTP method \"{Method}\".", nameof(Method));
        var host = (Host ?? "").Trim().ToLowerInvariant();
        if (host.Length is 0 or > 255 || host.Contains('/') || host.Contains(':') || host.Contains(' '))
            throw new ArgumentException("Host must be a bare hostname (no scheme, port or path), at most 255 characters.", nameof(Host));
        var endpoint = (Endpoint ?? "").Trim();
        if (!endpoint.StartsWith('/') || endpoint.Length > 4096 || endpoint.Contains('?') || endpoint.Contains(' '))
            throw new ArgumentException("Endpoint must be a path starting with '/', without query, at most 4096 characters.", nameof(Endpoint));
        return new JsonObject { ["method"] = method, ["host"] = host, ["endpoint"] = endpoint };
    }

    internal string Key => $"{(Method ?? "").Trim().ToUpperInvariant()} {(Host ?? "").Trim().ToLowerInvariant()}{(Endpoint ?? "").Trim()}";
}

/// <summary>Result of <see cref="ApiShieldClient.EnsureOperationsAsync"/>: operations that were already saved and the ones that were added.</summary>
public sealed record ApiOperationsEnsureResult(IReadOnlyList<ApiGatewayOperation> Existing, IReadOnlyList<ApiGatewayOperation> Added);

/// <summary>A schema (OpenAPI v3) to upload for schema validation.</summary>
public sealed class ApiShieldSchemaInput
{
    public string Name { get; init; } = "";
    /// <summary>The OpenAPI v3 document (JSON or YAML text). It is sent to Cloudflare but never shown in previews or summaries (size and SHA-256 only).</summary>
    public string Source { get; init; } = "";
    public string Kind { get; init; } = "openapi_v3";
    /// <summary>Default false: the schema is stored but does not validate anything until it is enabled explicitly (<see cref="ApiShieldClient.SetSchemaValidationEnabledAsync"/>).</summary>
    public bool ValidationEnabled { get; init; }
}

/// <summary>Local checks before a schema upload. Nothing is sent when a check fails.</summary>
public sealed class ApiShieldSchemaUploadOptions
{
    /// <summary>Upper limit of the schema text in bytes (UTF-8), default 10 MiB (the largest plan limit; Cloudflare enforces the plan's own limit: Free 200 KiB, Pro 500 KiB, Business 2 MiB, Enterprise 5 MiB/10+ MiB).</summary>
    public int MaxBytes { get; init; } = 10 * 1024 * 1024;
    /// <summary>When set, every server host of the schema (<c>servers[].url</c>) must be in this list and at least one must be present; needs a JSON schema.</summary>
    public IReadOnlyCollection<string>? AllowedHosts { get; init; }
}

/// <summary>Where API Shield finds the session identifier ("auth id"): a header, a cookie or a JWT claim (<c>{token_config_id}:$.json.path</c>).</summary>
public sealed record ApiShieldAuthIdCharacteristic(string Type, string Name)
{
    internal JsonObject ToJson()
    {
        if (Type is not ("header" or "cookie" or "jwt")) throw new ArgumentException("Type must be \"header\", \"cookie\" or \"jwt\".", nameof(Type));
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > 128) throw new ArgumentException("Name must be 1 to 128 characters.", nameof(Name));
        return new JsonObject { ["type"] = Type, ["name"] = Name };
    }
}

/// <summary>
/// A JWT key set (JWKS) for token validation. Built from JSON (<c>{"keys":[…]}</c> or an array of JWKs). Private key members
/// (<c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>, <c>qi</c>, <c>oth</c>) are refused, so a private key is never uploaded by mistake.
/// </summary>
/// <remarks>
/// The key material is kept privately and only written into the request body. <see cref="ToString"/>, <see cref="Keys"/>, previews and
/// exception messages contain key id, type and algorithm only. Symmetric keys (<c>kty: oct</c>, HS256/384/512) are secrets: prefer asymmetric keys.
/// </remarks>
[DebuggerDisplay("JwtKeySet({Keys.Count} key(s), material [redacted])")]
public sealed class JwtKeySet : IDisposable
{
    private static readonly string[] PrivateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth"];

    // N-5 (0.7.1): the key material as a character buffer that Dispose overwrites; hidden from the debugger's variable views.
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private char[]? _json;

    private JwtKeySet(string json, IReadOnlyList<JwtKeyInfo> keys)
    {
        _json = json.ToCharArray();
        Keys = keys;
    }

    /// <summary>Key ids, types and algorithms (no key material).</summary>
    public IReadOnlyList<JwtKeyInfo> Keys { get; }

    /// <summary>True when the set contains a symmetric (secret) key.</summary>
    public bool ContainsSymmetricKey => Keys.Any(k => k.Kty == "oct");

    /// <summary>Parses and checks a JWKS. Error messages never repeat the input.</summary>
    public static JwtKeySet Parse(string jwksJson)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(jwksJson); }
        catch (JsonException) { throw new ArgumentException("JWKS is not valid JSON.", nameof(jwksJson)); }
        var array = root switch
        {
            JsonArray a => a,
            JsonObject o when o["keys"] is JsonArray a => a,
            _ => throw new ArgumentException("JWKS must be {\"keys\":[…]} or an array of keys.", nameof(jwksJson)),
        };
        if (array.Count is 0 or > 64) throw new ArgumentException("A key set holds 1 to 64 keys.", nameof(jwksJson));

        var infos = new List<JwtKeyInfo>();
        var clean = new JsonArray();
        for (var i = 0; i < array.Count; i++)
        {
            if (array[i] is not JsonObject key) throw new ArgumentException($"Key {i + 1} is not an object.", nameof(jwksJson));
            if (PrivateMembers.Any(key.ContainsKey))
                throw new ArgumentException($"Key {i + 1} contains private key members; upload the public key only.", nameof(jwksJson));
            var kty = Str(key, "kty");
            var alg = Str(key, "alg");
            string[] required = kty switch
            {
                "RSA" => ["n", "e"],
                "EC" => ["crv", "x", "y"],
                "oct" => ["k"],
                _ => throw new ArgumentException($"Key {i + 1}: kty must be RSA, EC or oct.", nameof(jwksJson)),
            };
            if (string.IsNullOrEmpty(alg)) throw new ArgumentException($"Key {i + 1}: alg is required.", nameof(jwksJson));
            if (required.Any(r => string.IsNullOrEmpty(Str(key, r)))) throw new ArgumentException($"Key {i + 1}: {kty} key misses {string.Join("/", required)}.", nameof(jwksJson));
            infos.Add(new JwtKeyInfo { Kid = Str(key, "kid"), Kty = kty, Alg = alg, Crv = Str(key, "crv") });
            clean.Add(key.DeepClone());
        }
        return new JwtKeySet(clean.ToJsonString(), infos);
    }

    private static string? Str(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    internal JsonObject ToCredentials() => new() { ["keys"] = JsonNode.Parse(_json is { } j ? new string(j) : throw new ObjectDisposedException(nameof(JwtKeySet))) };

    /// <summary>Overwrites the key material buffer (symmetric keys are secrets). The string passed to <see cref="Parse"/> cannot be wiped by .NET.</summary>
    public void Dispose()
    {
        if (_json is { } j) Array.Clear(j);
        _json = null;
    }

    internal JsonObject ToRedactedCredentials() =>
        new() { ["keys"] = new JsonArray(Keys.Select(k => (JsonNode?)new JsonObject { ["kid"] = k.Kid, ["kty"] = k.Kty, ["alg"] = k.Alg, ["material"] = "[redacted]" }).ToArray()) };

    public override string ToString() => $"JwtKeySet({Keys.Count} key(s): {string.Join(", ", Keys)})";
}

/// <summary>A new token (JWT) validation configuration: where the token is read and which keys check it.</summary>
public sealed class TokenValidationConfigInput
{
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary>1 to 4 sources, for example <c>http.request.headers["authorization"][0]</c> (header names lowercase) or <c>http.request.cookies["jwt"][0]</c>.</summary>
    public IReadOnlyList<string> TokenSources { get; init; } = [];
    public required JwtKeySet Keys { get; init; }
}

/// <summary>A new token validation rule. Default action <c>log</c>; <c>block</c> only with <c>allowBlock</c>.</summary>
public sealed class TokenValidationRuleInput
{
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Action { get; init; } = ApiShieldActions.Log;
    public bool Enabled { get; init; } = true;
    /// <summary>Rule expression, for example <c>is_jwt_valid("&lt;config id&gt;")</c>.</summary>
    public string Expression { get; init; } = "";
    /// <summary>Hosts whose operations the rule applies to.</summary>
    public IReadOnlyList<string>? IncludeHosts { get; init; }
    /// <summary>Operations excluded from the rule.</summary>
    public IReadOnlyList<string>? ExcludeOperationIds { get; init; }
}

/// <summary>Change of a token validation rule: only set fields are sent. Position: one of index (1-based), before or after a rule id.</summary>
public sealed class TokenValidationRuleChange
{
    public string? Title { get; init; }
    public string? Description { get; init; }
    public string? Action { get; init; }
    public bool? Enabled { get; init; }
    public string? Expression { get; init; }
    public IReadOnlyList<string>? IncludeHosts { get; init; }
    public IReadOnlyList<string>? ExcludeOperationIds { get; init; }
    public int? PositionIndex { get; init; }
    public string? PositionBefore { get; init; }
    public string? PositionAfter { get; init; }
}

/// <summary>Hostnames for which Cloudflare requests a client certificate (mTLS), optionally bound to a customer CA (<see cref="MtlsCertificateId"/>; null = Cloudflare-managed CA).</summary>
public sealed class MtlsHostnameAssociations : CloudflareModel
{
    public List<string> Hostnames { get; init; } = [];
    public string? MtlsCertificateId { get; init; }
}

public sealed partial class ApiShieldClient
{
    private static readonly Regex TokenSource = new(@"^http\.request\.(headers|cookies)\[""[^""]+""\]\[\d+\]$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    // =====================================================================================================================
    // Operations (endpoint management)
    // =====================================================================================================================

    /// <summary>Plan of a bulk add (no request). Inputs are checked locally.</summary>
    public CloudflareChangePreview PreviewAddOperations(IEnumerable<ApiOperationInput> operations, string? zoneId = null)
    {
        var body = OperationsBody(operations);
        return new("POST", ZonePath(zoneId, "api_gateway", "operations"), body, $"Save {body.Count} API operation(s) in API Shield.");
    }

    /// <summary>
    /// Saves operations in one bulk call. POST is never retried automatically (only on HTTP 429, which Cloudflare sends before processing);
    /// use <see cref="EnsureOperationsAsync"/> to skip operations that are already saved.
    /// </summary>
    public Task<IReadOnlyList<ApiGatewayOperation>> AddOperationsAsync(IEnumerable<ApiOperationInput> operations, string? zoneId = null, CancellationToken ct = default) =>
        SendListAsync<ApiGatewayOperation>(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "operations"), OperationsBody(operations), ct);

    /// <summary>Reads the saved operations and plans only the missing ones (read-only, never writes). Null when nothing is missing.</summary>
    public async Task<CloudflareChangePreview?> PreviewEnsureOperationsAsync(IEnumerable<ApiOperationInput> operations, string? zoneId = null, CancellationToken ct = default)
    {
        var (_, missing) = await SplitExistingAsync(operations, zoneId, ct).ConfigureAwait(false);
        return missing.Count == 0 ? null : PreviewAddOperations(missing, zoneId);
    }

    /// <summary>
    /// Idempotent add: saves only operations that are not saved yet (match on method, host and endpoint; the endpoint is compared literally,
    /// so use Cloudflare's placeholder form <c>{var1}</c>). Checks the write guard first, then reads, then writes once.
    /// </summary>
    public async Task<ApiOperationsEnsureResult> EnsureOperationsAsync(IEnumerable<ApiOperationInput> operations, string? zoneId = null, CancellationToken ct = default)
    {
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "operations"));
        var (existing, missing) = await SplitExistingAsync(operations, zoneId, ct).ConfigureAwait(false);
        IReadOnlyList<ApiGatewayOperation> added = missing.Count == 0 ? [] : await AddOperationsAsync(missing, zoneId, ct).ConfigureAwait(false);
        return new ApiOperationsEnsureResult(existing, added);
    }

    public CloudflareChangePreview PreviewDeleteOperation(string operationId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "api_gateway", "operations", operationId), null,
            $"Delete API operation {operationId} (its schema validation and labels go with it).");

    /// <summary>Deletes one operation. True when deleted, false when it did not exist (idempotent).</summary>
    public Task<bool> DeleteOperationAsync(string operationId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "api_gateway", "operations", operationId), null, ct);

    public CloudflareChangePreview PreviewDeleteOperations(IEnumerable<string> operationIds, string? zoneId = null)
    {
        var body = IdsBody(operationIds, "operation_id");
        return new("DELETE", ZonePath(zoneId, "api_gateway", "operations"), body, $"Delete {body.Count} API operation(s).");
    }

    /// <summary>Deletes several operations in one call (DELETE is idempotent and may be retried).</summary>
    public async Task DeleteOperationsAsync(IEnumerable<string> operationIds, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Delete, ZonePath(zoneId, "api_gateway", "operations"), IdsBody(operationIds, "operation_id"), ct).ConfigureAwait(false);

    private async Task<(IReadOnlyList<ApiGatewayOperation> Existing, List<ApiOperationInput> Missing)> SplitExistingAsync(IEnumerable<ApiOperationInput> operations, string? zoneId, CancellationToken ct)
    {
        var wanted = operations.ToList();
        foreach (var o in wanted) o.ToJson(); // validate before any request
        var saved = await ListOperationsAsync(new ApiOperationQuery { MaxItems = int.MaxValue }, zoneId, ct).ConfigureAwait(false);
        var byKey = saved.GroupBy(s => $"{s.Method.ToUpperInvariant()} {s.Host.ToLowerInvariant()}{s.Endpoint}").ToDictionary(g => g.Key, g => g.First());
        var existing = new List<ApiGatewayOperation>();
        var missing = new List<ApiOperationInput>();
        foreach (var o in wanted.DistinctBy(w => w.Key))
        {
            if (byKey.TryGetValue(o.Key, out var hit)) existing.Add(hit);
            else missing.Add(o);
        }
        return (existing, missing);
    }

    private static JsonArray OperationsBody(IEnumerable<ApiOperationInput> operations)
    {
        var list = operations.Select(o => (JsonNode?)o.ToJson()).ToArray();
        if (list.Length == 0) throw new ArgumentException("At least one operation is required.", nameof(operations));
        return new JsonArray(list);
    }

    // =====================================================================================================================
    // API Discovery
    // =====================================================================================================================

    public CloudflareChangePreview PreviewSetDiscoveryState(string discoveryId, string state, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "api_gateway", "discovery", "operations", discoveryId), new JsonObject { ["state"] = CheckDiscoveryState(state) },
            $"Mark discovered operation {discoveryId} as \"{state}\".");

    /// <summary>Marks a discovered operation as "review" or "ignored" (saving it is <see cref="AddOperationsAsync"/>).</summary>
    public async Task SetDiscoveryStateAsync(string discoveryId, string state, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Patch, ZonePath(zoneId, "api_gateway", "discovery", "operations", discoveryId), new JsonObject { ["state"] = CheckDiscoveryState(state) }, ct).ConfigureAwait(false);

    public CloudflareChangePreview PreviewSetDiscoveryStates(IReadOnlyDictionary<string, string> states, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "api_gateway", "discovery", "operations"), DiscoveryStatesBody(states), $"Change the state of {states.Count} discovered operation(s).");

    public async Task SetDiscoveryStatesAsync(IReadOnlyDictionary<string, string> states, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Patch, ZonePath(zoneId, "api_gateway", "discovery", "operations"), DiscoveryStatesBody(states), ct).ConfigureAwait(false);

    private static JsonObject DiscoveryStatesBody(IReadOnlyDictionary<string, string> states)
    {
        if (states.Count == 0) throw new ArgumentException("At least one state is required.", nameof(states));
        var body = new JsonObject();
        foreach (var (id, state) in states) body[id] = new JsonObject { ["state"] = CheckDiscoveryState(state) };
        return body;
    }

    private static string CheckDiscoveryState(string state) =>
        state is "review" or "ignored" ? state : throw new ArgumentException("State must be \"review\" or \"ignored\".", nameof(state));

    // =====================================================================================================================
    // Session identifier
    // =====================================================================================================================

    public CloudflareChangePreview PreviewSetSessionIdentifier(IEnumerable<ApiShieldAuthIdCharacteristic> characteristics, string? zoneId = null)
    {
        var body = SessionIdentifierBody(characteristics);
        return new("PUT", ZonePath(zoneId, "api_gateway", "configuration"), body, "Replace the session identifier characteristics of API Shield.");
    }

    /// <summary>Replaces the session identifier characteristics (1 to 10; PUT, idempotent).</summary>
    public Task<JsonElement> SetSessionIdentifierAsync(IEnumerable<ApiShieldAuthIdCharacteristic> characteristics, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(ZonePath(zoneId, "api_gateway", "configuration"), SessionIdentifierBody(characteristics), ct);

    private static JsonObject SessionIdentifierBody(IEnumerable<ApiShieldAuthIdCharacteristic> characteristics)
    {
        var list = characteristics.Distinct().Select(c => (JsonNode?)c.ToJson()).ToArray();
        if (list.Length is 0 or > 10) throw new ArgumentException("1 to 10 characteristics are required.", nameof(characteristics));
        return new JsonObject { ["auth_id_characteristics"] = new JsonArray(list) };
    }

    // =====================================================================================================================
    // Schema validation: schemas
    // =====================================================================================================================

    /// <summary>Plan of a schema upload. The body shows size and SHA-256 of the schema instead of its text.</summary>
    public CloudflareChangePreview PreviewUploadSchema(ApiShieldSchemaInput schema, ApiShieldSchemaUploadOptions? options = null, string? zoneId = null)
    {
        var (bytes, hash) = CheckSchema(schema, options);
        var body = new JsonObject
        {
            ["name"] = schema.Name, ["kind"] = schema.Kind, ["validation_enabled"] = schema.ValidationEnabled,
            ["source"] = $"[{bytes} bytes, sha256 {hash}]",
        };
        return new("POST", ZonePath(zoneId, "schema_validation", "schemas"), body,
            $"Upload schema \"{schema.Name}\" ({bytes} bytes), validation {(schema.ValidationEnabled ? "enabled" : "not enabled")}.");
    }

    /// <summary>
    /// Uploads a schema (JSON endpoint <c>schema_validation/schemas</c>). Local checks: name, kind <c>openapi_v3</c>, size, OpenAPI 3.x and allowed hosts
    /// (<paramref name="options"/>). Validation stays off unless <see cref="ApiShieldSchemaInput.ValidationEnabled"/> is set. Not retried (POST).
    /// Cloudflare cannot replace a schema's text: upload a new one, switch, then delete the old one.
    /// </summary>
    public Task<ApiShieldSchema> UploadSchemaAsync(ApiShieldSchemaInput schema, ApiShieldSchemaUploadOptions? options = null, string? zoneId = null, CancellationToken ct = default)
    {
        CheckSchema(schema, options);
        var body = new JsonObject { ["name"] = schema.Name, ["kind"] = schema.Kind, ["source"] = schema.Source, ["validation_enabled"] = schema.ValidationEnabled };
        return Api.PostAsync<ApiShieldSchema>(ZonePath(zoneId, "schema_validation", "schemas"), body, ct);
    }

    /// <summary>
    /// Idempotent upload by name: returns the existing schema with the same name (Created = false) or uploads it (Created = true).
    /// The text of an existing schema is not compared; give a new version a new name.
    /// </summary>
    public async Task<(ApiShieldSchema Schema, bool Created)> EnsureSchemaAsync(ApiShieldSchemaInput schema, ApiShieldSchemaUploadOptions? options = null, string? zoneId = null, CancellationToken ct = default)
    {
        CheckSchema(schema, options);
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "schema_validation", "schemas"));
        var existing = (await ListSchemasAsync(false, zoneId, ct).ConfigureAwait(false)).FirstOrDefault(s => s.Name == schema.Name);
        if (existing is not null) return (existing, false);
        try
        {
            return (await UploadSchemaAsync(schema, options, zoneId, ct).ConfigureAwait(false), true);
        }
        catch (CloudflareConflictException)
        {
            // Created concurrently by someone else: read it back instead of failing.
            var raced = (await ListSchemasAsync(false, zoneId, ct).ConfigureAwait(false)).FirstOrDefault(s => s.Name == schema.Name);
            if (raced is null) throw;
            return (raced, false);
        }
    }

    public CloudflareChangePreview PreviewSetSchemaValidationEnabled(string schemaId, bool enabled, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "schema_validation", "schemas", schemaId), new JsonObject { ["validation_enabled"] = enabled },
            $"{(enabled ? "Enable" : "Disable")} validation with schema {schemaId}.{(enabled ? " The zone/operation action decides what happens to failing requests." : "")}");

    /// <summary>Turns validation with a schema on or off. What a failing request causes is the action (<see cref="SetDefaultActionAsync"/>, per operation).</summary>
    public Task<ApiShieldSchema> SetSchemaValidationEnabledAsync(string schemaId, bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<ApiShieldSchema>(ZonePath(zoneId, "schema_validation", "schemas", schemaId), new JsonObject { ["validation_enabled"] = enabled }, ct);

    public CloudflareChangePreview PreviewDeleteSchema(string schemaId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "schema_validation", "schemas", schemaId), null, $"Delete schema {schemaId} (validation with it stops).");

    /// <summary>Deletes a schema. True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteSchemaAsync(string schemaId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "schema_validation", "schemas", schemaId), null, ct);

    private static (int Bytes, string Sha256) CheckSchema(ApiShieldSchemaInput schema, ApiShieldSchemaUploadOptions? options)
    {
        options ??= new();
        if (string.IsNullOrWhiteSpace(schema.Name)) throw new ArgumentException("Schema name is required.", nameof(schema));
        if (schema.Kind != "openapi_v3") throw new ArgumentException("Kind must be \"openapi_v3\".", nameof(schema));
        if (string.IsNullOrWhiteSpace(schema.Source)) throw new ArgumentException("Schema source is empty.", nameof(schema));
        var bytes = Encoding.UTF8.GetByteCount(schema.Source);
        if (bytes > options.MaxBytes) throw new ArgumentException($"Schema has {bytes} bytes, the limit is {options.MaxBytes}.", nameof(schema));

        JsonDocument? doc = null;
        try { doc = JsonDocument.Parse(schema.Source); }
        catch (JsonException) { /* YAML or invalid JSON: Cloudflare checks it */ }
        using (doc)
        {
            if (doc is not null)
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("openapi", out var v) || v.ValueKind != JsonValueKind.String || !(v.GetString() ?? "").StartsWith("3.", StringComparison.Ordinal))
                    throw new ArgumentException("Schema must be an OpenAPI 3.x document (\"openapi\": \"3.…\").", nameof(schema));
                if (options.AllowedHosts is { Count: > 0 } allowed) CheckHosts(root, allowed);
            }
            else if (options.AllowedHosts is { Count: > 0 })
                throw new ArgumentException("The host check needs a JSON schema; convert the YAML schema to JSON or drop AllowedHosts.", nameof(schema));
            else if (!schema.Source.Contains("openapi:", StringComparison.Ordinal))
                throw new ArgumentException("Schema is neither JSON nor a YAML OpenAPI document.", nameof(schema));
        }
        return (bytes, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(schema.Source))).ToLowerInvariant());
    }

    private static void CheckHosts(JsonElement root, IReadOnlyCollection<string> allowed)
    {
        var hosts = new List<string>();
        if (root.TryGetProperty("servers", out var servers) && servers.ValueKind == JsonValueKind.Array)
            foreach (var s in servers.EnumerateArray())
                if (s.TryGetProperty("url", out var u) && u.GetString() is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    hosts.Add(uri.Host.ToLowerInvariant());
        if (hosts.Count == 0) throw new ArgumentException("Schema has no absolute server URL (servers[].url); Cloudflare needs the host.", "schema");
        var set = allowed.Select(a => a.Trim().ToLowerInvariant()).ToHashSet();
        var foreign = hosts.Where(h => !set.Contains(h)).Distinct().ToList();
        if (foreign.Count > 0) throw new ArgumentException($"Schema names hosts that are not allowed: {string.Join(", ", foreign)}.", "schema");
    }

    // =====================================================================================================================
    // Schema validation: zone and operation settings
    // =====================================================================================================================

    /// <summary>
    /// Plan of the zone override. <c>"none"</c> switches schema validation off for the whole zone regardless of the per-operation actions (a loosening:
    /// let the application ask for a second approval); null removes the override.
    /// </summary>
    public CloudflareChangePreview PreviewSetOverrideAction(string? overrideAction, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "schema_validation", "settings"), OverrideBody(overrideAction),
            overrideAction is null ? "Remove the zone override of schema validation (operation actions apply again)." : "Override schema validation of the whole zone with \"none\" (validation is effectively off).");

    /// <summary>
    /// Sets or removes the zone override. <c>"none"</c> switches schema validation off for the whole zone and needs <paramref name="allowLoosen"/> (M-8, 0.7.1);
    /// null (remove the override) is always allowed.
    /// </summary>
    public Task<SchemaValidationSettings> SetOverrideActionAsync(string? overrideAction, string? zoneId = null, bool allowLoosen = false, CancellationToken ct = default)
    {
        var body = OverrideBody(overrideAction);
        if (overrideAction == "none") ResourceKit.Allow(allowLoosen, "the override \"none\" switches schema validation off for the whole zone", nameof(allowLoosen));
        return Api.PatchAsync<SchemaValidationSettings>(ZonePath(zoneId, "schema_validation", "settings"), body, ct);
    }

    private static JsonObject OverrideBody(string? overrideAction) =>
        overrideAction is null or "none"
            ? new JsonObject { ["validation_override_mitigation_action"] = overrideAction }
            : throw new ArgumentException("Override must be \"none\" or null.", nameof(overrideAction));

    /// <summary>Plan of a bulk change of per-operation actions (value null = inherit the zone default).</summary>
    public CloudflareChangePreview PreviewSetOperationActions(IReadOnlyDictionary<string, string?> actions, string? zoneId = null, bool allowBlock = false) =>
        new("PATCH", ZonePath(zoneId, "schema_validation", "settings", "operations"), OperationActionsBody(actions, allowBlock),
            $"Set the schema validation action of {actions.Count} operation(s).{ApiShieldActions.Warning(actions.Values.Contains(ApiShieldActions.Block) ? ApiShieldActions.Block : null)}");

    /// <inheritdoc cref="PreviewSetOperationActions"/>
    public async Task SetOperationActionsAsync(IReadOnlyDictionary<string, string?> actions, string? zoneId = null, bool allowBlock = false, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Patch, ZonePath(zoneId, "schema_validation", "settings", "operations"), OperationActionsBody(actions, allowBlock), ct).ConfigureAwait(false);

    public CloudflareChangePreview PreviewResetOperationAction(string operationId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "schema_validation", "settings", "operations", operationId), null, $"Remove the action of operation {operationId} (it inherits the zone default).");

    /// <summary>Removes the per-operation action (inherits the zone default). False when there was none.</summary>
    public Task<bool> ResetOperationActionAsync(string operationId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "schema_validation", "settings", "operations", operationId), null, ct);

    private static JsonObject OperationActionsBody(IReadOnlyDictionary<string, string?> actions, bool allowBlock)
    {
        if (actions.Count == 0) throw new ArgumentException("At least one operation is required.", nameof(actions));
        var body = new JsonObject();
        foreach (var (id, action) in actions)
            body[id] = new JsonObject { ["mitigation_action"] = action is null ? null : ApiShieldActions.Check(action, allowBlock, nameof(actions)) };
        return body;
    }

    // =====================================================================================================================
    // Token (JWT) validation
    // =====================================================================================================================

    /// <summary>Plan of a new token validation configuration. Keys appear as id/type/algorithm only.</summary>
    public CloudflareChangePreview PreviewCreateTokenValidationConfig(TokenValidationConfigInput config, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "token_validation", "config"), ConfigBody(config, redacted: true),
            $"Create token validation configuration \"{config.Title}\" with {config.Keys.Keys.Count} key(s){(config.Keys.ContainsSymmetricKey ? " (includes a symmetric secret key)" : "")}.");

    /// <summary>
    /// Creates a token validation configuration (Cloudflare: Enterprise with the API Shield add-on, otherwise <see cref="CloudflareNotEntitledException"/>).
    /// A configuration alone does not reject anything; a rule (<see cref="CreateTokenValidationRuleAsync"/>) does. Not retried (POST).
    /// </summary>
    public Task<TokenValidationConfig> CreateTokenValidationConfigAsync(TokenValidationConfigInput config, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<TokenValidationConfig>(ZonePath(zoneId, "token_validation", "config"), ConfigBody(config, redacted: false), ct);

    public CloudflareChangePreview PreviewUpdateTokenValidationConfig(string configId, string? title = null, string? description = null, IReadOnlyList<string>? tokenSources = null, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "token_validation", "config", configId), ConfigPatchBody(title, description, tokenSources), $"Change token validation configuration {configId}.");

    /// <summary>Changes title, description or token sources (only given values are sent).</summary>
    public Task<TokenValidationConfig> UpdateTokenValidationConfigAsync(string configId, string? title = null, string? description = null, IReadOnlyList<string>? tokenSources = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<TokenValidationConfig>(ZonePath(zoneId, "token_validation", "config", configId), ConfigPatchBody(title, description, tokenSources), ct);

    public CloudflareChangePreview PreviewReplaceTokenValidationKeys(string configId, JwtKeySet keys, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "token_validation", "config", configId, "credentials"), keys.ToRedactedCredentials(),
            $"Replace the keys of token validation configuration {configId} with {keys.Keys.Count} key(s). Tokens signed with a removed key fail validation.");

    /// <summary>
    /// Replaces the whole key set (key rotation). Warning: tokens signed with a key that is no longer in the set fail validation at once; add the new key
    /// first, wait until all tokens use it, then remove the old one.
    /// </summary>
    /// <returns>Cloudflare's answer with the key values replaced by <c>[redacted]</c> (id, type and algorithm stay).</returns>
    /// <remarks>
    /// M-8 (0.7.1): the current key ids are read first (after the guard check); a key set that drops a current key (or a configuration whose keys cannot be read)
    /// needs <paramref name="allowKeyRemoval"/>, because every token signed with the dropped key fails at once.
    /// </remarks>
    public async Task<JsonElement> ReplaceTokenValidationKeysAsync(string configId, JwtKeySet keys, string? zoneId = null, bool allowKeyRemoval = false, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var path = ZonePath(zoneId, "token_validation", "config", configId, "credentials");
        EnsureWritable(HttpMethod.Put, path);
        if (!allowKeyRemoval)
        {
            var current = await GetTokenValidationConfigAsync(configId, zoneId, ct).ConfigureAwait(false);
            var currentKids = current?.Credentials?.Keys?.Select(k => k.Kid).ToList();
            if (currentKids is null || currentKids.Any(k => k is null))
                throw new InvalidOperationException("Refused: the current keys of the configuration cannot be identified, so removed keys cannot be ruled out. Pass allowKeyRemoval: true deliberately.");
            var removed = currentKids.Where(k => keys.Keys.All(n => n.Kid != k)).ToList();
            if (removed.Count > 0)
                throw new InvalidOperationException($"Refused: the new key set drops the keys {string.Join(", ", removed)}; tokens signed with them fail at once. Add the new key first; pass allowKeyRemoval: true deliberately.");
        }
        return RedactKeys(await Api.PutAsync<JsonElement>(path, keys.ToCredentials(), ct).ConfigureAwait(false));
    }

    public CloudflareChangePreview PreviewDeleteTokenValidationConfig(string configId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "token_validation", "config", configId), null, $"Delete token validation configuration {configId} (rules that use it stop validating).");

    /// <summary>Deletes a configuration (rules that use it stop validating): needs <paramref name="allowRemoval"/> (M-8, 0.7.1). True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteTokenValidationConfigAsync(string configId, string? zoneId = null, bool allowRemoval = false, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowRemoval, "deleting a token validation configuration stops the validation of the rules that use it", nameof(allowRemoval));
        return DeleteIfExistsAsync(ZonePath(zoneId, "token_validation", "config", configId), null, ct);
    }

    /// <summary>Plan of a new token validation rule. <c>block</c> needs <paramref name="allowBlock"/> (requests without a valid token are rejected).</summary>
    public CloudflareChangePreview PreviewCreateTokenValidationRule(TokenValidationRuleInput rule, string? zoneId = null, bool allowBlock = false) =>
        new("POST", ZonePath(zoneId, "token_validation", "rules"), RuleBody(rule, allowBlock),
            $"Create token validation rule \"{rule.Title}\" (action {rule.Action}, {(rule.Enabled ? "enabled" : "disabled")}).{ApiShieldActions.Warning(rule.Action)}");

    /// <inheritdoc cref="PreviewCreateTokenValidationRule"/>
    public Task<TokenValidationRule> CreateTokenValidationRuleAsync(TokenValidationRuleInput rule, string? zoneId = null, bool allowBlock = false, CancellationToken ct = default) =>
        Api.PostAsync<TokenValidationRule>(ZonePath(zoneId, "token_validation", "rules"), RuleBody(rule, allowBlock), ct);

    public CloudflareChangePreview PreviewUpdateTokenValidationRule(string ruleId, TokenValidationRuleChange change, string? zoneId = null, bool allowBlock = false) =>
        new("PATCH", ZonePath(zoneId, "token_validation", "rules", ruleId), RuleChangeBody(change, allowBlock),
            $"Change token validation rule {ruleId}.{ApiShieldActions.Warning(change.Action)}");

    /// <inheritdoc cref="PreviewUpdateTokenValidationRule"/>
    public Task<TokenValidationRule> UpdateTokenValidationRuleAsync(string ruleId, TokenValidationRuleChange change, string? zoneId = null, bool allowBlock = false, CancellationToken ct = default) =>
        Api.PatchAsync<TokenValidationRule>(ZonePath(zoneId, "token_validation", "rules", ruleId), RuleChangeBody(change, allowBlock), ct);

    public CloudflareChangePreview PreviewDeleteTokenValidationRule(string ruleId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "token_validation", "rules", ruleId), null, $"Delete token validation rule {ruleId}.");

    /// <summary>Deletes a rule (its requests are no longer checked): needs <paramref name="allowRemoval"/> (M-8, 0.7.1). True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteTokenValidationRuleAsync(string ruleId, string? zoneId = null, bool allowRemoval = false, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowRemoval, "deleting a token validation rule stops checking the tokens of its requests", nameof(allowRemoval));
        return DeleteIfExistsAsync(ZonePath(zoneId, "token_validation", "rules", ruleId), null, ct);
    }

    private static JsonObject ConfigBody(TokenValidationConfigInput c, bool redacted)
    {
        if (string.IsNullOrWhiteSpace(c.Title) || c.Title.Length > 50) throw new ArgumentException("Title must be 1 to 50 characters.", nameof(c));
        if (c.Description is null || c.Description.Length > 500) throw new ArgumentException("Description must be at most 500 characters.", nameof(c));
        ArgumentNullException.ThrowIfNull(c.Keys);
        return new JsonObject
        {
            ["title"] = c.Title, ["description"] = c.Description, ["token_type"] = "JWT",
            ["token_sources"] = SourcesArray(c.TokenSources),
            ["credentials"] = redacted ? c.Keys.ToRedactedCredentials() : c.Keys.ToCredentials(),
        };
    }

    private static JsonObject ConfigPatchBody(string? title, string? description, IReadOnlyList<string>? sources)
    {
        var body = new JsonObject();
        if (title is not null) body["title"] = title.Length is > 0 and <= 50 ? title : throw new ArgumentException("Title must be 1 to 50 characters.", nameof(title));
        if (description is not null) body["description"] = description.Length <= 500 ? description : throw new ArgumentException("Description must be at most 500 characters.", nameof(description));
        if (sources is not null) body["token_sources"] = SourcesArray(sources);
        if (body.Count == 0) throw new ArgumentException("Nothing to change.");
        return body;
    }

    private static JsonArray SourcesArray(IReadOnlyList<string> sources)
    {
        if (sources is null || sources.Count is 0 or > 4) throw new ArgumentException("1 to 4 token sources are required.", nameof(sources));
        foreach (var s in sources)
        {
            if (!TokenSource.IsMatch(s ?? "")) throw new ArgumentException($"Token source \"{s}\" must look like http.request.headers[\"name\"][0] or http.request.cookies[\"name\"][0].", nameof(sources));
            if (s!.StartsWith("http.request.headers", StringComparison.Ordinal) && s != s.ToLowerInvariant())
                throw new ArgumentException($"Header names in token sources must be lowercase: \"{s}\".", nameof(sources));
        }
        return Arr(sources);
    }

    private static JsonObject RuleBody(TokenValidationRuleInput r, bool allowBlock)
    {
        if (string.IsNullOrWhiteSpace(r.Title) || r.Title.Length > 50) throw new ArgumentException("Title must be 1 to 50 characters.", nameof(r));
        if (r.Description is null || r.Description.Length > 500) throw new ArgumentException("Description must be at most 500 characters.", nameof(r));
        if (string.IsNullOrWhiteSpace(r.Expression)) throw new ArgumentException("Expression is required.", nameof(r));
        return new JsonObject
        {
            ["title"] = r.Title, ["description"] = r.Description, ["action"] = ApiShieldActions.Check(r.Action, allowBlock, nameof(r), allowNone: false),
            ["enabled"] = r.Enabled, ["expression"] = r.Expression, ["selector"] = Selector(r.IncludeHosts, r.ExcludeOperationIds) ?? new JsonObject(),
        };
    }

    private static JsonObject RuleChangeBody(TokenValidationRuleChange c, bool allowBlock)
    {
        var body = new JsonObject();
        if (c.Title is not null) body["title"] = c.Title.Length is > 0 and <= 50 ? c.Title : throw new ArgumentException("Title must be 1 to 50 characters.", nameof(c));
        if (c.Description is not null) body["description"] = c.Description.Length <= 500 ? c.Description : throw new ArgumentException("Description must be at most 500 characters.", nameof(c));
        if (c.Action is not null) body["action"] = ApiShieldActions.Check(c.Action, allowBlock, nameof(c), allowNone: false);
        if (c.Enabled is { } e) body["enabled"] = e;
        if (c.Expression is not null) body["expression"] = c.Expression;
        if (Selector(c.IncludeHosts, c.ExcludeOperationIds) is { } sel) body["selector"] = sel;
        var positions = (c.PositionIndex is null ? 0 : 1) + (c.PositionBefore is null ? 0 : 1) + (c.PositionAfter is null ? 0 : 1);
        if (positions > 1) throw new ArgumentException("Give at most one of PositionIndex, PositionBefore, PositionAfter.", nameof(c));
        if (c.PositionIndex is { } i) body["position"] = i >= 1 ? new JsonObject { ["index"] = i } : throw new ArgumentException("PositionIndex starts at 1.", nameof(c));
        if (c.PositionBefore is { } b) body["position"] = new JsonObject { ["before"] = b };
        if (c.PositionAfter is { } a) body["position"] = new JsonObject { ["after"] = a };
        if (body.Count == 0) throw new ArgumentException("Nothing to change.", nameof(c));
        return body;
    }

    private static JsonObject? Selector(IReadOnlyList<string>? hosts, IReadOnlyList<string>? excludeOperationIds)
    {
        if (hosts is null && excludeOperationIds is null) return null;
        var sel = new JsonObject();
        if (hosts is not null) sel["include"] = new JsonArray(new JsonObject { ["host"] = Arr(hosts) });
        if (excludeOperationIds is not null) sel["exclude"] = new JsonArray(new JsonObject { ["operation_ids"] = Arr(excludeOperationIds) });
        return sel;
    }

    private static readonly string[] KeyMaterial = ["n", "e", "x", "y", "k", "d", "p", "q", "dp", "dq", "qi", "oth"];

    /// <summary>Replaces key material in every JWK-like object (one with <c>kty</c>) anywhere in the answer, whatever its shape.</summary>
    private static JsonElement RedactKeys(JsonElement result)
    {
        if (result.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return result;
        var node = JsonNode.Parse(result.GetRawText());
        Redact(node);
        return JsonSerializer.SerializeToElement(node, CloudflareJson.Options);

        static void Redact(JsonNode? n)
        {
            switch (n)
            {
                case JsonObject o:
                    if (o.ContainsKey("kty"))
                        foreach (var name in KeyMaterial)
                            if (o.ContainsKey(name)) o[name] = "[redacted]";
                    foreach (var child in o.Select(p => p.Value).ToList()) Redact(child);
                    break;
                case JsonArray a:
                    foreach (var child in a) Redact(child);
                    break;
            }
        }
    }

    // =====================================================================================================================
    // Labels
    // =====================================================================================================================

    public CloudflareChangePreview PreviewCreateUserLabels(IEnumerable<(string Name, JsonElement? Metadata)> labels, string? zoneId = null)
    {
        var body = LabelsBody(labels);
        return new("POST", ZonePath(zoneId, "api_gateway", "labels", "user"), body, $"Create {body.Count} user label(s).");
    }

    /// <summary>Creates user labels (POST, not retried; a name that exists raises <see cref="CloudflareConflictException"/>; see <see cref="EnsureUserLabelAsync"/>).</summary>
    public Task<IReadOnlyList<ApiShieldLabel>> CreateUserLabelsAsync(IEnumerable<(string Name, JsonElement? Metadata)> labels, string? zoneId = null, CancellationToken ct = default) =>
        SendListAsync<ApiShieldLabel>(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "labels", "user"), LabelsBody(labels), ct);

    /// <summary>Idempotent: returns the user label with this name or creates it.</summary>
    public async Task<(ApiShieldLabel Label, bool Created)> EnsureUserLabelAsync(string name, JsonElement? metadata = null, string? zoneId = null, CancellationToken ct = default)
    {
        var body = LabelsBody([(name, metadata)]);
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "labels", "user"));
        var existing = (await ListLabelsAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(l => l.Name == name && l.Source is null or "user");
        if (existing is not null) return (existing, false);
        try
        {
            var created = await SendListAsync<ApiShieldLabel>(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "labels", "user"), body, ct).ConfigureAwait(false);
            return (created.FirstOrDefault() ?? new ApiShieldLabel { Name = name, Source = "user" }, true);
        }
        catch (CloudflareConflictException)
        {
            var raced = (await ListLabelsAsync(zoneId, ct).ConfigureAwait(false)).FirstOrDefault(l => l.Name == name);
            if (raced is null) throw;
            return (raced, false);
        }
    }

    public CloudflareChangePreview PreviewUpdateUserLabel(string name, JsonElement? metadata, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "api_gateway", "labels", "user", name), new JsonObject { ["metadata"] = MetadataNode(metadata) }, $"Replace the metadata of user label \"{name}\".");

    /// <summary>Replaces the metadata of a user label (PUT, idempotent).</summary>
    public Task<ApiShieldLabel> UpdateUserLabelAsync(string name, JsonElement? metadata, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<ApiShieldLabel>(ZonePath(zoneId, "api_gateway", "labels", "user", name), new JsonObject { ["metadata"] = MetadataNode(metadata) }, ct);

    public CloudflareChangePreview PreviewDeleteUserLabel(string name, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "api_gateway", "labels", "user", name), null, $"Delete user label \"{name}\" (it is removed from all operations).");

    /// <summary>Deletes a user label. True when deleted, false when it did not exist. Managed labels (cf-…) cannot be deleted.</summary>
    public Task<bool> DeleteUserLabelAsync(string name, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "api_gateway", "labels", "user", name), null, ct);

    public CloudflareChangePreview PreviewAddLabelsToOperations(IEnumerable<string> operationIds, IEnumerable<string>? userLabels = null, IEnumerable<string>? managedLabels = null, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "api_gateway", "operations", "labels"), OperationLabelsBody(operationIds, userLabels, managedLabels), "Attach labels to operations.");

    /// <summary>Attaches labels to operations (adds, keeps existing labels).</summary>
    public async Task AddLabelsToOperationsAsync(IEnumerable<string> operationIds, IEnumerable<string>? userLabels = null, IEnumerable<string>? managedLabels = null, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Post, ZonePath(zoneId, "api_gateway", "operations", "labels"), OperationLabelsBody(operationIds, userLabels, managedLabels), ct).ConfigureAwait(false);

    public CloudflareChangePreview PreviewRemoveLabelsFromOperations(IEnumerable<string> operationIds, IEnumerable<string>? userLabels = null, IEnumerable<string>? managedLabels = null, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "api_gateway", "operations", "labels"), OperationLabelsBody(operationIds, userLabels, managedLabels), "Remove labels from operations.");

    /// <summary>Removes labels from operations (DELETE with body, idempotent).</summary>
    public async Task RemoveLabelsFromOperationsAsync(IEnumerable<string> operationIds, IEnumerable<string>? userLabels = null, IEnumerable<string>? managedLabels = null, string? zoneId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Delete, ZonePath(zoneId, "api_gateway", "operations", "labels"), OperationLabelsBody(operationIds, userLabels, managedLabels), ct).ConfigureAwait(false);

    private static JsonArray LabelsBody(IEnumerable<(string Name, JsonElement? Metadata)> labels)
    {
        var list = new List<JsonNode?>();
        foreach (var (name, metadata) in labels)
        {
            if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Label name is required.", nameof(labels));
            if (name.StartsWith("cf-", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Names starting with \"cf-\" are reserved for managed labels.", nameof(labels));
            var o = new JsonObject { ["name"] = name };
            if (metadata is { } m) o["metadata"] = MetadataNode(m);
            list.Add(o);
        }
        if (list.Count == 0) throw new ArgumentException("At least one label is required.", nameof(labels));
        return new JsonArray([.. list]);
    }

    private static JsonNode? MetadataNode(JsonElement? metadata) =>
        metadata is { ValueKind: JsonValueKind.Object } m ? JsonNode.Parse(m.GetRawText())
        : metadata is null or { ValueKind: JsonValueKind.Undefined or JsonValueKind.Null } ? new JsonObject()
        : throw new ArgumentException("Label metadata must be a JSON object.", nameof(metadata));

    private static JsonObject OperationLabelsBody(IEnumerable<string> operationIds, IEnumerable<string>? userLabels, IEnumerable<string>? managedLabels)
    {
        var ids = operationIds.ToList();
        if (ids.Count == 0) throw new ArgumentException("At least one operation is required.", nameof(operationIds));
        var body = new JsonObject { ["selector"] = new JsonObject { ["include"] = new JsonObject { ["operation_ids"] = Arr(ids) } } };
        var user = userLabels?.ToList();
        var managed = managedLabels?.ToList();
        if (user is { Count: > 0 }) body["user"] = new JsonObject { ["labels"] = Arr(user) };
        if (managed is { Count: > 0 }) body["managed"] = new JsonObject { ["labels"] = Arr(managed) };
        if (user is not { Count: > 0 } && managed is not { Count: > 0 }) throw new ArgumentException("At least one label is required.");
        return body;
    }

    // =====================================================================================================================
    // mTLS: client certificates of the zone (Cloudflare-managed CA) and hostname associations
    // =====================================================================================================================

    /// <summary>Plan of a client certificate from a CSR. The CSR is public; a private key is refused locally.</summary>
    public CloudflareChangePreview PreviewCreateClientCertificate(string csrPem, int validityDays = 365, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "client_certificates"), ClientCertificateBody(csrPem, validityDays), $"Have Cloudflare sign a client certificate valid for {validityDays} days.");

    /// <summary>
    /// Lets the Cloudflare-managed CA sign a client certificate for a CSR (POST, not retried). The private key never leaves the caller:
    /// pass only the CSR (<c>-----BEGIN CERTIFICATE REQUEST-----</c>); input that contains a private key is refused before anything is sent.
    /// </summary>
    public Task<ZoneClientCertificate> CreateClientCertificateAsync(string csrPem, int validityDays = 365, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<ZoneClientCertificate>(ZonePath(zoneId, "client_certificates"), ClientCertificateBody(csrPem, validityDays), ct);

    public CloudflareChangePreview PreviewRevokeClientCertificate(string certificateId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "client_certificates", certificateId), null,
            $"Revoke client certificate {certificateId}. WARNING: devices using it fail mTLS at once; with a WAF rule on cf.tls_client_auth.cert_verified they are locked out.");

    /// <summary>
    /// Revokes a client certificate (status becomes pending_revocation, then revoked). Lock-out risk: every client that presents this certificate fails
    /// <c>cf.tls_client_auth.cert_verified</c> and is blocked by an mTLS rule. Issue and roll out the replacement first. <see cref="ReactivateClientCertificateAsync"/> undoes a revocation.
    /// </summary>
    /// <remarks>Needs <paramref name="allowRevoke"/> (M-8, 0.7.1): nothing is sent without it.</remarks>
    public async Task<ZoneClientCertificate> RevokeClientCertificateAsync(string certificateId, string? zoneId = null, bool allowRevoke = false, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowRevoke, "revoking a client certificate locks out every device that presents it", nameof(allowRevoke));
        return (await Api.SendAsync<ZoneClientCertificate>(HttpMethod.Delete, ZonePath(zoneId, "client_certificates", certificateId), null, ct).ConfigureAwait(false)).Result!;
    }

    public CloudflareChangePreview PreviewReactivateClientCertificate(string certificateId, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "client_certificates", certificateId), new JsonObject { ["reactivate"] = true }, $"Reactivate the revoked client certificate {certificateId}.");

    /// <summary>Reactivates a revoked client certificate.</summary>
    public Task<ZoneClientCertificate> ReactivateClientCertificateAsync(string certificateId, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<ZoneClientCertificate>(ZonePath(zoneId, "client_certificates", certificateId), new JsonObject { ["reactivate"] = true }, ct);

    /// <summary>Hostnames for which Cloudflare requests a client certificate. <paramref name="mtlsCertificateId"/> selects a customer CA (null = Cloudflare-managed CA).</summary>
    public Task<MtlsHostnameAssociations> GetHostnameAssociationsAsync(string? mtlsCertificateId = null, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<MtlsHostnameAssociations>(CloudflarePath.WithQuery(ZonePath(zoneId, "certificate_authorities", "hostname_associations"), ("mtls_certificate_id", mtlsCertificateId)), ct);

    /// <summary>Reads the current associations and plans the replacement (read-only). The summary lists added and removed hostnames.</summary>
    public async Task<CloudflareChangePreview> PreviewReplaceHostnameAssociationsAsync(IEnumerable<string> hostnames, string? mtlsCertificateId = null, string? zoneId = null, CancellationToken ct = default)
    {
        var body = AssociationsBody(hostnames, mtlsCertificateId, out var wanted);
        var current = await GetHostnameAssociationsAsync(mtlsCertificateId, zoneId, ct).ConfigureAwait(false);
        var (added, removed) = Diff(current.Hostnames, wanted);
        return new("PUT", ZonePath(zoneId, "certificate_authorities", "hostname_associations"), body,
            $"Replace the mTLS hostnames: add {Join(added)}, remove {Join(removed)}." +
            (removed.Count > 0 ? " WARNING: removed hostnames no longer ask for a client certificate; an mTLS rule on them then blocks every client." : ""));
    }

    /// <summary>
    /// Replaces the set of hostnames that ask for a client certificate (PUT, the whole set). Lock-out risk: a hostname that drops out of the set no longer
    /// requests a certificate, so <c>cf.tls_client_auth.cert_verified</c> is false for every client and an mTLS rule blocks all of them.
    /// With <paramref name="allowRemovals"/> = false (default) the method reads the current set first and refuses (nothing written) when a hostname would be removed.
    /// </summary>
    public async Task<MtlsHostnameAssociations> ReplaceHostnameAssociationsAsync(IEnumerable<string> hostnames, string? mtlsCertificateId = null, bool allowRemovals = false,
        string? zoneId = null, CancellationToken ct = default)
    {
        var path = ZonePath(zoneId, "certificate_authorities", "hostname_associations");
        var body = AssociationsBody(hostnames, mtlsCertificateId, out var wanted);
        EnsureWritable(HttpMethod.Put, path);
        if (!allowRemovals)
        {
            var current = await GetHostnameAssociationsAsync(mtlsCertificateId, zoneId, ct).ConfigureAwait(false);
            var (_, removed) = Diff(current.Hostnames, wanted);
            if (removed.Count > 0)
                throw new InvalidOperationException($"Refused: the change would remove the mTLS hostnames {Join(removed)} (lock-out risk). Pass allowRemovals: true deliberately.");
        }
        return await Api.PutAsync<MtlsHostnameAssociations>(path, body, ct).ConfigureAwait(false);
    }

    private static JsonObject ClientCertificateBody(string csrPem, int validityDays)
    {
        var csr = (csrPem ?? "").Trim();
        if (csr.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The input contains a private key. Pass the certificate signing request (CSR) only; the private key must not leave your system.", nameof(csrPem));
        if (!csr.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", StringComparison.Ordinal) && !csr.StartsWith("-----BEGIN NEW CERTIFICATE REQUEST-----", StringComparison.Ordinal))
            throw new ArgumentException("Expected a PEM certificate signing request (-----BEGIN CERTIFICATE REQUEST-----).", nameof(csrPem));
        if (validityDays is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(validityDays), "Validity must be 1 to 3650 days.");
        return new JsonObject { ["csr"] = csr, ["validity_days"] = validityDays };
    }

    private static JsonObject AssociationsBody(IEnumerable<string> hostnames, string? mtlsCertificateId, out HashSet<string> wanted)
    {
        wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hostnames)
        {
            var host = (h ?? "").Trim().ToLowerInvariant();
            if (host.Length is 0 or > 255 || host.Contains('/') || host.Contains(':') || host.Contains(' ')) throw new ArgumentException($"\"{h}\" is not a bare hostname.", nameof(hostnames));
            wanted.Add(host);
        }
        if (mtlsCertificateId is not null && mtlsCertificateId.Length != 36) throw new ArgumentException("mTLS certificate id must be 36 characters.", nameof(mtlsCertificateId));
        var body = new JsonObject { ["hostnames"] = Arr(wanted.Order(StringComparer.Ordinal)) };
        if (mtlsCertificateId is not null) body["mtls_certificate_id"] = mtlsCertificateId;
        return body;
    }

    private static (List<string> Added, List<string> Removed) Diff(IEnumerable<string> current, HashSet<string> wanted)
    {
        var now = new HashSet<string>(current.Select(c => c.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
        return (wanted.Where(w => !now.Contains(w)).Order(StringComparer.Ordinal).ToList(), now.Where(n => !wanted.Contains(n)).Order(StringComparer.Ordinal).ToList());
    }

    private static string Join(IReadOnlyCollection<string> items) => items.Count == 0 ? "none" : string.Join(", ", items);

    // =====================================================================================================================
    // helpers
    // =====================================================================================================================

    private static JsonArray IdsBody(IEnumerable<string> ids, string property)
    {
        var list = ids.Distinct().Select(id => (JsonNode?)new JsonObject { [property] = string.IsNullOrWhiteSpace(id) ? throw new ArgumentException("Empty id.", nameof(ids)) : id }).ToArray();
        if (list.Length == 0) throw new ArgumentException("At least one id is required.", nameof(ids));
        return new JsonArray(list);
    }

    private static JsonArray Arr(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

    private async Task<IReadOnlyList<T>> SendListAsync<T>(HttpMethod method, string path, object body, CancellationToken ct) =>
        (await Api.SendAsync<List<T>>(method, path, body, ct).ConfigureAwait(false)).Result ?? [];
}
