using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class R2Bucket : CloudflareModel
{
    public string Name { get; init; } = "";
    public DateTimeOffset? CreationDate { get; init; }
    public string? Location { get; init; }
    public string? StorageClass { get; init; }
    public string? Jurisdiction { get; init; }
}

internal sealed class R2BucketList
{
    public List<R2Bucket> Buckets { get; init; } = [];
}

/// <summary>R2 bucket management. Object access uses the S3-compatible API.</summary>
public sealed partial class R2Client(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>S3-compatible endpoint of the account (for the AWS SDK and similar tools).</summary>
    public string S3Endpoint(string? accountId = null) => $"https://{Account(accountId)}.r2.cloudflarestorage.com";

    public async Task<IReadOnlyList<R2Bucket>> ListBucketsAsync(string? accountId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<R2BucketList>(AccountPath(accountId, "r2", "buckets"), ct).ConfigureAwait(false))?.Buckets ?? [];

    public Task<R2Bucket> GetBucketAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets", name), ct);

    /// <summary>Creates a bucket. <paramref name="locationHint"/> for example "weur", "eeur", "enam"; <paramref name="storageClass"/> "Standard" or "InfrequentAccess".</summary>
    [Obsolete("No local checks and no preview. Use EnsureBucketAsync (0.7.0). Removed in 1.0.")]
    public Task<R2Bucket> CreateBucketAsync(string name, string? locationHint = null, string? storageClass = null, string? accountId = null, CancellationToken ct = default)
    {
        // This endpoint expects camelCase in the body.
        var body = new JsonObject { ["name"] = name };
        if (locationHint is not null) body["locationHint"] = locationHint;
        if (storageClass is not null) body["storageClass"] = storageClass;
        return Api.PostAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets"), body, ct);
    }

    /// <summary>Always refused since 0.7.1 (no switch in this signature): use <see cref="RemoveBucketAsync"/> with <c>allowDelete: true</c>.</summary>
    [Obsolete("Always refused since 0.7.1: deleting data needs an explicit switch. Use RemoveBucketAsync(name, allowDelete: true). Removed in 1.0.")]
    public async Task DeleteBucketAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        await RemoveBucketAsync(name, allowDelete: false, accountId, ct).ConfigureAwait(false);

    public Task<JsonElement> GetLifecycleAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "lifecycle"), ct);

    /// <summary>
    /// Sets lifecycle rules (body for example <c>{ "rules": [ … ] }</c>). Since 0.7.1 a rule that deletes objects (<c>deleteObjectsTransition</c>) is refused
    /// (use <see cref="SetLifecycleAsync"/> with <c>allowDeletion</c>).
    /// </summary>
    [Obsolete("Untyped. Rules that delete objects are refused since 0.7.1; use SetLifecycleAsync (0.7.0). Removed in 1.0.")]
    public Task<JsonElement> PutLifecycleAsync(string bucket, object rules, string? accountId = null, CancellationToken ct = default)
    {
        var node = ToNode(rules);
        if (node is JsonObject o && o["rules"] is JsonArray arr && arr.OfType<JsonObject>().Any(r => r["deleteObjectsTransition"] is not null && r["enabled"]?.GetValueKind() != JsonValueKind.False))
            P2.Allow(false, "a lifecycle rule deletes objects automatically (use SetLifecycleAsync with allowDeletion)", "allowDeletion");
        return Api.PutAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", BucketName(bucket), "lifecycle"), node, ct);
    }

    public Task<JsonElement> GetCorsAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "cors"), ct);

    /// <summary>
    /// Sets CORS rules (untyped). Since 0.7.1 the origins are checked like in <see cref="SetCorsAsync"/> without <c>allowAnyOrigin</c>: <c>*</c>, <c>https://*</c>
    /// and other wildcards that cover every site are refused.
    /// </summary>
    [Obsolete("Untyped. Wildcard origins are refused since 0.7.1; use SetCorsAsync (0.7.0). Removed in 1.0.")]
    public Task<JsonElement> PutCorsAsync(string bucket, object cors, string? accountId = null, CancellationToken ct = default)
    {
        var node = ToNode(cors);
        if (node is JsonObject o && o["rules"] is JsonArray arr)
            foreach (var origin in arr.OfType<JsonObject>().Select(r => r["allowed"]?["origins"]).OfType<JsonArray>().SelectMany(a => a).OfType<JsonValue>())
                CheckCorsOrigin(origin.TryGetValue<string>(out var text) ? text : "", allowAnyOrigin: false, allowHttp: true);
        return Api.PutAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", BucketName(bucket), "cors"), node, ct);
    }

    private static JsonNode? ToNode(object value) => value switch
    {
        null => throw new ArgumentNullException(nameof(value)),
        JsonNode n => n,
        string s => JsonNode.Parse(s),
        JsonElement e => JsonNode.Parse(e.GetRawText()),
        _ => JsonSerializer.SerializeToNode(value, value.GetType(), CloudflareJson.Options),
    };
}

public sealed class WorkerScript : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Etag { get; init; }
    public List<string> Handlers { get; init; } = [];
    public string? CompatibilityDate { get; init; }
    public string? UsageModel { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>Metadata for uploading an ES module Worker.</summary>
public sealed class WorkerMetadata
{
    [JsonPropertyName("main_module")] public string MainModule { get; init; } = "worker.js";
    [JsonPropertyName("compatibility_date")] public string CompatibilityDate { get; init; } = "2025-01-01";
    [JsonPropertyName("compatibility_flags")] public List<string>? CompatibilityFlags { get; init; }
    /// <summary>Bindings, for example <c>new { type = "plain_text", name = "TITLE", text = "…" }</c> or KV/R2/secrets.</summary>
    [JsonPropertyName("bindings")] public List<object>? Bindings { get; init; }
    /// <summary>Binding types to keep from the previous upload. <see cref="WorkersClient.UploadScriptAsync"/> defaults to <c>secret_text</c> and <c>secret_key</c>, so a redeploy does not drop the secrets.</summary>
    [JsonPropertyName("keep_bindings")] public List<string>? KeepBindings { get; init; }
}

public sealed class WorkerRoute : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Pattern { get; init; } = "";
    public string? Script { get; init; }
}

/// <summary>Workers scripts and routes.</summary>
public sealed partial class WorkersClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<List<WorkerScript>> ListScriptsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<WorkerScript>>(AccountPath(accountId, "workers", "scripts"), ct);

    /// <summary>Source of a Worker (multipart for module Workers).</summary>
    public Task<string> GetScriptContentAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        Api.GetRawAsync(AccountPath(accountId, "workers", "scripts", scriptName), ct);

    /// <summary>Always refused since 0.7.1 (no switch in this signature): use <see cref="UploadScriptAsync"/> with <c>allowDeploy: true</c>.</summary>
    [Obsolete("Always refused since 0.7.1: deploying code needs an explicit switch. Use UploadScriptAsync(..., allowDeploy: true). Removed in 1.0.")]
    public Task<CloudflareResponse<WorkerScript>> UploadModuleAsync(string scriptName, string moduleSource, WorkerMetadata? metadata = null, string? accountId = null, CancellationToken ct = default) =>
        UploadScriptAsync(scriptName, moduleSource, metadata, allowDeploy: false, accountId, ct);

    /// <summary>Always refused since 0.7.1 (no switch in this signature): use <see cref="RemoveScriptAsync"/> with <c>allowDelete: true</c>.</summary>
    [Obsolete("Always refused since 0.7.1: deleting a Worker needs an explicit switch. Use RemoveScriptAsync(name, allowDelete: true). Removed in 1.0.")]
    public async Task DeleteScriptAsync(string scriptName, bool force = false, string? accountId = null, CancellationToken ct = default) =>
        await RemoveScriptAsync(scriptName, allowDelete: false, force, allowForce: false, accountId, ct).ConfigureAwait(false);

    public Task<List<WorkerRoute>> ListRoutesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<WorkerRoute>>(ZonePath(zoneId, "workers", "routes"), ct);

    /// <summary>Creates a route, for example pattern "example.com/api/*".</summary>
    [Obsolete("No pattern checks. Use EnsureRouteAsync (0.7.0). Removed in 1.0.")]
    public Task<WorkerRoute> CreateRouteAsync(string pattern, string scriptName, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<WorkerRoute>(ZonePath(zoneId, "workers", "routes"), new { pattern, script = scriptName }, ct);

    [Obsolete("Use RemoveRouteAsync (idempotent, with preview) (0.7.0). Removed in 1.0.")]
    public Task DeleteRouteAsync(string routeId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "workers", "routes", routeId), ct);

    /// <summary>KV namespaces of the account.</summary>
    public Task<IReadOnlyList<JsonElement>> ListKvNamespacesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<JsonElement>(AccountPath(accountId, "storage", "kv", "namespaces"), 50, ct);
}
