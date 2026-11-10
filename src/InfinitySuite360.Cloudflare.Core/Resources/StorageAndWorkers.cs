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
public sealed class R2Client(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>S3-compatible endpoint of the account (for the AWS SDK and similar tools).</summary>
    public string S3Endpoint(string? accountId = null) => $"https://{Account(accountId)}.r2.cloudflarestorage.com";

    public async Task<IReadOnlyList<R2Bucket>> ListBucketsAsync(string? accountId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<R2BucketList>(AccountPath(accountId, "r2", "buckets"), ct).ConfigureAwait(false))?.Buckets ?? [];

    public Task<R2Bucket> GetBucketAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets", name), ct);

    /// <summary>Creates a bucket. <paramref name="locationHint"/> for example "weur", "eeur", "enam"; <paramref name="storageClass"/> "Standard" or "InfrequentAccess".</summary>
    public Task<R2Bucket> CreateBucketAsync(string name, string? locationHint = null, string? storageClass = null, string? accountId = null, CancellationToken ct = default)
    {
        // This endpoint expects camelCase in the body.
        var body = new JsonObject { ["name"] = name };
        if (locationHint is not null) body["locationHint"] = locationHint;
        if (storageClass is not null) body["storageClass"] = storageClass;
        return Api.PostAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets"), body, ct);
    }

    public Task DeleteBucketAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "r2", "buckets", name), ct);

    public Task<JsonElement> GetLifecycleAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "lifecycle"), ct);

    /// <summary>Sets lifecycle rules (body for example <c>{ "rules": [ … ] }</c>).</summary>
    public Task<JsonElement> PutLifecycleAsync(string bucket, object rules, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "lifecycle"), rules, ct);

    public Task<JsonElement> GetCorsAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "cors"), ct);

    public Task<JsonElement> PutCorsAsync(string bucket, object cors, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<JsonElement>(AccountPath(accountId, "r2", "buckets", bucket, "cors"), cors, ct);
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
}

public sealed class WorkerRoute : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Pattern { get; init; } = "";
    public string? Script { get; init; }
}

/// <summary>Workers scripts and routes.</summary>
public sealed class WorkersClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<List<WorkerScript>> ListScriptsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<WorkerScript>>(AccountPath(accountId, "workers", "scripts"), ct);

    /// <summary>Source of a Worker (multipart for module Workers).</summary>
    public Task<string> GetScriptContentAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        Api.GetRawAsync(AccountPath(accountId, "workers", "scripts", scriptName), ct);

    /// <summary>Uploads or replaces an ES module Worker.</summary>
    public Task<CloudflareResponse<WorkerScript>> UploadModuleAsync(string scriptName, string moduleSource, WorkerMetadata? metadata = null, string? accountId = null, CancellationToken ct = default)
    {
        var meta = metadata ?? new WorkerMetadata();
        var metaJson = JsonSerializer.Serialize(meta, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
        return Api.SendContentAsync<WorkerScript>(HttpMethod.Put, AccountPath(accountId, "workers", "scripts", scriptName), () =>
        {
            var form = new MultipartFormDataContent();
            form.Add(new StringContent(metaJson, Encoding.UTF8, "application/json"), "metadata");
            var module = new StringContent(moduleSource, Encoding.UTF8);
            module.Headers.ContentType = new MediaTypeHeaderValue("application/javascript+module");
            form.Add(module, meta.MainModule, meta.MainModule);
            return form;
        }, ct);
    }

    public Task DeleteScriptAsync(string scriptName, bool force = false, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(CloudflarePath.WithQuery(AccountPath(accountId, "workers", "scripts", scriptName), ("force", force ? "true" : null)), ct);

    public Task<List<WorkerRoute>> ListRoutesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<WorkerRoute>>(ZonePath(zoneId, "workers", "routes"), ct);

    /// <summary>Creates a route, for example pattern "example.com/api/*".</summary>
    public Task<WorkerRoute> CreateRouteAsync(string pattern, string scriptName, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<WorkerRoute>(ZonePath(zoneId, "workers", "routes"), new { pattern, script = scriptName }, ct);

    public Task DeleteRouteAsync(string routeId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "workers", "routes", routeId), ct);

    /// <summary>KV namespaces of the account.</summary>
    public Task<IReadOnlyList<JsonElement>> ListKvNamespacesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<JsonElement>(AccountPath(accountId, "storage", "kv", "namespaces"), 50, ct);
}
