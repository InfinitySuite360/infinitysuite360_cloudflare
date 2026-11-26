using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A CORS rule of an R2 bucket.</summary>
public sealed record R2CorsRule(IReadOnlyList<string> Origins, IReadOnlyList<string> Methods, IReadOnlyList<string>? Headers = null,
    IReadOnlyList<string>? ExposeHeaders = null, int? MaxAgeSeconds = null, string? Id = null);

/// <summary>
/// A lifecycle rule. Exactly one effect per rule is usual; <see cref="DeleteAfter"/> deletes objects (needs <c>allowDeletion</c>), the others only move
/// or clean up. Ages are whole seconds on the API; <see cref="TimeSpan"/>s are rounded down to seconds.
/// </summary>
public sealed record R2LifecycleRule(string Id, bool Enabled = true, string? Prefix = null, TimeSpan? DeleteAfter = null,
    TimeSpan? AbortIncompleteUploadsAfter = null, TimeSpan? InfrequentAccessAfter = null);

/// <summary>A custom domain of an R2 bucket (the bucket becomes publicly readable at this hostname).</summary>
public sealed class R2CustomDomain : CloudflareModel
{
    public string Domain { get; init; } = "";
    public bool Enabled { get; init; }
    public string? ZoneId { get; init; }
    public string? ZoneName { get; init; }
    public string? MinTls { get; init; }
    public JsonElement? Status { get; init; }
}

/// <summary>The r2.dev address of a bucket (for development; rate limited, no WAF or caching).</summary>
public sealed class R2ManagedDomain : CloudflareModel
{
    public string? BucketId { get; init; }
    public string? Domain { get; init; }
    public bool Enabled { get; init; }
}

/// <summary>
/// R2 beyond the base calls (developers.cloudflare.com/r2/ buckets/public-buckets, cors, object-lifecycles, platform/limits; retrieved 17.11.2026). Buckets are
/// private until a custom domain or the r2.dev address is enabled: both need <c>allowPublicAccess</c>. A wildcard CORS origin needs <c>allowAnyOrigin</c>, a lifecycle
/// rule that deletes objects <c>allowDeletion</c>, removing a custom domain <c>allowRemoval</c>, deleting a bucket <c>allowDelete</c> (and the bucket must be empty;
/// checked with one read after the guard). Buckets with a jurisdiction (eu, fedramp) need a header this client does not set: use <c>OpenApi</c> for them.
/// Token permission "Account: Workers R2 Storage: Edit" (reading "Read"). Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed partial class R2Client
{
    private static readonly Regex BucketNamePattern = P2.Rx(@"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$");
    private static readonly HashSet<string> CorsMethods = ["GET", "PUT", "POST", "DELETE", "HEAD"];
    private static readonly HashSet<string> StorageClasses = ["Standard", "InfrequentAccess"];
    private static readonly HashSet<string> LocationHints = ["wnam", "enam", "weur", "eeur", "apac", "oc"];
    private static readonly Regex OriginPattern = P2.Rx(@"^https?://[A-Za-z0-9*.\-]+(:[0-9]{1,5})?$");

    // ---- buckets ----

    public CloudflareChangePreview PreviewCreateBucket(string name, string? locationHint = null, string? storageClass = null, string? accountId = null) =>
        new("POST", AccountPath(accountId, "r2", "buckets"), BucketBody(name, locationHint, storageClass), $"Create private R2 bucket \"{name}\".");

    /// <summary>Returns the bucket with this name or creates it (private; survives a concurrent create).</summary>
    public async Task<(R2Bucket Bucket, bool Created)> EnsureBucketAsync(string name, string? locationHint = null, string? storageClass = null, string? accountId = null, CancellationToken ct = default)
    {
        var body = BucketBody(name, locationHint, storageClass);
        var path = AccountPath(accountId, "r2", "buckets");
        EnsureWritable(HttpMethod.Post, path);
        var existing = await GetOrNullAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets", name), ct).ConfigureAwait(false);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<R2Bucket>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = await GetOrNullAsync<R2Bucket>(AccountPath(accountId, "r2", "buckets", name), ct).ConfigureAwait(false);
            return again is null ? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"Bucket \"{name}\" is reported as existing but was not found." }]) : (again, false);
        }
    }

    public CloudflareChangePreview PreviewRemoveBucket(string name, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "r2", "buckets", BucketName(name)), null, $"Delete R2 bucket \"{name}\" (only possible when it is empty). WARNING: the name may be taken by someone else afterwards.");

    /// <summary>Deletes an empty bucket. Refused unless <paramref name="allowDelete"/> is true; a bucket with objects is refused (one read). False when it did not exist.</summary>
    public async Task<bool> RemoveBucketAsync(string name, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        P2.Allow(allowDelete, "deleting a bucket", nameof(allowDelete));
        var path = AccountPath(accountId, "r2", "buckets", BucketName(name));
        EnsureWritable(HttpMethod.Delete, path);
        try
        {
            var objects = await Api.SendAsync<JsonElement>(HttpMethod.Get, CloudflarePath.WithQuery(AccountPath(accountId, "r2", "buckets", name, "objects"), ("per_page", "1")), null, ct).ConfigureAwait(false);
            if (objects.Result.ValueKind == JsonValueKind.Array && objects.Result.GetArrayLength() > 0)
                throw new InvalidOperationException($"Refused: bucket \"{name}\" is not empty. Delete its objects first (through the S3 API).");
        }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return false; }
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ---- public access ----

    public async Task<List<R2CustomDomain>> ListCustomDomainsAsync(string bucket, string? accountId = null, CancellationToken ct = default)
    {
        var result = await P2.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "custom"), null, ct).ConfigureAwait(false);
        return P2.TryGet(result, "domains", out var d) ? P1.As<List<R2CustomDomain>>(CamelToSnake(d)) : [];
    }

    public CloudflareChangePreview PreviewAddCustomDomain(string bucket, string domain, string zoneId, bool allowPublicAccess = false, string? accountId = null)
    {
        P2.Allow(allowPublicAccess, "a custom domain makes every object of the bucket readable by anyone at that hostname", nameof(allowPublicAccess));
        return new("POST", AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "custom"), DomainBody(domain, zoneId, true, "1.2"),
            $"Serve bucket \"{bucket}\" publicly at {domain}. WARNING: all objects become readable by anyone.");
    }

    /// <summary>
    /// Adds a custom domain (the bucket becomes publicly readable there). Refused unless <paramref name="allowPublicAccess"/> is true. An existing domain is
    /// returned unchanged. The minimum TLS version defaults to 1.2.
    /// </summary>
    public async Task<(R2CustomDomain Domain, bool Created)> EnsureCustomDomainAsync(string bucket, string domain, string zoneId, bool allowPublicAccess = false, string minTls = "1.2", string? accountId = null, CancellationToken ct = default)
    {
        P2.Allow(allowPublicAccess, "a custom domain makes every object of the bucket readable by anyone at that hostname", nameof(allowPublicAccess));
        var body = DomainBody(domain, zoneId, true, minTls);
        var path = AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "custom");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await ListCustomDomainsAsync(bucket, accountId, ct).ConfigureAwait(false)).FirstOrDefault(d => string.Equals(d.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return (existing, false);
        var created = await P2.ResultAsync(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false);
        return (P1.As<R2CustomDomain>(CamelToSnake(created)), true);
    }

    /// <summary>Removes a custom domain from a bucket. Refused unless <paramref name="allowRemoval"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveCustomDomainAsync(string bucket, string domain, bool allowRemoval = false, string? accountId = null, CancellationToken ct = default)
    {
        P2.Allow(allowRemoval, "removing the custom domain stops serving the bucket at that hostname", nameof(allowRemoval));
        return DeleteIfExistsAsync(AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "custom", P1.Hostname(domain, nameof(domain))), null, ct);
    }

    public async Task<R2ManagedDomain> GetManagedDomainAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        P1.As<R2ManagedDomain>(CamelToSnake(await P2.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "managed"), null, ct).ConfigureAwait(false)));

    public CloudflareChangePreview PreviewSetManagedDomain(string bucket, bool enabled, string? accountId = null) =>
        new("PUT", AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "managed"), new JsonObject { ["enabled"] = enabled },
            enabled ? $"Enable the public r2.dev address of bucket \"{bucket}\". WARNING: all objects become readable by anyone." : $"Disable the r2.dev address of bucket \"{bucket}\".");

    /// <summary>Enables or disables the r2.dev address (PUT, idempotent). Enabling needs <paramref name="allowPublicAccess"/>; disabling is always allowed.</summary>
    public async Task<R2ManagedDomain> SetManagedDomainAsync(string bucket, bool enabled, bool allowPublicAccess = false, string? accountId = null, CancellationToken ct = default)
    {
        if (enabled) P2.Allow(allowPublicAccess, "the r2.dev address makes every object of the bucket readable by anyone", nameof(allowPublicAccess));
        var result = await P2.ResultAsync(Api, HttpMethod.Put, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "domains", "managed"), new JsonObject { ["enabled"] = enabled }, ct).ConfigureAwait(false);
        return P1.As<R2ManagedDomain>(CamelToSnake(result));
    }

    // ---- CORS ----

    /// <summary>The CORS rules of a bucket (empty when none are set).</summary>
    public async Task<IReadOnlyList<R2CorsRule>> GetCorsRulesAsync(string bucket, string? accountId = null, CancellationToken ct = default)
    {
        JsonElement result;
        try { result = await P2.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "cors"), null, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return []; }
        var rules = new List<R2CorsRule>();
        if (P2.TryGet(result, "rules", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var r in arr.EnumerateArray())
            {
                P2.TryGet(r, "allowed", out var allowed);
                rules.Add(new R2CorsRule(Strings(allowed, "origins"), Strings(allowed, "methods"), Strings(allowed, "headers"), Strings(r, "exposeHeaders"),
                    P2.TryGet(r, "maxAgeSeconds", out var age) && age.ValueKind == JsonValueKind.Number ? age.GetInt32() : null, P2.Str(r, "id")));
            }
        return rules;
    }

    public CloudflareChangePreview PreviewSetCors(string bucket, IReadOnlyList<R2CorsRule> rules, bool allowAnyOrigin = false, string? accountId = null) =>
        new("PUT", AccountPath(accountId, "r2", "buckets", BucketName(bucket), "cors"), CorsBody(rules, allowAnyOrigin),
            $"Replace the CORS rules of bucket \"{bucket}\" with {rules.Count} rule(s).");

    /// <summary>Replaces all CORS rules (PUT, idempotent). The origin <c>*</c> needs <paramref name="allowAnyOrigin"/>; origins have scheme, host and optional port, no path.</summary>
    public async Task SetCorsAsync(string bucket, IReadOnlyList<R2CorsRule> rules, bool allowAnyOrigin = false, string? accountId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Put, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "cors"), CorsBody(rules, allowAnyOrigin), ct).ConfigureAwait(false);

    /// <summary>Removes the CORS configuration. False when there was none.</summary>
    public Task<bool> DeleteCorsAsync(string bucket, string? accountId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(AccountPath(accountId, "r2", "buckets", BucketName(bucket), "cors"), null, ct);

    // ---- lifecycle ----

    /// <summary>The lifecycle rules of a bucket (empty when none are set).</summary>
    public async Task<IReadOnlyList<R2LifecycleRule>> GetLifecycleRulesAsync(string bucket, string? accountId = null, CancellationToken ct = default)
    {
        JsonElement result;
        try { result = await P2.ResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "lifecycle"), null, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return []; }
        var rules = new List<R2LifecycleRule>();
        if (P2.TryGet(result, "rules", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var r in arr.EnumerateArray())
            {
                TimeSpan? AgeOf(string member) => P2.TryGet(r, member, out var t) && P2.TryGet(t, "condition", out var c) && P2.TryGet(c, "maxAge", out var a) && a.ValueKind == JsonValueKind.Number ? TimeSpan.FromSeconds(a.GetInt64()) : null;
                TimeSpan? Transition() => P2.TryGet(r, "storageClassTransitions", out var t) && t.ValueKind == JsonValueKind.Array && t.GetArrayLength() > 0
                    && P2.TryGet(t[0], "condition", out var c) && P2.TryGet(c, "maxAge", out var a) && a.ValueKind == JsonValueKind.Number ? TimeSpan.FromSeconds(a.GetInt64()) : null;
                rules.Add(new R2LifecycleRule(P2.Str(r, "id") ?? "", !(P2.TryGet(r, "enabled", out var en) && en.ValueKind == JsonValueKind.False),
                    P2.TryGet(r, "conditions", out var cond) ? P2.Str(cond, "prefix") : null, AgeOf("deleteObjectsTransition"), AgeOf("abortMultipartUploadsTransition"), Transition()));
            }
        return rules;
    }

    public CloudflareChangePreview PreviewSetLifecycle(string bucket, IReadOnlyList<R2LifecycleRule> rules, bool allowDeletion = false, string? accountId = null) =>
        new("PUT", AccountPath(accountId, "r2", "buckets", BucketName(bucket), "lifecycle"), LifecycleBody(rules, allowDeletion),
            $"Replace the lifecycle rules of bucket \"{bucket}\" with {rules.Count} rule(s)." + (rules.Any(r => r.Enabled && r.DeleteAfter is not null) ? " WARNING: objects are deleted automatically." : ""));

    /// <summary>Replaces all lifecycle rules (PUT, idempotent). A rule that deletes objects needs <paramref name="allowDeletion"/>: it removes data without further prompt.</summary>
    public async Task SetLifecycleAsync(string bucket, IReadOnlyList<R2LifecycleRule> rules, bool allowDeletion = false, string? accountId = null, CancellationToken ct = default) =>
        await Api.SendAsync<JsonElement>(HttpMethod.Put, AccountPath(accountId, "r2", "buckets", BucketName(bucket), "lifecycle"), LifecycleBody(rules, allowDeletion), ct).ConfigureAwait(false);

    // ---- helpers ----

    private static string BucketName(string? name) => P2.Match(name, "bucket", BucketNamePattern, "3 to 63 characters: lowercase letters, digits and '-', starting and ending with a letter or digit");

    private static JsonObject BucketBody(string name, string? locationHint, string? storageClass)
    {
        var body = new JsonObject { ["name"] = BucketName(name) };
        if (locationHint is not null) body["locationHint"] = LocationHints.Contains(locationHint) ? locationHint : throw new ArgumentException("Hint: wnam, enam, weur, eeur, apac or oc.", nameof(locationHint));
        if (storageClass is not null) body["storageClass"] = StorageClasses.Contains(storageClass) ? storageClass : throw new ArgumentException("Storage class: Standard or InfrequentAccess.", nameof(storageClass));
        return body;
    }

    private static JsonObject DomainBody(string domain, string zoneId, bool enabled, string minTls) => new()
    {
        ["domain"] = P1.Hostname(domain, nameof(domain)),
        ["enabled"] = enabled,
        ["zoneId"] = P1.Required(zoneId, nameof(zoneId), 64),
        ["minTLS"] = minTls is "1.0" or "1.1" or "1.2" or "1.3" ? minTls : throw new ArgumentException("Minimum TLS: 1.0, 1.1, 1.2 or 1.3.", nameof(minTls)),
    };

    private static JsonObject CorsBody(IReadOnlyList<R2CorsRule> rules, bool allowAnyOrigin)
    {
        if (rules is null || rules.Count is < 1 or > 100) throw new ArgumentException("Between 1 and 100 rules.", nameof(rules));
        var arr = new JsonArray();
        foreach (var r in rules)
        {
            if (r.Origins.Count == 0 || r.Methods.Count == 0) throw new ArgumentException("A rule needs origins and methods.", nameof(rules));
            foreach (var o in r.Origins)
            {
                if (o == "*") P2.Allow(allowAnyOrigin, "the origin * lets every website call the bucket from a browser", nameof(allowAnyOrigin));
                else if (!OriginPattern.IsMatch(o)) throw new ArgumentException($"\"{o}\" is not an origin (scheme://host[:port], no path).", nameof(rules));
            }
            foreach (var m in r.Methods) if (!CorsMethods.Contains(m)) throw new ArgumentException($"\"{m}\" is not an allowed method (GET, PUT, POST, DELETE, HEAD).", nameof(rules));
            var allowed = new JsonObject { ["origins"] = P1.Arr(r.Origins), ["methods"] = P1.Arr(r.Methods) };
            if (r.Headers is { Count: > 0 }) allowed["headers"] = P1.Arr(r.Headers);
            var o2 = new JsonObject { ["allowed"] = allowed };
            if (r.Id is not null) o2["id"] = r.Id;
            if (r.ExposeHeaders is { Count: > 0 }) o2["exposeHeaders"] = P1.Arr(r.ExposeHeaders);
            if (r.MaxAgeSeconds is { } age) o2["maxAgeSeconds"] = age is >= 0 and <= 86_400 ? age : throw new ArgumentOutOfRangeException(nameof(rules), "Max age 0 to 86400 seconds.");
            arr.Add(o2);
        }
        return new JsonObject { ["rules"] = arr };
    }

    private static JsonObject LifecycleBody(IReadOnlyList<R2LifecycleRule> rules, bool allowDeletion)
    {
        if (rules is null || rules.Count > 1000) throw new ArgumentException("At most 1000 rules.", nameof(rules));
        if (rules.Select(r => r.Id).Distinct().Count() != rules.Count) throw new ArgumentException("Rule ids must be unique.", nameof(rules));
        var arr = new JsonArray();
        foreach (var r in rules)
        {
            if (string.IsNullOrWhiteSpace(r.Id) || r.Id.Length > 255) throw new ArgumentException("Every rule needs an id of at most 255 characters.", nameof(rules));
            if (r.DeleteAfter is null && r.AbortIncompleteUploadsAfter is null && r.InfrequentAccessAfter is null) throw new ArgumentException($"Rule \"{r.Id}\" does nothing.", nameof(rules));
            if (r.DeleteAfter is not null) P2.Allow(allowDeletion, $"rule \"{r.Id}\" deletes objects automatically", nameof(allowDeletion));
            var o = new JsonObject { ["id"] = r.Id, ["enabled"] = r.Enabled, ["conditions"] = new JsonObject { ["prefix"] = r.Prefix ?? "" } };
            if (r.DeleteAfter is { } d) o["deleteObjectsTransition"] = Age(d);
            if (r.AbortIncompleteUploadsAfter is { } a) o["abortMultipartUploadsTransition"] = Age(a);
            if (r.InfrequentAccessAfter is { } i)
                o["storageClassTransitions"] = new JsonArray(new JsonObject { ["condition"] = Age(i)["condition"]!.DeepClone(), ["storageClass"] = "InfrequentAccess" });
            arr.Add(o);
        }
        return new JsonObject { ["rules"] = arr };
    }

    private static JsonObject Age(TimeSpan age) =>
        new() { ["condition"] = new JsonObject { ["type"] = "Age", ["maxAge"] = age >= TimeSpan.FromSeconds(1) ? (long)age.TotalSeconds : throw new ArgumentOutOfRangeException(nameof(age), "At least one second.") } };

    private static List<string> Strings(JsonElement e, string name) =>
        P2.TryGet(e, name, out var arr) && arr.ValueKind == JsonValueKind.Array ? arr.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : [];

    // The domain endpoints answer in camelCase (zoneId, minTLS, bucketId); the models use the package's snake_case naming.
    private static JsonElement CamelToSnake(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Array)
            return JsonSerializer.SerializeToElement(e.EnumerateArray().Select(CamelToSnake).ToList());
        if (e.ValueKind != JsonValueKind.Object) return e;
        var o = new JsonObject();
        foreach (var p in e.EnumerateObject())
            o[p.Name switch { "zoneId" => "zone_id", "zoneName" => "zone_name", "minTLS" => "min_tls", "bucketId" => "bucket_id", _ => p.Name }] = JsonNode.Parse(p.Value.GetRawText());
        return JsonSerializer.SerializeToElement(o);
    }
}
