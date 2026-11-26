using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class KvNamespace : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public bool? SupportsUrlEncoding { get; init; }
}

public sealed class KvKey : CloudflareModel
{
    public string Name { get; init; } = "";
    /// <summary>Unix time (seconds) when the key expires.</summary>
    public long? Expiration { get; init; }
    public JsonElement? Metadata { get; init; }
}

/// <summary>One entry of a bulk write. <see cref="Value"/> is UTF-8 text, or base64 when <see cref="Base64"/> is true.</summary>
public sealed class KvBulkEntry
{
    public required string Key { get; init; }
    public required string Value { get; init; }
    public bool Base64 { get; init; }
    /// <summary>Unix time (seconds) when the key expires (at least 60 seconds ahead). Not together with <see cref="ExpirationTtl"/>.</summary>
    public long? Expiration { get; init; }
    /// <summary>Seconds until the key expires (at least 60).</summary>
    public int? ExpirationTtl { get; init; }
    /// <summary>JSON metadata of at most 1024 bytes.</summary>
    public JsonElement? Metadata { get; init; }
}

/// <summary>
/// Workers KV: namespaces, keys and values, bulk operations with the documented limits (key 512 bytes, value 25 MiB, metadata 1024 bytes, 10 000 pairs and
/// 100 MB per bulk write, 100 keys per bulk read; developers.cloudflare.com/kv/platform/limits/, retrieved 17.11.2026). Values are user data: they are never
/// put into previews, exceptions or logs by this package. Deleting a namespace needs <c>allowDelete</c> (and <c>allowNonEmpty</c> when it still has keys),
/// a bulk delete <c>allowBulkDelete</c>. Reading many keys with <see cref="GetBulkAsync"/> is a POST on the API, so the write guard applies to it.
/// Token permission "Account: Workers KV Storage: Edit" (reading "Read"). Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class KvClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private const int MaxKeyBytes = 512;
    private const int MaxValueBytes = 25 * 1024 * 1024;
    private const int MaxMetadataBytes = 1024;
    private const int MaxBulkPairs = 10_000;
    private const long MaxBulkBytes = 100L * 1000 * 1000;
    private const int MaxBulkRead = 100;

    // ---- namespaces ----

    public Task<IReadOnlyList<KvNamespace>> ListNamespacesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<KvNamespace>(AccountPath(accountId, "storage", "kv", "namespaces"), 100, ct);

    public Task<KvNamespace> GetNamespaceAsync(string namespaceId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<KvNamespace>(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId), ct);

    public CloudflareChangePreview PreviewCreateNamespace(string title, string? accountId = null) =>
        new("POST", AccountPath(accountId, "storage", "kv", "namespaces"), new JsonObject { ["title"] = Title(title) }, $"Create KV namespace \"{title}\".");

    /// <summary>Returns the namespace with this title or creates it (reads after the guard check; survives a concurrent create).</summary>
    public async Task<(KvNamespace Namespace, bool Created)> EnsureNamespaceAsync(string title, string? accountId = null, CancellationToken ct = default)
    {
        Title(title);
        var path = AccountPath(accountId, "storage", "kv", "namespaces");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await ListNamespacesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(n => n.Title == title);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<KvNamespace>(path, new JsonObject { ["title"] = title }, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListNamespacesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(n => n.Title == title);
            return again is null ? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"Namespace \"{title}\" is reported as existing but was not found." }]) : (again, false);
        }
    }

    /// <summary>Renames a namespace (PUT, idempotent).</summary>
    public Task<KvNamespace> RenameNamespaceAsync(string namespaceId, string title, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<KvNamespace>(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId), new JsonObject { ["title"] = Title(title) }, ct);

    public CloudflareChangePreview PreviewRemoveNamespace(string namespaceId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "storage", "kv", "namespaces", namespaceId), null,
            $"Delete KV namespace {namespaceId}. WARNING: every key in it is deleted and cannot be restored.");

    /// <summary>
    /// Deletes a namespace. Refused unless <paramref name="allowDelete"/> is true; a namespace that still has keys additionally needs
    /// <paramref name="allowNonEmpty"/> (checked with one read after the guard). False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveNamespaceAsync(string namespaceId, bool allowDelete = false, bool allowNonEmpty = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDelete, "deleting a namespace deletes all its keys", nameof(allowDelete));
        var path = AccountPath(accountId, "storage", "kv", "namespaces", namespaceId);
        EnsureWritable(HttpMethod.Delete, path);
        if (!allowNonEmpty)
        {
            IReadOnlyList<KvKey> keys;
            try { keys = await ListKeysAsync(namespaceId, null, 1, accountId, ct).ConfigureAwait(false); }
            catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return false; }
            ResourceKit.Allow(keys.Count == 0, $"namespace {namespaceId} still has keys", nameof(allowNonEmpty));
        }
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ---- keys ----

    /// <summary>Key names (with expiration and metadata) up to <paramref name="maxItems"/>, optionally below a prefix; pages of up to 1000 are followed by cursor.</summary>
    public async Task<IReadOnlyList<KvKey>> ListKeysAsync(string namespaceId, string? prefix = null, int maxItems = 1000, string? accountId = null, CancellationToken ct = default)
    {
        if (maxItems is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(maxItems), "Between 1 and 100000.");
        var keys = new List<KvKey>();
        string? cursor = null;
        // N-7 (0.7.1): stop on an empty page, on a repeated cursor and after a fixed number of pages, so a faulty answer cannot loop forever.
        var maxPages = maxItems / 10 + 2;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 0; page < maxPages; page++)
        {
            var path = CloudflarePath.WithQuery(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "keys"),
                ("prefix", prefix), ("limit", Math.Clamp(maxItems - keys.Count, 10, 1000).ToString()), ("cursor", cursor));
            var response = await Api.SendAsync<List<KvKey>>(HttpMethod.Get, path, null, ct).ConfigureAwait(false);
            var items = response.Result ?? [];
            keys.AddRange(items);
            cursor = response.ResultInfo?.Cursor;
            if (items.Count == 0 || string.IsNullOrEmpty(cursor) || !seen.Add(cursor) || keys.Count >= maxItems) break;
        }
        return keys.Take(maxItems).ToList();
    }

    /// <summary>The value of a key as text; null when the key does not exist.</summary>
    public async Task<string?> GetValueAsync(string namespaceId, string key, string? accountId = null, CancellationToken ct = default)
    {
        try { return await Api.GetRawAsync(CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "values"), Key(key)), ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>The metadata of a key; null when the key does not exist.</summary>
    public async Task<JsonElement?> GetMetadataAsync(string namespaceId, string key, string? accountId = null, CancellationToken ct = default)
    {
        try { return await Api.GetAsync<JsonElement>(CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "metadata"), Key(key)), ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>Plan of a write: key, size and expiry, never the value.</summary>
    public CloudflareChangePreview PreviewPutValue(string namespaceId, string key, string value, int? expirationTtl = null, long? expiration = null, JsonElement? metadata = null, string? accountId = null)
    {
        var bytes = ResourceKit.Utf8(value ?? throw new ArgumentNullException(nameof(value)));
        CheckPut(key, bytes, expirationTtl, expiration, metadata);
        return new("PUT", CloudflarePath.WithQuery(CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "values"), Key(key)),
                ("expiration_ttl", expirationTtl?.ToString()), ("expiration", expiration?.ToString())), new JsonObject { ["value_bytes"] = bytes },
            $"Write {bytes} bytes to key \"{key}\"{(expirationTtl is null && expiration is null ? "" : " with expiry")}. An existing value is overwritten.");
    }

    /// <summary>
    /// Writes a value (PUT, idempotent; one write per second per key). With <paramref name="allowOverwrite"/> = false an existing key is a
    /// <see cref="CloudflareConflictException"/> (one metadata read after the guard check; not atomic).
    /// </summary>
    public Task PutValueAsync(string namespaceId, string key, string value, int? expirationTtl = null, long? expiration = null, JsonElement? metadata = null, bool allowOverwrite = true, string? accountId = null, CancellationToken ct = default) =>
        PutValueAsync(namespaceId, key, Encoding.UTF8.GetBytes(value ?? throw new ArgumentNullException(nameof(value))), expirationTtl, expiration, metadata, allowOverwrite, accountId, ct);

    /// <summary>Writes binary data (see the text overload).</summary>
    public async Task PutValueAsync(string namespaceId, string key, byte[] value, int? expirationTtl = null, long? expiration = null, JsonElement? metadata = null, bool allowOverwrite = true, string? accountId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        CheckPut(key, value.Length, expirationTtl, expiration, metadata);
        var path = CloudflarePath.WithQuery(CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "values"), Key(key)),
            ("expiration_ttl", expirationTtl?.ToString()), ("expiration", expiration?.ToString()));
        if (!allowOverwrite)
        {
            EnsureWritable(HttpMethod.Put, path);
            if (await GetMetadataAsync(namespaceId, key, accountId, ct).ConfigureAwait(false) is not null)
                throw new CloudflareConflictException(HttpStatusCode.Conflict, "PUT", CloudflarePath.Normalize(path), [new CloudflareError { Message = $"Key \"{key}\" already exists." }]);
        }
        var metaJson = metadata is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) } m ? m.GetRawText() : null;
        await Api.SendContentAsync<JsonElement>(HttpMethod.Put, path, () =>
        {
            var form = new MultipartFormDataContent { { new ByteArrayContent(value), "value" } };
            if (metaJson is not null) form.Add(new StringContent(metaJson, Encoding.UTF8, "application/json"), "metadata");
            return form;
        }, ct).ConfigureAwait(false);
    }

    public CloudflareChangePreview PreviewDeleteKey(string namespaceId, string key, string? accountId = null) =>
        new("DELETE", CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "values"), Key(key)), null, $"Delete key \"{key}\".");

    /// <summary>Deletes a key (idempotent). False when the namespace or key did not exist.</summary>
    public Task<bool> DeleteKeyAsync(string namespaceId, string key, string? accountId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(CloudflarePath.Append(AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "values"), Key(key)), null, ct);

    // ---- bulk ----

    public CloudflareChangePreview PreviewPutBulk(string namespaceId, IReadOnlyList<KvBulkEntry> entries, string? accountId = null)
    {
        CheckBulk(entries);
        return new("PUT", AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "bulk"),
            new JsonObject { ["pairs"] = entries.Count, ["bytes"] = entries.Sum(e => (long)ResourceKit.Utf8(e.Value)) },
            $"Write {entries.Count} keys in one call. Existing values are overwritten.");
    }

    /// <summary>Writes up to 10 000 pairs (100 MB) in one call (PUT, idempotent).</summary>
    public async Task PutBulkAsync(string namespaceId, IReadOnlyList<KvBulkEntry> entries, string? accountId = null, CancellationToken ct = default)
    {
        CheckBulk(entries);
        var body = new JsonArray(entries.Select(e =>
        {
            var o = new JsonObject { ["key"] = e.Key, ["value"] = e.Value };
            if (e.Base64) o["base64"] = true;
            if (e.Expiration is { } x) o["expiration"] = x;
            if (e.ExpirationTtl is { } t) o["expiration_ttl"] = t;
            if (ResourceKit.Node(e.Metadata) is { } md) o["metadata"] = md;
            return (JsonNode?)o;
        }).ToArray());
        await Api.SendAsync<JsonElement>(HttpMethod.Put, AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "bulk"), body, ct).ConfigureAwait(false);
    }

    /// <summary>Reads up to 100 keys in one call (POST on the API, so the write guard applies). Missing keys are null.</summary>
    public async Task<IReadOnlyDictionary<string, string?>> GetBulkAsync(string namespaceId, IReadOnlyList<string> keys, string? accountId = null, CancellationToken ct = default)
    {
        if (keys is null || keys.Count is < 1 or > MaxBulkRead) throw new ArgumentException($"Between 1 and {MaxBulkRead} keys.", nameof(keys));
        foreach (var k in keys) Key(k);
        var result = await ResourceKit.ResultAsync(Api, HttpMethod.Post, AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "bulk", "get"),
            new JsonObject { ["keys"] = ResourceKit.Arr(keys), ["type"] = "text" }, ct).ConfigureAwait(false);
        var map = new Dictionary<string, string?>();
        if (ResourceKit.TryGet(result, "values", out var values) && values.ValueKind == JsonValueKind.Object)
            foreach (var p in values.EnumerateObject()) map[p.Name] = p.Value.ValueKind switch { JsonValueKind.Null => null, JsonValueKind.String => p.Value.GetString(), _ => p.Value.GetRawText() };
        return map;
    }

    public CloudflareChangePreview PreviewDeleteBulk(string namespaceId, IReadOnlyList<string> keys, string? accountId = null)
    {
        CheckKeys(keys);
        return new("POST", AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "bulk", "delete"), new JsonObject { ["keys"] = keys.Count },
            $"Delete {keys.Count} keys in one call. WARNING: the values cannot be restored.");
    }

    /// <summary>Deletes up to 10 000 keys in one call. Refused unless <paramref name="allowBulkDelete"/> is true. POST is never repeated automatically.</summary>
    public async Task DeleteBulkAsync(string namespaceId, IReadOnlyList<string> keys, bool allowBulkDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowBulkDelete, "a bulk delete removes many keys at once", nameof(allowBulkDelete));
        CheckKeys(keys);
        await Api.SendAsync<JsonElement>(HttpMethod.Post, AccountPath(accountId, "storage", "kv", "namespaces", namespaceId, "bulk", "delete"), ResourceKit.Arr(keys), ct).ConfigureAwait(false);
    }

    // ---- checks ----

    private static string Title(string? title) => ResourceKit.Required(title, nameof(title), 512);

    private static string Key(string? key)
    {
        if (string.IsNullOrEmpty(key) || ResourceKit.Utf8(key) > MaxKeyBytes) throw new ArgumentException($"A key has 1 to {MaxKeyBytes} bytes.", nameof(key));
        if (key is "." or "..") throw new ArgumentException("\".\" and \"..\" are not allowed as key names.", nameof(key));
        return key;
    }

    private static void CheckKeys(IReadOnlyList<string> keys)
    {
        if (keys is null || keys.Count is < 1 or > MaxBulkPairs) throw new ArgumentException($"Between 1 and {MaxBulkPairs} keys.", nameof(keys));
        foreach (var k in keys) Key(k);
    }

    private static void CheckPut(string key, int bytes, int? ttl, long? expiration, JsonElement? metadata)
    {
        Key(key);
        if (bytes > MaxValueBytes) throw new ArgumentException("A value may have at most 25 MiB.", "value");
        if (ttl is not null && expiration is not null) throw new ArgumentException("Use either an expiration or a TTL.", nameof(ttl));
        if (ttl is < 60) throw new ArgumentOutOfRangeException(nameof(ttl), "The TTL is at least 60 seconds.");
        if (expiration is not null && expiration < DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60) throw new ArgumentOutOfRangeException(nameof(expiration), "The expiration is at least 60 seconds ahead.");
        if (metadata is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) } m && ResourceKit.Utf8(m.GetRawText()) > MaxMetadataBytes)
            throw new ArgumentException("Metadata may have at most 1024 bytes.", nameof(metadata));
    }

    private static void CheckBulk(IReadOnlyList<KvBulkEntry> entries)
    {
        if (entries is null || entries.Count is < 1 or > MaxBulkPairs) throw new ArgumentException($"Between 1 and {MaxBulkPairs} entries.", nameof(entries));
        long total = 0;
        foreach (var e in entries)
        {
            CheckPut(e.Key, e.Base64 ? e.Value.Length : ResourceKit.Utf8(e.Value), e.ExpirationTtl, e.Expiration, e.Metadata);
            total += ResourceKit.Utf8(e.Key) + ResourceKit.Utf8(e.Value);
        }
        if (total > MaxBulkBytes) throw new ArgumentException("A bulk write has at most 100 MB.", nameof(entries));
    }
}
