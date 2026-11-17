using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class DnsRecord : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Type { get; init; } = "";
    public string Name { get; init; } = "";
    public string Content { get; init; } = "";
    public bool Proxied { get; init; }
    public bool Proxiable { get; init; }
    /// <summary>1 = automatic.</summary>
    public int Ttl { get; init; } = 1;
    public int? Priority { get; init; }
    public string? Comment { get; init; }
    public List<string> Tags { get; init; } = [];
    /// <summary>Structured data (CAA, SRV, …).</summary>
    public JsonElement? Data { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>Input for creating or replacing a DNS record.</summary>
public sealed class DnsRecordInput
{
    public required string Type { get; init; }
    public required string Name { get; init; }
    public string? Content { get; init; }
    public int Ttl { get; init; } = 1;
    public bool? Proxied { get; init; }
    public int? Priority { get; init; }
    public string? Comment { get; init; }
    public List<string>? Tags { get; init; }
    public object? Data { get; init; }

    /// <summary>CAA record, for example <c>Caa("example.com", "issue", "letsencrypt.org")</c>.</summary>
    public static DnsRecordInput Caa(string name, string tag, string value, int flags = 0) =>
        new() { Type = "CAA", Name = name, Data = new { flags, tag, value } };
}

public sealed class DnsRecordQuery
{
    public string? Type { get; init; }
    public string? Name { get; init; }
    public string? Content { get; init; }
    public bool? Proxied { get; init; }
    public string? Comment { get; init; }
}

/// <summary>DNS records of a zone.</summary>
public sealed partial class DnsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<DnsRecord>> ListAsync(DnsRecordQuery? query = null, string? zoneId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(ZonePath(zoneId, "dns_records"),
            ("type", query?.Type), ("name", query?.Name), ("content", query?.Content),
            ("proxied", CloudflarePath.Bool(query?.Proxied)), ("comment", query?.Comment));
        return Api.ListAllToListAsync<DnsRecord>(path, 500, ct);
    }

    public Task<DnsRecord> GetAsync(string recordId, string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<DnsRecord>(ZonePath(zoneId, "dns_records", recordId), ct);

    /// <summary>Records with exactly this name (and optionally type).</summary>
    public Task<IReadOnlyList<DnsRecord>> FindAsync(string name, string? type = null, string? zoneId = null, CancellationToken ct = default) =>
        ListAsync(new DnsRecordQuery { Name = name, Type = type }, zoneId, ct);

    public Task<DnsRecord> CreateAsync(DnsRecordInput record, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<DnsRecord>(ZonePath(zoneId, "dns_records"), record, ct);

    /// <summary>
    /// Replaces a record completely (PUT). Since 0.7.1 the current record is read first (after the guard check): switching a proxied record to DNS-only is
    /// refused (use <see cref="SafeUpsertAsync"/> with <c>allowUnproxy</c>), and <see cref="DnsRecordInput.Proxied"/> = null keeps the current value instead of
    /// letting Cloudflare's default (DNS-only) apply.
    /// </summary>
    public async Task<DnsRecord> UpdateAsync(string recordId, DnsRecordInput record, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        var path = ZonePath(zoneId, "dns_records", recordId);
        EnsureWritable(HttpMethod.Put, path);
        var current = await GetAsync(recordId, zoneId, ct).ConfigureAwait(false);
        RefuseUnproxy(current, record.Proxied, allowUnproxy: false);
        return await Api.PutAsync<DnsRecord>(path, WithProxied(record, current), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Partial update (PATCH), for example <c>new { proxied = true }</c>. Since 0.7.1 a change with <c>proxied: false</c> reads the record first and is refused
    /// when it is proxied (use <see cref="SafeUpsertAsync"/> with <c>allowUnproxy</c>).
    /// </summary>
    public async Task<DnsRecord> PatchAsync(string recordId, object changes, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(changes);
        var path = ZonePath(zoneId, "dns_records", recordId);
        var node = changes as JsonNode ?? JsonSerializer.SerializeToNode(changes, changes.GetType(), CloudflareJson.Options);
        if (node is JsonObject o && o["proxied"] is JsonValue v && v.TryGetValue<bool>(out var proxied) && !proxied)
        {
            EnsureWritable(HttpMethod.Patch, path);
            RefuseUnproxy(await GetAsync(recordId, zoneId, ct).ConfigureAwait(false), false, allowUnproxy: false);
        }
        return await Api.PatchAsync<DnsRecord>(path, node, ct).ConfigureAwait(false);
    }

    public Task DeleteAsync(string recordId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "dns_records", recordId), ct);

    /// <summary>
    /// Create or update: when exactly one record with this name and type exists it is replaced, otherwise a new one is created.
    /// With several matches the call fails instead of silently picking one. Since 0.7.1 this is <see cref="SafeUpsertAsync"/> without <c>allowUnproxy</c>:
    /// nothing is written when the record is already as wanted, and a proxied record is never switched to DNS-only.
    /// </summary>
    public async Task<DnsRecord> UpsertAsync(DnsRecordInput record, string? zoneId = null, CancellationToken ct = default) =>
        (await SafeUpsertAsync(record, allowUnproxy: false, zoneId, ct).ConfigureAwait(false)).Record;

    /// <summary>Exports the zone file in BIND format.</summary>
    public Task<string> ExportAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetRawAsync(ZonePath(zoneId, "dns_records", "export"), ct);
}
