using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed partial class DnsClient
{
    /// <summary>Plan of a new record (sends nothing).</summary>
    public CloudflareChangePreview PreviewCreate(DnsRecordInput record, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "dns_records"), Body(record), $"Create {record.Type} {record.Name} → {record.Content}{Proxy(record.Proxied)}.");

    public CloudflareChangePreview PreviewUpdate(string recordId, DnsRecordInput record, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "dns_records", recordId), Body(record), $"Replace record {recordId} with {record.Type} {record.Name} → {record.Content}{Proxy(record.Proxied)}.");

    public CloudflareChangePreview PreviewDelete(string recordId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "dns_records", recordId), null, $"Delete DNS record {recordId}.");

    /// <summary>Deletes a record. True when deleted, false when it did not exist (idempotent; <see cref="DeleteAsync"/> throws on 404).</summary>
    public Task<bool> DeleteIfExistsAsync(string recordId, string? zoneId = null, CancellationToken ct = default) =>
        base.DeleteIfExistsAsync(ZonePath(zoneId, "dns_records", recordId), (object?)null, ct);

    /// <summary>Reads the records with this name and type and plans the upsert (read-only). Null when the record is already as wanted.</summary>
    public async Task<CloudflareChangePreview?> PreviewUpsertAsync(DnsRecordInput record, string? zoneId = null, CancellationToken ct = default)
    {
        var existing = await FindAsync(record.Name, record.Type, zoneId, ct).ConfigureAwait(false);
        return Plan(record, existing, allowUnproxy: true, zoneId);
    }

    /// <summary>
    /// Upsert with guards: writes only on change, refuses several matches, and refuses to switch a proxied record to DNS-only (that publishes the origin
    /// address, which then can be attacked around Cloudflare) unless <paramref name="allowUnproxy"/> is true. The guard is checked before the preparing read.
    /// </summary>
    public async Task<(DnsRecord Record, bool Changed)> SafeUpsertAsync(DnsRecordInput record, bool allowUnproxy = false, string? zoneId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        Body(record);
        // N-3 (0.7.1): before the preparing read the guard is asked for the two possible plans (POST of a new record, PUT of a record below
        // dns_records/); the actual method and path of the plan are checked again before it is sent.
        EnsureAnyWritable((HttpMethod.Post, ZonePath(zoneId, "dns_records")), (HttpMethod.Put, ZonePath(zoneId, "dns_records") + "/"));
        var existing = await FindAsync(record.Name, record.Type, zoneId, ct).ConfigureAwait(false);
        var plan = Plan(record, existing, allowUnproxy, zoneId);
        if (plan is null) return (existing[0], false);
        EnsureWritable(new HttpMethod(plan.Method), plan.Path);
        var result = await Api.SendAsync<DnsRecord>(new HttpMethod(plan.Method), plan.Path, plan.Body, ct).ConfigureAwait(false);
        return (result.Result!, true);
    }

    private CloudflareChangePreview? Plan(DnsRecordInput record, IReadOnlyList<DnsRecord> existing, bool allowUnproxy, string? zoneId)
    {
        if (existing.Count > 1) throw new InvalidOperationException($"Several {record.Type} records exist for {record.Name}; update by ID instead.");
        if (existing.Count == 0) return PreviewCreate(record, zoneId);
        var current = existing[0];
        RefuseUnproxy(current, record.Proxied, allowUnproxy);
        var same = string.Equals(current.Content, record.Content, StringComparison.OrdinalIgnoreCase)
                   && (record.Proxied is null || record.Proxied == current.Proxied)
                   && record.Ttl == current.Ttl
                   && (record.Priority is null || record.Priority == current.Priority)
                   && (record.Comment is null || record.Comment == current.Comment)
                   && record.Data is null;
        if (same) return null;
        // M-6 (0.7.1): the update is a PUT (full replacement); without proxied Cloudflare would make the record DNS-only. Keep the current value.
        var preview = PreviewUpdate(current.Id, WithProxied(record, current), zoneId);
        return current.Proxied && record.Proxied == false ? preview with { Summary = preview.Summary + " WARNING: DNS-only publishes the origin address." } : preview;
    }

    private static void RefuseUnproxy(DnsRecord current, bool? proxied, bool allowUnproxy)
    {
        if (current.Proxied && proxied == false && !allowUnproxy)
            throw new InvalidOperationException($"Refused: {current.Name} is proxied; DNS-only publishes the origin address. Pass allowUnproxy: true deliberately (SafeUpsertAsync).");
    }

    /// <summary>The record with <see cref="DnsRecordInput.Proxied"/> taken from <paramref name="current"/> when it is not set.</summary>
    private static DnsRecordInput WithProxied(DnsRecordInput record, DnsRecord current) => record.Proxied is not null ? record : new DnsRecordInput
    {
        Type = record.Type, Name = record.Name, Content = record.Content, Ttl = record.Ttl, Proxied = current.Proxied, Priority = record.Priority,
        Comment = record.Comment, Tags = record.Tags, Data = record.Data,
    };

    private static JsonElement Body(DnsRecordInput record)
    {
        P1.Required(record.Type, nameof(record));
        P1.Required(record.Name, nameof(record), 255);
        return JsonSerializer.SerializeToElement(record, CloudflareJson.Options);
    }

    private static string Proxy(bool? proxied) => proxied switch { true => " (proxied)", false => " (DNS only)", null => "" };
}
