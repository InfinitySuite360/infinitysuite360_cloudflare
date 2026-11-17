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
        EnsureWritable(HttpMethod.Put, ZonePath(zoneId, "dns_records"));
        var existing = await FindAsync(record.Name, record.Type, zoneId, ct).ConfigureAwait(false);
        var plan = Plan(record, existing, allowUnproxy, zoneId);
        if (plan is null) return (existing[0], false);
        var result = await Api.SendAsync<DnsRecord>(new HttpMethod(plan.Method), plan.Path, plan.Body, ct).ConfigureAwait(false);
        return (result.Result!, true);
    }

    private CloudflareChangePreview? Plan(DnsRecordInput record, IReadOnlyList<DnsRecord> existing, bool allowUnproxy, string? zoneId)
    {
        if (existing.Count > 1) throw new InvalidOperationException($"Several {record.Type} records exist for {record.Name}; update by ID instead.");
        if (existing.Count == 0) return PreviewCreate(record, zoneId);
        var current = existing[0];
        if (current.Proxied && record.Proxied == false && !allowUnproxy)
            throw new InvalidOperationException($"Refused: {record.Name} is proxied; DNS-only publishes the origin address. Pass allowUnproxy: true deliberately.");
        var same = string.Equals(current.Content, record.Content, StringComparison.OrdinalIgnoreCase)
                   && (record.Proxied is null || record.Proxied == current.Proxied)
                   && record.Ttl == current.Ttl
                   && (record.Priority is null || record.Priority == current.Priority)
                   && (record.Comment is null || record.Comment == current.Comment)
                   && record.Data is null;
        if (same) return null;
        var preview = PreviewUpdate(current.Id, record, zoneId);
        return current.Proxied && record.Proxied == false ? preview with { Summary = preview.Summary + " WARNING: DNS-only publishes the origin address." } : preview;
    }

    private static JsonElement Body(DnsRecordInput record)
    {
        P1.Required(record.Type, nameof(record));
        P1.Required(record.Name, nameof(record), 255);
        return JsonSerializer.SerializeToElement(record, CloudflareJson.Options);
    }

    private static string Proxy(bool? proxied) => proxied switch { true => " (proxied)", false => " (DNS only)", null => "" };
}
