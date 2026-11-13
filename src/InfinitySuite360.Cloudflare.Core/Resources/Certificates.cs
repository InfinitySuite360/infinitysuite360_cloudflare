using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class OriginCaCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>PEM certificate.</summary>
    public string Certificate { get; init; } = "";
    public List<string> Hostnames { get; init; } = [];
    public string? RequestType { get; init; }
    public int RequestedValidity { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public string? Csr { get; init; }
}

public sealed class ClientCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Certificate { get; init; }
    public string? CommonName { get; init; }
    public string? Status { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
}

/// <summary>Settings of Universal SSL (the free edge certificate of a zone).</summary>
public sealed class UniversalSslSettings : CloudflareModel
{
    public bool Enabled { get; init; }
}

/// <summary>Validation state of one edge certificate pack.</summary>
public sealed class SslVerification : CloudflareModel
{
    public string? CertPackUuid { get; init; }
    /// <summary>"active", "pending_validation", "pending_issuance", "pending_deployment", …</summary>
    public string? CertificateStatus { get; init; }
    public string? VerificationType { get; init; }
    public string? ValidationMethod { get; init; }
    /// <summary>True when the validation has succeeded.</summary>
    public bool? VerificationStatus { get; init; }
    public string? BrandCheck { get; init; }
    public string? Signature { get; init; }
}

/// <summary>An edge certificate pack of a zone (Universal SSL, advanced or custom).</summary>
public sealed class CertificatePack : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"universal", "advanced" or "custom".</summary>
    public string Type { get; init; } = "";
    public List<string> Hosts { get; init; } = [];
    /// <summary>"active", "pending_validation", "pending_issuance", "pending_deployment", "expired", …</summary>
    public string Status { get; init; } = "";
    public string? CertificateAuthority { get; init; }
    public string? ValidationMethod { get; init; }
    public int? ValidityDays { get; init; }
    public bool? CloudflareBranding { get; init; }

    /// <summary>True when a certificate of the pack covers <paramref name="hostname"/> (wildcards cover one label).</summary>
    public bool Covers(string hostname) => CertificateHostMatcher.Covers(Hosts, hostname);
}

/// <summary>
/// Name depth of certificates: a wildcard covers exactly one label (<c>*.example.com</c> covers <c>www.example.com</c> but neither <c>example.com</c>
/// nor <c>a.b.example.com</c>). Universal SSL covers the zone and one level below it; deeper names need an advanced certificate.
/// </summary>
public static class CertificateHostMatcher
{
    /// <summary>True when one of the certificate hosts (exact or "*." wildcard) covers <paramref name="hostname"/>.</summary>
    public static bool Covers(IEnumerable<string> certificateHosts, string hostname)
    {
        var name = Normalize(hostname);
        if (name.Length == 0) return false;
        foreach (var raw in certificateHosts)
        {
            var host = Normalize(raw);
            if (host.Length == 0) continue;
            if (host == name) return true;
            if (host.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = host[1..]; // ".example.com"
                if (name.Length > suffix.Length && name.EndsWith(suffix, StringComparison.Ordinal))
                {
                    var label = name[..^suffix.Length];
                    if (!label.Contains('.') && label != "*") return true;
                }
            }
        }
        return false;
    }

    /// <summary>The names in <paramref name="hostnames"/> that no active pack of <paramref name="packs"/> covers.</summary>
    public static IReadOnlyList<string> Uncovered(IEnumerable<CertificatePack> packs, IEnumerable<string> hostnames)
    {
        var active = packs.Where(p => string.Equals(p.Status, "active", StringComparison.OrdinalIgnoreCase)).SelectMany(p => p.Hosts).ToList();
        return hostnames.Where(h => !Covers(active, h)).ToList();
    }

    private static string Normalize(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();
}

/// <summary>Origin CA certificates (origin server to Cloudflare), mTLS client certificates and the status of edge certificates.</summary>
public sealed class CertificatesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<OriginCaCertificate>> ListOriginCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<OriginCaCertificate>(CloudflarePath.WithQuery("certificates", ("zone_id", Zone(zoneId))), 50, ct);

    public Task<OriginCaCertificate> GetOriginCertificateAsync(string certificateId, CancellationToken ct = default) =>
        Api.GetAsync<OriginCaCertificate>(CloudflarePath.Of("certificates", certificateId), ct);

    /// <summary>
    /// Issues an Origin CA certificate. The private key stays with the caller: create <paramref name="csrPem"/> locally
    /// (for example with <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>).
    /// </summary>
    /// <param name="validityDays">7, 30, 90, 365, 730, 1095 or 5475.</param>
    /// <param name="requestType">"origin-rsa" or "origin-ecc".</param>
    public Task<OriginCaCertificate> CreateOriginCertificateAsync(string csrPem, IEnumerable<string> hostnames, int validityDays = 5475, string requestType = "origin-ecc", CancellationToken ct = default)
    {
        int[] allowed = [7, 30, 90, 365, 730, 1095, 5475];
        if (!allowed.Contains(validityDays)) throw new ArgumentOutOfRangeException(nameof(validityDays), "Allowed: 7, 30, 90, 365, 730, 1095, 5475.");
        return Api.PostAsync<OriginCaCertificate>("certificates", new { csr = csrPem, hostnames = hostnames.ToList(), requested_validity = validityDays, request_type = requestType }, ct);
    }

    public Task RevokeOriginCertificateAsync(string certificateId, CancellationToken ct = default) =>
        Api.DeleteAsync(CloudflarePath.Of("certificates", certificateId), ct);

    // ---- Edge certificates (Universal SSL, certificate packs) ----

    public Task<UniversalSslSettings> GetUniversalSslSettingsAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<UniversalSslSettings>(ZonePath(zoneId, "ssl", "universal", "settings"), ct);

    public Task<UniversalSslSettings> SetUniversalSslEnabledAsync(bool enabled, string? zoneId = null, CancellationToken ct = default) =>
        Api.PatchAsync<UniversalSslSettings>(ZonePath(zoneId, "ssl", "universal", "settings"), new { enabled }, ct);

    /// <summary>Validation state of the edge certificates (which step is pending).</summary>
    public async Task<List<SslVerification>> GetSslVerificationAsync(string? zoneId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<SslVerification>>(ZonePath(zoneId, "ssl", "verification"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Edge certificate packs of the zone, also those that are not active yet (<c>status=all</c>).</summary>
    public Task<IReadOnlyList<CertificatePack>> ListCertificatePacksAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<CertificatePack>(CloudflarePath.WithQuery(ZonePath(zoneId, "ssl", "certificate_packs"), ("status", "all")), 50, ct);

    /// <summary>Hostnames that no active certificate pack covers, for example names two levels below the zone with Universal SSL only.</summary>
    public async Task<IReadOnlyList<string>> FindUncoveredHostnamesAsync(IEnumerable<string> hostnames, string? zoneId = null, CancellationToken ct = default) =>
        CertificateHostMatcher.Uncovered(await ListCertificatePacksAsync(zoneId, ct).ConfigureAwait(false), hostnames);

    // ---- mTLS client certificates ----
    public Task<IReadOnlyList<ClientCertificate>> ListClientCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ClientCertificate>(ZonePath(zoneId, "client_certificates"), 50, ct);

    public Task<ClientCertificate> CreateClientCertificateAsync(string csrPem, int validityDays = 3650, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<ClientCertificate>(ZonePath(zoneId, "client_certificates"), new { csr = csrPem, validity_days = validityDays }, ct);

    public Task RevokeClientCertificateAsync(string certificateId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "client_certificates", certificateId), ct);
}
