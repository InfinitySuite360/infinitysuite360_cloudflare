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

/// <summary>Origin CA certificates (origin server to Cloudflare) and mTLS client certificates.</summary>
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

    // ---- mTLS client certificates ----
    public Task<IReadOnlyList<ClientCertificate>> ListClientCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<ClientCertificate>(ZonePath(zoneId, "client_certificates"), 50, ct);

    public Task<ClientCertificate> CreateClientCertificateAsync(string csrPem, int validityDays = 3650, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<ClientCertificate>(ZonePath(zoneId, "client_certificates"), new { csr = csrPem, validity_days = validityDays }, ct);

    public Task RevokeClientCertificateAsync(string certificateId, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "client_certificates", certificateId), ct);
}
