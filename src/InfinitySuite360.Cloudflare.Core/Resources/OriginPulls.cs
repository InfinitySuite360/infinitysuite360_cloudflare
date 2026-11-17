using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// Client certificate and private key that Cloudflare presents to your origin (Authenticated Origin Pulls with your own certificate). Cloudflare needs the
/// key to present the certificate, so it has to be uploaded; this type keeps it private: <see cref="ToString"/>, previews, models and exception messages
/// show subject, expiry and SHA-256 of the certificate only, and the key is written into the request body alone.
/// </summary>
/// <remarks>
/// <see cref="FromPem"/> checks locally that the certificate is a PEM certificate without key material, that the key is a PEM private key and that both
/// belong together (RSA and ECDSA). Use a dedicated key pair for origin pulls, never the key of your edge or origin server certificate.
/// </remarks>
[DebuggerDisplay("OriginPullKeyPair({Subject}, key [redacted])")]
public sealed class OriginPullKeyPair : IDisposable
{
    // N-5 (0.7.1): the private key as a character buffer that Dispose overwrites; hidden from the debugger's variable views.
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private char[]? _privateKeyPem;

    private OriginPullKeyPair(string certificatePem, string privateKeyPem, string subject, DateTimeOffset notAfter, string sha256)
    {
        CertificatePem = certificatePem;
        _privateKeyPem = privateKeyPem.ToCharArray();
        Subject = subject;
        NotAfter = notAfter;
        Sha256 = sha256;
    }

    /// <summary>The public certificate (PEM).</summary>
    public string CertificatePem { get; }
    public string Subject { get; }
    public DateTimeOffset NotAfter { get; }
    /// <summary>SHA-256 fingerprint of the certificate (hex, lowercase).</summary>
    public string Sha256 { get; }

    /// <summary>Checks and wraps a certificate and its private key. Error messages never repeat the input.</summary>
    /// <param name="skipPairCheck">Skip the local check that key and certificate match (for algorithms .NET cannot load, such as ML-DSA).</param>
    public static OriginPullKeyPair FromPem(string certificatePem, string privateKeyPem, bool skipPairCheck = false)
    {
        var cert = (certificatePem ?? "").Trim();
        var key = (privateKeyPem ?? "").Trim();
        if (cert.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The certificate input contains a private key; pass certificate and key separately.", nameof(certificatePem));
        if (!cert.StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            throw new ArgumentException("Expected a PEM certificate (-----BEGIN CERTIFICATE-----).", nameof(certificatePem));
        if (!key.StartsWith("-----BEGIN", StringComparison.Ordinal) || !key.Contains("PRIVATE KEY-----", StringComparison.Ordinal) || key.Contains("CERTIFICATE", StringComparison.Ordinal))
            throw new ArgumentException("Expected a PEM private key (-----BEGIN PRIVATE KEY----- or EC/RSA PRIVATE KEY) without certificates.", nameof(privateKeyPem));
        if (key.Contains("ENCRYPTED", StringComparison.Ordinal))
            throw new ArgumentException("Cloudflare needs an unencrypted private key.", nameof(privateKeyPem));

        X509Certificate2 parsed;
        try { parsed = X509Certificate2.CreateFromPem(cert); }
        catch (CryptographicException) { throw new ArgumentException("The certificate cannot be read.", nameof(certificatePem)); }
        using (parsed)
        {
            if (!skipPairCheck)
            {
                try { using var pair = X509Certificate2.CreateFromPem(cert, key); }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException) { throw new ArgumentException("Certificate and private key do not belong together (or the algorithm is not supported; then pass skipPairCheck: true).", nameof(privateKeyPem)); }
            }
            var hash = Convert.ToHexString(parsed.GetCertHash(HashAlgorithmName.SHA256)).ToLowerInvariant();
            return new OriginPullKeyPair(cert, key, parsed.Subject, new DateTimeOffset(parsed.NotAfter.ToUniversalTime(), TimeSpan.Zero), hash);
        }
    }

    internal JsonObject ToBody() => new()
    {
        ["certificate"] = CertificatePem,
        ["private_key"] = _privateKeyPem is { } k ? new string(k) : throw new ObjectDisposedException(nameof(OriginPullKeyPair)),
    };

    /// <summary>Overwrites the private key buffer. Strings passed to <see cref="FromPem"/> cannot be wiped by .NET.</summary>
    public void Dispose()
    {
        if (_privateKeyPem is { } k) Array.Clear(k);
        _privateKeyPem = null;
    }

    internal JsonObject ToRedactedBody() => new()
    {
        ["certificate"] = $"[{CertificatePem.Length} characters, sha256 {Sha256}]",
        ["private_key"] = ResourceKit.Redacted,
    };

    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"OriginPullKeyPair({Subject}, expires {NotAfter:yyyy-MM-dd}, sha256 {Sha256}, key {ResourceKit.Redacted})");
}

/// <summary>Zone-level Authenticated Origin Pulls setting.</summary>
public sealed class OriginPullSetting : CloudflareModel
{
    public bool Enabled { get; init; }
}

/// <summary>An uploaded origin pull certificate (zone-level or per-hostname). The private key is removed from every answer.</summary>
public sealed class OriginPullCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"initializing", "pending_deployment", "pending_deletion", "active", "deleted", "deployment_timed_out", "deletion_timed_out".</summary>
    public string? Status { get; init; }
    public bool? Enabled { get; init; }
    public string? Certificate { get; init; }
    public string? Issuer { get; init; }
    public string? Signature { get; init; }
    public string? SerialNumber { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? UploadedOn { get; init; }
}

/// <summary>Association of a hostname with a per-hostname origin pull certificate.</summary>
public sealed class OriginPullHostname : CloudflareModel
{
    public string Hostname { get; init; } = "";
    public string? CertId { get; init; }
    /// <summary>true = the certificate is presented, false = disabled, null = association invalidated.</summary>
    public bool? Enabled { get; init; }
    public string? Status { get; init; }
    public string? CertStatus { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
}

/// <summary>Desired state of one per-hostname association: <see cref="Enabled"/> null invalidates it.</summary>
public sealed record OriginPullHostnameConfig(string Hostname, string CertId, bool? Enabled = true);

/// <summary>
/// Authenticated Origin Pulls (<c>origin_tls_client_auth</c>): Cloudflare presents a client certificate to your origin, which then accepts only requests
/// that came through Cloudflare. All plans (developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/, 17.11.2026); not with
/// Cloudflare Tunnel; only with SSL mode Full or Full (strict). Global (shared certificate), zone-level and per-hostname are independent levels.
/// </summary>
/// <remarks>
/// Lock-out protection: when the origin demands the client certificate, switching AOP off, invalidating a hostname or deleting the certificate in use makes
/// the origin reject every request from Cloudflare (outage). These calls therefore need <c>allowDisable: true</c>. Enabling and uploading are not guarded.
/// Token permission: "Zone: SSL and Certificates: Edit" (reading "Read").
/// </remarks>
public sealed class OriginPullsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Secret = ["private_key"];

    // ---- zone level ----

    public Task<OriginPullSetting> GetZoneSettingAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.GetAsync<OriginPullSetting>(ZonePath(zoneId, "origin_tls_client_auth", "settings"), ct);

    public CloudflareChangePreview PreviewSetZoneEnabled(bool enabled, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "origin_tls_client_auth", "settings"), new JsonObject { ["enabled"] = enabled },
            enabled ? "Present the zone's origin pull certificate to the origin (configure the origin to verify it)."
                    : "Stop presenting a client certificate to the origin. WARNING: an origin that requires it rejects every request from Cloudflare.");

    /// <summary>Switches zone-level AOP on or off. Off is refused unless <paramref name="allowDisable"/> is true.</summary>
    public Task<OriginPullSetting> SetZoneEnabledAsync(bool enabled, bool allowDisable = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (!enabled && !allowDisable) throw Refused("switching zone-level Authenticated Origin Pulls off");
        return Api.PutAsync<OriginPullSetting>(ZonePath(zoneId, "origin_tls_client_auth", "settings"), new JsonObject { ["enabled"] = enabled }, ct);
    }

    public Task<IReadOnlyList<OriginPullCertificate>> ListZoneCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<OriginPullCertificate>(Api, ZonePath(zoneId, "origin_tls_client_auth"), 50, ct, Secret);

    public Task<OriginPullCertificate> GetZoneCertificateAsync(string certificateId, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.SendStrippedAsync<OriginPullCertificate>(Api, HttpMethod.Get, ZonePath(zoneId, "origin_tls_client_auth", certificateId), null, ct, Secret);

    /// <summary>Plan of a zone-level certificate upload: the certificate appears as length and SHA-256, the key as [redacted].</summary>
    public CloudflareChangePreview PreviewUploadZoneCertificate(OriginPullKeyPair keyPair, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "origin_tls_client_auth"), keyPair.ToRedactedBody(),
            $"Upload a zone-level origin pull certificate ({keyPair.Subject}, expires {keyPair.NotAfter:yyyy-MM-dd}). Keep only one certificate active.");

    /// <summary>Uploads a zone-level certificate (POST, not retried). It is used once zone-level AOP is enabled; keep only one active.</summary>
    public Task<OriginPullCertificate> UploadZoneCertificateAsync(OriginPullKeyPair keyPair, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.SendStrippedAsync<OriginPullCertificate>(Api, HttpMethod.Post, ZonePath(zoneId, "origin_tls_client_auth"), keyPair.ToBody(), ct, Secret);

    public CloudflareChangePreview PreviewDeleteZoneCertificate(string certificateId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "origin_tls_client_auth", certificateId), null,
            $"Delete zone-level origin pull certificate {certificateId}. WARNING: Cloudflare falls back to the shared certificate; an origin that trusts only yours rejects every request.");

    /// <summary>Deletes a zone-level certificate; refused unless <paramref name="allowDisable"/> is true. False when it did not exist.</summary>
    public Task<bool> DeleteZoneCertificateAsync(string certificateId, bool allowDisable = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (!allowDisable) throw Refused("deleting a zone-level origin pull certificate");
        return DeleteIfExistsAsync(ZonePath(zoneId, "origin_tls_client_auth", certificateId), null, ct);
    }

    // ---- per hostname ----

    public Task<IReadOnlyList<OriginPullCertificate>> ListHostnameCertificatesAsync(string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<OriginPullCertificate>(Api, ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates"), 50, ct, Secret);

    public Task<OriginPullCertificate> GetHostnameCertificateAsync(string certificateId, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.SendStrippedAsync<OriginPullCertificate>(Api, HttpMethod.Get, ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates", certificateId), null, ct, Secret);

    public CloudflareChangePreview PreviewUploadHostnameCertificate(OriginPullKeyPair keyPair, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates"), keyPair.ToRedactedBody(),
            $"Upload a per-hostname origin pull certificate ({keyPair.Subject}, expires {keyPair.NotAfter:yyyy-MM-dd}); at most 10 per zone.");

    /// <summary>Uploads a per-hostname certificate (POST, not retried). Associate it with <see cref="SetHostnamesAsync"/>.</summary>
    public Task<OriginPullCertificate> UploadHostnameCertificateAsync(OriginPullKeyPair keyPair, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.SendStrippedAsync<OriginPullCertificate>(Api, HttpMethod.Post, ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates"), keyPair.ToBody(), ct, Secret);

    public CloudflareChangePreview PreviewDeleteHostnameCertificate(string certificateId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates", certificateId), null,
            $"Delete per-hostname origin pull certificate {certificateId}. WARNING: hostnames that use it stop presenting a client certificate.");

    /// <summary>Deletes a per-hostname certificate; refused unless <paramref name="allowDisable"/> is true. False when it did not exist.</summary>
    public Task<bool> DeleteHostnameCertificateAsync(string certificateId, bool allowDisable = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (!allowDisable) throw Refused("deleting a per-hostname origin pull certificate");
        return DeleteIfExistsAsync(ZonePath(zoneId, "origin_tls_client_auth", "hostnames", "certificates", certificateId), null, ct);
    }

    /// <summary>Hostname associations of the zone (optionally only with this status).</summary>
    public Task<IReadOnlyList<OriginPullHostname>> ListHostnamesAsync(string? status = null, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<OriginPullHostname>(Api, CloudflarePath.WithQuery(ZonePath(zoneId, "origin_tls_client_auth", "hostnames"), ("status", status)), 50, ct, Secret);

    public Task<OriginPullHostname> GetHostnameAsync(string hostname, string? zoneId = null, CancellationToken ct = default) =>
        ResourceKit.SendStrippedAsync<OriginPullHostname>(Api, HttpMethod.Get, ZonePath(zoneId, "origin_tls_client_auth", "hostnames", ResourceKit.Hostname(hostname, nameof(hostname))), null, ct, Secret);

    public CloudflareChangePreview PreviewSetHostnames(IEnumerable<OriginPullHostnameConfig> configs, string? zoneId = null)
    {
        var (body, disabled) = HostnamesBody(configs);
        return new("PUT", ZonePath(zoneId, "origin_tls_client_auth", "hostnames"), body,
            $"Set the origin pull certificate of {body["config"]!.AsArray().Count} hostname(s)." +
            (disabled.Count > 0 ? $" WARNING: {ResourceKit.Join(disabled)} stop presenting a client certificate; an origin that requires it rejects them." : ""));
    }

    /// <summary>Associates hostnames with certificates and enables them (PUT). Disabling or invalidating (Enabled false/null) needs <paramref name="allowDisable"/>.</summary>
    public Task<IReadOnlyList<OriginPullHostname>> SetHostnamesAsync(IEnumerable<OriginPullHostnameConfig> configs, bool allowDisable = false, string? zoneId = null, CancellationToken ct = default)
    {
        var (body, disabled) = HostnamesBody(configs);
        if (disabled.Count > 0 && !allowDisable) throw Refused($"disabling origin pulls for {ResourceKit.Join(disabled)}");
        return SendList(ZonePath(zoneId, "origin_tls_client_auth", "hostnames"), body, ct);
    }

    private async Task<IReadOnlyList<OriginPullHostname>> SendList(string path, JsonObject body, CancellationToken ct) =>
        await ResourceKit.SendStrippedAsync<List<OriginPullHostname>>(Api, HttpMethod.Put, path, body, ct, Secret).ConfigureAwait(false) ?? [];

    private static (JsonObject Body, List<string> Disabled) HostnamesBody(IEnumerable<OriginPullHostnameConfig> configs)
    {
        var arr = new JsonArray();
        var disabled = new List<string>();
        foreach (var c in configs)
        {
            var host = ResourceKit.Hostname(c.Hostname, nameof(configs));
            var o = new JsonObject { ["hostname"] = host, ["cert_id"] = ResourceKit.Required(c.CertId, nameof(configs), 64), ["enabled"] = c.Enabled };
            if (c.Enabled != true) disabled.Add(host);
            arr.Add(o);
        }
        if (arr.Count is 0 or > 100) throw new ArgumentException("1 to 100 hostnames are required.", nameof(configs));
        return (new JsonObject { ["config"] = arr }, disabled);
    }

    private static InvalidOperationException Refused(string what) =>
        new($"Refused: {what} makes an origin that requires the Cloudflare client certificate reject every request (outage). Pass allowDisable: true deliberately.");
}
