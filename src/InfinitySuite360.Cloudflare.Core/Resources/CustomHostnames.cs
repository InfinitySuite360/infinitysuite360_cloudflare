using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A DNS record or HTTP file that proves control of a custom hostname or its certificate.</summary>
public sealed class CustomHostnameValidationRecord : CloudflareModel
{
    public string? TxtName { get; init; }
    public string? TxtValue { get; init; }
    public string? HttpUrl { get; init; }
    public string? HttpBody { get; init; }
    public string? CnameTarget { get; init; }
    public string? Cname { get; init; }
    public List<string>? Emails { get; init; }
    public string? Status { get; init; }
}

/// <summary>Certificate state of a custom hostname.</summary>
public sealed class CustomHostnameSsl : CloudflareModel
{
    public string? Id { get; init; }
    /// <summary>"initializing", "pending_validation", "pending_issuance", "pending_deployment", "active", "expired", "deleted", …</summary>
    public string? Status { get; init; }
    public string? Method { get; init; }
    public string? Type { get; init; }
    public string? BundleMethod { get; init; }
    public string? CertificateAuthority { get; init; }
    public bool? Wildcard { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public List<CustomHostnameValidationRecord>? ValidationRecords { get; init; }
    public List<JsonElement>? ValidationErrors { get; init; }
    public JsonElement? Settings { get; init; }
}

public sealed class CustomHostnameOwnershipVerification : CloudflareModel
{
    public string? Type { get; init; }
    public string? Name { get; init; }
    public string? Value { get; init; }
}

public sealed class CustomHostnameOwnershipVerificationHttp : CloudflareModel
{
    public string? HttpUrl { get; init; }
    public string? HttpBody { get; init; }
}

/// <summary>A custom hostname (Cloudflare for SaaS). Uploaded keys are never modelled; <c>custom_key</c> is removed from every answer.</summary>
public sealed class CustomHostname : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Hostname { get; init; } = "";
    /// <summary>"active", "pending", "active_redeploying", "moved", "pending_deletion", "deleted", "blocked", …</summary>
    public string? Status { get; init; }
    public CustomHostnameSsl? Ssl { get; init; }
    public string? CustomOriginServer { get; init; }
    public string? CustomOriginSni { get; init; }
    public Dictionary<string, string>? CustomMetadata { get; init; }
    public CustomHostnameOwnershipVerification? OwnershipVerification { get; init; }
    public CustomHostnameOwnershipVerificationHttp? OwnershipVerificationHttp { get; init; }
    public List<string>? VerificationErrors { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
}

/// <summary>A new custom hostname with a Cloudflare-issued DV certificate. Custom certificates (with private key) are deliberately not supported here.</summary>
public sealed class CustomHostnameInput
{
    public required string Hostname { get; init; }
    /// <summary>Domain control validation: "http" (default, recommended when the CNAME is in place), "txt" or "email" (needs <c>allowEmailValidation</c>).</summary>
    public string ValidationMethod { get; init; } = "http";
    /// <summary>"ubiquitous" (default), "optimal" or "force".</summary>
    public string? BundleMethod { get; init; }
    /// <summary>"google", "lets_encrypt", "ssl_com" (Enterprise; null = Cloudflare chooses).</summary>
    public string? CertificateAuthority { get; init; }
    /// <summary>Minimum TLS version of this hostname: "1.0", "1.1", "1.2" or "1.3" (null = zone default).</summary>
    public string? MinTlsVersion { get; init; }
    public string? CustomOriginServer { get; init; }
    public string? CustomOriginSni { get; init; }
    /// <summary>Per-hostname metadata (Enterprise add-on).</summary>
    public IReadOnlyDictionary<string, string>? CustomMetadata { get; init; }
}

/// <summary>Change of a custom hostname: only set fields are sent.</summary>
public sealed class CustomHostnameChange
{
    public string? ValidationMethod { get; init; }
    public string? MinTlsVersion { get; init; }
    public string? CustomOriginServer { get; init; }
    public string? CustomOriginSni { get; init; }
    public IReadOnlyDictionary<string, string>? CustomMetadata { get; init; }
}

/// <summary>Fallback origin of the custom hostnames of a zone.</summary>
public sealed class CustomHostnameFallbackOrigin : CloudflareModel
{
    public string? Origin { get; init; }
    /// <summary>"initializing", "pending_deployment", "pending_deletion", "active", "deployment_timed_out", "deletion_timed_out".</summary>
    public string? Status { get; init; }
    public List<string>? Errors { get; init; }
}

/// <summary>Filter of <see cref="CustomHostnamesClient.ListAsync"/>.</summary>
public sealed class CustomHostnameQuery
{
    public string? Hostname { get; init; }
    /// <summary>Certificate status filter, for example "pending_validation".</summary>
    public string? SslStatus { get; init; }
    public int MaxItems { get; init; } = 1000;
}

/// <summary>
/// Custom hostnames (Cloudflare for SaaS) and their fallback origin. Plans (developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/plans/,
/// 17.11.2026): Free to Business 100 hostnames included, up to 50 000; custom certificates, CSR, selectable CA, wildcard and mTLS only Enterprise.
/// Token permission: "Zone: SSL and Certificates: Edit" (reading "Read"). Deleting a hostname also deletes its certificate; removing the fallback origin
/// stops every custom hostname without its own origin, so it needs <c>allowRemoval: true</c>.
/// </summary>
public sealed class CustomHostnamesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Secret = ["custom_key", "private_key"];

    public async Task<IReadOnlyList<CustomHostname>> ListAsync(CustomHostnameQuery? query = null, string? zoneId = null, CancellationToken ct = default)
    {
        query ??= new();
        var path = CloudflarePath.WithQuery(ZonePath(zoneId, "custom_hostnames"), ("hostname", query.Hostname), ("ssl_status", query.SslStatus));
        var list = new List<CustomHostname>();
        await foreach (var item in Api.ListAllAsync<JsonElement>(path, 50, ct).ConfigureAwait(false))
        {
            list.Add(P1.As<CustomHostname>(P1.Strip(item, Secret)));
            if (list.Count >= query.MaxItems) break;
        }
        return list;
    }

    public Task<CustomHostname> GetAsync(string customHostnameId, string? zoneId = null, CancellationToken ct = default) =>
        P1.SendStrippedAsync<CustomHostname>(Api, HttpMethod.Get, ZonePath(zoneId, "custom_hostnames", customHostnameId), null, ct, Secret);

    /// <summary>The custom hostname with exactly this name, or null.</summary>
    public async Task<CustomHostname?> FindAsync(string hostname, string? zoneId = null, CancellationToken ct = default)
    {
        var host = P1.Hostname(hostname, nameof(hostname), allowWildcard: true);
        return (await ListAsync(new CustomHostnameQuery { Hostname = host }, zoneId, ct).ConfigureAwait(false))
            .FirstOrDefault(h => string.Equals(h.Hostname, host, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Plan of a new custom hostname (sends nothing).</summary>
    /// <param name="allowEmailValidation">Email validation makes Cloudflare write to the WHOIS contacts and admin@/hostmaster@… of the customer's domain.</param>
    public CloudflareChangePreview PreviewCreate(CustomHostnameInput input, bool allowEmailValidation = false, string? zoneId = null) =>
        new("POST", ZonePath(zoneId, "custom_hostnames"), CreateBody(input, allowEmailValidation),
            $"Add custom hostname {input.Hostname} with a DV certificate validated by {input.ValidationMethod}.");

    /// <summary>Adds a custom hostname and requests its certificate (POST, not retried; see <see cref="EnsureAsync"/>). The answer carries the validation records.</summary>
    /// <inheritdoc cref="PreviewCreate" path="/param"/>
    public Task<CustomHostname> CreateAsync(CustomHostnameInput input, bool allowEmailValidation = false, string? zoneId = null, CancellationToken ct = default) =>
        P1.SendStrippedAsync<CustomHostname>(Api, HttpMethod.Post, ZonePath(zoneId, "custom_hostnames"), CreateBody(input, allowEmailValidation), ct, Secret);

    /// <summary>Idempotent: returns the existing hostname of this name (unchanged) or adds it. Survives a concurrent create (409).</summary>
    public async Task<(CustomHostname Hostname, bool Created)> EnsureAsync(CustomHostnameInput input, bool allowEmailValidation = false, string? zoneId = null, CancellationToken ct = default)
    {
        var body = CreateBody(input, allowEmailValidation);
        EnsureWritable(HttpMethod.Post, ZonePath(zoneId, "custom_hostnames"));
        var existing = await FindAsync(input.Hostname, zoneId, ct).ConfigureAwait(false);
        if (existing is not null) return (existing, false);
        try
        {
            return (await P1.SendStrippedAsync<CustomHostname>(Api, HttpMethod.Post, ZonePath(zoneId, "custom_hostnames"), body, ct, Secret).ConfigureAwait(false), true);
        }
        catch (CloudflareConflictException)
        {
            var raced = await FindAsync(input.Hostname, zoneId, ct).ConfigureAwait(false);
            if (raced is null) throw;
            return (raced, false);
        }
    }

    public CloudflareChangePreview PreviewUpdate(string customHostnameId, CustomHostnameChange change, bool allowEmailValidation = false, string? zoneId = null) =>
        new("PATCH", ZonePath(zoneId, "custom_hostnames", customHostnameId), ChangeBody(change, allowEmailValidation), $"Change custom hostname {customHostnameId}.");

    /// <summary>Changes validation method, minimum TLS version, origin or metadata (PATCH). Sending the same validation method again restarts validation.</summary>
    public Task<CustomHostname> UpdateAsync(string customHostnameId, CustomHostnameChange change, bool allowEmailValidation = false, string? zoneId = null, CancellationToken ct = default) =>
        P1.SendStrippedAsync<CustomHostname>(Api, HttpMethod.Patch, ZonePath(zoneId, "custom_hostnames", customHostnameId), ChangeBody(change, allowEmailValidation), ct, Secret);

    public CloudflareChangePreview PreviewDelete(string customHostnameId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "custom_hostnames", customHostnameId), null,
            $"Delete custom hostname {customHostnameId} and its certificate. WARNING: the customer's traffic on this hostname stops being served.");

    /// <summary>Deletes a custom hostname and its certificate. True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteAsync(string customHostnameId, string? zoneId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(ZonePath(zoneId, "custom_hostnames", customHostnameId), null, ct);

    // ---- fallback origin ----

    /// <summary>The fallback origin; null when none is set.</summary>
    public Task<CustomHostnameFallbackOrigin?> GetFallbackOriginAsync(string? zoneId = null, CancellationToken ct = default) =>
        GetOrNullAsync<CustomHostnameFallbackOrigin>(ZonePath(zoneId, "custom_hostnames", "fallback_origin"), ct);

    public CloudflareChangePreview PreviewSetFallbackOrigin(string origin, string? zoneId = null) =>
        new("PUT", ZonePath(zoneId, "custom_hostnames", "fallback_origin"), new JsonObject { ["origin"] = P1.Hostname(origin, nameof(origin)) },
            $"Send custom hostname traffic without own origin to {origin} (must be a proxied record of the zone).");

    public Task<CustomHostnameFallbackOrigin> SetFallbackOriginAsync(string origin, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<CustomHostnameFallbackOrigin>(ZonePath(zoneId, "custom_hostnames", "fallback_origin"), new JsonObject { ["origin"] = P1.Hostname(origin, nameof(origin)) }, ct);

    public CloudflareChangePreview PreviewRemoveFallbackOrigin(string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "custom_hostnames", "fallback_origin"), null,
            "Remove the fallback origin. WARNING: every custom hostname without its own origin stops being served.");

    /// <summary>Removes the fallback origin; refused unless <paramref name="allowRemoval"/> is true. False when none was set.</summary>
    public Task<bool> RemoveFallbackOriginAsync(bool allowRemoval = false, string? zoneId = null, CancellationToken ct = default)
    {
        if (!allowRemoval)
            throw new InvalidOperationException("Refused: without a fallback origin every custom hostname without its own origin stops being served. Pass allowRemoval: true deliberately.");
        return DeleteIfExistsAsync(ZonePath(zoneId, "custom_hostnames", "fallback_origin"), null, ct);
    }

    private static JsonObject CreateBody(CustomHostnameInput input, bool allowEmailValidation)
    {
        var body = new JsonObject { ["hostname"] = P1.Hostname(input.Hostname, nameof(input), allowWildcard: true) };
        var ssl = new JsonObject { ["method"] = Method(input.ValidationMethod, allowEmailValidation), ["type"] = "dv" };
        if (input.BundleMethod is { } bm) ssl["bundle_method"] = bm is "ubiquitous" or "optimal" or "force" ? bm : throw new ArgumentException("Bundle method must be ubiquitous, optimal or force.", nameof(input));
        if (input.CertificateAuthority is { } ca) ssl["certificate_authority"] = ca is "google" or "lets_encrypt" or "ssl_com" ? ca : throw new ArgumentException("Certificate authority must be google, lets_encrypt or ssl_com.", nameof(input));
        if (input.Hostname.StartsWith("*.", StringComparison.Ordinal)) ssl["wildcard"] = true;
        if (input.MinTlsVersion is { } tls) ssl["settings"] = new JsonObject { ["min_tls_version"] = Tls(tls) };
        body["ssl"] = ssl;
        Origin(body, input.CustomOriginServer, input.CustomOriginSni, input.CustomMetadata);
        return body;
    }

    private static JsonObject ChangeBody(CustomHostnameChange c, bool allowEmailValidation)
    {
        var body = new JsonObject();
        if (c.ValidationMethod is not null || c.MinTlsVersion is not null)
        {
            var ssl = new JsonObject { ["type"] = "dv" };
            if (c.ValidationMethod is { } m) ssl["method"] = Method(m, allowEmailValidation);
            if (c.MinTlsVersion is { } tls) ssl["settings"] = new JsonObject { ["min_tls_version"] = Tls(tls) };
            body["ssl"] = ssl;
        }
        Origin(body, c.CustomOriginServer, c.CustomOriginSni, c.CustomMetadata);
        if (body.Count == 0) throw new ArgumentException("Nothing to change.", nameof(c));
        return body;
    }

    private static void Origin(JsonObject body, string? server, string? sni, IReadOnlyDictionary<string, string>? metadata)
    {
        if (server is not null) body["custom_origin_server"] = P1.Hostname(server, nameof(server));
        if (sni is not null) body["custom_origin_sni"] = sni == ":request_host_header:" ? sni : P1.Hostname(sni, nameof(sni));
        if (metadata is { Count: > 0 })
        {
            var md = new JsonObject();
            foreach (var (k, v) in metadata) md[k] = v;
            body["custom_metadata"] = md;
        }
    }

    private static string Method(string method, bool allowEmailValidation)
    {
        if (method is not ("http" or "txt" or "email")) throw new ArgumentException("Validation method must be http, txt or email.", nameof(method));
        if (method == "email" && !allowEmailValidation)
            throw new ArgumentException("Email validation makes Cloudflare send mail to the domain's WHOIS and admin addresses. Use http or txt, or pass allowEmailValidation: true.", nameof(method));
        return method;
    }

    internal static string Tls(string version) =>
        version is "1.0" or "1.1" or "1.2" or "1.3" ? version : throw new ArgumentException("TLS version must be 1.0, 1.1, 1.2 or 1.3.", nameof(version));
}
