using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Whether a Logpush call addresses a zone or an account.</summary>
public enum LogpushScope
{
    Zone,
    Account,
}

/// <summary>
/// A Logpush job. <see cref="DestinationConf"/> is <b>redacted</b>: credentials in the query (access keys, secrets, tokens, <c>header_*</c>), user info and
/// the path of HTTP destinations are replaced with <c>[redacted]</c>, so the model can be logged and shown.
/// </summary>
public sealed class LogpushJobInfo : CloudflareModel
{
    public int Id { get; init; }
    public string? Name { get; init; }
    public string Dataset { get; init; } = "";
    public bool Enabled { get; init; }
    /// <summary>Destination with credentials replaced by [redacted].</summary>
    public string? DestinationConf { get; init; }
    public string? Kind { get; init; }
    public string? Frequency { get; init; }
    public JsonElement? OutputOptions { get; init; }
    public JsonElement? Filter { get; init; }
    public DateTimeOffset? LastComplete { get; init; }
    public DateTimeOffset? LastError { get; init; }
    public string? ErrorMessage { get; init; }
}

/// <summary>A new Logpush job. The destination usually carries credentials; it is sent to Cloudflare but redacted in previews and summaries.</summary>
public sealed class LogpushJobInput
{
    /// <summary>Letters, digits, '-' and '.', at most 512 characters.</summary>
    public string? Name { get; init; }
    /// <summary>For example "http_requests", "firewall_events", "audit_logs", "access_requests", "workers_trace_events".</summary>
    public required string Dataset { get; init; }
    /// <summary>For example <c>r2://bucket/path?account-id=…&amp;access-key-id=…&amp;secret-access-key=…</c>, <c>s3://bucket/path?region=…</c>, <c>https://…</c>.</summary>
    public required string DestinationConf { get; init; }
    /// <summary>Token from <see cref="LogpushClient.RequestOwnershipChallengeAsync"/> (needed for S3, GCS, Azure and other storage destinations).</summary>
    public string? OwnershipChallenge { get; init; }
    public bool Enabled { get; init; } = true;
    /// <summary>For example <c>{"field_names":["ClientIP","EdgeResponseStatus"],"timestamp_format":"rfc3339"}</c>.</summary>
    public JsonElement? OutputOptions { get; init; }
    /// <summary>Filter, for example <c>{"where":{"key":"ClientRequestHost","operator":"eq","value":"api.example.com"}}</c>.</summary>
    public JsonElement? Filter { get; init; }
    /// <summary>"" (default) or "edge" (Instant Logs).</summary>
    public string? Kind { get; init; }

    public override string ToString() => $"LogpushJobInput({Dataset} → {LogpushClient.RedactDestination(DestinationConf)})";
}

/// <summary>Answer of an ownership challenge or destination check.</summary>
public sealed class LogpushCheckResult : CloudflareModel
{
    public bool Valid { get; init; }
    public string? Message { get; init; }
    /// <summary>Ownership challenge: name of the file Cloudflare wrote into the destination (read its content for <see cref="LogpushJobInput.OwnershipChallenge"/>).</summary>
    public string? Filename { get; init; }
}

/// <summary>
/// Logpush jobs of a zone or account, typed and with redacted destinations (developers.cloudflare.com/logs/logpush/, 17.11.2026: all plans; datasets depend
/// on the products of the account; up to 1000 jobs; a disabled or failing job loses the logs of that time, they are not backfilled).
/// Token permission: "Zone: Logs: Edit" or "Account: Logs: Edit" (reading "Logs: Read"). Disabling or deleting a job needs <c>allowRemoval</c> (0.7.1).
/// Since 0.7.1 the older <see cref="MonitoringClient"/> Logpush methods redact the destination too.
/// </summary>
public sealed class LogpushClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly Regex NamePattern = new(@"^[a-zA-Z0-9\-\.]{0,512}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex SchemePattern = new(@"^[a-z0-9+.\-]+://", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly HashSet<string> StoragePathSchemes = ["r2", "s3", "gs", "azure"];
    private static readonly string[] SecretKeyParts = ["secret", "key", "token", "password", "passwd", "sig", "auth", "credential", "header_", "sas", "api"];

    public Task<IReadOnlyList<LogpushJobInfo>> ListJobsAsync(LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default) =>
        ListAsync(Path(scope, scopeId, "logpush", "jobs"), ct);

    public async Task<LogpushJobInfo?> GetJobAsync(int jobId, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default)
    {
        try { return Redact((await Api.SendAsync<JsonElement>(HttpMethod.Get, JobPath(scope, scopeId, jobId), null, ct).ConfigureAwait(false)).Result); }
        catch (CloudflareApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>Fields of a dataset (name → description), for <c>output_options.field_names</c>.</summary>
    public async Task<IReadOnlyDictionary<string, string>> ListDatasetFieldsAsync(string dataset, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default) =>
        await Api.GetAsync<Dictionary<string, string>>(Path(scope, scopeId, "logpush", "datasets", P1.Required(dataset, nameof(dataset), 100), "fields"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Plan of a new job; the destination appears redacted.</summary>
    public CloudflareChangePreview PreviewCreateJob(LogpushJobInput job, LogpushScope scope = LogpushScope.Zone, string? scopeId = null)
    {
        var body = JobBody(job);
        body["destination_conf"] = RedactDestination(job.DestinationConf);
        if (body.ContainsKey("ownership_challenge")) body["ownership_challenge"] = P1.Redacted;
        return new("POST", Path(scope, scopeId, "logpush", "jobs"), body,
            $"Push {job.Dataset} logs to {RedactDestination(job.DestinationConf)}{(job.Enabled ? "" : " (created disabled)")}.");
    }

    /// <summary>Creates a job (POST, not retried; see <see cref="EnsureJobAsync"/>). The answer is redacted.</summary>
    public async Task<LogpushJobInfo> CreateJobAsync(LogpushJobInput job, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default) =>
        Redact((await Api.SendAsync<JsonElement>(HttpMethod.Post, Path(scope, scopeId, "logpush", "jobs"), JobBody(job), ct).ConfigureAwait(false)).Result)!;

    /// <summary>Idempotent by name and dataset: returns the existing job unchanged or creates it. Needs <see cref="LogpushJobInput.Name"/>.</summary>
    public async Task<(LogpushJobInfo Job, bool Created)> EnsureJobAsync(LogpushJobInput job, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default)
    {
        var body = JobBody(job);
        if (string.IsNullOrWhiteSpace(job.Name)) throw new ArgumentException("EnsureJobAsync needs a job name.", nameof(job));
        EnsureWritable(HttpMethod.Post, Path(scope, scopeId, "logpush", "jobs"));
        var existing = (await ListJobsAsync(scope, scopeId, ct).ConfigureAwait(false)).FirstOrDefault(j => j.Name == job.Name && j.Dataset == job.Dataset);
        if (existing is not null) return (existing, false);
        return (Redact((await Api.SendAsync<JsonElement>(HttpMethod.Post, Path(scope, scopeId, "logpush", "jobs"), body, ct).ConfigureAwait(false)).Result)!, true);
    }

    public CloudflareChangePreview PreviewSetJobEnabled(int jobId, bool enabled, LogpushScope scope = LogpushScope.Zone, string? scopeId = null) =>
        new("PUT", JobPath(scope, scopeId, jobId), new JsonObject { ["enabled"] = enabled },
            enabled ? $"Enable Logpush job {jobId}." : $"Disable Logpush job {jobId}. WARNING: logs of the time it is off are lost (no backfill).");

    /// <summary>
    /// Enables or disables a job (PUT, idempotent). Logs of the time it is off are lost (audit trail gap): disabling needs <paramref name="allowRemoval"/> (M-8, 0.7.1).
    /// </summary>
    public async Task<LogpushJobInfo> SetJobEnabledAsync(int jobId, bool enabled, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, bool allowRemoval = false, CancellationToken ct = default)
    {
        if (!enabled) P2.Allow(allowRemoval, "a disabled Logpush job loses the logs of that time (no backfill)", nameof(allowRemoval));
        return Redact((await Api.SendAsync<JsonElement>(HttpMethod.Put, JobPath(scope, scopeId, jobId), new JsonObject { ["enabled"] = enabled }, ct).ConfigureAwait(false)).Result)!;
    }

    public CloudflareChangePreview PreviewDeleteJob(int jobId, LogpushScope scope = LogpushScope.Zone, string? scopeId = null) =>
        new("DELETE", JobPath(scope, scopeId, jobId), null, $"Delete Logpush job {jobId}. WARNING: no more logs are pushed.");

    /// <summary>Deletes a job (no more logs are pushed): needs <paramref name="allowRemoval"/> (M-8, 0.7.1). True when deleted, false when it did not exist.</summary>
    public Task<bool> DeleteJobAsync(int jobId, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, bool allowRemoval = false, CancellationToken ct = default)
    {
        P2.Allow(allowRemoval, "deleting a Logpush job stops the log delivery (audit trail gap)", nameof(allowRemoval));
        return DeleteIfExistsAsync(JobPath(scope, scopeId, jobId), null, ct);
    }

    public CloudflareChangePreview PreviewRequestOwnershipChallenge(string destinationConf, LogpushScope scope = LogpushScope.Zone, string? scopeId = null) =>
        new("POST", Path(scope, scopeId, "logpush", "ownership"), new JsonObject { ["destination_conf"] = RedactDestination(CheckDestination(destinationConf)) },
            $"Ask Cloudflare to write an ownership challenge file to {RedactDestination(destinationConf)}.");

    /// <summary>Makes Cloudflare write a challenge file into the destination (POST; Cloudflare writes to your storage).</summary>
    public Task<LogpushCheckResult> RequestOwnershipChallengeAsync(string destinationConf, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default) =>
        Api.PostAsync<LogpushCheckResult>(Path(scope, scopeId, "logpush", "ownership"), new JsonObject { ["destination_conf"] = CheckDestination(destinationConf) }, ct);

    /// <summary>Checks a destination (Cloudflare uses POST, so the write guard applies, although nothing is created).</summary>
    public Task<LogpushCheckResult> ValidateDestinationAsync(string destinationConf, LogpushScope scope = LogpushScope.Zone, string? scopeId = null, CancellationToken ct = default) =>
        Api.PostAsync<LogpushCheckResult>(Path(scope, scopeId, "logpush", "validate", "destination"), new JsonObject { ["destination_conf"] = CheckDestination(destinationConf) }, ct);

    /// <summary>
    /// Replaces credentials in a destination: user info, query values whose name contains secret, key, token, password, sig, auth, credential, header_, sas or api,
    /// query parameters without <c>=</c> (a bare value can be a token) and the path of every destination except the storage schemes r2, s3, gs and azure
    /// (a collector path often carries a token, also for splunk://, datadog:// and similar; N-6, 0.7.1). Scheme, host and other parameters (region, account) stay.
    /// </summary>
    public static string RedactDestination(string? destinationConf)
    {
        var d = destinationConf ?? "";
        var schemeEnd = d.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0) return d.Length == 0 ? "" : P1.Redacted;
        var scheme = d[..schemeEnd];
        var rest = d[(schemeEnd + 3)..];
        var q = rest.IndexOf('?');
        var location = q < 0 ? rest : rest[..q];
        var query = q < 0 ? null : rest[(q + 1)..];
        var at = location.IndexOf('@');
        var slash = location.IndexOf('/');
        if (at >= 0 && (slash < 0 || at < slash)) location = P1.Redacted + "@" + location[(at + 1)..];
        if (!StoragePathSchemes.Contains(scheme.ToLowerInvariant()))
        {
            slash = location.IndexOf('/');
            if (slash >= 0 && slash < location.Length - 1) location = location[..(slash + 1)] + P1.Redacted;
        }
        var sb = new StringBuilder(scheme).Append("://").Append(location);
        if (query is not null)
        {
            var parts = query.Split('&').Select(p =>
            {
                var eq = p.IndexOf('=');
                var name = eq < 0 ? p : p[..eq];
                var lower = Uri.UnescapeDataString(name).ToLowerInvariant();
                if (eq < 0) return p.Length == 0 ? p : P1.Redacted;
                return SecretKeyParts.Any(lower.Contains) ? name + "=" + P1.Redacted : p;
            });
            sb.Append('?').Append(string.Join("&", parts));
        }
        return sb.ToString();
    }

    private async Task<IReadOnlyList<LogpushJobInfo>> ListAsync(string path, CancellationToken ct)
    {
        var raw = await Api.GetAsync<List<JsonElement>>(path, ct).ConfigureAwait(false) ?? [];
        return raw.Select(r => Redact(r)!).ToList();
    }

    private static LogpushJobInfo? Redact(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) return null;
        var node = JsonNode.Parse(element.GetRawText())!.AsObject();
        if (node["destination_conf"] is JsonValue v && v.TryGetValue<string>(out var dest)) node["destination_conf"] = RedactDestination(dest);
        node.Remove("ownership_challenge");
        return P1.As<LogpushJobInfo>(JsonSerializer.SerializeToElement(node, CloudflareJson.Options));
    }

    private string Path(LogpushScope scope, string? scopeId, params string[] rest) =>
        scope == LogpushScope.Account ? AccountPath(scopeId, rest) : ZonePath(scopeId, rest);

    private string JobPath(LogpushScope scope, string? scopeId, int jobId) =>
        Path(scope, scopeId, "logpush", "jobs", jobId.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static string CheckDestination(string destinationConf)
    {
        if (string.IsNullOrWhiteSpace(destinationConf) || destinationConf.Length > 4096 || !SchemePattern.IsMatch(destinationConf))
            throw new ArgumentException("Destination must look like scheme://… (r2://, s3://, gs://, azure://, https://, …), at most 4096 characters.", nameof(destinationConf));
        return destinationConf;
    }

    private static JsonObject JobBody(LogpushJobInput j)
    {
        if (j.Name is not null && !NamePattern.IsMatch(j.Name)) throw new ArgumentException("Name may contain letters, digits, '-' and '.' only (at most 512).", nameof(j));
        var body = new JsonObject
        {
            ["dataset"] = P1.Required(j.Dataset, nameof(j), 100),
            ["destination_conf"] = CheckDestination(j.DestinationConf),
            ["enabled"] = j.Enabled,
        };
        if (j.Name is not null) body["name"] = j.Name;
        if (j.OwnershipChallenge is not null) body["ownership_challenge"] = j.OwnershipChallenge;
        if (P1.Node(j.OutputOptions) is { } oo) body["output_options"] = oo;
        if (P1.Node(j.Filter) is { } f) body["filter"] = f.ToJsonString();
        if (j.Kind is not null) body["kind"] = j.Kind is "" or "edge" ? j.Kind : throw new ArgumentException("Kind must be \"\" or \"edge\".", nameof(j));
        return body;
    }
}
