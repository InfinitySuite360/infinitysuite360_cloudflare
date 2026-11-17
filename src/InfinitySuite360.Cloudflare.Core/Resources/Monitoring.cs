using System.Globalization;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class HealthCheck : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Address { get; init; } = "";
    /// <summary>"HTTP", "HTTPS" or "TCP".</summary>
    public string Type { get; init; } = "";
    /// <summary>"healthy", "unhealthy", "suspended", "unknown".</summary>
    public string Status { get; init; } = "";
    public bool Suspended { get; init; }
    public string? Description { get; init; }
    public int Interval { get; init; }
    public List<string> CheckRegions { get; init; } = [];
    public JsonElement? HttpConfig { get; init; }
    public JsonElement? TcpConfig { get; init; }
}

public sealed class HealthCheckInput
{
    public required string Name { get; init; }
    public required string Address { get; init; }
    public string Type { get; init; } = "HTTPS";
    public string? Description { get; init; }
    public int Interval { get; init; } = 60;
    public int Retries { get; init; } = 2;
    public int Timeout { get; init; } = 5;
    public List<string>? CheckRegions { get; init; }
    /// <summary>For example <c>new { path = "/health", expected_codes = new[] { "200" }, method = "GET" }</c>.</summary>
    public object? HttpConfig { get; init; }
    public object? TcpConfig { get; init; }
    public bool? Suspended { get; init; }
}

public sealed class LogpushJob : CloudflareModel
{
    public int Id { get; init; }
    public string? Name { get; init; }
    public string Dataset { get; init; } = "";
    public bool Enabled { get; init; }
    /// <summary>Destination with credentials replaced by [redacted] (since 0.7.1, <see cref="LogpushClient.RedactDestination"/>).</summary>
    public string? DestinationConf { get; init; }
    public string? LastError { get; init; }
    public string? ErrorMessage { get; init; }
    public DateTimeOffset? LastComplete { get; init; }
}

public sealed class AuditLogEntry : CloudflareModel
{
    public string Id { get; init; } = "";
    public DateTimeOffset? When { get; init; }
    public AuditActor? Actor { get; init; }
    public AuditAction? Action { get; init; }
    public AuditResource? Resource { get; init; }
}

public sealed class AuditActor : CloudflareModel
{
    public string? Id { get; init; }
    public string? Email { get; init; }
    public string? Ip { get; init; }
    public string? Type { get; init; }
}

public sealed class AuditAction : CloudflareModel
{
    public string? Type { get; init; }
    public bool Result { get; init; }
}

public sealed class AuditResource : CloudflareModel
{
    public string? Id { get; init; }
    public string? Type { get; init; }
}

public sealed class AlertPolicy : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string AlertType { get; init; } = "";
    public bool Enabled { get; init; }
    public string? Description { get; init; }
    public JsonElement? Mechanisms { get; init; }
    public JsonElement? Filters { get; init; }
}

public sealed class AlertWebhook : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Url { get; init; } = "";
    public string? Type { get; init; }
}

/// <summary>A notification Cloudflare sent (history of <c>alerting/v3/history</c>).</summary>
public sealed class AlertHistoryEntry : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Description { get; init; }
    public string? AlertType { get; init; }
    public string? AlertBody { get; init; }
    public string? Mechanism { get; init; }
    public string? MechanismType { get; init; }
    public string? PolicyId { get; init; }
    public DateTimeOffset? Sent { get; init; }
}

/// <summary>Health Checks, Logpush, audit logs and notifications.</summary>
public sealed class MonitoringClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    // ---- Health Checks (zone) ----
    public Task<IReadOnlyList<HealthCheck>> ListHealthChecksAsync(string? zoneId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<HealthCheck>(ZonePath(zoneId, "healthchecks"), 50, ct);

    public Task<HealthCheck> CreateHealthCheckAsync(HealthCheckInput input, string? zoneId = null, CancellationToken ct = default) =>
        Api.PostAsync<HealthCheck>(ZonePath(zoneId, "healthchecks"), input, ct);

    public Task<HealthCheck> UpdateHealthCheckAsync(string id, HealthCheckInput input, string? zoneId = null, CancellationToken ct = default) =>
        Api.PutAsync<HealthCheck>(ZonePath(zoneId, "healthchecks", id), input, ct);

    public Task DeleteHealthCheckAsync(string id, string? zoneId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(ZonePath(zoneId, "healthchecks", id), ct);

    // ---- Logpush (zone) ----
    /// <summary>Logpush jobs of the zone. Since 0.7.1 <see cref="LogpushJob.DestinationConf"/> is redacted (<see cref="LogpushClient.RedactDestination"/>).</summary>
    public async Task<List<LogpushJob>> ListLogpushJobsAsync(string? zoneId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<List<JsonElement>>(ZonePath(zoneId, "logpush", "jobs"), ct).ConfigureAwait(false) ?? []).Select(RedactJob).ToList();

    /// <summary>Creates a Logpush job (Enterprise). <paramref name="job"/> follows the Cloudflare schema (dataset, destination_conf, …). The answer is redacted (0.7.1).</summary>
    public async Task<LogpushJob> CreateLogpushJobAsync(object job, string? zoneId = null, CancellationToken ct = default) =>
        RedactJob(await Api.PostAsync<JsonElement>(ZonePath(zoneId, "logpush", "jobs"), job, ct).ConfigureAwait(false));

    /// <summary>Always refused since 0.7.1 (no switch in this signature): use <c>Logpush.DeleteJobAsync(jobId, allowRemoval: true)</c>.</summary>
    [Obsolete("Always refused since 0.7.1: deleting a Logpush job needs an explicit switch. Use Logpush.DeleteJobAsync(jobId, allowRemoval: true). Removed in 1.0.")]
    public async Task DeleteLogpushJobAsync(int jobId, string? zoneId = null, CancellationToken ct = default) =>
        await new LogpushClient(Api).DeleteJobAsync(jobId, LogpushScope.Zone, zoneId, allowRemoval: false, ct).ConfigureAwait(false);

    private static LogpushJob RedactJob(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object) return new LogpushJob();
        var node = System.Text.Json.Nodes.JsonNode.Parse(e.GetRawText())!.AsObject();
        if (node["destination_conf"] is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out var dest)) node["destination_conf"] = LogpushClient.RedactDestination(dest);
        node.Remove("ownership_challenge");
        return JsonSerializer.Deserialize<LogpushJob>(node.ToJsonString(), CloudflareJson.Options) ?? new LogpushJob();
    }

    // ---- Audit logs (account) ----
    /// <summary>Latest audit log entries of the account.</summary>
    public async Task<List<AuditLogEntry>> ListAuditLogsAsync(DateTimeOffset? since = null, DateTimeOffset? before = null, int perPage = 25, string? actorEmail = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "audit_logs"),
            ("per_page", perPage.ToString(CultureInfo.InvariantCulture)), ("direction", "desc"),
            ("since", since?.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)),
            ("before", before?.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)),
            ("actor.email", actorEmail));
        return await Api.GetAsync<List<AuditLogEntry>>(path, ct).ConfigureAwait(false) ?? [];
    }

    // ---- Notifications (account) ----
    /// <summary>Available alert types grouped by product.</summary>
    public Task<Dictionary<string, List<JsonElement>>> ListAvailableAlertsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<Dictionary<string, List<JsonElement>>>(AccountPath(accountId, "alerting", "v3", "available_alerts"), ct);

    /// <summary>
    /// History of the notifications sent. One page: <paramref name="perPage"/> entries (1 to 100) from <paramref name="page"/>.
    /// Cloudflare keeps the history for a limited time only.
    /// </summary>
    public async Task<List<AlertHistoryEntry>> ListAlertHistoryAsync(DateTimeOffset? since = null, DateTimeOffset? before = null, int perPage = 25, int page = 1, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "alerting", "v3", "history"),
            ("per_page", Math.Clamp(perPage, 1, 100).ToString(CultureInfo.InvariantCulture)),
            ("page", Math.Max(page, 1).ToString(CultureInfo.InvariantCulture)),
            ("since", since?.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)),
            ("before", before?.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)));
        return await Api.GetAsync<List<AlertHistoryEntry>>(path, ct).ConfigureAwait(false) ?? [];
    }

    public Task<List<AlertPolicy>> ListAlertPoliciesAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<AlertPolicy>>(AccountPath(accountId, "alerting", "v3", "policies"), ct);

    /// <summary>
    /// Creates a notification policy with <paramref name="emails"/> and/or <paramref name="webhookIds"/> as destinations; <paramref name="filters"/> depend on the alert type (for example <c>new { zones = new[] { zoneId } }</c>).
    /// </summary>
    public Task<IdResult> CreateAlertPolicyAsync(string name, string alertType, IEnumerable<string>? emails = null, IEnumerable<string>? webhookIds = null, object? filters = null, string? accountId = null, CancellationToken ct = default)
    {
        var mechanisms = new Dictionary<string, object>();
        if (emails?.ToList() is { Count: > 0 } e) mechanisms["email"] = e.Select(x => new { id = x }).ToList();
        if (webhookIds?.ToList() is { Count: > 0 } w) mechanisms["webhooks"] = w.Select(x => new { id = x }).ToList();
        if (mechanisms.Count == 0) throw new ArgumentException("At least one destination (email or webhook) is required.");
        return Api.PostAsync<IdResult>(AccountPath(accountId, "alerting", "v3", "policies"),
            new { name, alert_type = alertType, enabled = true, mechanisms, filters = filters ?? new { } }, ct);
    }

    public Task DeleteAlertPolicyAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "alerting", "v3", "policies", policyId), ct);

    public Task<List<AlertWebhook>> ListWebhooksAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<AlertWebhook>>(AccountPath(accountId, "alerting", "v3", "destinations", "webhooks"), ct);

    public Task<IdResult> CreateWebhookAsync(string name, string url, string? secret = null, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<IdResult>(AccountPath(accountId, "alerting", "v3", "destinations", "webhooks"), new { name, url, secret }, ct);

    public Task DeleteWebhookAsync(string webhookId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "alerting", "v3", "destinations", "webhooks", webhookId), ct);
}
