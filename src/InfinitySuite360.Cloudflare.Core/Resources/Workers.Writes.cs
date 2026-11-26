using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// The value of a Worker secret. It is only written into the request body of <see cref="WorkersClient.PutSecretAsync"/>; <see cref="ToString"/>, JSON
/// serialization, previews, models and exception messages never contain it. Cloudflare never returns secret values, so no model of this package has one.
/// </summary>
[JsonConverter(typeof(WorkerSecretTextConverter))]
[DebuggerDisplay("WorkerSecretText([redacted])")]
public sealed class WorkerSecretText : IDisposable
{
    // N-5 (0.7.1): a character buffer that Dispose overwrites; hidden from the debugger's variable views.
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private char[]? _value;

    private WorkerSecretText(string value) => _value = value.ToCharArray();

    /// <summary>Wraps a secret value (not empty, at most 5 KiB as UTF-8, Cloudflare's limit for variables).</summary>
    public static WorkerSecretText From(string value)
    {
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("A secret value is required.", nameof(value));
        if (ResourceKit.Utf8(value) > 5 * 1024) throw new ArgumentException("A secret value may have at most 5 KiB.", nameof(value));
        return new(value);
    }

    internal string Reveal() => _value is { } v ? new string(v) : throw new ObjectDisposedException(nameof(WorkerSecretText));

    /// <summary>Overwrites the internal buffer. The string passed to <see cref="From"/> cannot be wiped by .NET.</summary>
    public void Dispose()
    {
        if (_value is { } v) Array.Clear(v);
        _value = null;
    }

    public override string ToString() => $"WorkerSecretText({ResourceKit.Redacted})";
}

internal sealed class WorkerSecretTextConverter : JsonConverter<WorkerSecretText>
{
    public override WorkerSecretText Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("Worker secret values are not deserialized.");

    public override void Write(Utf8JsonWriter writer, WorkerSecretText value, JsonSerializerOptions options) => writer.WriteStringValue(ResourceKit.Redacted);
}

/// <summary>Name and type of a Worker secret (never the value).</summary>
public sealed class WorkerSecretInfo : CloudflareModel
{
    public string Name { get; init; } = "";
    /// <summary>"secret_text" or "secret_key".</summary>
    public string Type { get; init; } = "";
}

/// <summary>A custom domain of a Worker (the hostname is served by the Worker, DNS record and certificate are created by Cloudflare).</summary>
public sealed class WorkerDomain : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Hostname { get; init; } = "";
    public string? Service { get; init; }
    public string? Environment { get; init; }
    public string? ZoneId { get; init; }
    public string? ZoneName { get; init; }
}

/// <summary>A cron trigger of a Worker.</summary>
public sealed class WorkerSchedule : CloudflareModel
{
    public string Cron { get; init; } = "";
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

internal sealed class WorkerScheduleList
{
    public List<WorkerSchedule> Schedules { get; init; } = [];
}

/// <summary>An uploaded version of a Worker (not necessarily deployed).</summary>
public sealed class WorkerVersion : CloudflareModel
{
    public string Id { get; init; } = "";
    public int? Number { get; init; }
    public JsonElement? Metadata { get; init; }
    public JsonElement? Annotations { get; init; }
}

internal sealed class WorkerVersionList
{
    public List<WorkerVersion> Items { get; init; } = [];
}

/// <summary>A version with its share of the traffic in a deployment.</summary>
public sealed record WorkerDeploymentVersion(string VersionId, double Percentage);

/// <summary>A deployment of a Worker (which versions receive how much traffic).</summary>
public sealed class WorkerDeployment : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Source { get; init; }
    public string? Strategy { get; init; }
    public List<WorkerDeploymentVersion> Versions { get; init; } = [];
    public DateTimeOffset? CreatedOn { get; init; }
    public JsonElement? Annotations { get; init; }
}

internal sealed class WorkerDeploymentList
{
    public List<WorkerDeployment> Deployments { get; init; } = [];
}

/// <summary>Settings of a Worker: bindings (secrets only as name and type), compatibility, placement, tags.</summary>
public sealed class WorkerScriptSettings : CloudflareModel
{
    public JsonElement? Bindings { get; init; }
    public string? CompatibilityDate { get; init; }
    public List<string>? CompatibilityFlags { get; init; }
    public bool? Logpush { get; init; }
    public JsonElement? Placement { get; init; }
    public JsonElement? Limits { get; init; }
    public List<string>? Tags { get; init; }
}

/// <summary>
/// Workers beyond the base calls: reading (settings, secret names, cron triggers, versions, deployments, custom domains) and guarded writes. Anything that changes
/// what runs on the edge needs <c>allowDeploy: true</c> (upload, deploy a version, secrets: Cloudflare deploys a secret change at once); deleting a Worker needs
/// <c>allowDelete</c>, a wildcard host route <c>allowBroadRoute</c>, detaching a custom domain <c>allowRemoval</c>, removing every cron trigger <c>allowClear</c>.
/// Secret <b>values</b> exist only in <see cref="WorkerSecretText"/>; no model, preview, log or error contains one. Token permission "Account: Workers Scripts: Edit"
/// (reading "Read"), routes "Zone: Workers Routes: Edit". Sources: developers.cloudflare.com/workers/ (configuration/cron-triggers, configuration/versions-and-deployments,
/// platform/limits; retrieved 17.11.2026), endpoints from the API schema cloudflare/api-schemas@650bd71.
/// </summary>
public sealed partial class WorkersClient
{
    private static readonly Regex ScriptNamePattern = ResourceKit.Rx(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$");
    private static readonly Regex SecretNamePattern = ResourceKit.Rx(@"^[A-Za-z_$][A-Za-z0-9_$]{0,63}$");
    private static readonly Regex CronPattern = ResourceKit.Rx(@"^[0-9A-Za-z*/,\-?#LW]+( [0-9A-Za-z*/,\-?#LW]+){4}$");
    private static readonly Regex VersionIdPattern = ResourceKit.Rx(@"^[0-9a-fA-F-]{32,36}$");
    private const int MaxScriptBytes = 64 * 1024 * 1024;

    // ---- reading ----

    /// <summary>Settings of a Worker (bindings, compatibility date, placement …). Secret bindings only have name and type.</summary>
    public Task<WorkerScriptSettings> GetScriptSettingsAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<WorkerScriptSettings>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "settings"), ct);

    /// <summary>Names and types of the secrets of a Worker (values are never returned by Cloudflare).</summary>
    public Task<IReadOnlyList<WorkerSecretInfo>> ListSecretsAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<WorkerSecretInfo>(Api, AccountPath(accountId, "workers", "scripts", Script(scriptName), "secrets"), 100, ct, "text", "value");

    public async Task<IReadOnlyList<WorkerSchedule>> ListSchedulesAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<WorkerScheduleList>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "schedules"), ct).ConfigureAwait(false))?.Schedules ?? [];

    public async Task<IReadOnlyList<WorkerVersion>> ListVersionsAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<WorkerVersionList>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "versions"), ct).ConfigureAwait(false))?.Items ?? [];

    public Task<WorkerVersion> GetVersionAsync(string scriptName, string versionId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<WorkerVersion>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "versions", CheckVersionId(versionId)), ct);

    /// <summary>The deployments of a Worker, newest first.</summary>
    public async Task<IReadOnlyList<WorkerDeployment>> ListDeploymentsAsync(string scriptName, string? accountId = null, CancellationToken ct = default) =>
        (await Api.GetAsync<WorkerDeploymentList>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "deployments"), ct).ConfigureAwait(false))?.Deployments ?? [];

    /// <summary>Custom domains of the account's Workers (optionally filtered by hostname or Worker name).</summary>
    public Task<List<WorkerDomain>> ListDomainsAsync(string? hostname = null, string? service = null, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<WorkerDomain>>(CloudflarePath.WithQuery(AccountPath(accountId, "workers", "domains"), ("hostname", hostname), ("service", service)), ct);

    // ---- upload / delete ----

    /// <summary>Plan of an upload. The source code is <b>not</b> part of it (size and SHA-256 only), bindings appear as type and name.</summary>
    public CloudflareChangePreview PreviewUploadScript(string scriptName, string moduleSource, WorkerMetadata? metadata = null, string? accountId = null)
    {
        var (meta, bytes) = PrepareUpload(scriptName, moduleSource, metadata);
        var body = new JsonObject
        {
            ["script"] = scriptName,
            ["main_module"] = meta["main_module"]?.DeepClone(),
            ["compatibility_date"] = meta["compatibility_date"]?.DeepClone(),
            ["source_bytes"] = bytes.Length,
            ["source_sha256"] = ResourceKit.Sha256(bytes),
            ["bindings"] = new JsonArray((meta["bindings"] as JsonArray)?.Select(b => (JsonNode?)JsonValue.Create($"{b?["type"]} {b?["name"]}")).ToArray() ?? []),
            ["keep_bindings"] = meta["keep_bindings"]?.DeepClone(),
        };
        return new("PUT", AccountPath(accountId, "workers", "scripts", scriptName), body,
            $"Upload and deploy {bytes.Length} bytes as Worker \"{scriptName}\" ({body["source_sha256"]}). WARNING: the code runs on the edge for all traffic routed to it.");
    }

    /// <summary>
    /// Uploads (and so deploys) an ES module Worker (PUT, idempotent). Refused unless <paramref name="allowDeploy"/> is true. Secret bindings (<c>secret_text</c>,
    /// <c>secret_key</c>) are refused in the metadata (use <see cref="PutSecretAsync"/>); existing secrets are kept (<c>keep_bindings</c> defaults to both types).
    /// </summary>
    public Task<CloudflareResponse<WorkerScript>> UploadScriptAsync(string scriptName, string moduleSource, WorkerMetadata? metadata = null, bool allowDeploy = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDeploy, "uploading a Worker replaces the code that runs on the edge at once", nameof(allowDeploy));
        var (meta, _) = PrepareUpload(scriptName, moduleSource, metadata);
        var metaJson = meta.ToJsonString(CloudflareJson.Options);
        var mainModule = meta["main_module"]!.GetValue<string>();
        return Api.SendContentAsync<WorkerScript>(HttpMethod.Put, AccountPath(accountId, "workers", "scripts", scriptName), () =>
        {
            var form = new MultipartFormDataContent();
            form.Add(new StringContent(metaJson, Encoding.UTF8, "application/json"), "metadata");
            var module = new StringContent(moduleSource, Encoding.UTF8);
            module.Headers.ContentType = new MediaTypeHeaderValue("application/javascript+module");
            form.Add(module, mainModule, mainModule);
            return form;
        }, ct);
    }

    public CloudflareChangePreview PreviewRemoveScript(string scriptName, bool force = false, string? accountId = null) =>
        new("DELETE", CloudflarePath.WithQuery(AccountPath(accountId, "workers", "scripts", Script(scriptName)), ("force", force ? "true" : null)), null,
            $"Delete Worker \"{scriptName}\"{(force ? " together with its bindings and triggers" : "")}. WARNING: it stops answering requests; the code cannot be restored from Cloudflare.");

    /// <summary>
    /// Deletes a Worker. Refused unless <paramref name="allowDelete"/> is true; <paramref name="force"/> (also delete bindings and dependent resources) needs
    /// <paramref name="allowForce"/>. False when it did not exist.
    /// </summary>
    public Task<bool> RemoveScriptAsync(string scriptName, bool allowDelete = false, bool force = false, bool allowForce = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDelete, "deleting a Worker removes its code, versions and triggers", nameof(allowDelete));
        if (force) ResourceKit.Allow(allowForce, "force also deletes bindings and dependent resources", nameof(allowForce));
        return DeleteIfExistsAsync(CloudflarePath.WithQuery(AccountPath(accountId, "workers", "scripts", Script(scriptName)), ("force", force ? "true" : null)), null, ct);
    }

    // ---- routes ----

    public CloudflareChangePreview PreviewCreateRoute(string pattern, string scriptName, bool allowBroadRoute = false, string? zoneId = null)
    {
        CheckPattern(pattern, allowBroadRoute);
        return new("POST", ZonePath(zoneId, "workers", "routes"), new JsonObject { ["pattern"] = pattern, ["script"] = Script(scriptName) },
            $"Route \"{pattern}\" to Worker \"{scriptName}\".");
    }

    /// <summary>
    /// Makes sure the route exists: returns the existing one when pattern and Worker match, creates it otherwise; a pattern that already goes to another Worker is a
    /// <see cref="CloudflareConflictException"/>. A wildcard host (<c>*.example.com/*</c>) needs <paramref name="allowBroadRoute"/>.
    /// </summary>
    public async Task<(WorkerRoute Route, bool Created)> EnsureRouteAsync(string pattern, string scriptName, bool allowBroadRoute = false, string? zoneId = null, CancellationToken ct = default)
    {
        CheckPattern(pattern, allowBroadRoute);
        Script(scriptName);
        var path = ZonePath(zoneId, "workers", "routes");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await Api.GetAsync<List<WorkerRoute>>(path, ct).ConfigureAwait(false) ?? []).FirstOrDefault(r => string.Equals(r.Pattern, pattern, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            if (existing.Script == scriptName) return (existing, false);
            throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"The pattern \"{pattern}\" already routes to {(existing.Script is null ? "no Worker" : $"Worker \"{existing.Script}\"")}." }]);
        }
        return (await Api.PostAsync<WorkerRoute>(path, new JsonObject { ["pattern"] = pattern, ["script"] = scriptName }, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveRoute(string routeId, string? zoneId = null) =>
        new("DELETE", ZonePath(zoneId, "workers", "routes", routeId), null, $"Remove Worker route {routeId}; requests go to the origin again.");

    /// <summary>Removes a route. False when it did not exist.</summary>
    public Task<bool> RemoveRouteAsync(string routeId, string? zoneId = null, CancellationToken ct = default) => DeleteIfExistsAsync(ZonePath(zoneId, "workers", "routes", routeId), null, ct);

    // ---- custom domains ----

    public CloudflareChangePreview PreviewAttachDomain(string hostname, string scriptName, string? zoneId = null, string environment = "production", string? accountId = null) =>
        new("PUT", AccountPath(accountId, "workers", "domains"), DomainBody(hostname, scriptName, zoneId, environment),
            $"Serve {hostname} with Worker \"{scriptName}\" (Cloudflare creates the DNS record and certificate). WARNING: an existing site on this hostname is replaced by the Worker.");

    /// <summary>
    /// Attaches a hostname to a Worker (PUT, idempotent). The Worker answers every request of the hostname at once (an existing origin or record is taken over),
    /// so this needs <paramref name="allowDeploy"/> (M-8, 0.7.1).
    /// </summary>
    public Task<WorkerDomain> AttachDomainAsync(string hostname, string scriptName, string? zoneId = null, string environment = "production", string? accountId = null, bool allowDeploy = false, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDeploy, "attaching a domain makes the Worker answer every request of that hostname at once", nameof(allowDeploy));
        return Api.PutAsync<WorkerDomain>(AccountPath(accountId, "workers", "domains"), DomainBody(hostname, scriptName, zoneId, environment), ct);
    }

    /// <summary>Detaches a custom domain: the hostname stops being served by the Worker. Refused unless <paramref name="allowRemoval"/> is true. False when it did not exist.</summary>
    public Task<bool> DetachDomainAsync(string domainId, bool allowRemoval = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowRemoval, "detaching the custom domain stops the Worker answering for that hostname", nameof(allowRemoval));
        return DeleteIfExistsAsync(AccountPath(accountId, "workers", "domains", ResourceKit.Required(domainId, nameof(domainId))), null, ct);
    }

    // ---- cron triggers ----

    public CloudflareChangePreview PreviewSetSchedules(string scriptName, IEnumerable<string> crons, bool allowClear = false, string? accountId = null)
    {
        var list = CheckCrons(crons, allowClear);
        return new("PUT", AccountPath(accountId, "workers", "scripts", Script(scriptName), "schedules"), ScheduleBody(list),
            list.Count == 0 ? $"Remove every cron trigger of \"{scriptName}\"." : $"Set the cron triggers of \"{scriptName}\" to: {ResourceKit.Join(list)}.");
    }

    /// <summary>
    /// Replaces the cron triggers (PUT; read first, written only on change). Cron expressions are UTC, five fields. An empty list removes every trigger
    /// and needs <paramref name="allowClear"/>.
    /// </summary>
    public async Task<(IReadOnlyList<WorkerSchedule> Schedules, bool Changed)> SetSchedulesAsync(string scriptName, IEnumerable<string> crons, bool allowClear = false, string? accountId = null, CancellationToken ct = default)
    {
        var list = CheckCrons(crons, allowClear);
        var path = AccountPath(accountId, "workers", "scripts", Script(scriptName), "schedules");
        EnsureWritable(HttpMethod.Put, path);
        var current = await ListSchedulesAsync(scriptName, accountId, ct).ConfigureAwait(false);
        if (current.Select(s => s.Cron).OrderBy(c => c, StringComparer.Ordinal).SequenceEqual(list.OrderBy(c => c, StringComparer.Ordinal))) return (current, false);
        var result = await Api.PutAsync<WorkerScheduleList>(path, ScheduleBody(list), ct).ConfigureAwait(false);
        return (result?.Schedules ?? [], true);
    }

    // ---- versions and deployments ----

    public CloudflareChangePreview PreviewDeployVersions(string scriptName, IReadOnlyList<WorkerDeploymentVersion> versions, string? message = null, string? accountId = null)
    {
        var body = DeploymentBody(versions, message);
        return new("POST", AccountPath(accountId, "workers", "scripts", Script(scriptName), "deployments"), body,
            $"Deploy {string.Join(" and ", versions.Select(v => $"{v.Percentage:0.##}% of version {v.VersionId}"))} of \"{scriptName}\". WARNING: changes what runs on the edge at once.");
    }

    /// <summary>
    /// Deploys one version (100 %) or splits traffic between two (gradual rollout); rolling back is deploying an older version. Refused unless
    /// <paramref name="allowDeploy"/> is true. POST is never repeated automatically.
    /// </summary>
    public async Task<WorkerDeployment> DeployVersionsAsync(string scriptName, IReadOnlyList<WorkerDeploymentVersion> versions, string? message = null, bool allowDeploy = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDeploy, "deploying a version changes what runs on the edge at once", nameof(allowDeploy));
        var body = DeploymentBody(versions, message);
        return await Api.PostAsync<WorkerDeployment>(AccountPath(accountId, "workers", "scripts", Script(scriptName), "deployments"), body, ct).ConfigureAwait(false);
    }

    // ---- secrets ----

    /// <summary>Plan of a secret change. The value is shown as <c>[redacted]</c>.</summary>
    public CloudflareChangePreview PreviewPutSecret(string scriptName, string secretName, string? accountId = null) =>
        new("PUT", AccountPath(accountId, "workers", "scripts", Script(scriptName), "secrets"),
            new JsonObject { ["name"] = SecretName(secretName), ["text"] = ResourceKit.Redacted, ["type"] = "secret_text" },
            $"Set secret \"{secretName}\" of Worker \"{scriptName}\". WARNING: Cloudflare deploys the change at once.");

    /// <summary>Creates or replaces a secret (PUT, idempotent). Refused unless <paramref name="allowDeploy"/> is true. Only name and type come back.</summary>
    public Task<WorkerSecretInfo> PutSecretAsync(string scriptName, string secretName, WorkerSecretText value, bool allowDeploy = false, string? accountId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        ResourceKit.Allow(allowDeploy, "changing a secret creates a new version that Cloudflare deploys at once", nameof(allowDeploy));
        var body = new JsonObject { ["name"] = SecretName(secretName), ["text"] = value.Reveal(), ["type"] = "secret_text" };
        return ResourceKit.SendStrippedAsync<WorkerSecretInfo>(Api, HttpMethod.Put, AccountPath(accountId, "workers", "scripts", Script(scriptName), "secrets"), body, ct, "text", "value");
    }

    public CloudflareChangePreview PreviewRemoveSecret(string scriptName, string secretName, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "workers", "scripts", Script(scriptName), "secrets", SecretName(secretName)), null,
            $"Delete secret \"{secretName}\" of Worker \"{scriptName}\". WARNING: code that reads it fails after the deployment.");

    /// <summary>Deletes a secret by name. Refused unless <paramref name="allowDeploy"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveSecretAsync(string scriptName, string secretName, bool allowDeploy = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDeploy, "deleting a secret creates a new version that Cloudflare deploys at once", nameof(allowDeploy));
        return DeleteIfExistsAsync(AccountPath(accountId, "workers", "scripts", Script(scriptName), "secrets", SecretName(secretName)), null, ct);
    }

    // ---- helpers ----

    private static string Script(string? name) => ResourceKit.Match(name, "scriptName", ScriptNamePattern, "letters, digits, '-' and '_', at most 63 characters");

    private static string SecretName(string? name) => ResourceKit.Match(name, "secretName", SecretNamePattern, "an identifier of letters, digits, '_' and '$', at most 64 characters");

    private static string CheckVersionId(string? id) => ResourceKit.Match(id, "versionId", VersionIdPattern, "a version UUID");

    private static void CheckPattern(string? pattern, bool allowBroadRoute)
    {
        ResourceKit.Required(pattern, nameof(pattern), 255);
        if (pattern!.Contains("://", StringComparison.Ordinal) || pattern.Contains(' ')) throw new ArgumentException("A route pattern has no scheme and no spaces, for example example.com/api/*.", nameof(pattern));
        var slash = pattern.IndexOf('/');
        var host = slash < 0 ? pattern : pattern[..slash];
        if (host.Length == 0) throw new ArgumentException("A route pattern starts with the host.", nameof(pattern));
        if (host.StartsWith('*')) ResourceKit.Allow(allowBroadRoute, $"\"{pattern}\" puts the Worker in front of every matching hostname, including subdomains you may not mean", nameof(allowBroadRoute));
    }

    private JsonObject DomainBody(string hostname, string scriptName, string? zoneId, string environment) => new()
    {
        ["environment"] = ResourceKit.Required(environment, nameof(environment), 64),
        ["hostname"] = ResourceKit.Hostname(hostname, nameof(hostname)),
        ["service"] = Script(scriptName),
        ["zone_id"] = Zone(zoneId),
    };

    private static List<string> CheckCrons(IEnumerable<string> crons, bool allowClear)
    {
        var list = crons.Select(c => (c ?? "").Trim()).ToList();
        if (list.Count == 0) ResourceKit.Allow(allowClear, "an empty list removes every cron trigger", nameof(allowClear));
        foreach (var c in list)
            if (c.Length > 100 || !CronPattern.IsMatch(c)) throw new ArgumentException($"\"{c}\" is not a cron expression with five fields (minute hour day-of-month month day-of-week).", nameof(crons));
        return list.Distinct(StringComparer.Ordinal).ToList();
    }

    private static JsonArray ScheduleBody(IEnumerable<string> crons) => new(crons.Select(c => (JsonNode?)new JsonObject { ["cron"] = c }).ToArray());

    private static JsonObject DeploymentBody(IReadOnlyList<WorkerDeploymentVersion> versions, string? message)
    {
        if (versions is null || versions.Count is < 1 or > 2) throw new ArgumentException("A deployment has one or two versions.", nameof(versions));
        foreach (var v in versions)
        {
            CheckVersionId(v.VersionId);
            if (v.Percentage is <= 0 or > 100) throw new ArgumentException("Each percentage must be above 0 and at most 100.", nameof(versions));
        }
        if (Math.Abs(versions.Sum(v => v.Percentage) - 100) > 0.001) throw new ArgumentException("The percentages must add up to 100.", nameof(versions));
        if (versions.Select(v => v.VersionId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != versions.Count) throw new ArgumentException("A version appears only once.", nameof(versions));
        var body = new JsonObject
        {
            ["strategy"] = "percentage",
            ["versions"] = new JsonArray(versions.Select(v => (JsonNode?)new JsonObject { ["percentage"] = v.Percentage, ["version_id"] = v.VersionId }).ToArray()),
        };
        if (!string.IsNullOrWhiteSpace(message)) body["annotations"] = new JsonObject { ["workers/message"] = message.Length > 100 ? message[..100] : message };
        return body;
    }

    private static (JsonObject Metadata, byte[] Source) PrepareUpload(string scriptName, string moduleSource, WorkerMetadata? metadata)
    {
        Script(scriptName);
        ResourceKit.Required(moduleSource, nameof(moduleSource));
        var bytes = Encoding.UTF8.GetBytes(moduleSource);
        if (bytes.Length > MaxScriptBytes) throw new ArgumentException("A Worker may have at most 64 MiB uncompressed (Cloudflare's limit).", nameof(moduleSource));
        var meta = metadata ?? new WorkerMetadata();
        var node = JsonSerializer.SerializeToNode(meta, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull })!.AsObject();
        var main = meta.MainModule;
        if (string.IsNullOrWhiteSpace(main) || main.Contains('/') || main.Contains('\\') || !(main.EndsWith(".js", StringComparison.Ordinal) || main.EndsWith(".mjs", StringComparison.Ordinal)))
            throw new ArgumentException("The main module is a file name ending in .js or .mjs.", nameof(metadata));
        if (node["bindings"] is JsonArray bindings)
            foreach (var b in bindings)
            {
                var type = b?["type"]?.GetValue<string>();
                if (type is "secret_text" or "secret_key")
                    throw new ArgumentException($"Binding \"{b?["name"]}\" has the secret type {type}. Secret values do not belong in upload metadata; use PutSecretAsync.", nameof(metadata));
            }
        node["keep_bindings"] ??= new JsonArray("secret_text", "secret_key");
        return (node, bytes);
    }
}
