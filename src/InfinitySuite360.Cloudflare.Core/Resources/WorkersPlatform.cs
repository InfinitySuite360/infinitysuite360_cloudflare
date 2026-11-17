using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A Pages project (without environment variables and build tokens).</summary>
public sealed class PagesProject : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Subdomain { get; init; }
    public string? ProductionBranch { get; init; }
    public List<string> Domains { get; init; } = [];
    public DateTimeOffset? CreatedOn { get; init; }
}

/// <summary>A Pages deployment (without environment variables).</summary>
public sealed class PagesDeployment : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? ShortId { get; init; }
    public string? ProjectName { get; init; }
    /// <summary>"production" or "preview".</summary>
    public string? Environment { get; init; }
    public string? Url { get; init; }
    public List<string> Aliases { get; init; } = [];
    public JsonElement? LatestStage { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
}

/// <summary>
/// Cloudflare Pages, narrow wrapper (0.9.0, matrix priority 3): list and read projects and deployments; roll back production to an earlier deployment with
/// preview and <c>allowDeploy</c>. Creating projects, uploads, domains and environment variables are deliberately only reachable through <c>OpenApi</c>:
/// environment variables carry secrets, and uploads need the direct-upload flow. Environment variables (<c>env_vars</c>), <c>deployment_configs</c> and
/// analytics tokens are removed from every answer. Endpoints <c>pages-project-*</c>, <c>pages-deployment-*</c> of cloudflare/api-schemas@650bd71. Limits
/// (developers.cloudflare.com/pages/platform/limits/, retrieved 17.11.2026): Free 500 builds per month, one at a time; 100 custom domains per project on Free.
/// </summary>
public sealed class PagesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Hidden = ["env_vars", "deployment_configs", "web_analytics_token", "build_config"];

    public async Task<IReadOnlyList<PagesProject>> ListProjectsAsync(string? accountId = null, CancellationToken ct = default) =>
        (await ResourceKit.ListStrippedAsync<PagesProject>(Api, AccountPath(accountId, "pages", "projects"), 10, ct, Hidden).ConfigureAwait(false));

    public async Task<PagesProject?> GetProjectAsync(string projectName, string? accountId = null, CancellationToken ct = default)
    {
        try { return await ResourceKit.SendStrippedAsync<PagesProject>(Api, HttpMethod.Get, ProjectPath(accountId, projectName), null, ct, Hidden).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>Deployments of a project (newest first); <paramref name="environment"/> "production" or "preview" filters.</summary>
    public async Task<IReadOnlyList<PagesDeployment>> ListDeploymentsAsync(string projectName, string? environment = null, string? accountId = null, CancellationToken ct = default)
    {
        if (environment is not (null or "production" or "preview")) throw new ArgumentException("environment must be \"production\" or \"preview\".", nameof(environment));
        var path = CloudflarePath.WithQuery(ProjectPath(accountId, projectName) + "/deployments", ("env", environment));
        return await ResourceKit.ListStrippedAsync<PagesDeployment>(Api, path, 25, ct, Hidden).ConfigureAwait(false);
    }

    /// <summary>What <see cref="RollbackAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewRollback(string projectName, string deploymentId, string? accountId = null) =>
        Preview(HttpMethod.Post, DeploymentPath(accountId, projectName, deploymentId) + "/rollback", null,
            $"Roll production of {projectName} back to deployment {deploymentId}. Visitors get the older version at once.");

    /// <summary>Rolls production back to <paramref name="deploymentId"/> (write guard first; needs <paramref name="allowDeploy"/>; POST, never repeated).</summary>
    public Task<PagesDeployment> RollbackAsync(string projectName, string deploymentId, string? accountId = null, bool allowDeploy = false, CancellationToken ct = default)
    {
        var path = DeploymentPath(accountId, projectName, deploymentId) + "/rollback";
        EnsureWritable(HttpMethod.Post, path);
        ResourceKit.Allow(allowDeploy, "a rollback changes what visitors get at once", nameof(allowDeploy));
        return ResourceKit.SendStrippedAsync<PagesDeployment>(Api, HttpMethod.Post, path, null, ct, Hidden);
    }

    private string ProjectPath(string? accountId, string projectName) =>
        AccountPath(accountId, "pages", "projects", ResourceKit.Required(projectName, nameof(projectName)));

    private string DeploymentPath(string? accountId, string projectName, string deploymentId) =>
        AccountPath(accountId, "pages", "projects", ResourceKit.Required(projectName, nameof(projectName)), "deployments", ResourceKit.Required(deploymentId, nameof(deploymentId)));
}

/// <summary>A Hyperdrive configuration (origin without password or access secret).</summary>
public sealed class HyperdriveConfig : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>Host, port, database, scheme, user and access client id; the password and the access client secret are removed.</summary>
    public JsonElement? Origin { get; init; }
    public JsonElement? Caching { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>
/// Hyperdrive, narrow wrapper (0.9.0, matrix priority 3): list and read configurations (database password and access client secret removed); delete one
/// with preview and <c>allowDelete</c>. Creating and changing configurations needs the database password and is deliberately only reachable through
/// <c>OpenApi</c>. Endpoints <c>list-hyperdrive</c>, <c>get-hyperdrive</c>, <c>delete-hyperdrive</c> of cloudflare/api-schemas@650bd71. Limits
/// (developers.cloudflare.com/hyperdrive/platform/limits/, retrieved 17.11.2026): 10 configurations per account on Free, 25 on Paid.
/// </summary>
public sealed class HyperdriveClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<List<HyperdriveConfig>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeListAsync<HyperdriveConfig>(Api, AccountPath(accountId, "hyperdrive", "configs"), ct);

    public Task<HyperdriveConfig?> GetAsync(string configId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeOrNullAsync<HyperdriveConfig>(Api, AccountPath(accountId, "hyperdrive", "configs", ResourceKit.Required(configId, nameof(configId))), ct);

    public CloudflareChangePreview PreviewDelete(string configId, string? accountId = null) =>
        Preview(HttpMethod.Delete, AccountPath(accountId, "hyperdrive", "configs", ResourceKit.Required(configId, nameof(configId))), null,
            $"Delete Hyperdrive configuration {configId}. Workers bound to it lose their database connection.");

    /// <summary>Deletes a configuration (write guard first; needs <paramref name="allowDelete"/>). False when it did not exist.</summary>
    public Task<bool> DeleteAsync(string configId, string? accountId = null, bool allowDelete = false, CancellationToken ct = default) =>
        GuardedDeleteAsync(AccountPath(accountId, "hyperdrive", "configs", ResourceKit.Required(configId, nameof(configId))), allowDelete,
            "Workers bound to the configuration lose their database connection", nameof(allowDelete), ct);
}

/// <summary>A Workflow definition.</summary>
public sealed class WorkflowInfo : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? ClassName { get; init; }
    public string? ScriptName { get; init; }
    public JsonElement? Instances { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>A Workflow instance (status and timestamps; the parameters and step outputs are not part of the model).</summary>
public sealed class WorkflowInstance : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"queued", "running", "paused", "errored", "terminated", "complete", "waiting" …</summary>
    public string? Status { get; init; }
    public string? VersionId { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? StartedOn { get; init; }
    public DateTimeOffset? EndedOn { get; init; }
}

/// <summary>
/// Workflows, narrow wrapper (0.9.0, matrix priority 3): list workflows and instances, read an instance; pause, resume or terminate an instance with
/// preview (<c>terminate</c> needs <c>allowTerminate</c>, it cannot be resumed). Creating instances (with parameters), events and deleting workflows are
/// deliberately only reachable through <c>OpenApi</c>. Instance parameters and step outputs are removed from the answers (<c>params</c>, <c>output</c>,
/// <c>steps</c>), they may carry personal data. Endpoints <c>wor-*</c> of cloudflare/api-schemas@650bd71. Limits
/// (developers.cloudflare.com/workflows/reference/limits/, retrieved 17.11.2026): Free 100 000 executions per day (shared with Workers), Paid unlimited.
/// </summary>
public sealed class WorkflowsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly string[] Hidden = ["params", "output", "steps", "error"];

    public Task<IReadOnlyList<WorkflowInfo>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListAllSecretFreeAsync<WorkflowInfo>(Api, AccountPath(accountId, "workflows"), 50, ct);

    /// <summary>Instances of a workflow; <paramref name="status"/> filters (for example "errored").</summary>
    public Task<IReadOnlyList<WorkflowInstance>> ListInstancesAsync(string workflowName, string? status = null, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<WorkflowInstance>(Api, CloudflarePath.WithQuery(WorkflowPath(accountId, workflowName) + "/instances", ("status", status)), 50, ct, Hidden);

    public async Task<WorkflowInstance?> GetInstanceAsync(string workflowName, string instanceId, string? accountId = null, CancellationToken ct = default)
    {
        try { return await ResourceKit.SendStrippedAsync<WorkflowInstance>(Api, HttpMethod.Get, InstancePath(accountId, workflowName, instanceId), null, ct, Hidden).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>What <see cref="ChangeInstanceStatusAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewChangeInstanceStatus(string workflowName, string instanceId, string status, string? accountId = null) =>
        Preview(HttpMethod.Patch, InstancePath(accountId, workflowName, instanceId) + "/status", new { status = Status(status) },
            $"Set instance {instanceId} of {workflowName} to \"{status}\".{(status == "terminate" ? " WARNING: a terminated instance cannot be resumed." : "")}");

    /// <summary>
    /// Pauses, resumes, restarts or terminates an instance (<paramref name="status"/>: "pause", "resume", "restart", "terminate"). "terminate" and "restart" need
    /// <paramref name="allowTerminate"/> (the running state is lost). Write guard first.
    /// </summary>
    public Task<JsonElement> ChangeInstanceStatusAsync(string workflowName, string instanceId, string status, string? accountId = null, bool allowTerminate = false, CancellationToken ct = default)
    {
        var s = Status(status);
        return GuardedWriteAsync<JsonElement>(HttpMethod.Patch, InstancePath(accountId, workflowName, instanceId) + "/status", new { status = s }, ct,
            s is "pause" or "resume" || allowTerminate, $"\"{s}\" ends the running state of the instance", nameof(allowTerminate));
    }

    private static string Status(string? status) => status is "pause" or "resume" or "restart" or "terminate"
        ? status
        : throw new ArgumentException("status must be \"pause\", \"resume\", \"restart\" or \"terminate\".", nameof(status));

    private string WorkflowPath(string? accountId, string workflowName) =>
        AccountPath(accountId, "workflows", ResourceKit.Required(workflowName, nameof(workflowName)));

    private string InstancePath(string? accountId, string workflowName, string instanceId) =>
        AccountPath(accountId, "workflows", ResourceKit.Required(workflowName, nameof(workflowName)), "instances", ResourceKit.Required(instanceId, nameof(instanceId)));
}

/// <summary>A Durable Objects namespace.</summary>
public sealed class DurableObjectNamespace : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Class { get; init; }
    public string? Script { get; init; }
    public bool? UseSqlite { get; init; }
}

/// <summary>A Durable Object of a namespace.</summary>
public sealed class DurableObjectInfo : CloudflareModel
{
    public string Id { get; init; } = "";
    public bool? HasStoredData { get; init; }
}

/// <summary>
/// Durable Objects, read-only (0.9.0, matrix priority 3): namespaces and the objects of a namespace. The SQL query endpoint and namespace changes (only via
/// Worker deployments) are deliberately only reachable through <c>OpenApi</c>. Endpoints <c>durable-objects-namespace-*</c> of cloudflare/api-schemas@650bd71.
/// Limits (developers.cloudflare.com/durable-objects/platform/limits/, retrieved 17.11.2026): 100 classes on Free, 500 on Workers Paid; 10 GB per object.
/// </summary>
public sealed class DurableObjectsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<DurableObjectNamespace>> ListNamespacesAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListAllSecretFreeAsync<DurableObjectNamespace>(Api, AccountPath(accountId, "workers", "durable_objects", "namespaces"), 100, ct);

    /// <summary>Objects of a namespace (cursor paging, at most <paramref name="maxItems"/>).</summary>
    public async Task<IReadOnlyList<DurableObjectInfo>> ListObjectsAsync(string namespaceId, string? accountId = null, int maxItems = 10_000, CancellationToken ct = default)
    {
        if (maxItems < 1) throw new ArgumentOutOfRangeException(nameof(maxItems));
        var list = new List<DurableObjectInfo>();
        var path = AccountPath(accountId, "workers", "durable_objects", "namespaces", ResourceKit.Required(namespaceId, nameof(namespaceId)), "objects");
        await foreach (var e in Api.ListAllAsync<JsonElement>(path, 1000, ct).ConfigureAwait(false))
        {
            list.Add(ResourceKit.As<DurableObjectInfo>(ResourceKit.StripSecrets(e)));
            if (list.Count >= maxItems) break;
        }
        return list;
    }
}

/// <summary>A secrets store of the account.</summary>
public sealed class SecretsStore : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Modified { get; init; }
}

/// <summary>Metadata of a secret in a store. The value is never part of the model (Cloudflare does not return it either).</summary>
public sealed class SecretsStoreEntry : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? StoreId { get; init; }
    public string? Status { get; init; }
    public string? Comment { get; init; }
    public List<string> Scopes { get; init; } = [];
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Modified { get; init; }
}

/// <summary>
/// Secrets Store, narrow wrapper (0.9.0, matrix priority 3, open beta): list stores and the metadata of their secrets; delete a secret with preview and
/// <c>allowDelete</c>. Creating secrets and changing values are deliberately only reachable through <c>OpenApi</c>: a secret value must not pass through a
/// general-purpose client and its logs. The member <c>value</c> is removed from every answer in addition to the secret rule. Endpoints
/// <c>secrets-store-*</c> of cloudflare/api-schemas@650bd71. Limits (developers.cloudflare.com/secrets-store/manage-secrets/, retrieved 17.11.2026): one
/// store and 100 secrets per account in the beta, 65 536 bytes per value.
/// </summary>
public sealed class SecretsStoreClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<SecretsStore>> ListStoresAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.ListStrippedAsync<SecretsStore>(Api, AccountPath(accountId, "secrets_store", "stores"), 50, ct, "value");

    /// <summary>The secrets of a store: names, scopes, status, comment (no values).</summary>
    public async Task<IReadOnlyList<SecretsStoreEntry>> ListSecretsAsync(string storeId, string? accountId = null, CancellationToken ct = default)
    {
        var list = new List<SecretsStoreEntry>();
        await foreach (var e in Api.ListAllAsync<JsonElement>(SecretsPath(accountId, storeId), 100, ct).ConfigureAwait(false))
            list.Add(ResourceKit.As<SecretsStoreEntry>(ResourceKit.StripSecrets(ResourceKit.Strip(e, "value"))));
        return list;
    }

    public CloudflareChangePreview PreviewDeleteSecret(string storeId, string secretId, string? accountId = null) =>
        Preview(HttpMethod.Delete, SecretsPath(accountId, storeId) + "/" + CloudflarePath.Of(ResourceKit.Required(secretId, nameof(secretId))), null,
            $"Delete secret {secretId} from store {storeId}. Workers bound to it fail at once; the value cannot be recovered.");

    /// <summary>Deletes a secret (write guard first; needs <paramref name="allowDelete"/>). False when it did not exist.</summary>
    public Task<bool> DeleteSecretAsync(string storeId, string secretId, string? accountId = null, bool allowDelete = false, CancellationToken ct = default) =>
        GuardedDeleteAsync(SecretsPath(accountId, storeId) + "/" + CloudflarePath.Of(ResourceKit.Required(secretId, nameof(secretId))), allowDelete,
            "Workers bound to the secret fail and the value cannot be recovered", nameof(allowDelete), ct);

    private string SecretsPath(string? accountId, string storeId) =>
        AccountPath(accountId, "secrets_store", "stores", ResourceKit.Required(storeId, nameof(storeId)), "secrets");
}
