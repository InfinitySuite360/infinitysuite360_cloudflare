using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class CloudflareQueue : CloudflareModel
{
    public string QueueId { get; init; } = "";
    public string QueueName { get; init; } = "";
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
    public int? ProducersTotalCount { get; init; }
    public int? ConsumersTotalCount { get; init; }
    /// <summary>delivery_delay, delivery_paused, message_retention_period (seconds).</summary>
    public JsonElement? Settings { get; init; }
}

public sealed class QueueConsumer : CloudflareModel
{
    public string ConsumerId { get; init; } = "";
    public string? Type { get; init; }
    public string? ScriptName { get; init; }
    public string? DeadLetterQueue { get; init; }
    public JsonElement? Settings { get; init; }
}

/// <summary>A Worker consumer (push) or an HTTP pull consumer.</summary>
public sealed class QueueConsumerInput
{
    /// <summary>"worker" (default) or "http_pull".</summary>
    public string Type { get; init; } = "worker";
    /// <summary>The consuming Worker (type worker).</summary>
    public string? ScriptName { get; init; }
    public string? DeadLetterQueue { get; init; }
    /// <summary>Up to 100 (Cloudflare's maximum consumer batch size).</summary>
    public int? BatchSize { get; init; }
    /// <summary>Up to 100.</summary>
    public int? MaxRetries { get; init; }
    /// <summary>Up to 60 000 ms (60 seconds).</summary>
    public int? MaxWaitTimeMs { get; init; }
    public int? RetryDelay { get; init; }
}

public sealed class QueueBacklog : CloudflareModel
{
    public long? BacklogCount { get; init; }
    public long? BacklogBytes { get; init; }
    public long? OldestMessageTimestampMs { get; init; }
}

/// <summary>
/// Cloudflare Queues: queues, consumers, publishing and the backlog. Limits (developers.cloudflare.com/queues/platform/limits/, retrieved 17.11.2026): message
/// 128 KB, up to 100 messages (256 KB in total) per batch, consumer batch size 100, retries 100, delay up to 24 hours, retention up to 14 days. Deleting a queue
/// needs <c>allowDelete</c>, purging its messages <c>allowPurge</c>, pausing delivery <c>allowPause</c>. Message bodies can be sensitive: previews show sizes only.
/// Token permission "Account: Queues: Edit" (reading "Read"). Pulling and acknowledging messages (leases) are not included. Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class QueuesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly Regex NamePattern = ResourceKit.Rx(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$");
    private const int MaxMessageBytes = 128 * 1024;
    private const int MaxBatch = 100;
    private const int MaxBatchBytes = 256 * 1024;

    public Task<IReadOnlyList<CloudflareQueue>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<CloudflareQueue>(AccountPath(accountId, "queues"), 100, ct);

    public async Task<CloudflareQueue?> FindByNameAsync(string queueName, string? accountId = null, CancellationToken ct = default) =>
        (await ListAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(q => q.QueueName == queueName);

    public Task<CloudflareQueue> GetAsync(string queueId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<CloudflareQueue>(AccountPath(accountId, "queues", queueId), ct);

    public CloudflareChangePreview PreviewCreate(string queueName, string? accountId = null) =>
        new("POST", AccountPath(accountId, "queues"), new JsonObject { ["queue_name"] = Name(queueName) }, $"Create queue \"{queueName}\".");

    /// <summary>Returns the queue with this name or creates it (survives a concurrent create).</summary>
    public async Task<(CloudflareQueue Queue, bool Created)> EnsureAsync(string queueName, string? accountId = null, CancellationToken ct = default)
    {
        Name(queueName);
        var path = AccountPath(accountId, "queues");
        EnsureWritable(HttpMethod.Post, path);
        var existing = await FindByNameAsync(queueName, accountId, ct).ConfigureAwait(false);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<CloudflareQueue>(path, new JsonObject { ["queue_name"] = queueName }, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            return (await FindByNameAsync(queueName, accountId, ct).ConfigureAwait(false) ?? throw new CloudflareConflictException(HttpStatusCode.Conflict, "POST", path, [new CloudflareError { Message = $"Queue \"{queueName}\" is reported as existing but was not found." }]), false);
        }
    }

    public CloudflareChangePreview PreviewSettings(string queueId, int? deliveryDelaySeconds, bool? deliveryPaused, int? messageRetentionSeconds, string? accountId = null) =>
        new("PATCH", AccountPath(accountId, "queues", queueId), SettingsBody(deliveryDelaySeconds, deliveryPaused, messageRetentionSeconds),
            deliveryPaused == true ? $"Change settings of queue {queueId} and PAUSE delivery: consumers receive nothing until it is resumed." : $"Change settings of queue {queueId}.");

    /// <summary>
    /// Changes queue settings (only set values are sent): delivery delay (0 to 86 400 s), pause/resume delivery, retention (60 s to 14 days).
    /// Pausing delivery needs <paramref name="allowPause"/>.
    /// </summary>
    public async Task<CloudflareQueue> UpdateSettingsAsync(string queueId, int? deliveryDelaySeconds = null, bool? deliveryPaused = null, int? messageRetentionSeconds = null, bool allowPause = false, string? accountId = null, CancellationToken ct = default)
    {
        if (deliveryPaused == true) ResourceKit.Allow(allowPause, "pausing delivery stops every consumer of the queue", nameof(allowPause));
        return await Api.PatchAsync<CloudflareQueue>(AccountPath(accountId, "queues", ResourceKit.Required(queueId, nameof(queueId))), SettingsBody(deliveryDelaySeconds, deliveryPaused, messageRetentionSeconds), ct).ConfigureAwait(false);
    }

    public CloudflareChangePreview PreviewRemove(string queueId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "queues", queueId), null, $"Delete queue {queueId}. WARNING: the messages in it are lost.");

    /// <summary>Deletes a queue. Refused unless <paramref name="allowDelete"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveAsync(string queueId, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowDelete, "deleting a queue loses its messages and detaches producers and consumers", nameof(allowDelete));
        return DeleteIfExistsAsync(AccountPath(accountId, "queues", ResourceKit.Required(queueId, nameof(queueId))), null, ct);
    }

    public CloudflareChangePreview PreviewPurge(string queueId, string? accountId = null) =>
        new("POST", AccountPath(accountId, "queues", queueId, "purge"), new JsonObject { ["delete_messages_permanently"] = true }, $"Delete every message of queue {queueId}. WARNING: not reversible.");

    /// <summary>Deletes every message of a queue. Refused unless <paramref name="allowPurge"/> is true. POST is never repeated automatically.</summary>
    public async Task PurgeAsync(string queueId, bool allowPurge = false, string? accountId = null, CancellationToken ct = default)
    {
        ResourceKit.Allow(allowPurge, "purging deletes all messages of the queue", nameof(allowPurge));
        await Api.SendAsync<JsonElement>(HttpMethod.Post, AccountPath(accountId, "queues", ResourceKit.Required(queueId, nameof(queueId)), "purge"), new JsonObject { ["delete_messages_permanently"] = true }, ct).ConfigureAwait(false);
    }

    public Task<QueueBacklog> GetBacklogAsync(string queueId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<QueueBacklog>(AccountPath(accountId, "queues", queueId, "metrics"), ct);

    // ---- consumers ----

    public Task<List<QueueConsumer>> ListConsumersAsync(string queueId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<List<QueueConsumer>>(AccountPath(accountId, "queues", queueId, "consumers"), ct);

    public CloudflareChangePreview PreviewAddConsumer(string queueId, QueueConsumerInput consumer, string? accountId = null) =>
        new("POST", AccountPath(accountId, "queues", queueId, "consumers"), ConsumerBody(consumer), $"Attach {consumer.Type} consumer {consumer.ScriptName ?? ""} to queue {queueId}.");

    /// <summary>Attaches a consumer; a Worker that is already attached is returned unchanged (read after the guard check).</summary>
    public async Task<(QueueConsumer Consumer, bool Created)> EnsureConsumerAsync(string queueId, QueueConsumerInput consumer, string? accountId = null, CancellationToken ct = default)
    {
        var body = ConsumerBody(consumer);
        var path = AccountPath(accountId, "queues", queueId, "consumers");
        EnsureWritable(HttpMethod.Post, path);
        var existing = consumer.Type == "worker"
            ? (await ListConsumersAsync(queueId, accountId, ct).ConfigureAwait(false)).FirstOrDefault(c => c.ScriptName == consumer.ScriptName)
            : null;
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<QueueConsumer>(path, body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveConsumer(string queueId, string consumerId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "queues", queueId, "consumers", consumerId), null, $"Detach consumer {consumerId} from queue {queueId}; messages stay in the queue.");

    /// <summary>Detaches a consumer (messages stay queued). False when it did not exist.</summary>
    public Task<bool> RemoveConsumerAsync(string queueId, string consumerId, string? accountId = null, CancellationToken ct = default) =>
        DeleteIfExistsAsync(AccountPath(accountId, "queues", queueId, "consumers", ResourceKit.Required(consumerId, nameof(consumerId))), null, ct);

    // ---- publishing ----

    public CloudflareChangePreview PreviewPush(string queueId, object body, int? delaySeconds = null, string? accountId = null) =>
        new("POST", AccountPath(accountId, "queues", queueId, "messages"), new JsonObject { ["body_bytes"] = MessageBytes(body), ["delay_seconds"] = delaySeconds },
            $"Publish one message ({MessageBytes(body)} bytes) to queue {queueId}.");

    /// <summary>Publishes one message (JSON body, at most 128 KB). POST is never repeated automatically, so a failed call may or may not have delivered.</summary>
    public async Task PushAsync(string queueId, object body, int? delaySeconds = null, string? accountId = null, CancellationToken ct = default)
    {
        MessageBytes(body);
        var payload = new JsonObject { ["body"] = Node(body), ["content_type"] = "json" };
        if (delaySeconds is { } d) payload["delay_seconds"] = CheckDelay(d);
        await Api.SendAsync<JsonElement>(HttpMethod.Post, AccountPath(accountId, "queues", ResourceKit.Required(queueId, nameof(queueId)), "messages"), payload, ct).ConfigureAwait(false);
    }

    /// <summary>Publishes up to 100 messages (256 KB in total) in one call.</summary>
    public async Task PushBatchAsync(string queueId, IReadOnlyList<object> bodies, int? delaySeconds = null, string? accountId = null, CancellationToken ct = default)
    {
        if (bodies is null || bodies.Count is < 1 or > MaxBatch) throw new ArgumentException($"Between 1 and {MaxBatch} messages.", nameof(bodies));
        var total = bodies.Sum(MessageBytes);
        if (total > MaxBatchBytes) throw new ArgumentException("A batch has at most 256 KB.", nameof(bodies));
        var payload = new JsonObject { ["messages"] = new JsonArray(bodies.Select(b => (JsonNode?)new JsonObject { ["body"] = Node(b), ["content_type"] = "json" }).ToArray()) };
        if (delaySeconds is { } d) payload["delay_seconds"] = CheckDelay(d);
        await Api.SendAsync<JsonElement>(HttpMethod.Post, AccountPath(accountId, "queues", ResourceKit.Required(queueId, nameof(queueId)), "messages", "batch"), payload, ct).ConfigureAwait(false);
    }

    // ---- helpers ----

    private static string Name(string? name) => ResourceKit.Match(name, "queueName", NamePattern, "letters, digits, '-' and '_', at most 63 characters");

    private static JsonNode? Node(object body) => body is JsonNode n ? n.DeepClone() : JsonSerializer.SerializeToNode(body, body.GetType(), CloudflareJson.Options);

    private static int MessageBytes(object body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var bytes = ResourceKit.Utf8(Node(body)?.ToJsonString() ?? "null");
        if (bytes > MaxMessageBytes) throw new ArgumentException("A message has at most 128 KB.", nameof(body));
        return bytes;
    }

    private static int CheckDelay(int seconds) => seconds is >= 0 and <= 86_400 ? seconds : throw new ArgumentOutOfRangeException(nameof(seconds), "0 to 86400 seconds.");

    private static JsonObject SettingsBody(int? delay, bool? paused, int? retention)
    {
        var settings = new JsonObject();
        if (delay is { } d) settings["delivery_delay"] = CheckDelay(d);
        if (paused is { } p) settings["delivery_paused"] = p;
        if (retention is { } r) settings["message_retention_period"] = r is >= 60 and <= 14 * 86_400 ? r : throw new ArgumentOutOfRangeException(nameof(retention), "60 seconds to 14 days.");
        if (settings.Count == 0) throw new ArgumentException("Nothing to change.");
        return new JsonObject { ["settings"] = settings };
    }

    private static JsonObject ConsumerBody(QueueConsumerInput c)
    {
        if (c.Type is not ("worker" or "http_pull")) throw new ArgumentException("Type is worker or http_pull.", nameof(c));
        var body = new JsonObject { ["type"] = c.Type };
        if (c.Type == "worker") body["script_name"] = ResourceKit.Required(c.ScriptName, nameof(c), 63);
        else if (c.ScriptName is not null) throw new ArgumentException("An HTTP pull consumer has no Worker.", nameof(c));
        if (c.DeadLetterQueue is not null) body["dead_letter_queue"] = Name(c.DeadLetterQueue);
        var settings = new JsonObject();
        if (c.BatchSize is { } b) settings["batch_size"] = b is >= 1 and <= 100 ? b : throw new ArgumentOutOfRangeException(nameof(c), "Batch size 1 to 100.");
        if (c.MaxRetries is { } m) settings["max_retries"] = m is >= 0 and <= 100 ? m : throw new ArgumentOutOfRangeException(nameof(c), "Retries 0 to 100.");
        if (c.MaxWaitTimeMs is { } w) settings["max_wait_time_ms"] = w is >= 0 and <= 60_000 ? w : throw new ArgumentOutOfRangeException(nameof(c), "Wait time 0 to 60000 ms.");
        if (c.RetryDelay is { } r) settings["retry_delay"] = CheckDelay(r);
        if (settings.Count > 0) body["settings"] = settings;
        return body;
    }
}
