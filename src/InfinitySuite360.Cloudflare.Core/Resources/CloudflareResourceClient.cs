using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Base of the resource clients: resolves the default zone and account from the options.</summary>
public abstract class CloudflareResourceClient(ICloudflareApiConnection api)
{
    protected ICloudflareApiConnection Api { get; } = api;

    protected string Zone(string? zoneId) =>
        !string.IsNullOrWhiteSpace(zoneId) ? zoneId
        : !string.IsNullOrWhiteSpace(Api.Options.ZoneId) ? Api.Options.ZoneId
        : throw new CloudflareConfigurationException("Cloudflare: no zone ID passed and no default zone (CloudflareOptions.ZoneId) configured.");

    protected string Account(string? accountId) =>
        !string.IsNullOrWhiteSpace(accountId) ? accountId
        : !string.IsNullOrWhiteSpace(Api.Options.AccountId) ? Api.Options.AccountId
        : throw new CloudflareConfigurationException("Cloudflare: no account ID passed and no default account (CloudflareOptions.AccountId) configured.");

    protected string ZonePath(string? zoneId, params string[] rest) => CloudflarePath.Of(["zones", Zone(zoneId), .. rest]);

    protected string AccountPath(string? accountId, params string[] rest) => CloudflarePath.Of(["accounts", Account(accountId), .. rest]);

    /// <summary>GET that returns null on HTTP 404 instead of throwing.</summary>
    protected async Task<T?> GetOrNullAsync<T>(string path, CancellationToken ct) where T : class
    {
        try { return await Api.GetAsync<T>(path, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>
    /// DELETE that treats HTTP 404 as "already gone" (idempotent delete): true when Cloudflare deleted the object, false when it did not exist.
    /// The write guard still applies; other errors throw.
    /// </summary>
    protected async Task<bool> DeleteIfExistsAsync(string path, object? body, CancellationToken ct)
    {
        try
        {
            await Api.SendAsync<JsonElement>(HttpMethod.Delete, path, body, ct).ConfigureAwait(false);
            return true;
        }
        catch (CloudflareApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return false; }
    }

    /// <summary>
    /// Checks the write guard before a method reads the current state to decide what to write (Ensure/guarded methods), so that with
    /// <c>AllowWrites = false</c> nothing is sent at all, not even the preparing read.
    /// </summary>
    /// <remarks>0.9.1 (L-2): also marks the current asynchronous flow as a write operation, so the preparing reads count against the write share of the
    /// request budget until the write is sent (<see cref="CloudflareWriteOperation"/>). Callers are <c>async</c> methods, so the mark stays inside them.</remarks>
    protected void EnsureWritable(HttpMethod method, string path)
    {
        CloudflareWritePolicy.EnsureAllowed(method, path, Api.Options);
        CloudflareWriteOperation.Begin();
    }

    /// <summary>
    /// Before a preparing read whose write target is not known yet (an upsert decides between POST and PUT): passes when the guard allows at least one of the
    /// candidate writes, so that with <c>AllowWrites = false</c> or an allow-list that allows none of them nothing is sent. The caller checks the actual plan
    /// with <see cref="EnsureWritable"/> before it writes.
    /// </summary>
    protected void EnsureAnyWritable(params (HttpMethod Method, string Path)[] candidates)
    {
        CloudflareWriteNotAllowedException? first = null;
        foreach (var (method, path) in candidates)
        {
            try { EnsureWritable(method, path); return; }
            catch (CloudflareWriteNotAllowedException ex) { first ??= ex; }
        }
        if (first is not null) throw first;
    }

    protected static JsonElement ToElement(object value) => JsonSerializer.SerializeToElement(value, value.GetType(), CloudflareJson.Options);

    /// <summary>
    /// The preview base (0.9.0): describes a write without sending it. The path is shown without query; a body is passed through
    /// <see cref="ResourceKit.Redact"/>, so a member that looks like a secret never appears in a preview.
    /// </summary>
    protected static CloudflareChangePreview Preview(HttpMethod method, string path, object? body, string summary) =>
        new(method.Method, CloudflarePath.Normalize(path), body is null ? null : ResourceKit.Redact(ResourceKit.ToNode(body)), summary);

    /// <summary>
    /// A guarded write (0.9.0) whose answer becomes a model only after every secret-looking member was removed: write guard first, then the
    /// <c>allow…</c> switch (<paramref name="allowed"/> with <paramref name="what"/> and <paramref name="flag"/> for the message), then the call.
    /// The connection never repeats a POST after a server error.
    /// </summary>
    protected async Task<T> GuardedWriteAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct, bool allowed = true, string what = "this change", string flag = "allow")
    {
        EnsureWritable(method, path);
        ResourceKit.Allow(allowed, what, flag);
        return await ResourceKit.SendSecretFreeAsync<T>(Api, method, path, body, ct).ConfigureAwait(false);
    }

    /// <summary>A guarded DELETE (0.9.0; write guard, then the switch): true when deleted, false when Cloudflare answered 404.</summary>
    protected async Task<bool> GuardedDeleteAsync(string path, bool allowed, string what, string flag, CancellationToken ct)
    {
        EnsureWritable(HttpMethod.Delete, path);
        ResourceKit.Allow(allowed, what, flag);
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }
}
