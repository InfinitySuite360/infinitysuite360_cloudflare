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
    protected void EnsureWritable(HttpMethod method, string path) => CloudflareWritePolicy.EnsureAllowed(method, path, Api.Options);

    protected static JsonElement ToElement(object value) => JsonSerializer.SerializeToElement(value, value.GetType(), CloudflareJson.Options);
}
