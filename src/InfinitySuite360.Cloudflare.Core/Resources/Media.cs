using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>An image stored in Cloudflare Images (metadata, no image data).</summary>
public sealed class CloudflareImage : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Filename { get; init; }
    public string? Creator { get; init; }
    public DateTimeOffset? Uploaded { get; init; }
    /// <summary>True when the image is only delivered with a signed URL.</summary>
    [System.Text.Json.Serialization.JsonPropertyName("requireSignedURLs")]
    public bool? RequireSignedUrls { get; init; }
    /// <summary>Delivery URLs of the variants.</summary>
    public List<string> Variants { get; init; } = [];
}

/// <summary>Usage of Cloudflare Images (stored images and the allowance).</summary>
public sealed class ImagesStats : CloudflareModel
{
    public ImagesCount? Count { get; init; }
}

/// <summary>Number of stored images and the allowance of the account.</summary>
public sealed class ImagesCount : CloudflareModel
{
    public long? Allowed { get; init; }
    public long? Current { get; init; }
}

/// <summary>
/// Cloudflare Images, narrow wrapper (0.9.0, matrix priority 3): list and read images, usage and variants; delete one image with preview and
/// <c>allowDelete</c>. Uploads (multipart, direct-upload URLs), signing keys (key values) and variant changes are deliberately only reachable through
/// <c>OpenApi</c>: uploads need binary handling outside this pipeline, and the signing keys are secrets. Endpoints <c>cloudflare-images-*</c> of
/// cloudflare/api-schemas@650bd71. Tariff (developers.cloudflare.com/images/pricing/, retrieved 17.11.2026): storing images in Images needs the Paid
/// plan ($5 per 100 000 images stored per month); transformations of images stored elsewhere are part of the Free plan (5000 unique per month).
/// </summary>
public sealed class ImagesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Images of the account, page by page up to <paramref name="maxItems"/> (Images v1 pages, 100 per page).</summary>
    public async Task<IReadOnlyList<CloudflareImage>> ListAsync(string? accountId = null, int maxItems = 1000, CancellationToken ct = default)
    {
        if (maxItems < 1) throw new ArgumentOutOfRangeException(nameof(maxItems));
        var path = AccountPath(accountId, "images", "v1");
        var list = new List<CloudflareImage>();
        for (var page = 1; list.Count < maxItems && page <= 1000; page++)
        {
            var result = await ResourceKit.SecretFreeResultAsync(Api, HttpMethod.Get, CloudflarePath.WithQuery(path, ("page", page.ToString()), ("per_page", "100")), null, ct).ConfigureAwait(false);
            if (!ResourceKit.TryGet(result, "images", out var images) || images.ValueKind != JsonValueKind.Array) break;
            var batch = images.EnumerateArray().Select(ResourceKit.As<CloudflareImage>).ToList();
            list.AddRange(batch.Take(maxItems - list.Count));
            if (batch.Count < 100) break;
        }
        return list;
    }

    /// <summary>One image (metadata); null when it does not exist.</summary>
    public Task<CloudflareImage?> GetAsync(string imageId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeOrNullAsync<CloudflareImage>(Api, AccountPath(accountId, "images", "v1", ResourceKit.Required(imageId, nameof(imageId))), ct);

    /// <summary>Stored images and allowance.</summary>
    public Task<ImagesStats> GetStatsAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.SendSecretFreeAsync<ImagesStats>(Api, HttpMethod.Get, AccountPath(accountId, "images", "v1", "stats"), null, ct);

    /// <summary>The variants of the account as returned by Cloudflare (<c>variants</c> object: name → options).</summary>
    public async Task<JsonElement> GetVariantsAsync(string? accountId = null, CancellationToken ct = default)
    {
        var result = await ResourceKit.SecretFreeResultAsync(Api, HttpMethod.Get, AccountPath(accountId, "images", "v1", "variants"), null, ct).ConfigureAwait(false);
        return ResourceKit.TryGet(result, "variants", out var v) ? v.Clone() : result;
    }

    /// <summary>What <see cref="DeleteAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewDelete(string imageId, string? accountId = null) =>
        Preview(HttpMethod.Delete, AccountPath(accountId, "images", "v1", ResourceKit.Required(imageId, nameof(imageId))), null,
            $"Delete image {imageId}. Pages that embed it show a broken image; the deletion cannot be undone.");

    /// <summary>Deletes one image (write guard first; needs <paramref name="allowDelete"/>). False when it did not exist.</summary>
    public Task<bool> DeleteAsync(string imageId, string? accountId = null, bool allowDelete = false, CancellationToken ct = default) =>
        GuardedDeleteAsync(AccountPath(accountId, "images", "v1", ResourceKit.Required(imageId, nameof(imageId))), allowDelete,
            "deleting an image cannot be undone", nameof(allowDelete), ct);
}

/// <summary>A Stream video (metadata; no signed tokens, no upload URLs).</summary>
public sealed class StreamVideo : CloudflareModel
{
    public string Uid { get; init; } = "";
    public string? Creator { get; init; }
    public double? Duration { get; init; }
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Modified { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("readyToStream")]
    public bool? ReadyToStream { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("requireSignedURLs")]
    public bool? RequireSignedUrls { get; init; }
    public long? Size { get; init; }
    public JsonElement? Status { get; init; }
    public Dictionary<string, JsonElement>? Meta { get; init; }
}

/// <summary>Storage used by Stream.</summary>
public sealed class StreamStorageUsage : CloudflareModel
{
    public string? Creator { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("totalStorageMinutes")]
    public double? TotalStorageMinutes { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("totalStorageMinutesLimit")]
    public double? TotalStorageMinutesLimit { get; init; }
    [System.Text.Json.Serialization.JsonPropertyName("videoCount")]
    public long? VideoCount { get; init; }
}

/// <summary>
/// Cloudflare Stream, narrow wrapper (0.9.0, matrix priority 3): list and read videos, storage usage; delete one video with preview and
/// <c>allowDelete</c>. Uploads (tus, direct upload), signed-URL keys and tokens, live inputs, captions and downloads are deliberately only reachable through
/// <c>OpenApi</c> (binary uploads, secrets). Endpoints <c>stream-videos-*</c> of cloudflare/api-schemas@650bd71. Tariff (developers.cloudflare.com/stream/pricing/,
/// retrieved 17.11.2026): storage prepaid in steps of $5 per 1000 minutes per month, delivery $1 per 1000 minutes.
/// </summary>
public sealed class StreamClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    /// <summary>Videos of the account (newest first, at most <paramref name="limit"/>, Cloudflare allows up to 1000 per call).</summary>
    public Task<List<StreamVideo>> ListVideosAsync(string? accountId = null, string? search = null, int limit = 1000, CancellationToken ct = default)
    {
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit), "1 to 1000.");
        return ResourceKit.GetSecretFreeListAsync<StreamVideo>(Api,
            CloudflarePath.WithQuery(AccountPath(accountId, "stream"), ("search", search), ("limit", limit.ToString())), ct);
    }

    /// <summary>One video; null when it does not exist.</summary>
    public Task<StreamVideo?> GetVideoAsync(string videoId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeOrNullAsync<StreamVideo>(Api, AccountPath(accountId, "stream", ResourceKit.Required(videoId, nameof(videoId))), ct);

    /// <summary>Stored minutes, limit and number of videos.</summary>
    public Task<StreamStorageUsage> GetStorageUsageAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.SendSecretFreeAsync<StreamStorageUsage>(Api, HttpMethod.Get, AccountPath(accountId, "stream", "storage-usage"), null, ct);

    /// <summary>What <see cref="DeleteVideoAsync"/> would send (nothing is sent).</summary>
    public CloudflareChangePreview PreviewDeleteVideo(string videoId, string? accountId = null) =>
        Preview(HttpMethod.Delete, AccountPath(accountId, "stream", ResourceKit.Required(videoId, nameof(videoId))), null,
            $"Delete video {videoId}. Players that embed it stop working; the deletion cannot be undone.");

    /// <summary>Deletes one video (write guard first; needs <paramref name="allowDelete"/>). False when it did not exist.</summary>
    public Task<bool> DeleteVideoAsync(string videoId, string? accountId = null, bool allowDelete = false, CancellationToken ct = default) =>
        GuardedDeleteAsync(AccountPath(accountId, "stream", ResourceKit.Required(videoId, nameof(videoId))), allowDelete,
            "deleting a video cannot be undone", nameof(allowDelete), ct);
}
