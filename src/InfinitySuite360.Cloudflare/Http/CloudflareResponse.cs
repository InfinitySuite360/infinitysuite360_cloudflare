using System.Text.Json;
using System.Text.Json.Serialization;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Standard envelope of every Cloudflare API v4 response.</summary>
public sealed class CloudflareResponse<T>
{
    public bool Success { get; init; }
    public IReadOnlyList<CloudflareError> Errors { get; init; } = [];
    public IReadOnlyList<CloudflareMessage> Messages { get; init; } = [];
    public T? Result { get; init; }
    public CloudflareResultInfo? ResultInfo { get; init; }
}

public sealed class CloudflareError
{
    public int Code { get; init; }
    public string Message { get; init; } = "";
    public string? DocumentationUrl { get; init; }

    public override string ToString() => Code == 0 ? Message : $"{Code}: {Message}";
}

public sealed class CloudflareMessage
{
    public int Code { get; init; }
    public string Message { get; init; } = "";
}

/// <summary>Paging information (page- or cursor-based).</summary>
public sealed class CloudflareResultInfo
{
    public int Page { get; init; }
    public int PerPage { get; init; }
    public int Count { get; init; }
    public int TotalCount { get; init; }
    public int TotalPages { get; init; }
    public string? Cursor { get; init; }
    public CloudflareCursors? Cursors { get; init; }
}

public sealed class CloudflareCursors
{
    public string? After { get; init; }
    public string? Before { get; init; }
}

/// <summary>Base of all curated models: unknown fields are preserved (forward compatible with API additions).</summary>
public abstract class CloudflareModel
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalData { get; set; }
}

/// <summary>Result of many create/delete calls: just the ID.</summary>
public sealed class IdResult : CloudflareModel
{
    public string Id { get; init; } = "";
}
