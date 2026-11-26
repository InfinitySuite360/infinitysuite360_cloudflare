using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// A change that is described but not sent: method, relative path, body and a short text. Used by the <c>Preview…</c> methods so that an application can show
/// the change, ask for approval and only then call the matching write method. The body never contains the API token.
/// </summary>
public sealed record CloudflareChangePreview(string Method, string Path, object? Body, string Summary)
{
    /// <summary>The body as indented JSON (null without body).</summary>
    public string? BodyJson => Body is null ? null : JsonSerializer.Serialize(Body, Body.GetType(), new JsonSerializerOptions(CloudflareJson.Options) { WriteIndented = true });
}
