using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Shared helpers of the 0.7.0 clients (Workers, KV, D1, Queues, R2, Cache, Load Balancing, Spectrum, Argo).</summary>
internal static class P2
{
    /// <summary>Throws before anything is sent when a risky option was not switched on deliberately.</summary>
    public static void Allow(bool allowed, string what, string flag)
    {
        if (!allowed) throw new InvalidOperationException($"Refused: {what}. Pass {flag}: true deliberately.");
    }

    public static string Match(string? value, string parameter, Regex pattern, string rule)
    {
        if (string.IsNullOrWhiteSpace(value) || !pattern.IsMatch(value)) throw new ArgumentException($"\"{value}\" is not valid: {rule}.", parameter);
        return value;
    }

    public static int Utf8(string value) => Encoding.UTF8.GetByteCount(value);

    public static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static Regex Rx(string pattern) => new(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>The path of a <c>Preview…</c> without query (the query only carries non-secret flags).</summary>
    public static string Mask(string? value) => string.IsNullOrEmpty(value) ? "" : P1.Redacted;

    public static JsonNode? Clone(JsonElement? e) => P1.Node(e);

    /// <summary>The <c>result</c> of an envelope as <see cref="JsonElement"/>.</summary>
    public static async Task<JsonElement> ResultAsync(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct) =>
        (await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false)).Result;

    public static IEnumerable<T[]> Chunk<T>(IReadOnlyList<T> items, int size)
    {
        for (var i = 0; i < items.Count; i += size) yield return items.Skip(i).Take(size).ToArray();
    }

    /// <summary>True when a JSON element is an object with the member.</summary>
    public static bool TryGet(JsonElement e, string name, out JsonElement value)
    {
        value = default;
        return e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out value);
    }

    public static string? Str(JsonElement e, string name) => TryGet(e, name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
