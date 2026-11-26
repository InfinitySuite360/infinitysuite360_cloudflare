using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>Shared helpers of the 0.6.0 clients: secret stripping, JSON building, hostname checks.</summary>
internal static class P1
{
    public const string Redacted = "[redacted]";

    private static readonly Regex HostnamePattern = new(@"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Removes the named members anywhere in <paramref name="element"/> (for example <c>private_key</c>) before it is turned into a model.</summary>
    public static JsonElement Strip(JsonElement element, params string[] names)
    {
        if (element.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return element;
        var node = JsonNode.Parse(element.GetRawText());
        StripNode(node, names);
        return JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
    }

    private static void StripNode(JsonNode? node, string[] names)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var n in names) o.Remove(n);
                foreach (var child in o.Select(p => p.Value).ToList()) StripNode(child, names);
                break;
            case JsonArray a:
                foreach (var child in a) StripNode(child, names);
                break;
        }
    }

    public static T As<T>(JsonElement element) => element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
        ? default!
        : JsonSerializer.Deserialize<T>(element.GetRawText(), CloudflareJson.Options)!;

    /// <summary>Sends, strips <paramref name="secretMembers"/> from the answer and only then builds the model, so no secret lands in <c>AdditionalData</c>.</summary>
    public static async Task<T> SendStrippedAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct, params string[] secretMembers)
    {
        var response = await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false);
        return As<T>(Strip(response.Result, secretMembers));
    }

    public static async Task<IReadOnlyList<T>> ListStrippedAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct, params string[] secretMembers)
    {
        var list = new List<T>();
        await foreach (var item in api.ListAllAsync<JsonElement>(path, perPage, ct).ConfigureAwait(false))
            list.Add(As<T>(Strip(item, secretMembers)));
        return list;
    }

    public static JsonArray Arr(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

    public static JsonNode? Node(JsonElement? element) =>
        element is { } e && e.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) ? JsonNode.Parse(e.GetRawText()) : null;

    /// <summary>A bare hostname (lowercase, no scheme, port or path); <paramref name="allowWildcard"/> permits a leading <c>*.</c>.</summary>
    public static string Hostname(string? value, string parameter, bool allowWildcard = false)
    {
        var host = (value ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length is 0 or > 255 || !HostnamePattern.IsMatch(host) || (!allowWildcard && host.StartsWith("*.", StringComparison.Ordinal)))
            throw new ArgumentException($"\"{value}\" is not a valid hostname (no scheme, port or path{(allowWildcard ? "" : ", no wildcard")}).", parameter);
        return host;
    }

    public static string Required(string? value, string parameter, int maxLength = 0)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("A value is required.", parameter);
        if (maxLength > 0 && value.Length > maxLength) throw new ArgumentException($"At most {maxLength} characters.", parameter);
        return value;
    }

    public static string Join(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count == 0 ? "none" : string.Join(", ", list);
    }

    /// <summary>True when every member of <paramref name="desired"/> is present with the same value in <paramref name="current"/> (Cloudflare adds defaults).</summary>
    public static bool Covers(JsonNode? current, JsonNode? desired)
    {
        if (desired is null) return true;
        if (desired is JsonObject d)
        {
            if (current is not JsonObject c) return false;
            foreach (var (name, value) in d)
            {
                if (value is null) { if (c[name] is not null) return false; continue; }
                if (!c.ContainsKey(name) || !Covers(c[name], value)) return false;
            }
            return true;
        }
        return JsonNode.DeepEquals(current, desired);
    }
}
